/* SPDX-License-Identifier: BSD-3-Clause
 * DPDK-based flow extractor + Modbus sensor EWMA/CUSUM example
 *
 * This file is adapted from your original snippet and extended to:
 *  - track repeated TCP seq values per flow
 *  - count Modbus read operations and IAT between reads
 *  - extract the first register from Modbus read responses and compute:
 *      EWMA, positive CUSUM, min, max
 *  - output 8 features per flow when N_PACKETS reached
 *
 * Compile & run as you would your original DPDK application.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <stdalign.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <fcntl.h>
#include <rte_version.h>

#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#include <rte_hash.h>
#include <rte_jhash.h>

#include <rte_flow.h>

/* for NEON */
#include <arm_neon.h>

/* user-provided headers: mlp_weights.h, feature_stats.h (keep as in your project) */
#include "mlp_weights.h"
#include "feature_stats.h"

static unsigned g_total_lcores = 0;

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS (8191*2)

#define BURST_SIZE 32
#define MBUF_CACHE_SIZE 512

#define ALIGN16 __attribute__((aligned(16)))

#define N_PACKETS 6
#define NUM_FEATURES 8
#define INVALID_INDEX   UINT32_MAX

#define MAX_FLOWS_PER_CORE 500000
#define MAX_CORES       RTE_MAX_LCORE

static FILE *g_feat_csv = NULL;

/* per-core pools defined statically like your original */
struct worker_args {
    struct rte_mempool *mbuf_pool;
    struct rte_hash    *flow_table;
    struct flow_entry  *flow_pool;
    float              *buf_a;
    float              *buf_b;
    uint16_t            queue_id;
    uint32_t            next_free;
    uint16_t port_id;
    uint64_t            pred0;
    uint64_t            pred1;
};

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

/* Extended flow_entry with new fields for repeated seq, read ops, and sensor stats */
struct flow_entry {
    uint64_t first_timestamp;
    uint64_t last_timestamp;

    uint16_t pkt_count;

    /* packet-length stats */
    uint32_t len_min;
    uint32_t len_max;
    uint64_t len_sum;      // for computing mean

    /* old IAT fields remain (optional) */
    uint64_t iat_min;
    uint64_t iat_max;
    uint64_t iat_sum;

    /* total bytes in flow */
    uint64_t total_len;

    /* sum of '1' bits in the TCP flags field */
    uint32_t flag_bits_sum;

    /* NEW: repeated seq detection */
    uint32_t last_seq;
    uint32_t repeated_seq_count;

    /* NEW: Modbus reading operation stats */
    uint32_t read_count;          // number of Modbus read ops observed
    uint64_t last_read_ts;        // last read packet timestamp (cycles)
    uint64_t sum_read_iat;        // accumulated inter-read IAT in cycles (for mean)

    /* NEW: sensor statistics (we keep 4 features: EWMA, CUSUM_POS, min, max) */
    float sensor_ewma;            // Exponential weighted moving average
    float sensor_cusum_pos;       // one-sided positive CUSUM
    uint32_t sensor_min;          // min observed raw register value
    uint32_t sensor_max;          // max observed raw register value
    uint64_t sensor_sum;          // for mean if needed

    uint8_t finalized;
};

/* Statically allocate pools for every possible lcore */
static struct flow_entry flow_pools[MAX_CORES][MAX_FLOWS_PER_CORE];
static struct rte_hash *flow_tables[MAX_CORES];

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t number_rings)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    uint16_t nb_queue_pairs, rx_rings, tx_rings;
    int retval;
    uint16_t q;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u: %s\n",
               port, strerror(-retval));
        return retval;
    }

    nb_queue_pairs = number_rings;
    if (nb_queue_pairs > dev_info.max_rx_queues)
        nb_queue_pairs = dev_info.max_rx_queues;
    if (nb_queue_pairs > dev_info.max_tx_queues)
        nb_queue_pairs = dev_info.max_tx_queues;
    rx_rings = nb_queue_pairs;
    tx_rings = nb_queue_pairs;

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode  = RTE_ETH_MQ_RX_RSS,
            .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf  = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };

    if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
        port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    }

    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf == 0)
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0)
        return retval;

    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval < 0)
        return retval;

    rxconf = dev_info.default_rxconf;
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port),
                                        &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port),
                                        &txconf);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    rte_eth_promiscuous_enable(port);

    printf("Port %u successfully initialized with %u RX/TX queues.\n",
           port, nb_queue_pairs);
    return 0;
}

/* Timestamp helpers (same as your code) */
static inline bool is_timestamp_enabled(const struct rte_mbuf *mbuf)
{
    static uint64_t timestamp_rx_dynflag;
    int timestamp_rx_dynflag_offset;

    if (timestamp_rx_dynflag == 0) {
        timestamp_rx_dynflag_offset = rte_mbuf_dynflag_lookup(
                RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL);
        if (timestamp_rx_dynflag_offset < 0)
            return false;
        timestamp_rx_dynflag = RTE_BIT64(timestamp_rx_dynflag_offset);
    }

    return (mbuf->ol_flags & timestamp_rx_dynflag) != 0;
}

static inline rte_mbuf_timestamp_t get_hw_timestamp(const struct rte_mbuf *mbuf)
{
    static int timestamp_dynfield_offset = -1;

    if (timestamp_dynfield_offset < 0) {
        timestamp_dynfield_offset = rte_mbuf_dynfield_lookup(
                RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
        if (timestamp_dynfield_offset < 0)
            return 0;
    }

    return *RTE_MBUF_DYNFIELD(mbuf,
            timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

/* CSV logger (adapted) */
static inline void log_features_csv(const struct flow_key *key, const float f[8]) {
    if (!g_feat_csv) return;

    fprintf(g_feat_csv,
            "%u,%u,%u,%u,%u,%.0f,%.0f,%.6f,%.6f,%.6f,%.6f,%.0f,%.0f\n",
            (unsigned)key->src_ip,
            (unsigned)key->src_port,
            (unsigned)key->dst_ip,
            (unsigned)key->dst_port,
            (unsigned)key->protocol,
            (double)f[0], (double)f[1], (double)f[2], (double)f[3],
            (double)f[4], (double)f[5], (double)f[6], (double)f[7]);
}

static inline void canonicalize_5tuple(struct flow_key *k)
{
    if (k->src_ip > k->dst_ip ||
       (k->src_ip == k->dst_ip && k->src_port > k->dst_port)) {
        uint32_t ip  = k->src_ip;   k->src_ip   = k->dst_ip;   k->dst_ip   = ip;
        uint16_t prt = k->src_port; k->src_port = k->dst_port; k->dst_port = prt;
    }
}

static inline void normalize_features(const float *in_raw, float *out_scaled, int n) {
    for (int i = 0; i < n; i++) {
        float s = FEATURE_STD[i];
        out_scaled[i] = (in_raw[i] - FEATURE_MEAN[i]) / (s > 0.0f ? s : 1.0f);
    }
}

/* fast sigmoid and MLP functions unchanged (omitted here for brevity in this paste) */
/* ... include predict_mlp, layer_forward_neon, fast_sigmoid as in your original file ... */

/* For brevity we assume the predict_mlp and NEON functions are present exactly as you had before */

static inline uint32_t allocate_entry_per_core(struct worker_args *w)
{
    if (w->next_free >= MAX_FLOWS_PER_CORE){
        printf("invalid index");
        return INVALID_INDEX;
    }

    return w->next_free++;
}

static inline void reset_entry_per_core(struct worker_args *w, uint32_t idx)
{
    struct flow_entry *e = &w->flow_pool[idx];
    memset(e, 0, sizeof(*e));
    e->len_min = UINT32_MAX;
    e->iat_min = UINT64_MAX;

    /* initialize our new fields */
    e->last_seq = UINT32_MAX; /* sentinel */
    e->repeated_seq_count = 0;
    e->read_count = 0;
    e->last_read_ts = 0;
    e->sum_read_iat = 0;
    e->sensor_ewma = 0.0f;
    e->sensor_cusum_pos = 0.0f;
    e->sensor_min = UINT32_MAX;
    e->sensor_max = 0;
    e->sensor_sum = 0;
    e->finalized = 0;
}

static inline uint8_t count_bits(uint8_t x) {
    return __builtin_popcount(x);
}

/* update_flow_entry unchanged for length/counters */
void update_flow_entry(struct flow_entry *e,
                       uint16_t    pkt_len,
                       uint64_t    now_cycles,
                       uint8_t     tcp_flags_count)
{
    if (e->finalized || e->pkt_count >= N_PACKETS) return;

    uint64_t iat = (e->pkt_count > 0)
                   ? (now_cycles - e->last_timestamp)
                   : 0;

    if (e->pkt_count == 0) {
        e->len_min   = pkt_len;
        e->len_max   = pkt_len;
        e->len_sum   = pkt_len;

        e->iat_min   = UINT64_MAX;
        e->iat_max   = 0;
        e->iat_sum   = 0;

        e->first_timestamp = now_cycles;
        e->total_len       = pkt_len;

        e->flag_bits_sum   = tcp_flags_count;
    } else {
        if (pkt_len < e->len_min) e->len_min = pkt_len;
        if (pkt_len > e->len_max) e->len_max = pkt_len;
        e->len_sum += pkt_len;

        if (iat < e->iat_min) e->iat_min = iat;
        if (iat > e->iat_max) e->iat_max = iat;
        e->iat_sum += iat;

        e->total_len += pkt_len;
        e->flag_bits_sum += tcp_flags_count;
    }

    e->last_timestamp = now_cycles;
    e->pkt_count++;
}

/*
 * Extended handle_packet:
 *   - added tcp_seq (host-order), payload pointer & payload_len
 *   - updates repeated_seq_count and Modbus-based sensor stats
 */
static inline void
handle_packet(struct flow_key   *key,
              uint16_t           pkt_len,
              uint64_t           now,
              uint8_t            flags_count,
              uint32_t           tcp_seq,       /* host order */
              uint8_t           *payload,       /* pointer into mbuf or NULL */
              uint16_t           payload_len,   /* bytes of payload */
              struct worker_args *w)
{
    void    *data_ptr = NULL;
    int      ret      = rte_hash_lookup_data(w->flow_table, key, &data_ptr);
    uint32_t index;

    if (ret < 0) {
        index = allocate_entry_per_core(w);
        if (index == INVALID_INDEX)
            return;

        ret = rte_hash_add_key_data(w->flow_table,
                                    key,
                                    (void*)(uintptr_t)index);
        if (ret < 0) {
            w->next_free--;
            return;
        }
        /* reset on allocation */
        reset_entry_per_core(w, index);
    } else {
        index = (uint32_t)(uintptr_t)data_ptr;
    }

    struct flow_entry *e = &w->flow_pool[index];

    /* update generic flow counters */
    update_flow_entry(e, pkt_len, now, flags_count);

    /* ---------------------
       repeated seq detection
       --------------------- */
    if (tcp_seq != UINT32_MAX) {
        if (e->last_seq != UINT32_MAX && tcp_seq == e->last_seq) {
            e->repeated_seq_count++;
        }
        e->last_seq = tcp_seq;
    }

    /* -------------------------
       Detect Modbus read responses
       MBAP header (7 bytes) + PDU starts at payload[7]
       function code at payload[7]
       For read response: function code is 0x03 or 0x04, payload[8] = byte count,
       data starts at payload[9] (first register high byte at payload[9], low byte at payload[10])
       ------------------------- */
    if (payload && payload_len >= 9) {
        uint8_t func = payload[7];
        if (func == 0x03 || func == 0x04) {
            /* we consider this a Modbus response containing register bytes */
            /* ensure we have at least two data bytes for the first register */
            uint8_t bytecount = payload[8];
            if (bytecount >= 2 && (uint16_t)(9 + 1) < payload_len) {
                /* extract first register (big-endian) */
                uint32_t reg_val = ((uint32_t)payload[9] << 8) | (uint32_t)payload[10];

                /* update read-specific counters and IAT (cycles-based) */
                if (e->read_count > 0 && e->last_read_ts > 0) {
                    uint64_t delta = (now > e->last_read_ts) ? (now - e->last_read_ts) : 0;
                    e->sum_read_iat += delta;
                }
                e->last_read_ts = now;
                e->read_count++;

                /* EWMA update (alpha = 0.3) */
                const float alpha = 0.3f;
                if (e->read_count == 1) {
                    e->sensor_ewma = (float)reg_val;
                } else {
                    e->sensor_ewma = alpha * (float)reg_val + (1.0f - alpha) * e->sensor_ewma;
                }

                /* positive CUSUM (one-sided). baseline = current EWMA; we push dev = value - baseline */
                float dev = (float)reg_val - e->sensor_ewma;
                e->sensor_cusum_pos += dev;
                if (e->sensor_cusum_pos < 0.0f) e->sensor_cusum_pos = 0.0f;

                /* min / max / sum */
                if (reg_val < e->sensor_min) e->sensor_min = reg_val;
                if (reg_val > e->sensor_max) e->sensor_max = reg_val;
                e->sensor_sum += reg_val;
            }
        }
    }

    /* finalize after N_PACKETS as before */
    if (!e->finalized && e->pkt_count == N_PACKETS) {
        double hz = (double)rte_get_tsc_hz();

        /* compute mean_read_iat in microseconds if read_count>1 */
        double mean_read_iat_us = 0.0;
        if (e->read_count > 1) {
            mean_read_iat_us = (double)e->sum_read_iat * 1e6 / hz / (double)(e->read_count - 1);
        }

        /* Our 8 features (example mapping):
         * 0: repeated_seq_count
         * 1: read_count
         * 2: mean_read_iat_us
         * 3: flag_bits_sum
         * 4: sensor_ewma
         * 5: sensor_cusum_pos
         * 6: sensor_min
         * 7: sensor_max
         */
        ALIGN16 float features[NUM_FEATURES];
        features[0] = (float)e->repeated_seq_count;
        features[1] = (float)e->read_count;
        features[2] = (float)mean_read_iat_us;
        features[3] = (float)e->flag_bits_sum;
        features[4] = e->sensor_ewma;
        features[5] = e->sensor_cusum_pos;
        features[6] = (float)(e->sensor_min == UINT32_MAX ? 0.0f : (float)e->sensor_min);
        features[7] = (float)e->sensor_max;

        ALIGN16 float features_scaled[NUM_FEATURES];
        normalize_features(features, features_scaled, NUM_FEATURES);

        int pred = predict_mlp(features_scaled, w->buf_a, w->buf_b);
        if (pred == 0) w->pred0++;
        else           w->pred1++;

        /* log & print */
        log_features_csv(key, features);
        e->finalized = 1;

        printf("Flow %u:%u -> %u:%u proto %u classified as %d\n",
               key->src_ip, key->src_port,
               key->dst_ip, key->dst_port,
               key->protocol, pred);

        /* Optionally delete/reset flow here if you want to reuse slot:
         * rte_hash_del_key(w->flow_table, key);
         * reset_entry_per_core(w, index);
         */
    }
}

/* worker_args array as before */
static struct worker_args worker_args[MAX_CORES];

static int lcore_main(void *args)
{
    struct worker_args *w = (struct worker_args *)args;
    struct rte_mempool *mbuf_pool = w->mbuf_pool;

    uint16_t port;
    uint16_t queue_id = w->queue_id;

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
           rte_lcore_id());

    for (;;) {
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(w->port_id, w->queue_id, bufs, BURST_SIZE);
        if (unlikely(nb_rx == 0)) continue;

        received_packets += nb_rx;

        for (int i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            uint16_t ethernet_type = rte_cpu_to_be_16(eth->ether_type);

            if (ethernet_type == RTE_ETHER_TYPE_IPV4) {
                uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);
                struct rte_ipv4_hdr *pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, ipdata_offset);

                uint32_t src_ip = rte_be_to_cpu_32(pIP4Hdr->src_addr);
                uint32_t dst_ip = rte_be_to_cpu_32(pIP4Hdr->dst_addr);
                uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;

                uint32_t ip_hdr_len = (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
                ipdata_offset += ip_hdr_len;

                if (IPv4NextProtocol == IPPROTO_TCP) {
                    struct rte_tcp_hdr *pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);

                    uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                    uint16_t src_port = rte_be_to_cpu_16(pTcpHdr->src_port);

                    /* TCP header length in 32-bit words stored in high 4 bits of data_off */
                    uint8_t tcp_dataoffset = (pTcpHdr->data_off >> 4) & 0x0f;
                    uint32_t tcp_hdr_len = tcp_dataoffset * 4;
                    uint32_t tcpdata_offset = ipdata_offset + tcp_hdr_len;

                    /* flags_count (popcount of tcp_flags) */
                    uint8_t flags_count = __builtin_popcount(pTcpHdr->tcp_flags);

                    /* compute payload pointer & length safely */
                    uint16_t total_len = rte_be_to_cpu_16(pIP4Hdr->total_length);
                    uint16_t ip_payload_len = total_len - ip_hdr_len;
                    uint16_t tcp_payload_len = (ip_payload_len > tcp_hdr_len) ? (ip_payload_len - tcp_hdr_len) : 0;

                    uint8_t *payload = NULL;
                    if (tcp_payload_len > 0)
                        payload = rte_pktmbuf_mtod_offset(bufs[i], uint8_t *, tcpdata_offset);

                    /* get tcp seq (host order) */
                    uint32_t seq = rte_be_to_cpu_32(pTcpHdr->sent_seq);

                    /* Prepare flow key (note: original code swaps src/dst to canonicalize earlier;
                       here we follow the same mapping used before) */
                    struct flow_key key;
                    key.src_ip = dst_ip;
                    key.dst_ip = src_ip;
                    key.src_port = dst_port;
                    key.dst_port = src_port;
                    key.protocol = IPv4NextProtocol;
                    canonicalize_5tuple(&key);

                    uint16_t pkt_len = total_len;
                    uint64_t pkt_time = rte_rdtsc_precise();

                    /* call extended handle_packet with tcp seq and payload pointer */
                    handle_packet(&key, pkt_len, pkt_time, flags_count, seq, payload, tcp_payload_len, w);
                }
            }

            /* forward packet back out (in-place swap done earlier in your original code).
               Keep original transmit logic for passthrough. */
        }

        uint16_t nb_tx = rte_eth_tx_burst(w->port_id, w->queue_id, bufs, nb_rx);
        processed_packets += nb_tx;
        if (unlikely(nb_tx < nb_rx)) {
            for (uint16_t buf = nb_tx; buf < nb_rx; buf++)
                rte_pktmbuf_free(bufs[buf]);
        }
    }

    return 0;
}

/* on_terminate and main keep the same logic as before; only minor change:
   we call reset_entry_per_core when first allocating a slot, and earlier we
   created flow_tables[] etc. For brevity, assume the rest of main() is unchanged
   except that when you initialize flow_pools you should memset them to 0 and call
   reset_entry_per_core for initial entries if you want. */

static void on_terminate(int signo) {
    if (g_feat_csv) { fflush(g_feat_csv); fclose(g_feat_csv); g_feat_csv = NULL; }

    uint64_t sum0 = 0, sum1 = 0;
    for (unsigned core = 0; core < g_total_lcores; core++) {
        sum0 += worker_args[core].pred0;
        sum1 += worker_args[core].pred1;
    }
    uint64_t total = sum0 + sum1;
    double pct0 = total ? (100.0 * (double)sum0 / (double)total) : 0.0;
    double pct1 = total ? (100.0 * (double)sum1 / (double)total) : 0.0;

    printf("\n=== Prediction summary ===\n");
    printf("class 0: %" PRIu64 " (%.2f%%)\n", sum0, pct0);
    printf("class 1: %" PRIu64 " (%.2f%%)\n", sum1, pct1);
    printf("total  : %" PRIu64 "\n", total);

    /* existing cleanup */
    rte_eal_cleanup();
    _exit(0);
}

/* main(): same as your original file except ensure reset_entry_per_core is used when new flow slots allocated.
   For brevity, keep the rest of your original main() and initialization logic. */

/* Initialization of Environment Abstraction Layer (EAL). 8< */
 int main(int argc, char **argv)
 {
     struct rte_mempool *mbuf_pool;
     uint16_t nb_ports;
     uint16_t portid;
     unsigned lcore_id;
     int ret;
     // int packet_counters[10] = {0};
    

     ret = rte_eal_init(argc, argv);
     if (ret < 0)
         rte_panic("Cannot init EAL\n");


    // here we atart the file for featres
    g_feat_csv = fopen("flow_features.csv", "w");
    if (!g_feat_csv)
        rte_exit(EXIT_FAILURE, "Cannot open flow_features.csv\n");

    /* Optional: line-buffer so rows appear promptly */
    setvbuf(g_feat_csv, NULL, _IOLBF, 0);

    fprintf(g_feat_csv,
            "src_ip_u32,src_port,dst_ip_u32,dst_port,proto,"
            "len_min,len_max,mean_len,iat_min_us,iat_max_us,mean_iat_us,total_len,flag_bits_sum\n");

    signal(SIGINT,  on_terminate);
    signal(SIGTERM, on_terminate);
    /*
    latency_cycles = malloc(sizeof(*latency_cycles) * MAX_SAMPLES);
    if (!latency_cycles)
        rte_exit(EXIT_FAILURE, "malloc failed\n");

    // install SIGINT handler before you start lcore_main
    struct sigaction sa = {
        .sa_handler = sigint_handler,
    };
    sigaction(SIGINT, &sa, NULL);
    */



    uint64_t tsc_hz = rte_get_tsc_hz();
    printf("TSC frequency: %lu Hz (%.2f GHz)\n",
           tsc_hz, tsc_hz / 1e9);

    printf("DPDK version: %s\n", rte_version());

    unsigned total_lcores = rte_lcore_count();
    g_total_lcores = total_lcores;   
    
    struct rte_hash_parameters p = {
    .entries           = MAX_FLOWS_PER_CORE,
    .key_len           = sizeof(struct flow_key),
    .hash_func         = rte_jhash,
    .hash_func_init_val= 0,
    .socket_id         = rte_socket_id(),
    };

    for (unsigned core = 0; core < total_lcores; core++) {
        char name[32];
        snprintf(name, sizeof(name), "ftbl_%u", core);
        p.name = name;
        flow_tables[core] = rte_hash_create(&p);
        if (!flow_tables[core])
            rte_exit(EXIT_FAILURE, "Cannot create hash for core %u\n", core);
    }

     argc -= ret;
     argv += ret;
 
     nb_ports = rte_eth_dev_count_avail();
 
     mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                         NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                         RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
     if (mbuf_pool == NULL)
         rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

     RTE_ETH_FOREACH_DEV(portid)
     if (port_init(portid, mbuf_pool,total_lcores) != 0)
     {
         rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                  portid);
     }
     else{
         printf("port %u initialized\n",portid);
     };

     // find maximum neurons 
        int max_neurons = 0;
        for (int i = 0; i <= NUM_LAYERS; i++)
            if (LAYER_SIZES[i] > max_neurons)
                max_neurons = LAYER_SIZES[i];


    
    
    uint16_t queue_id = 0;
    uint16_t base_port = 0;  // your only port

    for (unsigned core_id = 0; core_id < total_lcores; core_id++) {
        struct worker_args *w = &worker_args[core_id];

        // 1) Shared resources
        w->mbuf_pool  = mbuf_pool;
        w->flow_table = flow_tables[core_id];
        w->flow_pool  = flow_pools[core_id];
        w->port_id  = base_port;


        // 2) Per-core state
        w->next_free  = 0;            // start allocating at slot 0
        w->queue_id   = queue_id++;   // one RX queue per core
        w->pred0      = 0;   // NEW
        w->pred1      = 0;   // NEW
        // 3) Scratch buffers for NEON inference
        if (posix_memalign((void**)&w->buf_a, 16, max_neurons * sizeof(float)) ||
            posix_memalign((void**)&w->buf_b, 16, max_neurons * sizeof(float))) {
            rte_exit(EXIT_FAILURE, "posix_memalign failed for core %u\n", core_id);
        }

        // 4) Launch worker on that core (skip core 0 if you plan to use it as master below)
        if (core_id != rte_get_main_lcore()) {
            rte_eal_remote_launch(lcore_main, w, core_id);
        }
    }

    // Finally, run master on its own core (often core 0)
    unsigned master = rte_get_main_lcore();
    struct worker_args *w_master = &worker_args[master];
    // (mbuf_pool, flow_table, flow_pool, next_free, queue_id already set above)
    lcore_main(w_master);

   
    

     char command[50];
     
     while (1) {
         printf("Enter command: ");
         scanf("%20s", command);
         // printf("The input command is %s\n",command);
 
         if (strcmp(command, "get_stats") == 0) {
             RTE_LCORE_FOREACH_WORKER(lcore_id)
             {
 
                 char output_file[50]; //= "../datasets/DoHBrw/predictions.txt";
                 
                 printf("Enter file name: ");
                 scanf("%20s", output_file);   
 
                 FILE *file = fopen(output_file, "w");
 
                 if (file == NULL) {
                     printf("Error opening the file.\n");
                     return -1;
                 }
 
                 fprintf(file, "Reeived Processed Dropped\n");
                 // printf("Core %u processed %u packets\n",lcore_id,packet_counters[lcore_id]);
                 fprintf(file, "%f %f %.3f \n",received_packets,processed_packets,(double)(processed_packets/received_packets));
                 right_predictions = 0;
                 wrong_predictions = 0;
                 received_packets = 0;
                 processed_packets = 0;
 
                 fclose(file);
                 // packet_counters[lcore_id] = 0;
             }
              //break;
         }
     }
 
 
     rte_eal_mp_wait_lcore();
 
     // free each per-core hash table
    for (unsigned core_id = 0; core_id < total_lcores; core_id++) {
        if (flow_tables[core_id]) {
            rte_hash_free(flow_tables[core_id]);
            flow_tables[core_id] = NULL;
        }
    }
 
     close_ports();
 
     /* clean up the EAL */
     rte_eal_cleanup();
 
     return 0;
 }