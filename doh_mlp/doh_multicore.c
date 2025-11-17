/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>     // usleep, etc.
#include <fcntl.h>
#include <math.h>

#include <stdalign.h>
#include <stdatomic.h>  // C11 atomics

/* DPDK headers - grouped */
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_version.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_cycles.h>
#include <rte_debug.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include <rte_memory.h>

/* platform / arch */
#include <arm_neon.h>   // for NEON optimized inference (BlueField2)

/* app-specific includes (weights, normalization constants, etc) */
#include "mlp_weights.h"
#include "feature_stats.h"

/* ------------------------------------------------------------------ */
/* Tunables and constants - tweak for perf/experimenting              */
/* ------------------------------------------------------------------ */

#define MAX_CORES       RTE_MAX_LCORE
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 512
#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024

#define QUEUE_SIZE      256
#define BURST_SIZE      32

#define ALIGN16 __attribute__((aligned(16)))

#define MAX_SAMPLES_PER_CORE 5000
#define MAX_FLOWS_PER_CORE 65536

#define N_PACKETS 64
#define NUM_FEATURES 16
#define INVALID_INDEX   UINT32_MAX

#define RSS_HASH_KEY_LENGTH 40

/* quick-and-dirty RSS key */
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
    0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,
    0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,
    0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,
    0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,
    0x6D,0x5A,0x6D,0x5A,0x6D,0x5A,0x6D,0x5A
};

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

/* flow 5-tuple key - packed so hash sees compact bytes */
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} __attribute__((packed));

/* per-flow entry - layout tuned for hot fields first */
struct flow_entry {
    uint32_t pkt_count_client;
    uint32_t pkt_count_server;
    uint64_t bytes_client;
    uint64_t bytes_server;

    uint32_t pkt_len_min_client;
    uint32_t pkt_len_max_client;
    uint32_t pkt_len_min_server;
    uint32_t pkt_len_max_server;
    uint64_t pkt_len_sum_client;
    uint64_t pkt_len_sum_server;

    uint8_t  last_direction;   // 0 unknown, 1 client, 2 server
    uint16_t dir_switches;
    uint8_t  finalized;
    uint64_t first_packet_tsc;
    uint64_t last_packet_tsc;

    uint32_t next_free;        // for the per-core free list
} __rte_cache_aligned;

/* per-worker / per-lcore state */
struct worker_args {
    struct rte_mempool *mbuf_pool;  // per-core mbuf pool
    struct rte_hash    *flow_table;
    struct flow_entry  *flow_pool;  // preallocated array per core
    float              *buf_a;      // scratch buffers for inference (NEON)
    float              *buf_b;
    uint16_t            queue_id;
    uint16_t            port_id;

    /* lock-free allocator state (actually single-writer per-core) */
    uint32_t free_flow_head;
    uint32_t free_flow_count;

    /* per-worker timing buffers */
    uint64_t *feat_cycles;      // cycles taken by feature extraction
    uint64_t *infer_cycles;     // cycles taken by inference
    uint64_t *flow_duration_cycles;
    int32_t  *sample_class;
    size_t   samples_capacity;
    size_t   samples_count;

    uint64_t *pred_count;       // histogram per class

    /* per-core counters */
    uint64_t received_packets;
    uint64_t processed_packets;
    uint64_t right_predictions;
    uint64_t wrong_predictions;

    /* per-core latency samples + CSV handle */
    uint64_t *latency_cycles;
    size_t    latency_count;
    FILE     *feat_csv;
};

/* ------------------------------------------------------------------ */
/* Global-ish arrays (statically allocated)                            */
/* ------------------------------------------------------------------ */

static struct flow_entry flow_pools[MAX_CORES][MAX_FLOWS_PER_CORE];
static struct rte_hash *flow_tables[MAX_CORES];
static struct rte_mempool *mbuf_pools[MAX_CORES];
static struct worker_args worker_args[MAX_CORES];

static unsigned g_total_lcores = 0;

/* shutdown flag - atomic so workers can poll it safely */
static atomic_int force_quit = 0;

/* ------------------------------------------------------------------ */
/* Small helpers / math / activation                                   */
/* ------------------------------------------------------------------ */

/* fast popcount wrapper */
static inline uint8_t count_bits(uint8_t x) {
    return __builtin_popcount(x);
}

/* piecewise sigmoid that is cheap-ish */
static inline float sigmoid_piece(float x) {
    if (x <= -4.0f) return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <= 0.0f)  return 0.125f * x + 0.5f;
    else if (x <= 2.0f)  return -0.125f * x + 0.5f;
    else if (x <= 4.0f)  return -0.0625f * x + 0.75f;
    else return 1.0f;
}

/* NEON sigmoid attempt - kept for vector paths (maybe not perfect) */
static inline float32x4_t sigmoid_neon(float32x4_t x) {
    float32x4_t abs_x = vabsq_f32(x);
    float32x4_t one = vdupq_n_f32(1.0f);
    float32x4_t ratio = vdivq_f32(abs_x, vaddq_f32(one, abs_x));
    uint32x4_t mask = vcgeq_f32(x, vdupq_n_f32(0.0f));
    float32x4_t pos = ratio;
    float32x4_t neg = vsubq_f32(one, ratio);
    return vbslq_f32(mask, pos, neg);
}

/* matrix-vector forward for a layer, NEON-optimized
 * - W is size_in x size_out in row-major (k * size_out + j)
 * - B is bias length size_out
 * - in/out are contiguous vectors
 * - is_output: if false apply relu, if true leave raw (caller will final-activate)
 *
 * Tail-handling done with scalar loop (no risk of skipping)
 */
static void layer_forward_neon(const float *W, const float *B,
                               const float *in, float *out,
                               int size_in, int size_out,
                               int is_output) {
    int j = 0;
    for (; j + 4 <= size_out; j += 4) {
        float32x4_t acc = vld1q_f32(&B[j]);
        for (int k = 0; k < size_in; k++) {
            acc = vfmaq_f32(acc,
                            vdupq_n_f32(in[k]),
                            vld1q_f32(&W[k*size_out + j]));
        }
        if (!is_output) acc = vmaxq_f32(acc, vdupq_n_f32(0.0f)); // relu
        vst1q_f32(&out[j], acc);
    }
    for (; j < size_out; j++) {
        float a = B[j];
        for (int k = 0; k < size_in; k++)
            a += W[k*size_out + j] * in[k];
        if (!is_output) a = (a > 0.0f) ? a : 0.0f;
        out[j] = a;
    }
}

/* run MLP prediction, returns predicted class
 * - copies input into scratch, runs layers, applies final activation depending on task
 * - returns - for binary classification: 0/1 ; multiclass: class index
 */
static int predict_mlp(const float *in_features, float *buf_a, float *buf_b) {
    float *in_buf = buf_a, *out_buf = buf_b;
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        int is_output_layer = (L == NUM_LAYERS - 1);
        layer_forward_neon(WEIGHTS[L], BIASES[L],
                           in_buf, out_buf,
                           LAYER_SIZES[L],
                           LAYER_SIZES[L+1],
                           is_output_layer);
        if (is_output_layer) {
            #if IS_BINARY_CLASSIFICATION
            for (int i = 0; i < LAYER_SIZES[L+1]; i++)
                out_buf[i] = sigmoid_piece(out_buf[i]);
            #elif IS_MULTICLASS_CLASSIFICATION
            float max_val = out_buf[0];
            for (int i = 1; i < LAYER_SIZES[L+1]; i++)
                if (out_buf[i] > max_val) max_val = out_buf[i];

            float sum = 0.0f;
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] = expf(out_buf[i] - max_val);
                sum += out_buf[i];
            }
            for (int i = 0; i < LAYER_SIZES[L+1]; i++)
                out_buf[i] /= sum;
            #endif
        }
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    int final_size = LAYER_SIZES[NUM_LAYERS];
    #if IS_BINARY_CLASSIFICATION
    return (in_buf[0] >= 0.5f) ? 1 : 0;
    #elif IS_MULTICLASS_CLASSIFICATION
    int best_class = 0;
    float best_probability = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_probability) {
            best_probability = in_buf[i];
            best_class = i;
        }
    }
    return best_class;
    #endif
}

/* ------------------------------------------------------------------ */
/* Flow allocator / helpers (per-core single-writer, so cheap ops)     */
/* ------------------------------------------------------------------ */

/* Reset an entry's fields (prepare for reuse)
 * - call while holding nothing (single-writer semantics guarantee no races)
 */
static inline void reset_entry_per_core(struct worker_args *w, uint32_t idx) {
    struct flow_entry *e = &w->flow_pool[idx];
    memset(e, 0, sizeof(*e));

    e->pkt_len_min_client = UINT32_MAX;
    e->pkt_len_min_server = UINT32_MAX;
    e->pkt_len_max_client = 0;
    e->pkt_len_max_server = 0;

    e->pkt_len_sum_client = 0;
    e->pkt_len_sum_server = 0;
    e->bytes_client = 0;
    e->bytes_server = 0;
    e->pkt_count_client = 0;
    e->pkt_count_server = 0;

    e->last_direction = 0;
    e->dir_switches = 0;

    e->finalized = 0;

    e->first_packet_tsc = 0;
    e->last_packet_tsc = 0;
}

/* add back to free list - single writer so no atomics here */
static inline void free_flow_entry(struct worker_args *w, uint32_t index) {
    if (index >= MAX_FLOWS_PER_CORE) return;
    w->flow_pool[index].next_free = w->free_flow_head;
    w->free_flow_head = index;
    w->free_flow_count++;
}

/* allocate a free entry (lock-free-ish since only owner core touches it) */
static inline uint32_t allocate_entry_lockfree(struct worker_args *w) {
    if (w->free_flow_head == INVALID_INDEX) {
        return INVALID_INDEX;
    }
    uint32_t index = w->free_flow_head;
    w->free_flow_head = w->flow_pool[index].next_free;
    w->free_flow_count--;
    reset_entry_per_core(w, index);
    return index;
}

/* canonicalize 5-tuple so flow direction doesn't matter (quick lexicographic) */
static inline void canonicalize_5tuple(struct flow_key *k) {
    if (k->src_ip > k->dst_ip ||
       (k->src_ip == k->dst_ip && k->src_port > k->dst_port)) {
        uint32_t ip  = k->src_ip;   k->src_ip   = k->dst_ip;   k->dst_ip   = ip;
        uint16_t prt = k->src_port; k->src_port = k->dst_port; k->dst_port = prt;
    }
}

/* ------------------------------------------------------------------ */
/* Feature extraction, logging, and packet handling                    */
/* ------------------------------------------------------------------ */

/* Write one line to per-core CSV. If file not open, it's a no-op. */
static inline void log_features_csv(const struct flow_key *key, const float features16[16], struct worker_args *w) {
    if (!w->feat_csv) return;
    int rc = fprintf(w->feat_csv,
        "%u,%u,%u,%u,%u,"   // 5-tuple (u32/u16)
        "%u,%u,%.6f,%u,%.6f,%.0f,%u,%u,%.3f,%.3f,%u,%.0f,%u,%u,%u,%.3f\n",
        key->src_ip, key->src_port, key->dst_ip, key->dst_port, key->protocol,

        (unsigned)features16[0],   // client_pkt_max
        (unsigned)features16[1],   // n_client
        features16[2],             // bytes_fraction_client
        (unsigned)features16[3],   // n_server
        features16[4],             // pkt_fraction_client
        features16[5],             // client_bytes (as integer)
        (unsigned)features16[6],   // server_pkt_max
        (unsigned)features16[7],   // size_min
        features16[8],             // size_mean
        features16[9],             // server_pkt_mean
        (unsigned)features16[10],  // dir_switches
        features16[11],            // server_bytes
        (unsigned)features16[12],  // size_max
        (unsigned)features16[13],  // client_pkt_min
        (unsigned)features16[14],  // server_pkt_min
        features16[15]             // client_pkt_mean
    );

    if (rc < 0) perror("fprintf(feat_csv) failed");
}

/* normalize features using global arrays FEATURE_MEAN, FEATURE_STD */
static inline void normalize_features(const float *in_raw, float *out_scaled, int n) {
    for (int i = 0; i < n; i++) {
        float s = FEATURE_STD[i];
        out_scaled[i] = (in_raw[i] - FEATURE_MEAN[i]) / (s > 0.0f ? s : 1.0f);
    }
}

/* update per-flow stats with a new packet - idempotent-ish until finalized */
static inline void update_flow_entry(struct flow_entry *e,
                  uint16_t           pkt_len,
                  bool               is_client,
                  uint64_t           current_tsc) {

    uint32_t total_pkts = e->pkt_count_client + e->pkt_count_server;

    if (e->finalized || total_pkts >= N_PACKETS) return;

    if (total_pkts == 0) e->first_packet_tsc = current_tsc;

    if (is_client) {
        if (e->pkt_count_client == 0) {
            e->pkt_len_min_client = pkt_len;
            e->pkt_len_max_client = pkt_len;
            e->pkt_len_sum_client = pkt_len;
        } else {
            if ((uint32_t)pkt_len < e->pkt_len_min_client) e->pkt_len_min_client = pkt_len;
            if ((uint32_t)pkt_len > e->pkt_len_max_client) e->pkt_len_max_client = pkt_len;
            e->pkt_len_sum_client += pkt_len;
        }
        e->bytes_client += pkt_len;
        e->pkt_count_client++;
    } else {
        if (e->pkt_count_server == 0) {
            e->pkt_len_min_server = pkt_len;
            e->pkt_len_max_server = pkt_len;
            e->pkt_len_sum_server = pkt_len;
        } else {
            if ((uint32_t)pkt_len < e->pkt_len_min_server) e->pkt_len_min_server = pkt_len;
            if ((uint32_t)pkt_len > e->pkt_len_max_server) e->pkt_len_max_server = pkt_len;
            e->pkt_len_sum_server += pkt_len;
        }
        e->bytes_server += pkt_len;
        e->pkt_count_server++;
    }

    uint8_t cur_dir = is_client ? 1 : 2;
    if (e->last_direction != 0 && e->last_direction != cur_dir) e->dir_switches++;
    e->last_direction = cur_dir;

    total_pkts = e->pkt_count_client + e->pkt_count_server;
    if (total_pkts == N_PACKETS) e->last_packet_tsc = current_tsc;
}

/* This function does most of the per-packet work:
 * - look up or allocate flow entry
 * - update stats
 * - when we've seen N_PACKETS, compute features, predict, log, then reset window
 *
 * note: single writer per-core semantics assumed for flow table and pool
 */
static inline void handle_packet(struct flow_key   *key,
              uint16_t           tls_payload_size,
              struct worker_args *w,
              bool                is_client) {

    void *data_ptr = NULL;
    int ret = rte_hash_lookup_data(w->flow_table, key, &data_ptr);
    uint32_t index;

    if (ret < 0) {
        index = allocate_entry_lockfree(w);
        if (index == INVALID_INDEX) return;

        ret = rte_hash_add_key_data(w->flow_table, key, (void*)(uintptr_t)index);
        if (ret < 0) {
            // hash insert failed - roll back
            free_flow_entry(w, index);
            return;
        }
    } else {
        index = (uint32_t)(uintptr_t)data_ptr;
    }

    struct flow_entry *e = &w->flow_pool[index];
    uint64_t current_tsc = rte_rdtsc_precise();
    update_flow_entry(e, tls_payload_size, is_client, current_tsc);

    uint32_t n_client = e->pkt_count_client;
    uint32_t n_server = e->pkt_count_server;
    uint32_t total_pkts = n_client + n_server;

    if (total_pkts >= N_PACKETS) {
        uint64_t flow_duration_cycles = e->last_packet_tsc - e->first_packet_tsc;
        double client_bytes = (double)e->bytes_client;
        double server_bytes = (double)e->bytes_server;
        double total_bytes = client_bytes + server_bytes;

        uint32_t global_min = UINT32_MAX;
        uint32_t global_max = 0;
        uint64_t global_sum = 0;

        if (n_client > 0) {
            if (e->pkt_len_min_client < global_min) global_min = e->pkt_len_min_client;
            if (e->pkt_len_max_client > global_max) global_max = e->pkt_len_max_client;
            global_sum += e->pkt_len_sum_client;
        }
        if (n_server > 0) {
            if (e->pkt_len_min_server < global_min) global_min = e->pkt_len_min_server;
            if (e->pkt_len_max_server > global_max) global_max = e->pkt_len_max_server;
            global_sum += e->pkt_len_sum_server;
        }

        float size_min = 0.0f;
        if (global_min != UINT32_MAX) size_min = (float)global_min;
        float size_max = (float)global_max;
        float size_mean = 0.0f;
        if (total_pkts > 0) size_mean = (float)((double)global_sum / (double)total_pkts);

        float client_pkt_max  = (n_client > 0) ? (float)e->pkt_len_max_client : 0.0f;
        float client_pkt_min  = (n_client > 0 && e->pkt_len_min_client != UINT32_MAX) ? (float)e->pkt_len_min_client : 0.0f;
        float client_pkt_mean = (n_client > 0) ? (float)((double)e->pkt_len_sum_client / (double)n_client) : 0.0f;

        float server_pkt_max  = (n_server > 0) ? (float)e->pkt_len_max_server : 0.0f;
        float server_pkt_min  = (n_server > 0 && e->pkt_len_min_server != UINT32_MAX) ? (float)e->pkt_len_min_server : 0.0f;
        float server_pkt_mean = (n_server > 0) ? (float)((double)e->pkt_len_sum_server / (double)n_server) : 0.0f;

        float n_client_f = (float)n_client;
        float n_server_f = (float)n_server;

        float bytes_fraction_client = 0.0f;
        if (total_bytes > 0.0) bytes_fraction_client = (float)(client_bytes / total_bytes);

        float pkt_fraction_client = 0.0f;
        if (total_pkts > 0) pkt_fraction_client = (float)((double)n_client / (double)total_pkts);

        float dir_switches_f = (float)e->dir_switches;

        ALIGN16 float features16[16];
        features16[0]  = client_pkt_max;
        features16[1]  = n_client_f;
        features16[2]  = bytes_fraction_client;
        features16[3]  = n_server_f;
        features16[4]  = pkt_fraction_client;
        features16[5]  = (float)client_bytes;
        features16[6]  = server_pkt_max;
        features16[7]  = size_min;
        features16[8]  = size_mean;
        features16[9]  = server_pkt_mean;
        features16[10] = dir_switches_f;
        features16[11] = (float)server_bytes;
        features16[12] = size_max;
        features16[13] = client_pkt_min;
        features16[14] = server_pkt_min;
        features16[15] = client_pkt_mean;

        ALIGN16 float features_scaled[16];

        //uint64_t t0_feat = rte_rdtsc_precise();
        normalize_features(features16, features_scaled, NUM_FEATURES);
        //uint64_t t1_feat = rte_rdtsc_precise();

        //int64_t t0_inf = rte_rdtsc_precise();
        int pred = predict_mlp(features_scaled, w->buf_a, w->buf_b);
        //uint64_t t1_inf = rte_rdtsc_precise();

        //if (pred >= 0 && pred < NUM_CLASSES) w->pred_count[pred]++;
        //size_t idx = w->samples_count;
        //if (idx < w->samples_capacity) {
            //w->feat_cycles[idx]  = t1_feat - t0_feat;
            //w->infer_cycles[idx] = t1_inf  - t0_inf;
            //w->flow_duration_cycles[idx] = flow_duration_cycles;
            //w->sample_class[idx] = pred;
            //w->samples_count = idx + 1;
        //}

        //log_features_csv(key, features16, w);

        /* Reset for next window but keep the flow alive */
        uint64_t new_start_tsc = e->last_packet_tsc;
        e->pkt_count_client = 0;
        e->pkt_count_server = 0;
        e->bytes_client = 0;
        e->bytes_server = 0;
        e->pkt_len_min_client = UINT32_MAX;
        e->pkt_len_min_server = UINT32_MAX;
        e->pkt_len_max_client = 0;
        e->pkt_len_max_server = 0;
        e->pkt_len_sum_client = 0;
        e->pkt_len_sum_server = 0;
        e->last_direction = 0;
        e->dir_switches = 0;
        e->finalized = 0;
        e->first_packet_tsc = new_start_tsc;
        e->last_packet_tsc = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Port init + misc                                                    */
/* ------------------------------------------------------------------ */

/* initialize a port with rx/tx queues, per-queue mbuf pools */
static inline int port_init(uint16_t port, struct rte_mempool **mbuf_pools, uint16_t number_rings) {
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    uint16_t nb_queue_pairs, rx_rings, tx_rings;
    int retval;
    uint16_t q;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u: %s\n", port, strerror(-retval));
        return retval;
    }

    printf("Port %u: max_rx_queues=%u, max_tx_queues=%u, rx_offload_capa=0x%016" PRIx64 ", flow_type=0x%08x\n",
           port, dev_info.max_rx_queues, dev_info.max_tx_queues,
           dev_info.rx_offload_capa, dev_info.flow_type_rss_offloads);

    nb_queue_pairs = number_rings;
    if (nb_queue_pairs > dev_info.max_rx_queues) {
        printf("  -> Capping RX queues from %u to %u\n", nb_queue_pairs, dev_info.max_rx_queues);
        nb_queue_pairs = dev_info.max_rx_queues;
    }
    if (nb_queue_pairs > dev_info.max_tx_queues) {
        printf("  -> Capping TX queues from %u to %u\n", nb_queue_pairs, dev_info.max_tx_queues);
        nb_queue_pairs = dev_info.max_tx_queues;
    }
    rx_rings = nb_queue_pairs;
    tx_rings = nb_queue_pairs;

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode  = RTE_ETH_MQ_RX_RSS,
            .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = hash_key,
                .rss_hf  = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
                .rss_key_len = RSS_HASH_KEY_LENGTH,
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };

    if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
        printf("  -> NIC does not support RX_TIMESTAMP. Disabling offload.\n");
        port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    }

    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
        printf("  -> WARNING: NIC does not support requested RSS hash types. Disabling RSS.\n");
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0) return retval;

    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval < 0) return retval;

    rxconf = dev_info.default_rxconf;
    for (q = 0; q < rx_rings; q++) {
        if (q >= number_rings) {
            printf("  -> WARNING: Queue %u exceeds available mbuf pools\n", q);
            break;
        }
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port),
                                        &rxconf, mbuf_pools[q]);  // queue q uses mbuf_pools[q]
        if (retval < 0) {
            printf("Error setting up RX queue %u: %s\n", q, strerror(-retval));
            return retval;
        }
        printf("  -> Queue %u using mbuf_pool %p\n", q, mbuf_pools[q]);
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port),
                                        &txconf);
        if (retval < 0) return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    rte_eth_promiscuous_enable(port);

    printf("Port %u successfully initialized with %u RX/TX queues.\n", port, nb_queue_pairs);
    return 0;
}

/* close all ports (best-effort) */
static void close_ports(void) {
    uint16_t portid;
    int ret;
    uint16_t nb_ports = rte_eth_dev_count_avail();
    for (portid = 0; portid < nb_ports; portid++) {
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            printf("Warning: rte_eth_dev_stop: err=%s, port=%u\n", strerror(-ret), portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
}

/* free per-core mbuf pools */
static void cleanup_mbuf_pools(struct rte_mempool **pools, unsigned num_cores) {
    for (unsigned i = 0; i < num_cores; i++) {
        if (pools[i]) {
            printf("Freeing mbuf pool for core %u (%p)...", i, pools[i]);
            rte_mempool_free(pools[i]);
            pools[i] = NULL;
            printf(" Done\n");
        }
    }
}

/* ------------------------------------------------------------------ */
/* Printing + final CSV output                                          */
/* ------------------------------------------------------------------ */

/* print latency summary across cores (quick check) */
static void print_latency_stats(struct worker_args *worker_args) {
    uint64_t tsc_hz = rte_get_tsc_hz();
    for (unsigned core = 0; core < g_total_lcores; core++) {
        struct worker_args *w = &worker_args[core];
        if (w->latency_count == 0) continue;
        uint64_t sum = 0, min = UINT64_MAX, max = 0;
        for (size_t i = 0; i < w->latency_count; i++) {
            uint64_t val = w->latency_cycles[i];
            sum += val;
            if (val < min) min = val;
            if (val > max) max = val;
        }
        double avg_cycles = (double)sum / w->latency_count;
        double avg_ns = (avg_cycles / tsc_hz) * 1e9;
        double min_ns = ((double)min / tsc_hz) * 1e9;
        double max_ns = ((double)max / tsc_hz) * 1e9;
        printf("Core %u: %zu samples, avg=%.2f ns (min=%.2f, max=%.2f)\n",
               core, w->latency_count, avg_ns, min_ns, max_ns);
    }
}

/* on_terminate: do heavy cleanup and write CSVs
 * - this is called when program is shutting down gracefully
 * - tries to free memory and write per-core files
 */
static void on_terminate(int signo) {
    (void)signo;
    printf("\n=== Received shutdown signal - Stopping gracefully ===\n");

    // wait for worker cores - keep it simple
    printf("Waiting for worker cores to finish...\n");
    rte_eal_mp_wait_lcore();

    usleep(100000); // let them breathe for 100ms

    printf("Writing statistics to CSV files...\n");
    uint64_t tsc_hz = rte_get_tsc_hz();

    // close per-core CSV flows
    for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
        if (worker_args[core].feat_csv) {
            fflush(worker_args[core].feat_csv);
            fclose(worker_args[core].feat_csv);
            worker_args[core].feat_csv = NULL;
            printf("Closed flow_features_core%u.csv\n", core);
        }
    }

    // write per-core latency data
    for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
        struct worker_args *w = &worker_args[core];
        if (w->latency_cycles != NULL && w->latency_count > 0) {
            char filename[64];
            snprintf(filename, sizeof(filename), "latencies_core%u.csv", core);
            FILE *f = fopen(filename, "w");
            if (f) {
                fprintf(f, "sample,cycles,ns\n");
                for (size_t i = 0; i < w->latency_count && i < MAX_SAMPLES_PER_CORE; i++) {
                    double ns = ((double)w->latency_cycles[i] / tsc_hz) * 1e9;
                    fprintf(f, "%zu,%lu,%.2f\n", i, w->latency_cycles[i], ns);
                }
                fclose(f);
                printf("✓ Core %u: %zu latency samples\n", core, w->latency_count);
            }
        }
    }

    // write prediction summary
    FILE *f_pred = fopen("prediction_summary.csv", "w");
    if (f_pred) {
        uint64_t total_predictions = 0;
        uint64_t class_counts[NUM_CLASSES];
        memset(class_counts, 0, sizeof(class_counts));
        for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
            if (worker_args[core].pred_count != NULL) {
                for (int c = 0; c < NUM_CLASSES; c++) {
                    class_counts[c] += worker_args[core].pred_count[c];
                    total_predictions += worker_args[core].pred_count[c];
                }
            }
        }
        fprintf(f_pred, "class,count,percentage\n");
        for (int c = 0; c < NUM_CLASSES; c++) {
            double pct = total_predictions ? (100.0 * (double)class_counts[c] / (double)total_predictions) : 0.0;
            fprintf(f_pred, "%d,%" PRIu64 ",%.2f\n", c, class_counts[c], pct);
        }
        fprintf(f_pred, "total,%" PRIu64 ",100.00\n", total_predictions);
        fclose(f_pred);
        printf("Prediction summary: %" PRIu64 " predictions\n", total_predictions);
    }

    // write packet stats
    FILE *f_pkt = fopen("packet_stats.csv", "w");
    if (f_pkt) {
        uint64_t total_received = 0;
        uint64_t total_processed = 0;
        for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
            total_received += worker_args[core].received_packets;
            total_processed += worker_args[core].processed_packets;
        }
        double drop_rate = (total_received > 0) ?
            (1.0 - (double)total_processed/total_received) * 100.0 : 0.0;
        fprintf(f_pkt, "received,processed,drop_rate_percent\n");
        fprintf(f_pkt, "%" PRIu64 ",%" PRIu64 ",%.2f\n", total_received, total_processed, drop_rate);
        fclose(f_pkt);
        printf("Packet stats: %" PRIu64 " received, %" PRIu64 " processed\n", total_received, total_processed);
    }

    // write per-core timings and free buffers
    for (unsigned core = 0; core < g_total_lcores; core++) {
        struct worker_args *w = &worker_args[core];
        if (!w->feat_cycles || w->samples_count == 0) continue;

        char fname[64];
        snprintf(fname, sizeof(fname), "timings_core%u.csv", core);
        FILE *f = fopen(fname, "w");
        if (!f) continue;

        fprintf(f, "sample,class,feat_cycles,inf_cycles,flow_duration_cycles,flow_duration_ns\n");
        for (size_t i = 0; i < w->samples_count; i++) {
            double flow_duration_ns = ((double)w->flow_duration_cycles[i] / tsc_hz) * 1e9;
            fprintf(f, "%zu,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.2f\n",
                    i, w->sample_class[i], w->feat_cycles[i], w->infer_cycles[i],
                    w->flow_duration_cycles[i], flow_duration_ns);
        }
        fclose(f);
        printf("✓ Core %u: %zu timing samples saved\n", core, w->samples_count);

        free(w->feat_cycles);
        free(w->infer_cycles);
        free(w->flow_duration_cycles);
        free(w->sample_class);
        w->feat_cycles = w->infer_cycles = NULL;
    }

    // cleanup per-core allocations
    printf("Performing cleanup...\n");
    for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
        struct worker_args *w = &worker_args[core];
        if (w->latency_cycles != NULL) { free(w->latency_cycles); w->latency_cycles = NULL; }
        if (w->pred_count != NULL)    { free(w->pred_count);    w->pred_count = NULL; }
        if (w->buf_a != NULL)         { free(w->buf_a);         w->buf_a = NULL; }
        if (w->buf_b != NULL)         { free(w->buf_b);         w->buf_b = NULL; }
    }

    printf("Closing ports...\n");
    close_ports();

    printf("Freeing per-core mbuf pools...\n");
    cleanup_mbuf_pools(mbuf_pools, g_total_lcores);

    // free hash tables
    for (unsigned core_id = 0; core_id < g_total_lcores; core_id++) {
        if (flow_tables[core_id]) {
            rte_hash_free(flow_tables[core_id]);
            flow_tables[core_id] = NULL;
        }
    }

    printf("DPDK cleanup...\n");
    rte_eal_cleanup();

    printf("=== Clean shutdown completed ===\n");
    exit(0);
}

/* ------------------------------------------------------------------ */
/* Signal handler (single place) - sets atomic flag; second hit -> force cleanup
 * - the idea: first CTRL-C asks workers to exit cleanly
 * - a second CTRL-C forces immediate on_terminate cleanup
 */
static void signal_handler(int signo) {
    (void)signo;
    int expected = 0;
    if (atomic_compare_exchange_strong(&force_quit, &expected, 1)) {
        // first CTRL-C, we set flag; workers poll this and exit
        printf("\n=== Received shutdown signal - Stopping gracefully ===\n");
    } else {
        // already set, user impatient; call final cleanup
        printf("\n=== Second shutdown signal - forcing cleanup ===\n");
        on_terminate(signo);
    }
}

/* ------------------------------------------------------------------ */
/* worker main - per-lcore packet loop                                 */
/* ------------------------------------------------------------------ */

static int lcore_main(void *args) {
    struct worker_args *w = (struct worker_args *)args;
    unsigned core_id = rte_lcore_id();

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", core_id);

    uint64_t last_print = rte_rdtsc();
    uint64_t print_interval = 5 * rte_get_tsc_hz(); // 5s

    // HIGH-PERFORMANCE: Remove empty poll counter and delays
    for (;;) {
        // Check shutdown flag - this is cheap (atomic load)
        if (atomic_load(&force_quit)) {
            printf("Core %u: quitting due to signal\n", core_id);
            break;
        }

        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(w->port_id, w->queue_id, bufs, BURST_SIZE);

        // HIGH-PERFORMANCE: Direct continue on empty RX - no counters, no delays
        if (unlikely(nb_rx == 0)) {
            continue;
        }

        // Print stats occasionally
        uint64_t now = rte_rdtsc();
        if (now - last_print > print_interval) {
            uint32_t flow_count = rte_hash_count(w->flow_table);
            printf("Core %u: %u active flows\n", core_id, flow_count);
            last_print = now;
            
            // Check shutdown during stats print (infrequent, so cheap)
            if (atomic_load(&force_quit)) {
                printf("Core %u: quitting during stats print\n", core_id);
                break;
            }
        }

        w->received_packets += nb_rx;

        // Your existing packet processing (keep this fast)
        for (int i = 0; i < nb_rx; i++) {

            //prefectch for cache performance
            if (i + 2 < nb_rx) rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 2], void *));
    
            uint8_t *pkt_data = rte_pktmbuf_mtod(bufs[i], uint8_t*);
            uint32_t pkt_total_len = rte_pktmbuf_pkt_len(bufs[i]);

            struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
            uint16_t ethernet_type = rte_be_to_cpu_16(eth->ether_type);

            if (ethernet_type != RTE_ETHER_TYPE_IPV4) continue;

            uint32_t ip_offset = sizeof(struct rte_ether_hdr);
            struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt_data + ip_offset);
            uint8_t ip_hlen = (ip->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
            uint8_t ip_proto = ip->next_proto_id;
            if (ip_proto != 6) continue;

            uint32_t tcp_offset = ip_offset + ip_hlen;
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(pkt_data + tcp_offset);
            uint8_t tcp_hlen = (tcp->data_off >> 4) * 4;
            uint16_t src_port = rte_be_to_cpu_16(tcp->src_port);
            uint16_t dst_port = rte_be_to_cpu_16(tcp->dst_port);

            if ((src_port != 443) && (dst_port != 443)) continue;

            uint32_t tls_offset = tcp_offset + tcp_hlen;
            uint32_t payload_len = pkt_total_len - tls_offset;
            if (payload_len < 5) continue;

            uint8_t *tls_data = pkt_data + tls_offset;
            uint8_t tls_type = tls_data[0];
            if (tls_type != 23) continue;

            struct rte_ether_addr tmp;
            rte_ether_addr_copy(&eth->src_addr, &tmp);
            rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
            rte_ether_addr_copy(&tmp, &eth->dst_addr);

            uint16_t tls_record_len = (uint16_t)((tls_data[3] << 8) | tls_data[4]);
            if ((uint32_t)tls_record_len > (payload_len - 5)) continue;

            struct flow_key key;
            key.src_ip = ip->src_addr;
            key.dst_ip = ip->dst_addr;
            key.src_port = src_port;
            key.dst_port = dst_port;
            key.protocol = ip_proto;
            canonicalize_5tuple(&key);

            bool is_client = (src_port != 443);
            handle_packet(&key, tls_record_len, w, is_client);
        }

        uint16_t nb_tx = rte_eth_tx_burst(w->port_id, w->queue_id, bufs, nb_rx);
        w->processed_packets += nb_tx;

        if (unlikely(nb_tx < nb_rx)) {
            for (uint16_t buf = nb_tx; buf < nb_rx; buf++) {
                rte_pktmbuf_free(bufs[buf]);
            }
        }
    }

    printf("Core %u: worker thread exiting cleanly\n", core_id);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_panic("Cannot init EAL\n");

    // register our single signal handler (first ctrl-c -> graceful, second -> force)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    argc -= ret;
    argv += ret;

    unsigned total_lcores = rte_lcore_count();
    g_total_lcores = total_lcores;

    uint64_t tsc_hz = rte_get_tsc_hz();
    printf("TSC frequency: %lu Hz (%.2f GHz)\n", tsc_hz, tsc_hz / 1e9);
    printf("DPDK version: %s\n", rte_version());

    // create one hash table per potential lcore
    struct rte_hash_parameters p = {
        .entries           = MAX_FLOWS_PER_CORE,
        .key_len           = sizeof(struct flow_key),
        .hash_func         = rte_hash_crc,
        .hash_func_init_val= 0,
        .socket_id         = rte_socket_id(),
    };

    for (unsigned core = 0; core < total_lcores; core++) {
        char name[32];
        snprintf(name, sizeof(name), "ftbl_%u", core);
        p.name = name;
        p.socket_id = rte_lcore_to_socket_id(core);
        if (p.socket_id < 0) p.socket_id = SOCKET_ID_ANY;
        flow_tables[core] = rte_hash_create(&p);
        if (!flow_tables[core]) rte_exit(EXIT_FAILURE, "Cannot create hash for core %u\n", core);
    }

    uint16_t nb_ports = rte_eth_dev_count_avail();

    // per-core mbuf pools (one per queue/core)
    for (unsigned core_id = 0; core_id < total_lcores; core_id++) {
        char name[32];
        snprintf(name, sizeof(name), "mbuf_pool_%u", core_id);
        int socket_id = rte_lcore_to_socket_id(core_id);
        if (socket_id < 0) socket_id = SOCKET_ID_ANY;
        mbuf_pools[core_id] = rte_pktmbuf_pool_create(name,
            NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (!mbuf_pools[core_id]) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool for core %u on socket %d\n",
                                            core_id, socket_id);
        printf("Created mbuf pool '%s' for core %u on socket %d\n", name, core_id, socket_id);
    }

    // init ports with per-core mbuf pools
    uint16_t portid;
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid, mbuf_pools, total_lcores) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
        } else {
            printf("port %u initialized with %u queues\n", portid, total_lcores);
        }
    }

    // find maximum neurons to allocate scratch buffers
    int max_neurons = 0;
    for (int i = 0; i <= NUM_LAYERS; i++)
        if (LAYER_SIZES[i] > max_neurons) max_neurons = LAYER_SIZES[i];

    uint16_t base_port = 0; // assume single port for demo

    // per-core initialization + launch workers
    for (unsigned core_id = 0; core_id < total_lcores; core_id++) {
        struct worker_args *w = &worker_args[core_id];

        // open per-core csv for features
        char csv_name[64];
        snprintf(csv_name, sizeof(csv_name), "flow_features_core%u.csv", core_id);
        w->feat_csv = fopen(csv_name, "w");
        if (!w->feat_csv) rte_exit(EXIT_FAILURE, "Cannot open flow_features_core%u.csv\n", core_id);
        setvbuf(w->feat_csv, NULL, _IOFBF, 4096);  //  4KB buffer
        fprintf(w->feat_csv,
            "src_ip_u32,src_port,dst_ip_u32,dst_port,proto,"
            "client_pkt_max,n_client,bytes_fraction_client,n_server,pkt_fraction_client,"
            "client_bytes,server_pkt_max,size_min,size_mean,server_pkt_mean,"
            "dir_switches,server_bytes,size_max,client_pkt_min,server_pkt_min,client_pkt_mean\n");

        w->mbuf_pool = mbuf_pools[core_id];
        w->flow_table = flow_tables[core_id];
        w->flow_pool  = flow_pools[core_id];
        w->port_id  = base_port;
        w->queue_id = core_id;

        // setup free list for flows
        w->free_flow_head = 0;
        w->free_flow_count = MAX_FLOWS_PER_CORE;
        for (uint32_t i = 0; i < MAX_FLOWS_PER_CORE - 1; i++) w->flow_pool[i].next_free = i + 1;
        w->flow_pool[MAX_FLOWS_PER_CORE - 1].next_free = INVALID_INDEX;

        const size_t SAMPLES_CAP = MAX_SAMPLES_PER_CORE;
        w->samples_capacity = SAMPLES_CAP;
        w->samples_count = 0;

        // allocate timing buffers with alignment
        w->latency_cycles = malloc(sizeof(uint64_t) * MAX_SAMPLES_PER_CORE);
        if (!w->latency_cycles) rte_exit(EXIT_FAILURE, "malloc failed for core %u latencies\n", core_id);
        w->latency_count = 0;

        if (posix_memalign((void **)&w->feat_cycles, 64, SAMPLES_CAP * sizeof(uint64_t)) ||
            posix_memalign((void **)&w->infer_cycles, 64, SAMPLES_CAP * sizeof(uint64_t)) ||
            posix_memalign((void **)&w->flow_duration_cycles, 64, SAMPLES_CAP * sizeof(uint64_t)) ||
            posix_memalign((void **)&w->sample_class, 64, SAMPLES_CAP * sizeof(int32_t))) {
            rte_exit(EXIT_FAILURE, "posix_memalign failed for per-core timing buffers (core %u)\n", core_id);
        }
        memset(w->feat_cycles, 0, SAMPLES_CAP * sizeof(uint64_t));
        memset(w->infer_cycles, 0, SAMPLES_CAP * sizeof(uint64_t));
        memset(w->flow_duration_cycles, 0, SAMPLES_CAP * sizeof(uint64_t));
        memset(w->sample_class, 0, SAMPLES_CAP * sizeof(int32_t));

        // prediction counter
        w->pred_count = malloc(sizeof(uint64_t) * NUM_CLASSES);
        if (!w->pred_count) rte_exit(EXIT_FAILURE, "malloc failed for pred_count core %u\n", core_id);
        memset(w->pred_count, 0, sizeof(uint64_t) * NUM_CLASSES);

        // scratch buffers for NEON inference
        if (posix_memalign((void**)&w->buf_a, 16, max_neurons * sizeof(float)) ||
            posix_memalign((void**)&w->buf_b, 16, max_neurons * sizeof(float))) {
            rte_exit(EXIT_FAILURE, "posix_memalign failed for core %u\n", core_id);
        }

        // init per-core counters
        w->received_packets = 0;
        w->processed_packets = 0;
        w->right_predictions = 0;
        w->wrong_predictions = 0;

        // launch workers on non-master lcores
        if (core_id != rte_get_main_lcore()) {
            rte_eal_remote_launch(lcore_main, w, core_id);
        }
    }

    // Replace your main core execution with:
    unsigned master = rte_get_main_lcore();
    struct worker_args *w_master = &worker_args[master];

    printf("Main core %u starting\n", master);
    lcore_main(w_master);
    printf("Main core %u finished\n", master);

    // Set shutdown flag
    atomic_store(&force_quit, 1);

    // HIGH-PERFORMANCE: Wait for workers with NO TIMEOUT - they'll exit quickly
    printf("Waiting for worker cores to finish...\n");
    rte_eal_mp_wait_lcore();

    // Continue with cleanup
    on_terminate(SIGTERM);

    // shouldn't reach here, but be tidy
    return 0;
}
