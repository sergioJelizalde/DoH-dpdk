/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
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
 #include <stdint.h>
 #include <stdlib.h>
 #include <inttypes.h>
 #include <getopt.h>
 #include <rte_eal.h>
 #include <rte_ethdev.h>
 #include <rte_cycles.h>
 #include <rte_lcore.h>
 #include <rte_mbuf.h>
 #include <rte_mbuf_dyn.h>
 #include <fcntl.h>
 #include <rte_version.h>

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <stdarg.h>
 #include <ctype.h>
 #include <errno.h>
 #include <getopt.h>

#include <signal.h>
#include <stdatomic.h>
 
 #include <rte_eal.h>
 #include <rte_common.h>
 #include <rte_malloc.h>
 #include <rte_mempool.h>
 #include <rte_mbuf.h>
 #include <rte_cycles.h>

 #include <rte_hash.h>
 #include <rte_jhash.h>
 
 #include <rte_flow.h>
 #include <math.h>
 //for bluefield2
 #include <arm_neon.h>


//#include "mlp_8.h"
//#include "mlp_32.h"
//#include "mlp_64_32.h"
//#include "mlp_128_64_32.h"
//#include "mlp_256_128_64_32.h"

//for demo
#include "mlp_weights.h"
#include "feature_stats.h"
static unsigned g_total_lcores = 0;

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191*2 

 // #define BURST_SIZE (1 << 9)
 
 #define QUEUE_SIZE 256
 
 #define BURST_SIZE 32
 
 // #define QUEUE_SIZE (1 << 6)
 
 #define MBUF_CACHE_SIZE 512
 
 //#define HASH_TABLE_SIZE (1 << 15) 
 
#define ALIGN16 __attribute__((aligned(16)))

#define MAX_CORES       RTE_MAX_LCORE
#define MAX_SAMPLES_PER_CORE 5000
static uint64_t *latency_cycles[MAX_CORES];
static size_t latency_count[MAX_CORES] = {0};

static volatile sig_atomic_t force_quit = 0;

static FILE *g_feat_csv = NULL;

#define N_PACKETS 16
#define NUM_FEATURES 16
#define INVALID_INDEX   UINT32_MAX

#define MAX_FLOWS_PER_CORE 65536
#define MAX_CORES       RTE_MAX_LCORE


#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};


struct worker_args {
    struct rte_mempool *mbuf_pool;
    struct rte_hash    *flow_table;
    struct flow_entry  *flow_pool; 
    float              *buf_a;
    float              *buf_b;
    uint16_t            queue_id;    
    uint32_t            next_free;
    uint16_t port_id;

    /* per-worker timing buffers - allocate at init */
    uint64_t *feat_cycles;   /* length: samples_capacity */
    uint64_t *infer_cycles;  /* length: samples_capacity */
    uint64_t *flow_duration_cycles; /* NEW: flow duration in cycles */
    int32_t  *sample_class;  /* length: samples_capacity */
    size_t    samples_capacity;
    size_t    samples_count;

    uint64_t           *pred_count;
};

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_entry {
    // Frequently accessed fields first
    uint32_t pkt_count_client;
    uint32_t pkt_count_server;
    uint64_t bytes_client;
    uint64_t bytes_server;
    
    // Less frequently accessed
    uint32_t pkt_len_min_client;
    uint32_t pkt_len_max_client;
    uint32_t pkt_len_min_server;
    uint32_t pkt_len_max_server;
    uint64_t pkt_len_sum_client;
    uint64_t pkt_len_sum_server;
    
    // Infrequently accessed
    uint8_t last_direction;
    uint16_t dir_switches;
    uint8_t finalized;
    uint64_t first_packet_tsc;
    uint64_t last_packet_tsc;
    
    // For free list
    uint32_t next_free;
} __rte_cache_aligned;

/* Statically allocate pools for every possible lcore */
static struct flow_entry flow_pools[MAX_CORES][MAX_FLOWS_PER_CORE];
static struct rte_hash *flow_tables[MAX_CORES];


/* simple async-signal-safe handler */
static void simple_signal_handler(int signo)
{
    (void)signo;
    force_quit = 1;
}

 /* >8 End of launching function on lcore. */
 static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t number_rings)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    uint16_t nb_queue_pairs, rx_rings, tx_rings;
    int retval;
    uint16_t q;

    /* Fetch device info */
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u: %s\n",
               port, strerror(-retval));
        return retval;
    }

    printf("Port %u: max_rx_queues=%u, max_tx_queues=%u, rx_offload_capa=0x%016" PRIx64 ", flow_type=0x%08x\n",
           port, dev_info.max_rx_queues, dev_info.max_tx_queues,
           dev_info.rx_offload_capa, dev_info.flow_type_rss_offloads);

    /* Cap number_rings to NIC capabilities */
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

    /* Build port_conf with safe defaults */
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode  = RTE_ETH_MQ_RX_RSS,
            .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP, // Enable RX timestamping
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = hash_key,
                .rss_hf  = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
                .rss_key_len = RSS_HASH_KEY_LENGTH,  // Toeplitz uses 40-byte key
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };
    
    /* Remove unsupported offloads */
    if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
        printf("  -> NIC does not support RX_TIMESTAMP. Disabling offload.\n");
        port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    }

    /* Mask RSS hash types */
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
        printf("  -> WARNING: NIC does not support requested RSS hash types. Disabling RSS.\n");
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    }

    /* Configure the device */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0)
        return retval;

    /* Adjust descriptors */
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval < 0)
        return retval;

    /* Setup RX queues */
    rxconf = dev_info.default_rxconf;
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port),
                                        &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Setup TX queues */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port),
                                        &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the device */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode */
    rte_eth_promiscuous_enable(port);

    printf("Port %u successfully initialized with %u RX/TX queues.\n",
           port, nb_queue_pairs);
    return 0;
}

static void print_latency_stats(void) {
    uint64_t tsc_hz = rte_get_tsc_hz();
    
    for (unsigned core = 0; core < g_total_lcores; core++) {
        if (latency_count[core] == 0) continue;
        
        uint64_t sum = 0, min = UINT64_MAX, max = 0;
        for (size_t i = 0; i < latency_count[core]; i++) {
            uint64_t val = latency_cycles[core][i];
            sum += val;
            if (val < min) min = val;
            if (val > max) max = val;
        }
        
        double avg_cycles = (double)sum / latency_count[core];
        double avg_ns = (avg_cycles / tsc_hz) * 1e9;
        double min_ns = ((double)min / tsc_hz) * 1e9;
        double max_ns = ((double)max / tsc_hz) * 1e9;
        
        printf("Core %u: %zu samples, avg=%.2f ns (min=%.2f, max=%.2f)\n",
               core, latency_count[core], avg_ns, min_ns, max_ns);
    }
}


static inline void log_features_csv(const struct flow_key *key, const float features16[16]) {
    if (!g_feat_csv) return;

    int rc = fprintf(g_feat_csv,
        "%u,%u,%u,%u,%u,"   // 5-tuple
        "%u,%u,%.6f,%u,%.6f,%.0f,%u,%u,%.3f,%.3f,%u,%.0f,%u,%u,%u,%.3f\n",
        key->src_ip, key->src_port, key->dst_ip, key->dst_port, key->protocol,

        /* 16 features in the requested order */
        (unsigned)features16[0],   // client_pkt_max
        (unsigned)features16[1],   // n_client
        features16[2],             // bytes_fraction_client
        (unsigned)features16[3],   // n_server
        features16[4],             // pkt_fraction_client
        features16[5],             // client_bytes (printed as integer via "%.0f")
        (unsigned)features16[6],   // server_pkt_max
        (unsigned)features16[7],   // size_min
        features16[8],             // size_mean
        features16[9],             // server_pkt_mean
        (unsigned)features16[10],  // dir_switches
        features16[11],            // server_bytes (printed as integer via "%.0f")
        (unsigned)features16[12],  // size_max
        (unsigned)features16[13],  // client_pkt_min
        (unsigned)features16[14],  // server_pkt_min
        features16[15]             // client_pkt_mean
    );

    if (rc < 0) {
        perror("fprintf(g_feat_csv) failed");
    }
}





static inline void canonicalize_5tuple(struct flow_key *k)
{
    /* Lexicographic order on (IP,port). Keep protocol as-is. */
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


// Fast piecewise sigmoid approximation
static inline float sigmoid_piece(float x) {
    if (x <= -4.0f) return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <= 0.0f)  return 0.125f * x + 0.5f;
    else if (x <= 2.0f)  return -0.125f * x + 0.5f;
    else if (x <= 4.0f)  return -0.0625f * x + 0.75f;
    else return 1.0f;
}

// NEON version for vectorized code
static inline float32x4_t sigmoid_neon(float32x4_t x) {
    float32x4_t abs_x = vabsq_f32(x);
    float32x4_t one = vdupq_n_f32(1.0f);
    float32x4_t ratio = vdivq_f32(abs_x, vaddq_f32(one, abs_x));
    uint32x4_t mask = vcgeq_f32(x, vdupq_n_f32(0.0f));
    float32x4_t pos = ratio;
    float32x4_t neg = vsubq_f32(one, ratio);
    return vbslq_f32(mask, pos, neg);
}

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
        if (!is_output) acc = vmaxq_f32(acc, vdupq_n_f32(0.0f));
        vst1q_f32(&out[j], acc);
    }

    // UNCOMMENTED TAIL HANDLING - CRITICAL!
    for (; j < size_out; j++) {
        float a = B[j];
        for (int k = 0; k < size_in; k++)
            a += W[k*size_out + j] * in[k];
        if (!is_output) a = (a > 0.0f) ? a : 0.0f;
        out[j] = a;
    }
}

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
        
        // Apply activation functions ONLY to final output
        if (is_output_layer) {
            #if IS_BINARY_CLASSIFICATION
            // Apply sigmoid to final output only
            for (int i = 0; i < LAYER_SIZES[L+1]; i++)
                out_buf[i] = sigmoid_piece(out_buf[i]);
            
            #elif IS_MULTICLASS_CLASSIFICATION  
            // Apply softmax to final output only
            float max_val = out_buf[0];
            for (int i = 1; i < LAYER_SIZES[L+1]; i++) {
                if (out_buf[i] > max_val) max_val = out_buf[i];
            }
            
            float sum = 0.0f;
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] = expf(out_buf[i] - max_val);
                sum += out_buf[i];
            }
            
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] /= sum;
            }
            #endif
        }
        
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // Final result is now in in_buf (due to the last swap)
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


static inline uint32_t
allocate_entry_per_core(struct worker_args *w)
{
    if (w->next_free >= MAX_FLOWS_PER_CORE){
        printf("invalid index");
        return INVALID_INDEX;
    }
        
    /* grab the next slot; it’s already zeroed at startup */
    return w->next_free++;
}


static inline void
reset_entry_per_core(struct worker_args *w, uint32_t idx)
{
    struct flow_entry *e = &w->flow_pool[idx];

    // Zero everything we track
    memset(e, 0, sizeof(*e));

    // Initialize per-side mins/maxes so first packet replaces them
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

    // Initialize timing fields
    e->first_packet_tsc = 0;
    e->last_packet_tsc = 0;

}

static inline uint8_t
count_bits(uint8_t x) {
    // GCC/Clang builtin popcount
    return __builtin_popcount(x);
}

static inline void
update_flow_entry(struct flow_entry *e,
                  uint16_t           pkt_len,
                  bool               is_client,
                  uint64_t           current_tsc)
{
    // Total packets already seen for this flow (client + server)
    uint32_t total_pkts = e->pkt_count_client + e->pkt_count_server;

    // Stop updating if flow already finalized or we've seen enough packets
    if (e->finalized || total_pkts >= N_PACKETS) return;

    // Record first packet timestamp
    if (total_pkts == 0) {
        e->first_packet_tsc = current_tsc;
    }

    if (is_client) {
        /* Client-side update */
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
        /* Server-side update */
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

    /* direction switch detection - last_direction: 0 unknown, 1 client, 2 server */
    uint8_t cur_dir = is_client ? 1 : 2;
    if (e->last_direction != 0 && e->last_direction != cur_dir) {
        e->dir_switches++;
    }
    e->last_direction = cur_dir;

    // Record timestamp for the Nth packet (when we reach N_PACKETS)
    total_pkts = e->pkt_count_client + e->pkt_count_server;
    if (total_pkts == N_PACKETS) {
        e->last_packet_tsc = current_tsc;
    }
}


static inline void
handle_packet(struct flow_key   *key,
              uint16_t           tls_payload_size,
              struct worker_args *w,
              bool                is_client)
{
    void    *data_ptr = NULL;
    int      ret      = rte_hash_lookup_data(w->flow_table, key, &data_ptr);
    uint32_t index;

    if (ret < 0) {
        // not found: new flow
        index = allocate_entry_per_core(w);
        if (index == INVALID_INDEX) return;

        ret = rte_hash_add_key_data(w->flow_table, key, (void*)(uintptr_t)index);
        if (ret < 0) { w->next_free--; return; }

        struct flow_entry *new_e = &w->flow_pool[index];
        reset_entry_per_core(w, index);
    } else {
        // found existing flow
        index = (uint32_t)(uintptr_t)data_ptr;
    }

    struct flow_entry *e = &w->flow_pool[index];

    uint64_t current_tsc = rte_rdtsc_precise();
    update_flow_entry(e, tls_payload_size, is_client, current_tsc);

    /* compute totals after update */
    uint32_t n_client = e->pkt_count_client;
    uint32_t n_server = e->pkt_count_server;
    uint32_t total_pkts = n_client + n_server;

    /* only finalize / build features when we've seen exactly N_PACKETS packets */
    if (!e->finalized && total_pkts >= N_PACKETS) {

        uint64_t flow_duration_cycles = e->last_packet_tsc - e->first_packet_tsc;
        
        double client_bytes = (double)e->bytes_client;
        double server_bytes = (double)e->bytes_server;
        double total_bytes = client_bytes + server_bytes;

        /* derive global size stats from per-side values */
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

        /* normalize sentinels for empty sides */
        float size_min = 0.0f;
        if (global_min != UINT32_MAX) size_min = (float)global_min;
        float size_max = (float)global_max;
        float size_mean = 0.0f;
        if (total_pkts > 0) size_mean = (float)((double)global_sum / (double)total_pkts);

        /* client-side stats (guard empty side) */
        float client_pkt_max  = (n_client > 0) ? (float)e->pkt_len_max_client : 0.0f;
        float client_pkt_min  = (n_client > 0 && e->pkt_len_min_client != UINT32_MAX) ? (float)e->pkt_len_min_client : 0.0f;
        float client_pkt_mean = (n_client > 0) ? (float)((double)e->pkt_len_sum_client / (double)n_client) : 0.0f;

        /* server-side stats (guard empty side) */
        float server_pkt_max  = (n_server > 0) ? (float)e->pkt_len_max_server : 0.0f;
        float server_pkt_min  = (n_server > 0 && e->pkt_len_min_server != UINT32_MAX) ? (float)e->pkt_len_min_server : 0.0f;
        float server_pkt_mean = (n_server > 0) ? (float)((double)e->pkt_len_sum_server / (double)n_server) : 0.0f;

        /* counts cast to float */
        float n_client_f = (float)n_client;
        float n_server_f = (float)n_server;

        /* fractions (guard divide-by-zero) */
        float bytes_fraction_client = 0.0f;
        if (total_bytes > 0.0) bytes_fraction_client = (float)(client_bytes / total_bytes);

        float pkt_fraction_client = 0.0f;
        if (total_pkts > 0) pkt_fraction_client = (float)((double)n_client / (double)total_pkts);

        /* dir_switches */
        float dir_switches_f = (float)e->dir_switches;

        /* Feature index mapping:
        0: client_pkt_max
        1: n_client
        2: bytes_fraction_client
        3: n_server
        4: pkt_fraction_client
        5: client_bytes
        6: server_pkt_max
        7: size_min
        8: size_mean
        9: server_pkt_mean
        10: dir_switches
        11: server_bytes
        12: size_max
        13: client_pkt_min
        14: server_pkt_min
        15: client_pkt_mean
        */
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

        /* Normalize & predict: ensure FEATURE_MEAN/STD match NUM_FEATURES */
       
        ALIGN16 float features_scaled[16];

        uint64_t t0_feat = rte_rdtsc_precise();
        normalize_features(features16, features_scaled, 16);
        uint64_t t1_feat = rte_rdtsc_precise();

        int64_t t0_inf = rte_rdtsc_precise();
        int pred = predict_mlp(features_scaled, w->buf_a, w->buf_b);
        uint64_t t1_inf = rte_rdtsc_precise();

        if (pred >= 0 && pred < NUM_CLASSES) w->pred_count[pred]++;
        size_t idx = w->samples_count;
        if (idx < w->samples_capacity) {
            w->feat_cycles[idx]  = t1_feat - t0_feat;
            w->infer_cycles[idx] = t1_inf  - t0_inf;
            w->flow_duration_cycles[idx] = flow_duration_cycles; //
            w->sample_class[idx] = pred;
            w->samples_count = idx + 1;
        }
        /* Log features — pass actual features buffer */
        //log_features_csv(key, features16);

        e->finalized = 1;  // prevent repeats

        // Print flow ID + classification
        /*printf("Flow %u:%u -> %u:%u proto %u classified as %d\n",
               key->src_ip, key->src_port,
               key->dst_ip, key->dst_port,
               key->protocol, pred);*/
    }
}


static struct worker_args worker_args[MAX_CORES];


 double right_predictions=0;
 double wrong_predictions=0;
 
 double received_packets=0;
 double processed_packets=0;
 

 static int lcore_main(void *args)
 {
    struct worker_args *w = (struct worker_args *)args;
    unsigned core_id = rte_lcore_id();
    struct rte_mempool *mbuf_pool = w->mbuf_pool;
    struct rte_hash    *flow_table = w->flow_table;

    uint16_t port;
    uint16_t ret;
    uint16_t queue_id = w->queue_id;

    struct flow_key key;
    struct flow_entry entry;
 
    double sample[5];
 
    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) !=
            (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
            "polling thread.\n\tPerformance will "
            "not be optimal.\n",
            port);
 
    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
            rte_lcore_id());
 
 
    uint32_t pkt_count = 0;

    for (;;)
    {
        // Check shutdown flag at the start of each iteration
  
        if (force_quit) {
            printf("Core %u: quitting due to signal\n", core_id);
            break;
        }

        struct rte_mbuf *bufs[BURST_SIZE];
        
        uint16_t nb_rx = rte_eth_rx_burst(w->port_id, w->queue_id, bufs, BURST_SIZE);
        //printf(" -> burst returned %u pkts\n", nb_rx);
        if (unlikely(nb_rx == 0)) continue;

        // break;
        if (nb_rx > 0)
        {
            uint64_t start_cycles = rte_rdtsc_precise(); 

        
            received_packets+=nb_rx;
            struct rte_ether_hdr *ethernet_header; 
            struct rte_ipv4_hdr *pIP4Hdr;
            struct rte_tcp_hdr *pTcpHdr;
        
            u_int16_t ethernet_type;
            for (int i = 0; i < nb_rx; i++)
            {
                //uint64_t start_cycles = rte_rdtsc_precise();
                // pkt_count +=1;
                ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                ethernet_type = rte_be_to_cpu_16(ethernet_header->ether_type);

                //swap
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                struct rte_ether_addr tmp;
                rte_ether_addr_copy(&eth->src_addr, &tmp);
                rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
                rte_ether_addr_copy(&tmp,         &eth->dst_addr);
                if (ethernet_type == RTE_ETHER_TYPE_IPV4)
                {
                    uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);

                    pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, ipdata_offset);
                    uint32_t src_ip = rte_be_to_cpu_32(pIP4Hdr->src_addr);
                    uint32_t dst_ip = rte_be_to_cpu_32(pIP4Hdr->dst_addr);
                    uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;
                    ipdata_offset += (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

                    if (IPv4NextProtocol == 6)
                    {

                        pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);
                        uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                        uint16_t src_port = rte_be_to_cpu_16(pTcpHdr->src_port);
                        uint8_t tcp_dataoffset = pTcpHdr->data_off >> 4;
                        uint32_t tcpdata_offset = ipdata_offset + sizeof(struct rte_tcp_hdr) + (tcp_dataoffset - 5) * 4;
                        /* figure out how many ‘1’ bits are set in TCP flags, or 0 otherwise */
                        // integrate code below with down code

                        if (dst_port == 443 || src_port == 443) {

                           /* Build canonical flow key (keep your convention) */
                            key.src_ip = dst_ip;
                            key.dst_ip = src_ip;
                            key.src_port = dst_port;
                            key.dst_port = src_port;
                            key.protocol = IPv4NextProtocol;

                            /* Who sent this packet relative to port 443? */
                            bool is_client = (src_port != 443);

                            /* Compute pointer to TCP payload and its total length (handles chained mbufs) */
                            uint32_t pkt_total_len = rte_pktmbuf_pkt_len(bufs[i]);
                            if (pkt_total_len <= tcpdata_offset) {
                                /* No TCP payload */
                                continue;
                            }
                            uint32_t payload_len = pkt_total_len - tcpdata_offset;

                            /* We need at least 5 bytes to read the TLS record header:
                             *   byte 0: content_type (23 = application_data)
                             *   byte 1-2: version
                             *   byte 3-4: length (big-endian)
                             */
                            if (payload_len < 5) {
                                /* Not enough data to examine TLS record header; skip */
                                continue;
                            }

                            /* Pointer to start of TCP payload (first segment) */
                            uint8_t *tcp_payload = rte_pktmbuf_mtod_offset(bufs[i], uint8_t *, tcpdata_offset);

                            /* Read TLS content type */
                            uint8_t tls_content_type = tcp_payload[0];

                            if (tls_content_type != 23) {
                                /* Not TLS Application Data — skip (could be Handshake(22), Alert(21), ChangeCipherSpec(20), etc.) */
                                continue;
                            }

                            /* Extract TLS record length from bytes 3..4 (big-endian) */
                            uint16_t tls_record_len = (uint16_t)((tcp_payload[3] << 8) | tcp_payload[4]);

                            /* Sanity: make sure the record length is plausible given payload_len.
                               If tls_record_len > payload_len - 5, the record is fragmented (across TCP segments)
                               and we skip for now. You can extend to reassemble if needed. */
                            if ((uint32_t)tls_record_len > (payload_len - 5)) {
                                /* record not complete in this TCP segment — skip */
                                continue;
                            }

                            /* canonicalize key and call handle_packet using tls_record_len as pkt_len */
                            canonicalize_5tuple(&key);

                            /* use TLS application-data record length (in bytes) as the packet 'size' for features */
                            uint16_t tls_payload_size = tls_record_len;


                            //printf("Pkt length: %" PRIu16 " bytes\n", pkt_len);
                            //uint64_t pkt_time = is_timestamp_enabled(bufs[i]) ? get_hw_timestamp(bufs[i]) : 0; 
                            //uint64_t pkt_time = rte_rdtsc_precise();
                            //printf("Pkt time: %" PRIu64 " cycles\n", pkt_time);
                            // printf("TSC frequency: %lu Hz\n", hz);
                            
                            // int prediction = predict_mlp(features);
                            // uint64_t start_cycles = rte_rdtsc_precise();

                            handle_packet(&key, tls_payload_size, w, is_client);

                            //uint64_t end_cycles = rte_rdtsc_precise();
                            //uint64_t inference_cycles = end_cycles - start_cycles;
                            //if (latency_count[core_id] < MAX_SAMPLES_PER_CORE) latency_cycles[core_id][latency_count[core_id]++] = inference_cycles;

                            // // Convert to nanoseconds
                            // double latency_ns = ((double)inference_cycles / hz) * 1e9;

                            // printf("Latency: %.2f ns (%lu cycles)\n", latency_ns, inference_cycles); 
                        }
                                                                       
                    }
                }
            }
            uint64_t end_cycles = rte_rdtsc_precise();
            uint64_t inference_cycles = end_cycles - start_cycles;
            if (latency_count[core_id] < MAX_SAMPLES_PER_CORE) latency_cycles[core_id][latency_count[core_id]++] = inference_cycles;

            if (unlikely(nb_rx == 0))
                continue;
            //printf("Core %u: about to burst %u pkts on port %u queue %u\n",
                //rte_lcore_id(), nb_rx, w->port_id, w->queue_id);

            
            uint16_t nb_tx = rte_eth_tx_burst(w->port_id, w->queue_id, bufs, nb_rx);

            //printf("Core %u: burst returned %u (dropped %u)\n",
                //rte_lcore_id(), nb_tx, nb_rx - nb_tx);

            //const uint16_t nb_tx = rte_eth_tx_burst(w->port_id, w->queue_id, bufs, nb_rx);

            processed_packets += nb_tx;

            if (unlikely(nb_tx < nb_rx))
            {
                uint16_t buf;

                // printf("SOme packets are not processed\n");

                for (buf = nb_tx; buf < nb_rx; buf++)
                    rte_pktmbuf_free(bufs[buf]); 
            }

            // printf("Core %u proceesed %u packets\n",core_id,*packet_counter);

        }
         
    }
    return 0;
 }
 

 static void close_ports(void);
 static void close_ports(void)
 {
     uint16_t portid;
     int ret;
     uint16_t nb_ports;
     nb_ports = rte_eth_dev_count_avail();
     for (portid = 0; portid < nb_ports; portid++)
     {
         printf("Closing port %d...", portid);
         ret = rte_eth_dev_stop(portid);
         if (ret != 0)
             rte_exit(EXIT_FAILURE, "rte_eth_dev_stop: err=%s, port=%u\n",
                      strerror(-ret), portid);
         rte_eth_dev_close(portid);
         printf(" Done\n");
     }
 }

static void on_terminate(int signo) {
    printf("\n=== Received shutdown signal - Stopping gracefully ===\n");
    
    // Set shutdown flag to stop worker cores
    
    // Wait for all worker cores to finish
    printf("Waiting for worker cores to finish...\n");
    rte_eal_mp_wait_lcore();
    
    // Small delay to allow workers to exit their loops
    usleep(100000); // 100ms
    
    // Then proceed with CSV writing and cleanup
    printf("Writing statistics to CSV files...\n");
    
    uint64_t tsc_hz = rte_get_tsc_hz();
    
    // 1. Close features CSV
    if (g_feat_csv) {
        fflush(g_feat_csv);
        fclose(g_feat_csv);
        g_feat_csv = NULL;
        printf("Closed flow_features.csv\n");
    }
    
    // 2. Write latency data
    for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
        if (latency_cycles[core] != NULL && latency_count[core] > 0) {
            char filename[64];
            snprintf(filename, sizeof(filename), "latencies_core%u.csv", core);
            
            FILE *f = fopen(filename, "w");
            if (f) {
                fprintf(f, "sample,cycles,ns\n");
                for (size_t i = 0; i < latency_count[core] && i < MAX_SAMPLES_PER_CORE; i++) {
                    double ns = ((double)latency_cycles[core][i] / tsc_hz) * 1e9;
                    fprintf(f, "%zu,%lu,%.2f\n", i, latency_cycles[core][i], ns);
                }
                fclose(f);
                printf("✓ Core %u: %zu latency samples\n", core, latency_count[core]);
            }
        }
    }
    
    // 3. Write prediction summary
    FILE *f_pred = fopen("prediction_summary.csv", "w");
    if (f_pred) {
        uint64_t total_predictions = 0;
        uint64_t class_counts[NUM_CLASSES] = {0};
        
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
    
    // 4. Write packet statistics
    FILE *f_pkt = fopen("packet_stats.csv", "w");
    if (f_pkt) {
        double drop_rate = (received_packets > 0) ? 
            (1.0 - (double)processed_packets/received_packets) * 100.0 : 0.0;
        fprintf(f_pkt, "received,processed,drop_rate_percent\n");
        fprintf(f_pkt, "%.0f,%.0f,%.2f\n", received_packets, processed_packets, drop_rate);
        fclose(f_pkt);
        printf("Packet stats: %.0f received, %.0f processed\n", received_packets, processed_packets);
    }
    

    for (unsigned core = 0; core < g_total_lcores; core++) {
        struct worker_args *w = &worker_args[core];
        if (!w->feat_cycles || w->samples_count == 0) continue;

        char fname[64];
        snprintf(fname, sizeof(fname), "timings_core%u.csv", core);
        FILE *f = fopen(fname, "w");
        if (!f) continue;

        // In the timing file writing section:
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
        w->feat_cycles = w->infer_cycles = (void *)0;
    }


    printf("Performing cleanup...\n");
    
    // Cleanup memory
    for (unsigned core = 0; core < g_total_lcores && core < MAX_CORES; core++) {
        if (latency_cycles[core] != NULL) {
            free(latency_cycles[core]);
            latency_cycles[core] = NULL;
        }
    }
    
    printf("Closing ports...\n");
    close_ports();
    
    printf("DPDK cleanup...\n");
    rte_eal_cleanup();
    
    printf("=== Clean shutdown completed ===\n");
    _exit(0);
}

// signal handler 
 static void sigint_handler(int signo) {
    uint64_t tsc_hz = rte_get_tsc_hz();
    
    // Write individual core files
    for (unsigned core = 0; core < g_total_lcores; core++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "latencies_core%u.csv", core);
        
        FILE *f = fopen(filename, "w");
        if (!f) {
            perror("fopen");
            continue;
        }
        
        fprintf(f, "sample,cycles,ns\n");
        for (size_t i = 0; i < latency_count[core]; i++) {
            double ns = ((double)latency_cycles[core][i] / tsc_hz) * 1e9;
            fprintf(f, "%zu,%lu,%.2f\n", i, latency_cycles[core][i], ns);
        }
        fclose(f);
        printf("Wrote %zu samples to %s\n", latency_count[core], filename);
    }
    
    // Write aggregated file
    FILE *f_all = fopen("latencies_all.csv", "w");
    if (f_all) {
        fprintf(f_all, "core,sample,cycles,ns\n");
        for (unsigned core = 0; core < g_total_lcores; core++) {
            for (size_t i = 0; i < latency_count[core]; i++) {
                double ns = ((double)latency_cycles[core][i] / tsc_hz) * 1e9;
                fprintf(f_all, "%u,%zu,%lu,%.2f\n", core, i, latency_cycles[core][i], ns);
            }
        }
        fclose(f_all);
        printf("Wrote aggregated data to latencies_all.csv\n");
    }
    
    on_terminate(signo); // call your existing cleanup
}


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
    "client_pkt_max,n_client,bytes_fraction_client,n_server,pkt_fraction_client,"
    "client_bytes,server_pkt_max,size_min,size_mean,server_pkt_mean,"
    "dir_switches,server_bytes,size_max,client_pkt_min,server_pkt_min,client_pkt_mean\n");


    //signal(SIGINT,  on_terminate);
    //signal(SIGTERM, on_terminate);

    signal(SIGINT,  simple_signal_handler);
    signal(SIGTERM, simple_signal_handler);

    unsigned total_lcores = rte_lcore_count();
    g_total_lcores = total_lcores;  

    for (unsigned core = 0; core < total_lcores; core++) {
        latency_cycles[core] = malloc(sizeof(uint64_t) * MAX_SAMPLES_PER_CORE);
        if (!latency_cycles[core])
            rte_exit(EXIT_FAILURE, "malloc failed for core %u latencies\n", core);
        latency_count[core] = 0;
    }

    uint64_t tsc_hz = rte_get_tsc_hz();
    printf("TSC frequency: %lu Hz (%.2f GHz)\n",
           tsc_hz, tsc_hz / 1e9);

    printf("DPDK version: %s\n", rte_version());

     
    
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

        // Shared resources
        w->mbuf_pool  = mbuf_pool;
        w->flow_table = flow_tables[core_id];
        w->flow_pool  = flow_pools[core_id];
        w->port_id  = base_port;

        const size_t SAMPLES_CAP = MAX_SAMPLES_PER_CORE;
        w->samples_capacity = SAMPLES_CAP;
        w->samples_count = 0;

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


        //  Per-core state
        w->next_free  = 0;            // start allocating at slot 0
        w->queue_id   = queue_id++;   // one RX queue per core
        /* allocate per-core prediction counters */
        w->pred_count = malloc(sizeof(uint64_t) * NUM_CLASSES);
        if (!w->pred_count) {
            rte_exit(EXIT_FAILURE, "malloc failed for pred_count core %u\n", core_id);
        }
        memset(w->pred_count, 0, sizeof(uint64_t) * NUM_CLASSES);
        // Scratch buffers for NEON inference
        if (posix_memalign((void**)&w->buf_a, 16, max_neurons * sizeof(float)) ||
            posix_memalign((void**)&w->buf_b, 16, max_neurons * sizeof(float))) {
            rte_exit(EXIT_FAILURE, "posix_memalign failed for core %u\n", core_id);
        }

        // Launch worker on that core (skip core 0 if you plan to use it as master below)
        if (core_id != rte_get_main_lcore()) {
            rte_eal_remote_launch(lcore_main, w, core_id);
        }
    }

    // run master0)
    unsigned master = rte_get_main_lcore();
    struct worker_args *w_master = &worker_args[master];
    
    lcore_main(w_master);

    if (force_quit) {
        on_terminate(SIGTERM);   
    }
    
    //

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

                print_latency_stats();  
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
            free(worker_args[core_id].pred_count);
            worker_args[core_id].pred_count = NULL;
            rte_hash_free(flow_tables[core_id]);
            flow_tables[core_id] = NULL;
        }
    }
 
     close_ports();
 
     /* clean up the EAL */
     rte_eal_cleanup();
 
     return 0;
 }