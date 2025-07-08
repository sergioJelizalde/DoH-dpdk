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
 
 #include <rte_eal.h>
 #include <rte_common.h>
 #include <rte_malloc.h>
 #include <rte_mempool.h>
 #include <rte_mbuf.h>
 #include <rte_cycles.h>
 #include <rte_regexdev.h>
 
 #include <rte_crypto.h>
 #include <rte_cryptodev.h>
 
 #include <rte_hash.h>
 #include <rte_jhash.h>
 #include <jansson.h>
 
 #include <rte_flow.h>
 #include <signal.h>
 
 //for bluefield2
 #include <arm_neon.h>
 #include "mlp_model.h"

 #define RX_RING_SIZE (1 << 15)
 #define TX_RING_SIZE (1 << 15)
 
 #define NUM_MBUFS (1 << 16)
 // #define BURST_SIZE (1 << 9)
 
 #define QUEUE_SIZE 128
 
 #define BURST_SIZE 64
 
 // #define QUEUE_SIZE (1 << 6)
 
 #define MBUF_CACHE_SIZE 256
 
 //#define HASH_TABLE_SIZE (1 << 15) 
 
 #define MAX_TREES 100
 #define MAX_NODES 500

#define MAX_FLOWS 16384 
#define N_PACKETS 8
#define INVALID_INDEX UINT32_MAX

 typedef struct
 {
     rte_be32_t words[8];
 } uint256_t;
 
 typedef struct
 {
     uint8_t bytes[3];
 } uint24_t;
 
 uint16_t uint24_to_16(uint24_t value);
 uint16_t uint24_to_16(uint24_t value){
     return((uint16_t)value.bytes[1] << 8)| value.bytes[2];
 }
 
 struct tls_hdr
 {
     uint8_t type;
     uint16_t version;
     uint16_t len;
 };
 
 struct rte_tls_hdr
 {
     uint8_t type;
     rte_be16_t version;
     rte_be16_t length;
 } __attribute__((__packed__));
 
 struct rte_tls_hello_hdr
 {
     uint8_t type;
     uint24_t len;
     rte_be16_t version;
     uint256_t random;
 } __attribute__((__packed__));
 
 struct rte_tls_session_hdr
 {
     uint8_t len;
 } __attribute__((__packed__));
 
 struct rte_tls_cipher_hdr
 {
     uint16_t len;
 } __attribute__((__packed__));
 
 struct rte_tls_compression_hdr
 {
     uint8_t len;
 } __attribute__((__packed__));
 
 struct rte_tls_ext_len_hdr
 {
     uint16_t len;
 } __attribute__((__packed__));
 
 struct rte_tls_ext_hdr
 {
     uint16_t type;
     uint16_t len;
 } __attribute__((__packed__));
 
 struct rte_ctls_ext_sni_hdr
 {
     uint16_t sni_list_len;
     uint8_t type;
     uint16_t sni_len;
 } __attribute__((__packed__));
 
 struct rte_server_name
 {
     uint16_t name;
 } __attribute__((__packed__));
 
 
 struct rte_client_hello_dpdk_hdr
 {
     uint8_t type;
     uint16_t len;
     uint16_t exts_num;
 } __attribute__((__packed__));
 
 struct rte_server_hello_dpdk_hdr
 {
     uint8_t type;
     uint16_t len;
     uint16_t exts_num;
     uint16_t version;
 } __attribute__((__packed__));
 
 struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_entry {
    uint16_t len_min;
    uint16_t len_max;
    uint64_t total_len;

    uint64_t first_timestamp;
    uint64_t last_timestamp;
    uint64_t iat_min;
    uint64_t iat_max;
    uint32_t pkt_count;
};

typedef struct {
    int n_nodes;
    int left_child;
    int right_child;
    int feature;
    double threshold;
    int is_leaf;
    int class_label;
} TreeNode;

// Structure to hold random forest model
typedef struct {
    int n_estimators;
    int max_depth;
    double feature_importances[5];
    TreeNode trees[MAX_TREES][MAX_NODES];
} RandomForest;

struct rte_hash *flow_table;
struct rte_hash_parameters hash_params = {0};
struct flow_entry flow_pool[MAX_FLOWS];

 /* >8 End of launching function on lcore. */
 static inline int
 port_init(uint16_t port, struct rte_mempool *mbuf_pool)
 {
     uint16_t nb_queue_pairs = 1;
     uint16_t rx_rings = nb_queue_pairs, tx_rings = nb_queue_pairs;
     uint16_t nb_rxd = RX_RING_SIZE;
     uint16_t nb_txd = TX_RING_SIZE;
     uint16_t rx_queue_size = QUEUE_SIZE;
     uint16_t tx_queue_size = QUEUE_SIZE;
     int retval;
     uint16_t q;
     struct rte_eth_dev_info dev_info;
     struct rte_eth_rxconf rxconf;
     struct rte_eth_txconf txconf;
     struct rte_eth_conf port_conf = {
         .rxmode = {
             .mq_mode = RTE_ETH_MQ_RX_RSS,
             .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP,
         },
         .rx_adv_conf = {
             .rss_conf = {
                 .rss_key = NULL,
                 .rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
             },
         },
         .txmode = {
             .mq_mode = RTE_ETH_MQ_TX_NONE,
         },
     };
 
     if (!rte_eth_dev_is_valid_port(port))
         return -1;
 
     rte_eth_promiscuous_enable(port);
 
     retval = rte_eth_dev_info_get(port, &dev_info);
     if (retval != 0)
     {
         printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
 
         return retval;
     }
 
     retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
     if (retval != 0)
         return retval;
 
     retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
     if (retval != 0)
         return retval;
     rxconf = dev_info.default_rxconf;
 
     for (q = 0; q < rx_rings; q++)
     {
         retval = rte_eth_rx_queue_setup(port, q, rx_queue_size,
                                         rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
         if (retval < 0)
             return retval;
     }
 
     txconf = dev_info.default_txconf;
     txconf.offloads = port_conf.txmode.offloads;
     for (q = 0; q < tx_rings; q++)
     {
         retval = rte_eth_tx_queue_setup(port, q, tx_queue_size,
                                         rte_eth_dev_socket_id(port), &txconf);
         if (retval < 0)
             return retval;
     }
     retval = rte_eth_dev_start(port);
     if (retval < 0)
     {
         return retval;
     }
     return 0;
 }
 
 
 
 // Start of HW timestamps
 static inline bool
is_timestamp_enabled(const struct rte_mbuf *mbuf)
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

static inline rte_mbuf_timestamp_t
get_hw_timestamp(const struct rte_mbuf *mbuf)
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

// End of HW timetamps


 // Function to read the JSON file and load the Random Forest model
 int load_rf_model(const char *filename, RandomForest *rf) {
     json_error_t error;
     json_t *root = json_load_file(filename, 0, &error);
 
     if (!root) {
         fprintf(stderr, "Error loading JSON file: %s\n", error.text);
         return -1;
     }
 
     // Parse the general model parameters
     json_t *n_estimators = json_object_get(root, "n_estimators");
     json_t *max_depth = json_object_get(root, "max_depth");
     json_t *feature_importances = json_object_get(root, "feature_importances");
 
     rf->n_estimators = json_integer_value(n_estimators);
     rf->max_depth = json_integer_value(max_depth);
 
     // Parse feature importances
     for (int i = 0; i < 5; i++) {
         rf->feature_importances[i] = json_real_value(json_array_get(feature_importances, i));
     }
 
     // Parse each decision tree
     json_t *estimators = json_object_get(root, "estimators");
     size_t index;
     json_t *tree_data;
 
     json_array_foreach(estimators, index, tree_data) {
         TreeNode *tree = rf->trees[index];
         size_t n_nodes = json_integer_value(json_object_get(tree_data, "n_nodes"));
 
         // Parse the nodes of the tree
         json_t *children_left = json_object_get(tree_data, "children_left");
         json_t *children_right = json_object_get(tree_data, "children_right");
         json_t *feature = json_object_get(tree_data, "feature");
         json_t *threshold = json_object_get(tree_data, "threshold");
         json_t *class_label = json_object_get(tree_data, "class_label"); // Holds the class probabilities/counts
         json_t *leaves = json_object_get(tree_data, "leaves");
 
         for (int i = 0; i < n_nodes; i++) {
             TreeNode *node = &tree[i];
             node->feature = json_integer_value(json_array_get(feature, i));
             node->threshold = json_real_value(json_array_get(threshold, i));
             node->left_child = json_integer_value(json_array_get(children_left, i));
             node->right_child = json_integer_value(json_array_get(children_right, i));
             node->class_label = json_integer_value(json_array_get(class_label, i));
             node->is_leaf = json_integer_value(json_array_get(leaves, i));
         }
     }
 
     json_decref(root);
     return 0;
 }
 
 // Function to traverse a tree and make a prediction
 int predict_tree(TreeNode *tree, double *sample, int node_index) {
     TreeNode *node = &tree[node_index];
 
     if (node->is_leaf) {
         return node->class_label;
     }
 
     if (sample[node->feature] <= node->threshold) {
         return predict_tree(tree, sample, node->left_child);
     } else {
         return predict_tree(tree, sample, node->right_child);
     }
 }

 int predict_rf(RandomForest *rf, double *sample) {
     if (rf == NULL || rf->n_estimators <= 0) {
         return -1; // Error or empty forest
     }
 
     int count[3] = {0};
 
     for (int i = 0; i < rf->n_estimators; i++) {
         int prediction = predict_tree(rf->trees[i], sample, 0);
         if (prediction >= 0 && prediction < 3) {
             count[prediction]++;
         }
     }
 
     // Find the majority class
     int final_prediction = 0;
     int max_votes = count[0];
 
     for (int i = 1; i < 3; i++) {
         if (count[i] > max_votes) {
             final_prediction = i;
             max_votes = count[i];
         }
     }
 
     return final_prediction;
 }
 
// ReLU activation for vector of 4 floats
static inline float32x4_t relu4(float32x4_t x) {
    return vmaxq_f32(x, vdupq_n_f32(0.0f));
}

// ReLU for scalar
static inline float relu(float x) {
    return (x > 0.0f) ? x : 0.0f;
}

// Fast piecewise sigmoid approximation
static inline float fast_sigmoid(float x) {
    if (x <= -4.0f) return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <= 0.0f)  return 0.125f * x + 0.5f;
    else if (x <= 2.0f)  return -0.125f * x + 0.5f;
    else if (x <= 4.0f)  return -0.0625f * x + 0.75f;
    else return 1.0f;
}

// Perform MLP inference with fixed structure: 
// Returns 0 or 1 (binary class)
static inline int predict_mlp(const float input[4]) {
    float hidden1[8], hidden2[4];

    // Layer 1: 
    for (int j = 0; j < 8; j += 4) {
        float32x4_t acc = vld1q_f32(&B0[j]);
        for (int i = 0; i < 4; i++) {
            float32x4_t w = vld1q_f32(&W0[i * 8 + j]);
            float32x4_t x = vdupq_n_f32(input[i]);
            acc = vfmaq_f32(acc, x, w);
        }
        acc = relu4(acc);
        vst1q_f32(&hidden1[j], acc);
        
    }

    // Layer 2:
    for (int j = 0; j < 4; j++) {
        float acc = B1[j];
        for (int i = 0; i < 8; i++) {
            acc += W1[i * 4 + j] * hidden1[i];
        }
        hidden2[j] = relu(acc);
    }

    // Output
    float acc = B2[0];
    for (int i = 0; i < 4; i++) {
        acc += W2[i] * hidden2[i];
    }

    float y = fast_sigmoid(acc);
    return (y > 0.5f) ? 1 : 0;
}

 static inline uint32_t allocate_entry() {
    for (uint32_t i = 0; i < MAX_FLOWS; i++) {
        if (flow_pool[i].pkt_count == 0) {
            flow_pool[i].len_min = UINT16_MAX;
            flow_pool[i].iat_min = UINT64_MAX;
            return i;
        }
    }
    return INVALID_INDEX;
}

static inline void reset_entry(uint32_t idx) {
    if (idx < MAX_FLOWS)
        memset(&flow_pool[idx], 0, sizeof(struct flow_entry));
}


void update_flow_entry(struct flow_entry *entry, uint16_t pkt_len, uint64_t now_cycles) {
    uint64_t iat = (entry->pkt_count > 0) ? (now_cycles - entry->last_timestamp) : 0;

    if (entry->pkt_count == 0) {
        entry->len_min = pkt_len;
        entry->len_max = pkt_len;
        entry->first_timestamp = now_cycles;
        entry->total_len = pkt_len;
    } else {
        if (pkt_len < entry->len_min) entry->len_min = pkt_len;
        if (pkt_len > entry->len_max) entry->len_max = pkt_len;
        entry->total_len += pkt_len;

        if (iat < entry->iat_min) entry->iat_min = iat;
        if (iat > entry->iat_max) entry->iat_max = iat;
    }

    entry->last_timestamp = now_cycles;
    entry->pkt_count++;
}


void handle_packet(struct flow_key *key, uint16_t pkt_len, uint64_t now, RandomForest *rf) {
    struct flow_entry *entry = NULL;
    uint32_t index;
    int ret = rte_hash_lookup_data(flow_table, key, (void **)&index);

    if (ret < 0) {
        index = allocate_entry();
        if (index == INVALID_INDEX)
            return;

        ret = rte_hash_add_key_data(flow_table, key, (void *)(uintptr_t)index);
        if (ret < 0) {
            reset_entry(index);
            return;
        }
    }

    entry = &flow_pool[index];
    update_flow_entry(entry, pkt_len, now);

    if (entry->pkt_count >= N_PACKETS) {
        uint64_t hz = rte_get_tsc_hz();
        printf("TSC frequency: %lu Hz\n", hz);

        float features[4] = {
            (float)entry->total_len,
            (float)(entry->len_max - entry->len_min),
            (float)((entry->last_timestamp - entry->first_timestamp) / (double)hz * 1e6),
            (float)((entry->iat_max - entry->iat_min) / (double)hz * 1e6)
        };

        // uint64_t start_cycles = rte_rdtsc_precise();
        // printf("TSC frequency: %lu Hz\n", hz);

        int prediction = predict_mlp(features);
        printf("MLP prediction: %d\n", prediction);
        // uint64_t end_cycles = rte_rdtsc_precise();
        // uint64_t inference_cycles = end_cycles - start_cycles;

        // // Convert to nanoseconds
        // double latency_ns = ((double)inference_cycles / hz) * 1e9;

        // printf("Latency: %.2f ns (%lu cycles)\n", latency_ns, inference_cycles);

        rte_hash_del_key(flow_table, key);
        reset_entry(index);
    }

}

 struct
 {
     struct rte_mempool *mbuf_pool;
     struct rte_hash *flow_table;
     RandomForest *rf;
     int packet_counters[10];
 }worker_args;
 
 double right_predictions=0;
 double wrong_predictions=0;
 
 double received_packets=0;
 double processed_packets=0;
 
 static int
 lcore_main(void *args)
 {
     // struct worker_args *w_args = (struct worker_args *)args;
     struct rte_mempool *mbuf_pool = worker_args.mbuf_pool;
     struct rte_hash *flow_table = worker_args.flow_table;
     RandomForest *rf = worker_args.rf;
     // int core_id = rte_lcore_id();
     // int *packet_counter = &worker_args.packet_counters[core_id];
 
     uint16_t port;
     uint16_t ret;
 
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
     uint16_t queue_id =  rte_lcore_id() - 1;
 
 
     for (;;)
     {
         // port=1;
         RTE_ETH_FOREACH_DEV(port)
         {
             struct rte_mbuf *bufs[BURST_SIZE];
             
             uint16_t nb_rx = rte_eth_rx_burst(port, queue_id,
                                               bufs, BURST_SIZE);
 
             // break;
             if (nb_rx > 0)
             {
                uint64_t start_cycles = rte_rdtsc_precise();
                 received_packets+=nb_rx;
                 struct rte_ether_hdr *ethernet_header; 
                 struct rte_ipv4_hdr *pIP4Hdr;
                 struct rte_tcp_hdr *pTcpHdr;
                 struct rte_tls_hdr *pTlsHdr;
                 struct rte_tls_hdr *pTlsRecord1;
                 struct rte_tls_hdr *pTlsRecord2;
                 struct rte_tls_hello_hdr *pTlsHandshakeHdr;
                 struct rte_tls_session_hdr *pTlsSessionHdr;
                 struct rte_tls_cipher_hdr *pTlsChiperHdr;
                 struct rte_tls_compression_hdr *pTlsCmpHdr;
                 struct rte_tls_ext_len_hdr *pTlsExtLenHdr;
                 struct rte_tls_ext_hdr *pTlsExtHdr;
 
                 u_int16_t ethernet_type;
                 for (int i = 0; i < nb_rx; i++)
                 {
                     // pkt_count +=1;
                     ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                     ethernet_type = ethernet_header->ether_type;
                     ethernet_type = rte_cpu_to_be_16(ethernet_type);
 
                     if (ethernet_type == 2048)
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
                             if (dst_port == 443 || src_port == 443)
                             {
 
                                 pTlsHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hdr *, tcpdata_offset);
                                 uint8_t tls_type = pTlsHdr->type;
                                 uint32_t tlsdata_offset = tcpdata_offset + sizeof(struct rte_tls_hdr);

                                if (tls_type == 0x17)
                                {
                                    //printf("This is a application data packet");
                                    key.src_ip = dst_ip;  
                                    key.dst_ip = src_ip; 
                                    key.src_port = dst_port;
                                    key.dst_port = src_port;
                                    key.protocol = IPv4NextProtocol;

                                    uint16_t pkt_len = pIP4Hdr->total_length;
                                    uint64_t pkt_time = is_timestamp_enabled(bufs[i]) ? get_hw_timestamp(bufs[i]) : 0;    
                                    // printf("TSC frequency: %lu Hz\n", hz);
                                    
                                    // int prediction = predict_mlp(features);
                                    // uint64_t start_cycles = rte_rdtsc_precise();

                                    handle_packet(&key, pkt_len, pkt_time, rf);

                                    // uint64_t end_cycles = rte_rdtsc_precise();
                                    // uint64_t inference_cycles = end_cycles - start_cycles;

                                    // // Convert to nanoseconds
                                    // double latency_ns = ((double)inference_cycles / hz) * 1e9;

                                    // printf("Latency: %.2f ns (%lu cycles)\n", latency_ns, inference_cycles);                                       
                                }
                            }
                        }
                    }
                }
                uint64_t end_cycles = rte_rdtsc_precise();
                uint64_t inference_cycles = end_cycles - start_cycles;

                // Convert to nanoseconds
                uint64_t hz = rte_get_tsc_hz();
                double latency_ns = ((double)inference_cycles / hz) * 1e9;

                printf("Latency: %.2f ns (%lu cycles). %d number of packets\n", latency_ns, inference_cycles,nb_rx);
                if (unlikely(nb_rx == 0))
                    continue;

                const uint16_t nb_tx = rte_eth_tx_burst(port, queue_id,
                                                        bufs, nb_rx);

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
 
 


     hash_params.name = "flow_table";
     hash_params.entries = MAX_FLOWS;
     hash_params.key_len = sizeof(struct flow_key);
     hash_params.hash_func = rte_jhash;
     hash_params.hash_func_init_val = 0;
     hash_params.socket_id = rte_socket_id();
 
     flow_table = rte_hash_create(&hash_params);
     if (!flow_table) {
         rte_panic("Failed to create hash table\n");
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
     if (port_init(portid, mbuf_pool) != 0)
     {
         rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                  portid);
     }
     else{
         printf("port %u initialized\n",portid);
     };
 
     
     RandomForest rf;
 
     // Load the model from the JSON file
     if (load_rf_model("rf_model.json", &rf) != 0) {
         return -1;
     }
 
   
     worker_args.mbuf_pool = mbuf_pool;
     worker_args.flow_table = flow_table;
     worker_args.rf = &rf;
 
     RTE_LCORE_FOREACH_WORKER(lcore_id)
     {
         rte_eal_remote_launch(lcore_main, &worker_args, lcore_id);
     }
 
     char command[50];
 
     int *packet_counters = worker_args.packet_counters;
     
     while (1) {
         printf("Enter command: ");
         scanf("%s", command);
         // printf("The input command is %s\n",command);
 
         if (strcmp(command, "get_stats") == 0) {
             RTE_LCORE_FOREACH_WORKER(lcore_id)
             {
 
                 char output_file[50]; //= "../datasets/DoHBrw/predictions.txt";
                 
                 printf("Enter file name: ");
                 scanf("%s", output_file);   
 
                 FILE *file = fopen(output_file, "w");
 
                 if (file == NULL) {
                     printf("Error opening the file.\n");
                     return -1;
                 }
 
                 fprintf(file, "Received Processed Dropped\n");
                 // printf("Core %u processed %u packets\n",lcore_id,packet_counters[lcore_id]);
                 fprintf(file, "%f %f %.3f \n",received_packets,processed_packets,(double)(processed_packets/received_packets));
                 right_predictions = 0;
                 wrong_predictions = 0;
                 received_packets = 0;
                 processed_packets = 0;
 
                 fclose(file);
                 // packet_counters[lcore_id] = 0;
             }
             // break;
         }
     }
 
 
     rte_eal_mp_wait_lcore();
 
     rte_hash_free(flow_table);
 
     close_ports();
 
     /* clean up the EAL */
     rte_eal_cleanup();
 
     return 0;
 }