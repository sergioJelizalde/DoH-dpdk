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

 #include <rte_hash.h>
 #include <rte_jhash.h>
 
 #include <rte_flow.h>
 
 //for bluefield2
 #include <arm_neon.h>
 #include "mlp_8.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191 

 // #define BURST_SIZE (1 << 9)
 
 #define QUEUE_SIZE 256
 
 #define BURST_SIZE 128
 
 // #define QUEUE_SIZE (1 << 6)
 
 #define MBUF_CACHE_SIZE 256
 
 //#define HASH_TABLE_SIZE (1 << 15) 
 

#define MAX_FLOWS 16384 
#define N_PACKETS 8
#define INVALID_INDEX UINT32_MAX


struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_entry {
    uint64_t first_timestamp;
    uint64_t last_timestamp;

    uint16_t pkt_count;

    /* packet‐length stats */
    uint32_t len_min;
    uint32_t len_max;
    uint64_t len_sum;      // for computing mean

    /* inter‐arrival time (IAT) stats */
    uint64_t iat_min;
    uint64_t iat_max;
    uint64_t iat_sum;      // for computing mean

    /* total bytes in flow (you already had: total_len) */
    uint64_t total_len;

    /* sum of '1' bits in the TCP flags field */
    uint32_t flag_bits_sum;
};

struct rte_hash *flow_table;
struct rte_hash_parameters hash_params = {0};
struct flow_entry flow_pool[MAX_FLOWS];

 /* >8 End of launching function on lcore. */
 static inline int
 port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t number_rings)
 {

     uint16_t nb_queue_pairs = number_rings;
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


// Fast piecewise sigmoid approximation
static inline float fast_sigmoid(float x) {
    if (x <= -4.0f) return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <= 0.0f)  return 0.125f * x + 0.5f;
    else if (x <= 2.0f)  return -0.125f * x + 0.5f;
    else if (x <= 4.0f)  return -0.0625f * x + 0.75f;
    else return 1.0f;
}

// -------------------------------------------------------------------------
// NEON‐vectorized layer
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
        if (!is_output)  acc = vmaxq_f32(acc, vdupq_n_f32(0.0f));
        vst1q_f32(&out[j], acc);
    }
    // tail scalar in case the model does not align to multiple of 4
    for (; j < size_out; j++) {
        float a = B[j];
        for (int k = 0; k < size_in; k++)
            a += W[k*size_out + j] * in[k];
        out[j] = is_output ? a : (a > 0.0f ? a : 0.0f);
    }
    if (is_output) {
        for (int i = 0; i < size_out; i++)
            out[i] = fast_sigmoid(out[i]);
    }
}

// NEON MLP over arbitrary layers
static int predict_mlp(const float *in_features,
                                    float *buf_a, float *buf_b) {
    float *in_buf  = buf_a, *out_buf = buf_b;
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        layer_forward_neon(
          WEIGHTS[L], BIASES[L],
          in_buf, out_buf,
          LAYER_SIZES[L],
          LAYER_SIZES[L+1],
          (L == NUM_LAYERS - 1)
        );
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // argmax
    int final_size = LAYER_SIZES[NUM_LAYERS], best = 0;
    float best_v = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_v) {
            best_v = in_buf[i];
            best   = i;
        }
    }
    return best;
}
//--------------------------------------------------------------------------


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


static inline uint8_t
count_bits(uint8_t x) {
    // GCC/Clang builtin popcount
    return __builtin_popcount(x);
}

void update_flow_entry(struct flow_entry *e,
                       uint16_t    pkt_len,
                       uint64_t    now_cycles,
                       uint8_t     tcp_flags_count)
{
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
        /* length stats */
        if (pkt_len < e->len_min) e->len_min = pkt_len;
        if (pkt_len > e->len_max) e->len_max = pkt_len;
        e->len_sum += pkt_len;

        /* IAT stats */
        if (iat < e->iat_min) e->iat_min = iat;
        if (iat > e->iat_max) e->iat_max = iat;
        e->iat_sum += iat;

        /* total bytes */
        e->total_len += pkt_len;

        /* flag bits sum */
        e->flag_bits_sum += tcp_flags_count;
    }

    e->last_timestamp = now_cycles;
    e->pkt_count++;
}


void handle_packet(struct flow_key *key,
                   uint16_t        pkt_len,
                   uint64_t        now,
                   uint8_t         flags_count,
                   float          *aux_a,
                   float           *aux_b)
{
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

    struct flow_entry *e = &flow_pool[index];

    /* update all stats*/
    update_flow_entry(e, pkt_len, now, flags_count);

    /* once we have N_PACKETS, compute features and predict */
    if (e->pkt_count >= N_PACKETS) {
        double hz = (double)rte_get_tsc_hz();

        /* compute means */
        float mean_len = (float)(e->len_sum   / (double)e->pkt_count);
        float mean_iat = (float)(e->iat_sum   / (double)(e->pkt_count - 1)) * 1e6 / hz;  // in µs

        /* range in µs */
        float duration_us =
          (float)((e->last_timestamp - e->first_timestamp) / hz * 1e6);

        /* build your feature vector: */
        float features[] = {
            /* packet‐length features (bytes) */
            (float)e->len_min,
            (float)e->len_max,
            mean_len,

            /* IAT features (µs) */
            (float)(e->iat_min / hz * 1e6),
            (float)(e->iat_max / hz * 1e6),
            mean_iat,

            /* total bytes*/
            (float)e->total_len,

            /* TCP flag‐bit sum */
            (float)e->flag_bits_sum
        };

        int prediction = predict_mlp(features, aux_a, aux_b);
        //printf("MLP prediction: %d\n", prediction);

        /* cleanup flow */
        rte_hash_del_key(flow_table, key);
        reset_entry(index);
    }
}

struct worker_args {
    struct rte_mempool *mbuf_pool;
    struct rte_hash    *flow_table;
    float              *buf_a;
    float              *buf_b;
    uint16_t            queue_id;    //
    /* add other per-core buffers here if you need them, e.g.: */
    // float *raw_input;
    // float *input;
};
static struct worker_args worker_args[RTE_MAX_LCORE];


 double right_predictions=0;
 double wrong_predictions=0;
 
 double received_packets=0;
 double processed_packets=0;
 

 static int lcore_main(void *args)
 {
    struct worker_args *w = (struct worker_args *)args;

    struct rte_mempool *mbuf_pool = w->mbuf_pool;
    struct rte_hash    *flow_table = w->flow_table;
    float *aux_a = w->buf_a;
    float *aux_b = w->buf_b;

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
         // port=1;
         RTE_ETH_FOREACH_DEV(port)
         {
             struct rte_mbuf *bufs[BURST_SIZE];
             
             uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);
 
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
                               /* figure out how many ‘1’ bits are set in TCP flags, or 0 otherwise */
                               // integrate code below with down code
                            uint8_t flags_count = __builtin_popcount(pTcpHdr->tcp_flags);


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

                           handle_packet(&key, pkt_len, pkt_time, flags_count, aux_a, aux_b);

                            // uint64_t end_cycles = rte_rdtsc_precise();
                            // uint64_t inference_cycles = end_cycles - start_cycles;

                            // // Convert to nanoseconds
                            // double latency_ns = ((double)inference_cycles / hz) * 1e9;

                            // printf("Latency: %.2f ns (%lu cycles)\n", latency_ns, inference_cycles);                                       
                          
                        }
                    }
                }
                uint64_t end_cycles = rte_rdtsc_precise();
                uint64_t inference_cycles = end_cycles - start_cycles;

                // Convert to nanoseconds
                uint64_t hz = rte_get_tsc_hz();
                double latency_ns = ((double)inference_cycles / hz) * 1e9;

                //printf("Latency: %.2f ns (%lu cycles). %d number of packets\n", latency_ns, inference_cycles,nb_rx);
                if (unlikely(nb_rx == 0))
                    continue;

                const uint16_t nb_tx = rte_eth_tx_burst(port, queue_id, bufs, nb_rx);

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


 
    unsigned total_lcores = rte_lcore_count(); 
    uint16_t q = 0;


     RTE_ETH_FOREACH_DEV(portid)
     if (port_init(portid, mbuf_pool,total_lcores) != 0)
     {
         rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                  portid);
     }
     else{
         printf("port %u initialized\n",portid);
     };
 

     RTE_LCORE_FOREACH_WORKER(lcore_id)
     {
        struct worker_args *w = &worker_args[lcore_id];

        // share pool and table
        w->mbuf_pool  = mbuf_pool;
        w->flow_table = flow_table;
        w->queue_id   = q++;

        // mlp initialization
        // find maximum neurons 
        int max_neurons = 0;
        for (int i = 0; i <= NUM_LAYERS; i++)
            if (LAYER_SIZES[i] > max_neurons)
                max_neurons = LAYER_SIZES[i];

        // allocate *this core’s* NEON buffers
        if (posix_memalign((void**)&w->buf_a, 16, max_neurons * sizeof(float)) ||
            posix_memalign((void**)&w->buf_b, 16, max_neurons * sizeof(float))) {
            rte_exit(EXIT_FAILURE, "posix_memalign failed\n");
        }

         rte_eal_remote_launch(lcore_main, w, lcore_id);
     }

     {
        unsigned master_id = rte_lcore_id();
        struct worker_args *w = &worker_args[master_id];
        w->mbuf_pool  = mbuf_pool;
        w->flow_table = flow_table;
        w->queue_id   = q;
        
        // mlp initialization
        // find maximum neurons 
        int max_neurons = 0;
        for (int i = 0; i <= NUM_LAYERS; i++)
            if (LAYER_SIZES[i] > max_neurons)
                max_neurons = LAYER_SIZES[i];

        posix_memalign((void**)&w->buf_a, 16, max_neurons * sizeof(float));
        posix_memalign((void**)&w->buf_b, 16, max_neurons * sizeof(float));

        lcore_main(w);   // call in the master thread
    }

 
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