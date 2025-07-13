#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_launch.h>  // for rte_eal_remote_launch

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arm_acle.h>    // for __crc32* intrinsics

#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  512
#define BURST_SIZE       64
#define NUM_RX_QUEUES    3  // Number of RSS queues on port 0
#define QUEUE_SIZE       256  // Number of descriptors in each RX/TX queue

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode  = RTE_ETH_MQ_RX_RSS,
        .offloads = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf  = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
        }
    }
};

struct lcore_params {
    uint16_t port_id;
    uint16_t queue_id;
};

// Fixed JA3 string for testing
static const char fixed_msg[] =
  "771,4865-4866-4867-49195-49199-49196-49200-"
  "52393-52392-49171-49172-156-157-47-53-"
  "10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0";
static const size_t fixed_len = sizeof(fixed_msg) - 1;

// Hardware-accelerated CRC32
static uint32_t
crc32_hw(const uint8_t *buf, size_t len, uint32_t seed)
{
    uint32_t crc = ~seed;
    while (len >= 8) {
        uint64_t v; memcpy(&v, buf, 8);
        crc = __crc32d(crc, v);
        buf += 8; len -= 8;
    }
    while (len >= 4) {
        uint32_t v; memcpy(&v, buf, 4);
        crc = __crc32w(crc, v);
        buf += 4; len -= 4;
    }
    while (len >= 2) {
        uint16_t v; memcpy(&v, buf, 2);
        crc = __crc32h(crc, v);
        buf += 2; len -= 2;
    }
    while (len--) {
        crc = __crc32b(crc, *buf++);
    }
    return ~crc;
}

static int
lcore_main_loop(void *arg)
{
    struct lcore_params *params = arg;
    const uint16_t port_id  = params->port_id;
    const uint16_t queue_id = params->queue_id;
    uint32_t total_pkts_rec = 0;
    uint32_t total_pkts_proc = 0;
    struct rte_mbuf *bufs[BURST_SIZE];
    uint64_t hz       = rte_get_tsc_hz();
    uint64_t next_tsc = rte_get_tsc_cycles() + 2*hz;

    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);
        total_pkts_rec +=nb_rx;
        
        if (nb_rx == 0)
            continue;

       // printf("[Core %u] Received %u packets on port %u, queue %u\n", rte_lcore_id(), nb_rx, port_id, queue_id);

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth =
                rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);


            // Swap MAC addresses
            struct rte_ether_addr tmp_mac;
            rte_ether_addr_copy(&eth->src_addr, &tmp_mac);
            rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
            rte_ether_addr_copy(&tmp_mac, &eth->dst_addr);

            // --- compute CRC32 on fixed_msg ---
            uint32_t crc = crc32_hw((const uint8_t*)fixed_msg, fixed_len, 0x00000000);
            //printf("[Core %u] CRC32(fixed_msg)=0x%08x\n", rte_lcore_id(), crc);
        }

        // Send packets back to port
        uint16_t nb_tx = rte_eth_tx_burst(port_id, queue_id, bufs, nb_rx);
        total_pkts_proc += nb_tx;
        uint64_t cur = rte_get_tsc_cycles();
        if (cur >= next_tsc) {
            printf("Number of packets received on CPU %d is  %u and %u are processed\n", rte_lcore_id(),total_pkts_rec,total_pkts_proc);
            // fflush(stdout);
            next_tsc += 2*hz;
            total_pkts_rec = 0;
            total_pkts_proc=0;
        }
        if (nb_tx < nb_rx) {
            for (uint16_t i = nb_tx; i < nb_rx; i++)
                rte_pktmbuf_free(bufs[i]);
        }
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    uint16_t port_id = 0;
    if (rte_eth_dev_count_avail() < 1)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS * rte_eth_dev_count_avail(),
                                        MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    ret = rte_eth_dev_configure(port_id,
                                NUM_RX_QUEUES, NUM_RX_QUEUES,
                                &port_conf_default);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d\n", ret);

    for (uint16_t q = 0; q < NUM_RX_QUEUES; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, QUEUE_SIZE,
                                     rte_eth_dev_socket_id(port_id),
                                     NULL, mbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "RX queue setup failed on queue %u\n", q);

        ret = rte_eth_tx_queue_setup(port_id, q, QUEUE_SIZE,
                                     rte_eth_dev_socket_id(port_id),
                                     NULL);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "TX queue setup failed on queue %u\n", q);
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to start device on port %u\n", port_id);

    rte_eth_promiscuous_enable(port_id);
    printf("Started port %u in promiscuous mode with %d RX/TX queues.\n",
           port_id, NUM_RX_QUEUES);
    
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    printf("── RSS / hash info ──\n");
    printf("  hash_key_size      = %u bytes\n",
        dev_info.hash_key_size);
    printf("  flow_type_rss_offloads = 0x%" PRIx64 "\n",
        dev_info.flow_type_rss_offloads);

    static struct lcore_params params_array[NUM_RX_QUEUES];
    uint16_t q = 0;
    unsigned core_id;

    RTE_LCORE_FOREACH_WORKER(core_id) {
        if (q >= NUM_RX_QUEUES - 1) break;
        params_array[q].port_id  = port_id;
        params_array[q].queue_id = q;
        rte_eal_remote_launch(lcore_main_loop,
                              &params_array[q],
                              core_id);
        q++;
    }

    // Use main core for the last queue
    params_array[q].port_id  = port_id;
    params_array[q].queue_id = q;
    lcore_main_loop(&params_array[q]);

    return 0;
}
