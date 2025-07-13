#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <rte_launch.h>  // Include for rte_eal_remote_launch

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
#define NUM_RX_QUEUES 4  // Number of RSS queues on port 0
#define QUEUE_SIZE 128  // Number of descriptors in each RX/TX queue

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP,
        }
    }
};

struct lcore_params {
    uint16_t port_id;
    uint16_t queue_id;
};

static int lcore_main_loop(void *arg) {
    struct lcore_params *params = (struct lcore_params *)arg;
    const uint16_t port_id = params->port_id;
    const uint16_t queue_id = params->queue_id;

    struct rte_mbuf *bufs[BURST_SIZE];

   while (1) {
    uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);

    if (nb_rx > 0) {
        printf("[Core %u] Received %u packets on port %u, queue %u\n", rte_lcore_id(), nb_rx, port_id, queue_id);

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);

            // Swap MAC addresses
            struct rte_ether_addr tmp_mac;
            rte_ether_addr_copy(&eth->src_addr, &tmp_mac);
            rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
            rte_ether_addr_copy(&tmp_mac, &eth->dst_addr);
        }

        // Send packets back to port
        uint16_t nb_tx = rte_eth_tx_burst(port_id, queue_id, bufs, nb_rx);
        if (nb_tx < nb_rx) {
            for (uint16_t i = nb_tx; i < nb_rx; i++)
                rte_pktmbuf_free(bufs[i]);
        }
    }
}


    return 0;
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    uint16_t port_id = 0;

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    ret = rte_eth_dev_configure(port_id, NUM_RX_QUEUES, NUM_RX_QUEUES, &port_conf_default);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d\n", ret);

    for (uint16_t q = 0; q < NUM_RX_QUEUES; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, QUEUE_SIZE,
                                     rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "RX queue setup failed on queue %u\n", q);

        ret = rte_eth_tx_queue_setup(port_id, q, QUEUE_SIZE,
                                     rte_eth_dev_socket_id(port_id), NULL);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "TX queue setup failed on queue %u\n", q);
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to start device on port %u\n", port_id);

    rte_eth_promiscuous_enable(port_id);

    printf("Started port %u in promiscuous mode with %d RX/TX queues.\n", port_id, NUM_RX_QUEUES);

    static struct lcore_params params_array[NUM_RX_QUEUES];
    uint16_t q = 0;
    unsigned core_id;

    RTE_LCORE_FOREACH_WORKER(core_id) {
        if (q >= NUM_RX_QUEUES - 1) break;
        params_array[q].port_id = port_id;
        params_array[q].queue_id = q;
        rte_eal_remote_launch(lcore_main_loop, &params_array[q], core_id);
        q++;
    }

    // Use main core for the last queue
    params_array[q].port_id = port_id;
    params_array[q].queue_id = q;
    lcore_main_loop(&params_array[q]);

    return 0;
}
