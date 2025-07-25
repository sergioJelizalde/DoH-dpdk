#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>

#define RXQ 3
#define TXQ 3
#define QUEUE_SIZE 256
#define BURST_SIZE 64

static int bf_port_id = 0;   // BlueField port (pf0hpf)
static int host_port_id = 1; // Host-facing port (e.g., p0)
static volatile uint64_t core_pkt_counter[RTE_MAX_LCORE] = {0};

static struct rte_flow *
create_mirror_rule(uint16_t src_port, uint16_t dst_port_id, struct rte_flow_error *error) {
    struct rte_flow_attr attr = {
    .ingress = 1,
    .transfer = 1,  // required for port-based mirror/forward actions
};

    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4 },
        { .type = RTE_FLOW_ITEM_TYPE_END }
    };

    struct rte_flow_action_port_id mirror = { .id = dst_port_id };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &mirror }, // mirror to host
        { .type = RTE_FLOW_ACTION_TYPE_PASSTHRU },                 // allow packet to DPDK path
        { .type = RTE_FLOW_ACTION_TYPE_END }
    };

    struct rte_flow *flow = rte_flow_create(src_port, &attr, pattern, actions, error);
    if (!flow) {
        printf("Failed to create mirror rule: %s\n", error->message ? error->message : "(no message)");
    } else {
        printf("Mirror rule created: pf0hpf → p0 (host) and continue to DPDK\n");
    }
    return flow;
}

static int lcore_main_loop(void *arg) {
    uint16_t queue_id = (uintptr_t)arg;
    struct rte_mbuf *bufs[BURST_SIZE];

    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(bf_port_id, queue_id, bufs, BURST_SIZE);
        if (nb_rx == 0) continue;

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            struct rte_ether_addr tmp;
            rte_ether_addr_copy(&eth->src_addr, &tmp);
            rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
            rte_ether_addr_copy(&tmp, &eth->dst_addr);
        }

        uint16_t nb_tx = rte_eth_tx_burst(bf_port_id, queue_id, bufs, nb_rx);
        for (uint16_t i = nb_tx; i < nb_rx; i++)
            rte_pktmbuf_free(bufs[i]);

        core_pkt_counter[rte_lcore_id()] += nb_rx;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct rte_mempool *mbuf_pool;
    struct rte_flow_error error;
    struct rte_flow *mirror_flow = NULL;

    if (rte_eal_init(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192, 256, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "MBUF pool creation failed\n");

    struct rte_eth_conf port_conf = {
        .rxmode = { .mq_mode = RTE_ETH_MQ_RX_RSS },
        .rx_adv_conf.rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        }
    };

    if (rte_eth_dev_configure(bf_port_id, RXQ, TXQ, &port_conf) < 0)
        rte_exit(EXIT_FAILURE, "BF port configuration failed\n");

    for (int i = 0; i < RXQ; i++) {
        if (rte_eth_rx_queue_setup(bf_port_id, i, QUEUE_SIZE,
                                   rte_eth_dev_socket_id(bf_port_id), NULL, mbuf_pool) < 0)
            rte_exit(EXIT_FAILURE, "RX queue %d setup failed\n", i);
    }

    for (int i = 0; i < TXQ; i++) {
        if (rte_eth_tx_queue_setup(bf_port_id, i, QUEUE_SIZE,
                                   rte_eth_dev_socket_id(bf_port_id), NULL) < 0)
            rte_exit(EXIT_FAILURE, "TX queue %d setup failed\n", i);
    }

    if (rte_eth_dev_start(bf_port_id) < 0)
        rte_exit(EXIT_FAILURE, "Failed to start BF device\n");

    rte_eth_promiscuous_enable(bf_port_id);
    printf("BlueField port started with RSS across %d queues\n", RXQ);

    // Create mirror rule: pf0hpf (DPDK) → p0 (host) + passthrough
    mirror_flow = create_mirror_rule(bf_port_id, host_port_id, &error);

    unsigned lcore_id;
    uint16_t queue_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (queue_id >= RXQ) break;
        rte_eal_remote_launch(lcore_main_loop, (void *)(uintptr_t)queue_id, lcore_id);
        queue_id++;
    }

    if (queue_id < RXQ)
        lcore_main_loop((void *)(uintptr_t)queue_id);

    printf("Press Enter to exit...\n");
    getchar();

    if (mirror_flow)
        rte_flow_destroy(bf_port_id, mirror_flow, &error);

    for (int i = 0; i < RTE_MAX_LCORE; i++) {
        if (core_pkt_counter[i] > 0)
            printf("Core %d processed %lu packets\n", i, core_pkt_counter[i]);
    }

    rte_eth_dev_stop(bf_port_id);
    rte_eth_dev_close(bf_port_id);

    return 0;
}
