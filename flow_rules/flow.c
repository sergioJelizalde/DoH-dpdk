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

#define RXQ 2
#define TXQ 2
#define QUEUE_SIZE 256
#define BURST_SIZE 64

static int pf0hpf_port_id = 0; // SmartNIC DPDK port
static int sf2_port_id    = 1; // Representor (e.g., en3f0pf0sf2)
static int p0_port_id     = 2; // Physical port

static struct rte_flow *
create_mirror_rule(uint16_t from_port, uint16_t to_port, struct rte_flow_error *error) {
    struct rte_flow_attr attr = { .transfer = 1 };

    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_END }
    };

    struct rte_flow_action_port_id mirror = { .id = to_port };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &mirror },
        { .type = RTE_FLOW_ACTION_TYPE_PASSTHRU },
        { .type = RTE_FLOW_ACTION_TYPE_END }
    };

    struct rte_flow *flow = rte_flow_create(from_port, &attr, pattern, actions, error);
    if (!flow) {
        printf("Failed to mirror from port %d to port %d: %s\n",
               from_port, to_port,
               error->message ? error->message : "(no message)");
    } else {
        printf("Mirror rule created: p0 → port %d (mirror) and passthrough\n", to_port);
    }
    return flow;
}

static int
lcore_main_loop(void *arg) {
    uint16_t queue_id = (uintptr_t)arg;
    struct rte_mbuf *bufs[BURST_SIZE];

    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(pf0hpf_port_id, queue_id, bufs, BURST_SIZE);
        if (nb_rx == 0)
            continue;

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            printf("Packet %u received: src %02x:%02x:%02x:%02x:%02x:%02x\n", i,
                   eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
                   eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
                   eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);
        }

        rte_pktmbuf_free_bulk(bufs, nb_rx);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct rte_flow_error error;
    struct rte_flow *mirror_flow_pf = NULL, *mirror_flow_sf = NULL;

    if (rte_eal_init(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");

    struct rte_eth_conf port_conf = {
        .rxmode = { .mq_mode = RTE_ETH_MQ_RX_RSS },
        .rx_adv_conf.rss_conf = {
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        }
    };

    if (rte_eth_dev_configure(pf0hpf_port_id, RXQ, TXQ, &port_conf) < 0)
        rte_exit(EXIT_FAILURE, "Failed to configure pf0hpf\n");

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192, 256, 0,
                                                            RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Failed to create mbuf pool\n");

    for (int q = 0; q < RXQ; q++) {
        if (rte_eth_rx_queue_setup(pf0hpf_port_id, q, QUEUE_SIZE, rte_socket_id(), NULL, mbuf_pool) < 0)
            rte_exit(EXIT_FAILURE, "RX queue %d setup failed\n", q);
        if (rte_eth_tx_queue_setup(pf0hpf_port_id, q, QUEUE_SIZE, rte_socket_id(), NULL) < 0)
            rte_exit(EXIT_FAILURE, "TX queue %d setup failed\n", q);
    }

    if (rte_eth_dev_start(pf0hpf_port_id) < 0)
        rte_exit(EXIT_FAILURE, "Failed to start pf0hpf\n");

    rte_eth_promiscuous_enable(pf0hpf_port_id);
    printf("Started pf0hpf (port %d)\n", pf0hpf_port_id);

    mirror_flow_pf = create_mirror_rule(p0_port_id, pf0hpf_port_id, &error);
    mirror_flow_sf = create_mirror_rule(p0_port_id, sf2_port_id, &error);

    RTE_LCORE_FOREACH_WORKER(uint16_t lcore_id) {
        rte_eal_remote_launch(lcore_main_loop, (void *)(uintptr_t)0, lcore_id);
        break;  // Just one core for demo
    }

    printf("Press Enter to exit...\n");
    getchar();

    if (mirror_flow_pf)
        rte_flow_destroy(p0_port_id, mirror_flow_pf, &error);
    if (mirror_flow_sf)
        rte_flow_destroy(p0_port_id, mirror_flow_sf, &error);

    rte_eth_dev_stop(pf0hpf_port_id);
    rte_eth_dev_close(pf0hpf_port_id);

    return 0;
}
