#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>

#define RX_RING_SIZE 128
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const uint16_t port_id = 0;

static struct rte_mempool *mbuf_pool;

// For TSC timestamp comparison
static uint64_t last_tsc_timestamp = 0;

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

static inline uint64_t
tsc_to_ns(uint64_t tsc)
{
    return tsc * 1e9 / rte_get_tsc_hz();
}

static void
process_tsc_timestamp()
{
    uint64_t tsc = rte_rdtsc();
    uint64_t tsc_ns = tsc_to_ns(tsc);

    if (last_tsc_timestamp == 0) {
        printf("[TSC] Timestamp: %" PRIu64 " ns\n", tsc_ns);
    } else {
        uint64_t delta = tsc_ns - last_tsc_timestamp;
        printf("[TSC] Timestamp: %" PRIu64 " ns, Inter-arrival: %" PRIu64 " ns\n", tsc_ns, delta);
    }

    last_tsc_timestamp = tsc_ns;
}

static void
lcore_main(void)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx;
    uint64_t last_hw_timestamp = 0;

    printf("Core %u forwarding packets. [Press Ctrl+C to quit]\n", rte_lcore_id());

    for (;;) {
        nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        for (uint16_t i = 0; i < nb_rx; i++) {
            process_tsc_timestamp();

            if (is_timestamp_enabled(bufs[i])) {
                uint64_t hw_ts = get_hw_timestamp(bufs[i]);

                if (last_hw_timestamp == 0) {
                    printf(" [HW] Timestamp: %" PRIu64 " ns\n", hw_ts);
                } else {
                    printf(" [HW] Timestamp: %" PRIu64 " ns, Inter-arrival: %" PRIu64 " ns\n",
                           hw_ts, hw_ts - last_hw_timestamp);
                }

                last_hw_timestamp = hw_ts;
            }

            rte_pktmbuf_free(bufs[i]);
        }
    }
}

static void
init_port(void)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP
        }
    };
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    int ret;

    rte_eth_dev_info_get(port_id, &dev_info);
    port_conf.rxmode.offloads &= dev_info.rx_offload_capa;

    ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to configure port %u\n", port_id);

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;

    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port_id),
                                 &rxq_conf, mbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to setup RX queue\n");

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to start port\n");

    printf("Port %u initialized and started.\n", port_id);
}

int
main(int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * 2,
                                        MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    init_port();

    lcore_main();

    return 0;
}
