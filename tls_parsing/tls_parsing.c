#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>

struct tls_hdr {
    uint8_t  content_type;
    uint16_t version;
    uint16_t length;
} __attribute__((__packed__));

static void
parse_tls(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return;

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    if (ip->next_proto_id != IPPROTO_TCP)
        return;

    uint16_t ip_hdr_len = (ip->version_ihl & 0x0f) * 4;
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((unsigned char *)ip + ip_hdr_len);

    uint16_t tcp_hdr_len = (tcp->data_off >> 4) * 4;
    uint8_t *payload = (uint8_t *)tcp + tcp_hdr_len;
    uint16_t payload_len = rte_be_to_cpu_16(ip->total_length) - ip_hdr_len - tcp_hdr_len;

    if (payload_len < sizeof(struct tls_hdr)) return;

    struct tls_hdr *tls = (struct tls_hdr *)payload;
    printf("TLS content_type=0x%02x version=0x%04x length=%u\n",
           tls->content_type,
           rte_be_to_cpu_16(tls->version),
           rte_be_to_cpu_16(tls->length));
}

static __rte_noreturn void
main_loop(void) {
    const uint16_t port = 0;
    struct rte_mbuf *bufs[32];
    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, 32);
        for (int i = 0; i < nb_rx; i++) {
            parse_tls(bufs[i]);
            rte_pktmbuf_free(bufs[i]);
        }
    }
}

int main(int argc, char **argv) {
    rte_eal_init(argc, argv);

    // Configure port 0
    uint16_t portid = 0;
    struct rte_eth_conf port_conf = {0};
    rte_eth_dev_configure(portid, 1, 1, &port_conf);
    rte_eth_rx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL, rte_pktmbuf_pool_create("mbuf_pool", 8192, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()));
    rte_eth_tx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL);
    rte_eth_dev_start(portid);

    main_loop();
}
