#include <stdio.h>
#include <stdlib.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <stdint.h>
#include <time.h>

#define RX_RING_SIZE 128  // Size of the RX ring buffer
#define TX_RING_SIZE 512  // Size of the TX ring buffer

// Global variable to store the last timestamp for IAT calculation
struct rte_ethdev_timestamp last_timestamp = {0, 0}; // Initialize to 0

// Function to calculate the inter-arrival time (IAT) between two timestamps
double calculate_iat(struct rte_ethdev_timestamp *current, struct rte_ethdev_timestamp *last)
{
    // Convert timestamps to seconds (assuming 64-bit timestamp in nanoseconds)
    uint64_t delta_ns = (current->sec - last->sec) * 1000000000 + (current->nsec - last->nsec);
    
    // Convert to microseconds for easier display
    return (double)delta_ns / 1000.0;
}

// Set up the port to enable timestamping for all incoming packets
void enable_hw_timestamping(uint16_t port_id)
{
    struct rte_eth_hwtstamp_config timestamp_config;
    int ret;

    // Initialize timestamp configuration
    timestamp_config.rx_filter = HWTSTAMP_FILTER_ALL; // Enable timestamping for all RX packets
    timestamp_config.tx_type = HWTSTAMP_TX_OFF;  // Turn off TX timestamping (if not needed)
    
    // Set hardware timestamp configuration for the port using rte_eth_dev_configure
    ret = rte_eth_dev_configure(port_id, 1, 0, NULL); // Configuring 1 RX queue, 0 TX queues
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to configure port %u for timestamping\n", port_id);
    }

    // Apply the timestamp config (using standard way for DPDK timestamping)
    ret = rte_eth_dev_adjust_hwtstamp(port_id, &timestamp_config);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to set hardware timestamping on port %u\n", port_id);
    }

    printf("Hardware timestamping enabled on port %u with RX filter %d\n", port_id, timestamp_config.rx_filter);
}

// Initialize the port and configure timestamping
void init_port(uint16_t port_id)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP // Enable timestamp offload for RX packets
        }
    };
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf = {0}; // Zero out the RX queue configuration
    int ret;
    struct rte_mempool *mbuf_pool;

    // Create a memory pool for receiving packets
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    // Get the device info and check offload capabilities
    rte_eth_dev_info_get(port_id, &dev_info);
    port_conf.rxmode.offloads &= dev_info.rx_offload_capa; // Mask off unsupported offloads

    // Configure the port
    ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);  // 1 RX queue, 0 TX queues
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to configure port %u\n", port_id);

    // Enable hardware timestamping on the port
    enable_hw_timestamping(port_id);

    // Setup the RX queue
    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port_id),
                                 &rxq_conf, mbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to setup RX queue\n");

    // Start the port
    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to start port\n");

    printf("Port %u initialized and started.\n", port_id);
}

// Main function to initialize and start the DPDK application
int main(int argc, char *argv[])
{
    int ret;
    uint16_t port_id;
    struct rte_eth_dev_info dev_info;
    struct rte_mbuf *pkt;
    struct rte_ethdev_timestamp current_timestamp;
    double iat;

    // Initialize the DPDK environment
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Check that at least one port is available
    if (rte_eth_dev_count_avail() == 0) {
        rte_exit(EXIT_FAILURE, "No available Ethernet devices\n");
    }

    // Use the first available port (port_id = 0 in this case)
    port_id = 0;

    // Get the device info
    rte_eth_dev_info_get(port_id, &dev_info);

    // Check if the device supports timestamping
    if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
        rte_exit(EXIT_FAILURE, "Timestamping not supported on port %u\n", port_id);
    }

    // Initialize the port with timestamping enabled
    init_port(port_id);

    // Main processing loop
    while (1) {
        // Receive packets here (e.g., with rte_eth_rx_burst)
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, &pkt, 1); // Receive one packet
        if (nb_rx > 0) {
            // Get the timestamp for the received packet
            ret = rte_eth_timestamp_get(port_id, &current_timestamp);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "Failed to get timestamp\n");
            }

            // Calculate the inter-arrival time (IAT)
            if (last_timestamp.sec != 0 || last_timestamp.nsec != 0) {
                iat = calculate_iat(&current_timestamp, &last_timestamp);
                printf("Inter-Arrival Time (IAT) = %.6f ms\n", iat);  // Print IAT in milliseconds
            }

            // Store the current timestamp for the next iteration
            last_timestamp = current_timestamp;
        }
    }

    return 0;
}
