#!/bin/bash

# change interface name here
INTERFACE="ens192f1np1"

# vport or physical
get_vport_rx_packets() {
    # Run ethtool and extract vport_rx_packets
    vport_rx_packets=$(ethtool -S $INTERFACE | grep "rx_packets_phy:" | awk '{print $2}')
    echo $vport_rx_packets
}

# Get initial vport_rx_packets value
initial_vport_rx_packets=$(get_vport_rx_packets)

if [ -z "$initial_vport_rx_packets" ]; then
    echo "Error: Could not get vport_rx_packets for interface $INTERFACE"
    exit 1
fi

# Variable to store total packets in 10 seconds
total_packets=0
# Duration for monitoring (10 seconds)
duration=$1

# Monitor packets per second for 10 seconds
for ((i=1; i<=duration; i++)); do
    # Wait for 1 second
    sleep 1

    # Get the current vport_rx_packets value
    final_vport_rx_packets=$(get_vport_rx_packets)

    if [ -z "$final_vport_rx_packets" ]; then
        echo "Error: Could not get vport_rx_packets for interface $INTERFACE"
        exit 1
    fi

    # Calculate the difference in vport_rx_packets (packets per second)
    pps=$((final_vport_rx_packets - initial_vport_rx_packets))

    # Add the pps to the total
    total_packets=$((total_packets + pps))

    # Output packets per second (PPS) for this second
    echo "Packets per second (vport_rx_packets): $pps"

    # Update initial_vport_rx_packets for the next interval
    initial_vport_rx_packets=$final_vport_rx_packets
done

# Calculate the average packets per second over 10 seconds
average_pps=$((total_packets / duration))

# Output the average packets per second
echo "Average packets per second (vport_rx_packets) over $duration seconds: $average_pps"
