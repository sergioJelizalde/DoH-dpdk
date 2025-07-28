import gzip
from scapy.all import *
from collections import defaultdict
from statistics import mean
from tqdm import tqdm
import csv

# File path (compressed PCAP)
pcap_file = "202406182345.pcap.gz"
MAX_FLOWS = 20000

# Flow table: key = (src_ip, dst_ip, sport, dport), value = list of packets
flows = defaultdict(list)
last_ts = {}

# Extract flow key for TCP packets
def get_flow_key(pkt):
    if IP in pkt and TCP in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]
        return (ip.src, ip.dst, tcp.sport, tcp.dport)
    return None

print("Parsing packets and building flows (up to 20k flows)...")
with gzip.open(pcap_file, 'rb') as f:
    pcap = RawPcapReader(f)
    for pkt_data, meta in tqdm(pcap):
        try:
            pkt = Ether(pkt_data)
            ts = meta.sec + meta.usec / 1e6
            key = get_flow_key(pkt)
            if not key:
                continue

            if key not in flows and len(flows) >= MAX_FLOWS:
                break

            size = len(pkt)
            delta = None
            if key in last_ts:
                delta = ts - last_ts[key]
            last_ts[key] = ts

            flows[key].append({
                'timestamp': ts,
                'size': size,
                'iat': delta,
                'flags': pkt[TCP].flags
            })
        except Exception:
            continue

print(f"Total flows collected: {len(flows)}")

# Helper to count TCP flags
def flag_counts(pkts):
    syn = rst = fin = 0
    for p in pkts:
        flags = p['flags']
        if flags & 0x02: syn += 1
        if flags & 0x04: rst += 1
        if flags & 0x01: fin += 1
    return syn, rst, fin

# Compute flow-level features
csv_rows = []

for key, pkts in flows.items():
    iats = [p['iat'] for p in pkts if p['iat'] is not None]
    sizes = [p['size'] for p in pkts]
    syn, rst, fin = flag_counts(pkts)

    csv_rows.append({
        'src_ip': key[0],
        'dst_ip': key[1],
        'src_port': key[2],
        'dst_port': key[3],
        'num_packets': len(pkts),
        'iat_min': min(iats) if iats else 0,
        'iat_max': max(iats) if iats else 0,
        'iat_mean': mean(iats) if iats else 0,
        'pkt_size_min': min(sizes),
        'pkt_size_max': max(sizes),
        'pkt_size_mean': mean(sizes),
        'total_bytes': sum(sizes),
        'syn_count': syn,
        'rst_count': rst,
        'fin_count': fin
    })

# Save CSV
csv_file = "flow_features_with_packet_count.csv"
with open(csv_file, "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
    writer.writeheader()
    writer.writerows(csv_rows)

print(f"Saved flow feature CSV: {csv_file}")
