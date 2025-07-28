import gzip
from scapy.all import *
from collections import defaultdict
from statistics import mean
from tqdm import tqdm
import csv

pcap_file = "202406182345.pcap.gz"
flows = defaultdict(list)
last_ts = {}

def get_flow_key(pkt):
    if IP in pkt and TCP in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]
        return (ip.src, ip.dst, tcp.sport, tcp.dport)
    return None

print("Parsing packets...")
with gzip.open(pcap_file, 'rb') as f:
    pcap = RawPcapReader(f)

    for pkt_data, meta in tqdm(pcap):
        try:
            pkt = Ether(pkt_data)
            ts = meta.sec + meta.usec / 1e6
            key = get_flow_key(pkt)
            if not key:
                continue

            if len(flows[key]) >= 8:
                continue  # Only keep first 8 packets

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

print(f"Extracted {len(flows)} flows with at least 1 packet.")

def flag_counts(pkts):
    syn = rst = fin = 0
    for p in pkts:
        flags = p['flags']
        if flags & 0x02: syn += 1
        if flags & 0x04: rst += 1
        if flags & 0x01: fin += 1
    return syn, rst, fin

# Build CSV rows
csv_rows = []

for key, pkts in flows.items():
    if len(pkts) < 1:
        continue

    # Use only the first 8 packets
    limited_pkts = pkts[:8]
    iats = [p['iat'] for p in limited_pkts if p['iat'] is not None]
    sizes = [p['size'] for p in limited_pkts]

    syn, rst, fin = flag_counts(limited_pkts)

    csv_rows.append({
        'src_ip': key[0],
        'dst_ip': key[1],
        'src_port': key[2],
        'dst_port': key[3],
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

# Write to CSV
csv_file = "flow_features_mawi1.csv"
with open(csv_file, "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
    writer.writeheader()
    writer.writerows(csv_rows)

print(f"Saved CSV with {len(csv_rows)} flows as {csv_file}")
