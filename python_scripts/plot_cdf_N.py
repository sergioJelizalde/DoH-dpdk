import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the CSV file (assumes it was uploaded or present in the directory)
csv_path = "flow_features_with_packet_count.csv"
df = pd.read_csv(csv_path)

# Filter out flows with only 1 packet
df_multi = df[df["num_packets"] > 1]

# Extract number of packets per flow (after filtering)
packet_counts = df_multi["num_packets"].values
packet_counts_sorted = np.sort(packet_counts)

# Compute CDF
cdf = np.arange(1, len(packet_counts_sorted)+1) / len(packet_counts_sorted)

# Plot CDF
plt.figure(figsize=(8, 5))
plt.plot(packet_counts_sorted, cdf, label="CDF (Flows > 1 pkt)", color="green", linewidth=2)
plt.xlabel("Number of Packets per Flow", fontsize=14)
plt.ylabel("Cumulative Probability", fontsize=14)
plt.title("CDF of Packet Counts (Filtered: >1 pkt)", fontsize=16)
plt.grid(True, linestyle="--", alpha=0.7)
plt.tight_layout()

# Save plot to PDF
pdf_path = "flow_packet_count_cdf_filtered.pdf"
plt.savefig(pdf_path, format='pdf')
plt.show()

pdf_path
