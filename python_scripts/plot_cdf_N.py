import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the CSV file
csv_path = "flow_features_with_packet_count.csv"
df = pd.read_csv(csv_path)

# Extract number of packets per flow
packet_counts = df["num_packets"].values
packet_counts_sorted = np.sort(packet_counts)

# Compute CDF
cdf = np.arange(1, len(packet_counts_sorted)+1) / len(packet_counts_sorted)

# Plot
plt.figure(figsize=(8, 5))
plt.plot(packet_counts_sorted, cdf, label="CDF", color="blue", linewidth=2)
plt.xlabel("Number of Packets per Flow", fontsize=14)
plt.ylabel("Cumulative Probability", fontsize=14)
plt.title("CDF of Flow Packet Counts (N=20,000 Flows)", fontsize=16)
plt.grid(True, linestyle="--", alpha=0.7)
plt.tight_layout()

# Save to PDF
pdf_path = "flow_packet_count_cdf.pdf"
plt.savefig(pdf_path, format='pdf')
plt.show()
