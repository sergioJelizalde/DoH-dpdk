import pandas as pd

# Load CSV (this assumes it's present in the working directory)
csv_path = "flow_features_with_packet_count.csv"
df = pd.read_csv(csv_path)

# Check if the expected column exists
if "num_packets" not in df.columns:
    raise ValueError("Column 'num_packets' not found in the CSV.")

# Count flows based on thresholds
total_flows = len(df)
flows_gt_2 = (df["num_packets"] > 2).sum()
flows_gt_4 = (df["num_packets"] > 4).sum()
flows_gt_8 = (df["num_packets"] > 8).sum()

counts = {
    "Total flows": total_flows,
    "Flows with > 2 packets": flows_gt_2,
    "Flows with > 4 packets": flows_gt_4,
    "Flows with > 8 packets": flows_gt_8
}

# Print results
print("Flow Counts Summary:")
for label, count in counts.items():
    print(f"{label:<25}: {count}")
