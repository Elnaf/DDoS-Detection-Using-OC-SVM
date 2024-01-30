import pandas as pd
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import LabelEncoder
from datetime import timedelta
import matplotlib.pyplot as plt

# Column names based on your dataset
column_names = [
    'destination_ip', 'source_ip', 'destination_port', 'source_port', 'protocol',
    'start_timestamp', 'ack_number', 'end_timestamp', 'packet_number',
    'length', 'syn', 'flag', 'counter1', 'counter2', 'data_field', 'data_direction'
]

# Read the dataset
file_path = 'DUMP.txt'  # Adjust this to the correct path of your dataset
df = pd.read_csv(file_path, delim_whitespace=True, names=column_names)

# Convert 'start_timestamp' to datetime and sort
df['start_timestamp'] = pd.to_datetime(df['start_timestamp'], unit='s')
df.sort_values('start_timestamp', inplace=True)

# Encoding categorical data (IP addresses and ports)
le_destination_ip = LabelEncoder()
df['destination_ip_encoded'] = le_destination_ip.fit_transform(df['destination_ip'])

# Feature Engineering focusing on destination IP
features = df[['destination_ip_encoded']]

# Sliding Window Technique
window_size = 300  # seconds
start_time = df['start_timestamp'].min()
df['window'] = df['start_timestamp'].apply(lambda x: int((x - start_time) / timedelta(seconds=window_size)))

# Aggregating data by window
windowed_data = features.groupby(df['window']).sum()

# OC-SVM Model - Adjust the parameters based on your dataset characteristics
oc_svm_model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.0026)
oc_svm_model.fit(windowed_data)

# Anomaly Detection using OC-SVM
predictions = oc_svm_model.predict(windowed_data)
anomalies = windowed_data[predictions == -1]

# Postprocessing for Anomaly Detection
anomaly_indices = anomalies.index
anomaly_details = df[df['window'].isin(anomaly_indices)]

# SYN Packet Analysis for Flooding
# Filter for SYN packets and create a copy to avoid SettingWithCopyWarning
syn_packets = df[df['syn'] == 1].copy()

# Group data by window, destination_ip, and destination_port
grouped_syn_data = syn_packets.groupby(['window', 'destination_ip', 'destination_port']).size().reset_index(name='packet_count')

# Sort and select top potential attacks
top_attacks = grouped_syn_data.sort_values('packet_count', ascending=False).head(10)

# Iterate over top attacks to print details
for index, row in top_attacks.iterrows():
    window = row['window']
    window_start_time = df[df['window'] == window]['start_timestamp'].min()
    window_end_time = df[df['window'] == window]['start_timestamp'].max()
    dest_ip = row['destination_ip']
    dest_port = row['destination_port']
    packet_count = row['packet_count']
    unique_source_ips = syn_packets[(syn_packets['window'] == window) & (syn_packets['destination_ip'] == dest_ip) & (syn_packets['destination_port'] == dest_port)]['source_ip'].nunique()

    print(f"----------------------------------------")
    print(f"SYN Flooding Attack Details (Rank {index+1}):")
    print(f"  Start Time: {window_start_time}")
    print(f"  End Time: {window_end_time}")
    print(f"  Destination IP: {dest_ip}")
    print(f"  Destination Port: {dest_port}")
    print(f"  Packet Count: {packet_count}")
    print(f"  Unique Source IPs: {unique_source_ips}")
    print(f"----------------------------------------")

# Convert 'start_timestamp' to minutes since the start for plotting
syn_packets['minutes'] = (syn_packets['start_timestamp'] - start_time).dt.total_seconds() / 60

# Define windows for 1 minute and 5 minutes
one_minute_windows = syn_packets.groupby(syn_packets['minutes'].astype(int)).size()
five_minute_windows = syn_packets.groupby((syn_packets['minutes'] / 5).astype(int)).size()

# Plotting
plt.figure(figsize=(12, 6))
plt.plot(one_minute_windows.index, one_minute_windows.values, label='Max size in 1min')
plt.plot(five_minute_windows.index * 5, five_minute_windows.values, linestyle='--', label='Max size in 5min')
plt.yscale('log')
plt.title('Maximum SYN stream size over time')
plt.xlabel('Time (minutes)')
plt.ylabel('Maximum SYN Stream Size')
plt.legend()
plt.grid(True)
plt.show()

# Optional: Save the results to a CSV file
anomaly_details.to_csv('anomalies.csv', index=False)
grouped_syn_data.to_csv('syn_packet_analysis.csv', index=False)
