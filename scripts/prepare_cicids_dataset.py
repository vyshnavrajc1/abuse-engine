#!/usr/bin/env python3
"""
prepare_cicids_dataset.py - robust version for GeneratedLabelledFlows.zip
"""

import os
import sys
import pandas as pd
import numpy as np
import argparse
from datetime import datetime

DATASET_DIR = "datasets/CICIDS2017"  # CSVs live in the subdirectory, not the root datasets/ folder
OUTPUT_DIR = "datasets/processed"
OUTPUT_FILE = "cicids2017_api_logs.csv"

# Column name candidates (including spaces)
TIMESTAMP_CANDIDATES = ['Timestamp', ' Timestamp', 'Time', 'Start Time']
SRC_IP_CANDIDATES   = ['Src IP', ' Source IP', 'Source IP', 'SrcAddr', ' Source Address']
DST_PORT_CANDIDATES  = ['Destination Port', 'Dst Port', 'Port']
FLOW_DURATION_CANDIDATES = ['Flow Duration', ' Flow Duration']
TOTAL_FWD_PKTS_CANDIDATES = ['Total Fwd Packets', ' Total Fwd Packets']
LABEL_CANDIDATES    = ['Label', ' Label', 'Attack', ' Attack']

def find_column(df, candidates, default=None):
    for col in candidates:
        if col in df.columns:
            return col
    if default is not None:
        for col in df.columns:
            if default.lower() in col.lower():
                print(f"  WARNING: Using '{col}' as fallback for {default}")
                return col
    return None

def categorize_label(label):
    label = str(label).strip()
    if label == "BENIGN":
        return "Benign"
    # DDoS must be checked BEFORE DoS — "DoS" is a substring of "DDoS"
    elif "DDoS" in label:
        return "DDoS"
    elif "Brute Force" in label or "FTP-Patator" in label or "SSH-Patator" in label:
        return "Brute Force"
    elif "DoS" in label or "Hulk" in label or "GoldenEye" in label:
        return "DoS"
    elif "PortScan" in label:
        return "Port Scan"
    elif "Bot" in label:
        return "Botnet"
    elif "Web Attack" in label:
        return "Web Attack"
    elif "Infiltration" in label:
        return "Infiltration"
    elif "Heartbleed" in label:
        return "Heartbleed"
    else:
        return "Other"

def assign_status(label, attack_category):
    if attack_category == "Benign":
        return 200
    elif attack_category == "Brute Force":
        r = np.random.random()
        if r < 0.05:
            return 200
        elif r < 0.70:
            return 401
        else:
            return 403
    else:
        return 200

def process_cicids_files(files, output_path):
    all_dfs = []
    np.random.seed(42)

    for file_path in files:
        # Try UTF-8 first, fallback to latin-1
        try:
            df = pd.read_csv(file_path, low_memory=False, encoding='utf-8')
        except UnicodeDecodeError:
            print(f"  UTF-8 failed, trying latin-1 for {file_path}")
            df = pd.read_csv(file_path, low_memory=False, encoding='latin-1')
        except Exception as e:
            print(f"  ERROR: Could not read {file_path}: {e}")
            continue

        print(f"Reading {file_path}...  Rows: {len(df)}")
        # Strip leading/trailing spaces from column names
        df.columns = [col.strip() for col in df.columns]

        # Find required columns
        timestamp_col = find_column(df, TIMESTAMP_CANDIDATES)
        src_ip_col    = find_column(df, SRC_IP_CANDIDATES)
        label_col     = find_column(df, LABEL_CANDIDATES)

        if timestamp_col is None:
            print(f"  WARNING: No timestamp column found in {file_path}. Skipping.")
            continue
        if src_ip_col is None:
            print(f"  WARNING: No source IP column found in {file_path}. Skipping.")
            continue
        if label_col is None:
            print(f"  WARNING: No label column found in {file_path}. Skipping.")
            continue

        # Parse timestamp – use pd.to_datetime which handles common formats
        # We'll also print some sample timestamps for debugging
        sample_timestamps = df[timestamp_col].dropna().head(3).tolist()
        print(f"  Sample timestamps: {sample_timestamps}")

        df['timestamp_parsed'] = pd.to_datetime(df[timestamp_col], errors='coerce')
        valid_timestamps = df['timestamp_parsed'].notna().sum()
        print(f"  Valid timestamps: {valid_timestamps} / {len(df)}")
        df = df.dropna(subset=['timestamp_parsed'])
        if len(df) == 0:
            print(f"  WARNING: No valid timestamps found in {file_path}. Skipping.")
            continue

        df['timestamp'] = df['timestamp_parsed'].dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        # Extract IP
        df['ip'] = df[src_ip_col].astype(str)

        # Optional columns (if missing, use defaults)
        dst_port_col      = find_column(df, DST_PORT_CANDIDATES)
        flow_duration_col = find_column(df, FLOW_DURATION_CANDIDATES)
        total_fwd_pkts_col = find_column(df, TOTAL_FWD_PKTS_CANDIDATES)

        # Endpoint: use destination port if available, else a default
        if dst_port_col is not None:
            df['endpoint'] = df[dst_port_col].apply(lambda p: f"/port_{int(p) if pd.notnull(p) else 0}")
        else:
            df['endpoint'] = "/unknown"

        df['method'] = 'GET'   # placeholder
        df['attack_category'] = df[label_col].apply(categorize_label)
        df['is_attack'] = df['attack_category'] != 'Benign'

        # Synthetic status code
        df['status'] = df.apply(lambda row: assign_status(row[label_col], row['attack_category']), axis=1)

        # Latency: Flow Duration (microseconds) -> milliseconds
        if flow_duration_col is not None:
            df['latency'] = df[flow_duration_col].fillna(0).astype(float) / 1000.0
            df['latency'] = df['latency'].clip(0, 10000)
        else:
            df['latency'] = 0

        # Response size: total forward packets as proxy
        if total_fwd_pkts_col is not None:
            df['response_size'] = df[total_fwd_pkts_col].fillna(0).astype(int)
        else:
            df['response_size'] = 0

        # User agent not available
        df['user_agent'] = ''

        # Keep only the columns we need
        keep_cols = ['timestamp', 'ip', 'method', 'endpoint', 'status',
                     'response_size', 'latency', 'user_agent',
                     'label', 'attack_category', 'is_attack']
        df['label'] = df[label_col]   # rename original label
        all_dfs.append(df[keep_cols])

    if not all_dfs:
        print("No valid files processed. Exiting.")
        sys.exit(1)

    # Concatenate all dataframes — preserve natural temporal ordering within each
    # day file; sorted file names (alphabetical) ensure deterministic output.
    data = pd.concat(all_dfs, ignore_index=True)
    print(f"Total rows after concatenation: {len(data)}")

    # Write to output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    data.to_csv(output_path, index=False)
    print(f"Saved {len(data)} records to {output_path}")
    print("\nAttack category distribution:")
    print(data['attack_category'].value_counts())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_dir", default=DATASET_DIR)
    parser.add_argument("--output_dir", default=OUTPUT_DIR)
    parser.add_argument("--output_file", default=OUTPUT_FILE)
    args = parser.parse_args()

    input_dir = args.input_dir
    csv_files = sorted([os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith('.csv')])
    if not csv_files:
        print(f"No CSV files found in {input_dir}")
        sys.exit(1)

    output_path = os.path.join(args.output_dir, args.output_file)
    process_cicids_files(csv_files, output_path)