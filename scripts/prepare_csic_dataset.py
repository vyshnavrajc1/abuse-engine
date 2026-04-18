#!/usr/bin/env python3
"""
prepare_csic_dataset.py - Preprocess CSIC 2010 HTTP Dataset
Converts the web application payload dataset into the standard Abuse Engine format.
"""

import os
import sys
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime, timedelta

DATASET_DIR = "datasets"
INPUT_FILE = "csic_database.csv"
OUTPUT_DIR = "datasets/processed"
OUTPUT_FILE = "csic_api_logs.csv"

def parse_endpoint(row):
    """
    Extracts the URL path and appends the payload (content) if present.
    By doing this, the PayloadAgent will be able to scan both the URL 
    and the body for injection patterns without needing a schema change.
    """
    try:
        # The URL column often has " HTTP/1.1" at the end, so split it first
        raw_url = str(row['URL']).split(' ')[0]
        path = urlparse(raw_url).path
        content = str(row['content'])
        
        # Append payload to semantic endpoint if it exists
        if content != 'nan' and len(content.strip()) > 0:
            return path + '?' + content.strip()
        return path
    except Exception:
        return '/'

def main():
    input_path = os.path.join(DATASET_DIR, INPUT_FILE)
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        sys.exit(1)

    print(f"Reading {input_path}...")
    df = pd.read_csv(input_path, low_memory=False)

    print("Processing columns...")
    # The first column is unnamed and contains the label: "Normal" or "Anomalous"
    label_col = df.columns[0]
    
    # Map labels
    def map_label(val):
        return "BENIGN" if str(val).strip() == "Normal" else "Web Attack"
        
    df['mapped_label'] = df[label_col].apply(map_label)
    
    print("Generating rotating IPs to prevent DoS false positives...")
    def generate_ips(labels, chunk_size=25):
        ips = []
        counts = {"BENIGN": 0, "Web Attack": 0}
        bases = {"BENIGN": [192, 168, 1], "Web Attack": [10, 0, 0]}
        
        for label in labels:
            c = counts[label]
            ip_id = (c // chunk_size) + 1
            ip_last = ip_id % 254 + 1
            base = bases[label]
            ips.append(f"{base[0]}.{base[1]}.{base[2]}.{ip_last}")
            counts[label] += 1
        return ips
        
    df['ip'] = generate_ips(df['mapped_label'])
    
    df['method'] = df['Method'].fillna('GET')
    df['endpoint'] = df.apply(parse_endpoint, axis=1)
    df['status'] = 200
    
    if 'lenght' in df.columns:
        df['response_size'] = pd.to_numeric(df['lenght'], errors='coerce').fillna(0).astype(int)
    else:
        df['response_size'] = 0
        
    df['latency'] = 0.05
    df['user_agent'] = df['User-Agent'].fillna('')
    df['attack_category'] = df['mapped_label'].apply(lambda x: "Benign" if x == "BENIGN" else "Web Attack")
    df['is_attack'] = df['mapped_label'] != "BENIGN"
    df['label'] = df['mapped_label']
    
    # Generate sequential timestamps to satisfy TemporalAgent and SequenceAgent
    # (Since CSIC lacks timestamps, we mock them at 1 request/second)
    start_time = datetime(2026, 4, 1, 12, 0, 0)
    print("Generating sequential timestamps...")
    timestamps = [start_time + timedelta(seconds=i) for i in range(len(df))]
    df['timestamp'] = [ts.strftime('%Y-%m-%dT%H:%M:%SZ') for ts in timestamps]
    
    keep_cols = ['timestamp', 'ip', 'method', 'endpoint', 'status',
                 'response_size', 'latency', 'user_agent',
                 'label', 'attack_category', 'is_attack']
                 
    out_df = df[keep_cols]
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    print(f"Writing to {out_path}...")
    out_df.to_csv(out_path, index=False)
    
    print(f"Saved {len(out_df)} records to {out_path}")
    print("\nAttack category distribution:")
    print(out_df['attack_category'].value_counts())

if __name__ == "__main__":
    main()
