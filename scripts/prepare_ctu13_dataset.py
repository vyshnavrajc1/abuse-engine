#!/usr/bin/env python3
"""
prepare_ctu13_dataset.py  —  Preprocess CTU-13 Scenario 10 dataset
for the Abuse Engine.

Dataset: capture20110818.binetflow
Source: CTU-13 (scenario 10)

Column mapping
--------------
StartTime -> timestamp   (parsed -> ISO-8601 UTC string)
SrcAddr   -> ip
Proto     -> method      (TCP->GET, UDP->POST, ICMP->OPTIONS)
Dport     -> endpoint    (/port_<Dport>)
TotBytes  -> response_size
Dur       -> latency
Label     -> extracted to is_attack, label, attack_category

Output schema (identical to other processed CSVs consumed by CICIDSIngestion):
  timestamp, ip, method, endpoint, status,
  response_size, latency, user_agent,
  label, attack_category, is_attack
"""

import argparse
import os
import sys

import pandas as pd

# ── Paths ─────────────────────────────────────────────────────────────────────
DATASET_DIR  = "datasets"
INPUT_FILE   = "capture20110818.binetflow"
OUTPUT_DIR   = "datasets/processed"
OUTPUT_FILE  = "ctu13_scenario10_logs.csv"

def parse_timestamp(raw: str) -> str | None:
    # "2011/08/18 09:56:29.146156"
    try:
        # Some datetimes might be malformed, coerce errors
        dt = pd.to_datetime(raw, errors='coerce', utc=False)
        if pd.isna(dt):
            return None
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

def map_proto_to_method(proto: str) -> str:
    proto = str(proto).strip().upper()
    mapping = {
        "TCP":  "GET",
        "UDP":  "POST",
        "ICMP": "OPTIONS",
    }
    return mapping.get(proto, "GET")

def main(input_path: str, output_path: str) -> None:
    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)

    print(f"Reading {input_path} ...")
    df = pd.read_csv(input_path, low_memory=False)

    df.columns = [c.strip() for c in df.columns]
    print(f"  Raw rows: {len(df)}")

    # ── Validate required columns ─────────────────────────────────────────────
    required = {"StartTime", "SrcAddr", "DstAddr", "Proto", "Dport", "TotBytes", "Dur", "Label"}
    missing  = required - set(df.columns)
    if missing:
        print(f"ERROR: Required columns missing: {missing}")
        sys.exit(1)

    # ── timestamp ─────────────────────────────────────────────────────────────
    print("Parsing timestamps ...")
    # Native vectorized parsing
    df["timestamp"] = pd.to_datetime(df["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce").dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    n_bad = df["timestamp"].isna().sum()
    if n_bad:
        print(f"  WARNING: {n_bad} rows with unparseable timestamps — dropping.")
    df = df.dropna(subset=["timestamp"])

    # ── ip ────────────────────────────────────────────────────────────────────
    import numpy as np
    src_addr = df["SrcAddr"].astype(str).str.strip()
    dst_addr = df["DstAddr"].astype(str).str.strip()
    is_local_src = src_addr.str.startswith("147.32.")
    df["ip"] = np.where(is_local_src, dst_addr, src_addr)

    # ── method ────────────────────────────────────────────────────────────────
    df["method"] = df["Proto"].apply(map_proto_to_method)

    # ── endpoint ──────────────────────────────────────────────────────────────
    df["endpoint"] = df["Dport"].apply(
        lambda p: f"/port_{int(float(p))}" if pd.notna(p) and str(p).replace('.', '').isdigit() else (f"/port_{p}" if pd.notna(p) else "/port_unknown")
    ).str.replace(r"/port_0x.*", "/port_unknown", regex=True)
    # clean up endpoints that have weird hex characters if any

    # ── status / response_size / latency / user_agent ─────────────────────────
    df["status"]        = 200
    df["response_size"] = pd.to_numeric(df["TotBytes"], errors='coerce').fillna(0).astype('int64')
    df["latency"]       = pd.to_numeric(df["Dur"], errors='coerce').fillna(0.0)
    df["user_agent"]    = ""

    # ── Ground-truth labels ───────────────────────────────────────────────────
    df["is_attack"] = df["Label"].str.contains("Botnet", case=False, na=False)
    
    # Assign standard labels
    df["label"] = df["is_attack"].apply(lambda x: "BOTNET" if x else "BENIGN")
    df["attack_category"] = df["is_attack"].apply(lambda x: "Botnet" if x else "Benign")

    # ── tenant_home_country ───────────────────────────────────────────────────
    # The attacks are from CVUT (Czech Republic) so we use 'CZ' as default.
    df["tenant_home_country"] = "CZ"

    # ── Select output columns ─────────────────────────────────────────────────
    core_cols = [
        "timestamp", "ip", "method", "endpoint", "status",
        "response_size", "latency", "user_agent",
        "label", "attack_category", "is_attack", "tenant_home_country"
    ]
    
    out_df = df[core_cols].copy()

    # ── Sort chronologically ──────────────────────────────────────────────────
    out_df = out_df.sort_values("timestamp").reset_index(drop=True)

    # ── Write ─────────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    print(f"Writing parsed data to {output_path} ...")
    out_df.to_csv(output_path, index=False)

    print(f"\nSaved {len(out_df)} records -> {output_path}")
    print("\nAttack distribution:")
    print(out_df["is_attack"].value_counts().to_string())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Preprocess CTU-13 Scenario 10 dataset"
    )
    parser.add_argument(
        "--input",
        default=os.path.join(DATASET_DIR, INPUT_FILE),
        help=f"Path to raw CSV (default: {DATASET_DIR}/{INPUT_FILE})",
    )
    parser.add_argument(
        "--output_dir",
        default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--output_file",
        default=OUTPUT_FILE,
        help=f"Output filename (default: {OUTPUT_FILE})",
    )
    args = parser.parse_args()

    out = os.path.join(args.output_dir, args.output_file)
    main(args.input, out)
