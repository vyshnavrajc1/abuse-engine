#!/usr/bin/env python3
"""
prepare_honeypot_dataset.py  —  Preprocess AWS Honeypot (marx-geo) dataset
for GeoIPAgent verification in the Abuse Engine.

Dataset: AWS_Honeypot_marx-geo.csv
Source:  https://www.kaggle.com/datasets/maveris/aws-honeypot-attack-data

Column mapping
--------------
datetime  -> timestamp   (parsed M/D/YY H:MM -> ISO-8601 UTC string)
srcstr    -> ip          (human-readable dotted-quad; ignores raw int `src`)
proto     -> method      (TCP/UDP/ICMP used as method proxy)
dpt       -> endpoint    (/port_<dpt>)
cc        -> [kept as extra column `src_country_code` for GeoIP ground-truth]
country   -> [kept as extra column `src_country` for human readability]
All rows  -> is_attack=True / attack_category="Geo Attack" / label="GEO_ATTACK"
             (every record in a honeypot is hostile by definition)

Output schema (identical to other processed CSVs consumed by CICIDSIngestion):
  timestamp, ip, method, endpoint, status,
  response_size, latency, user_agent,
  label, attack_category, is_attack,
  [+ src_country_code, src_country]   <- bonus columns, ignored by ingestion
"""

import argparse
import os
import sys

import pandas as pd

# ── Paths ─────────────────────────────────────────────────────────────────────
DATASET_DIR  = "datasets"
INPUT_FILE   = "AWS_Honeypot_marx-geo.csv"
OUTPUT_DIR   = "datasets/processed"
OUTPUT_FILE  = "honeypot_geo_logs.csv"

# ── Datetime format in the raw CSV ────────────────────────────────────────────
# Samples: "3/3/13 21:53", "10/15/13 9:07"
_DT_FORMAT = "%m/%d/%y %H:%M"


def parse_timestamp(raw: str) -> str | None:
    """
    Parse raw datetime string to ISO-8601 UTC string expected by the engine.
    Returns None on failure (rows will be dropped).
    """
    try:
        dt = pd.to_datetime(raw, format=_DT_FORMAT, utc=False)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def map_proto_to_method(proto: str) -> str:
    """
    Map network protocol to an HTTP-style method placeholder.
    The engine expects a non-empty string; the GeoIPAgent ignores it.
    """
    proto = str(proto).strip().upper()
    mapping = {
        "TCP":  "GET",
        "UDP":  "POST",
        "ICMP": "OPTIONS",
    }
    return mapping.get(proto, "GET")


def main(input_path: str, output_path: str, home_country: str = "US") -> None:
    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"Reading {input_path} ...")
    try:
        df = pd.read_csv(input_path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        print("  UTF-8 failed, retrying with latin-1 ...")
        df = pd.read_csv(input_path, low_memory=False, encoding="latin-1")

    df.columns = [c.strip() for c in df.columns]  # strip accidental spaces
    print(f"  Raw rows: {len(df)}")
    print(f"  Columns:  {df.columns.tolist()}")

    # ── Validate required columns ─────────────────────────────────────────────
    required = {"datetime", "srcstr", "proto", "dpt"}
    missing  = required - set(df.columns)
    if missing:
        print(f"ERROR: Required columns missing: {missing}")
        sys.exit(1)

    # ── timestamp ─────────────────────────────────────────────────────────────
    print("Parsing timestamps ...")
    df["timestamp"] = df["datetime"].astype(str).apply(parse_timestamp)
    n_bad = df["timestamp"].isna().sum()
    if n_bad:
        print(f"  WARNING: {n_bad} rows with unparseable timestamps — dropping.")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        print("ERROR: No rows remaining after timestamp parse.")
        sys.exit(1)

    # ── ip ────────────────────────────────────────────────────────────────────
    # `srcstr` is the human-readable dotted-quad (e.g. "61.131.218.218").
    # The `src` column is an integer representation — we skip it.
    df["ip"] = df["srcstr"].astype(str).str.strip()

    # Drop rows where ip is missing or obviously invalid
    df = df[df["ip"].str.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
    if df.empty:
        print("ERROR: No valid IP addresses found.")
        sys.exit(1)

    # ── method ────────────────────────────────────────────────────────────────
    df["method"] = df["proto"].apply(map_proto_to_method)

    # ── endpoint ──────────────────────────────────────────────────────────────
    # Destination port → /port_<dpt>  (mirrors CICIDS approach)
    df["endpoint"] = df["dpt"].apply(
        lambda p: f"/port_{int(p)}" if pd.notna(p) else "/port_unknown"
    )

    # ── status / response_size / latency / user_agent ─────────────────────────
    # Honeypot data has no HTTP-layer fields; use safe defaults consistent with
    # the existing preprocessing scripts.
    df["status"]        = 200
    df["response_size"] = 0
    df["latency"]       = 0.0
    df["user_agent"]    = ""

    # ── Ground-truth labels ───────────────────────────────────────────────────
    # Every connection to a honeypot is hostile by definition.
    df["label"]           = "GEO_ATTACK"
    df["attack_category"] = "Geo Attack"
    df["is_attack"]       = True

    # ── Tenant home country (passed to GeoIPAgent via tenant_home_country column) ──
    # AWS Honeypot groucho-oregon → US-East; every non-US IP is genuinely foreign.
    df["tenant_home_country"] = home_country
    print(f"  tenant_home_country set to: {home_country}")

    # ── Bonus geo columns (NOT consumed by ingestion, for manual inspection) ──
    if "cc" in df.columns:
        df["src_country_code"] = df["cc"].fillna("").astype(str).str.strip()
    else:
        df["src_country_code"] = ""

    if "country" in df.columns:
        df["src_country"] = df["country"].fillna("").astype(str).str.strip()
    else:
        df["src_country"] = ""

    # ── Select output columns ─────────────────────────────────────────────────
    # Core columns — identical contract to CICIDS / CSIC processed files
    core_cols = [
        "timestamp", "ip", "method", "endpoint", "status",
        "response_size", "latency", "user_agent",
        "label", "attack_category", "is_attack",
    ]
    # tenant_home_country feeds GeoIPAgent; src_* columns for ground-truth inspection
    extra_cols = ["tenant_home_country", "src_country_code", "src_country"]
    out_df = df[core_cols + extra_cols].copy()

    # ── Sort chronologically (mirrors CICIDS temporal ordering) ──────────────
    out_df = out_df.sort_values("timestamp").reset_index(drop=True)

    # ── Write ─────────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    out_df.to_csv(output_path, index=False)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\nSaved {len(out_df)} records -> {output_path}")
    print("\nTop source countries (ground-truth cc -> GeoIP verification):")
    if "src_country_code" in out_df.columns:
        print(out_df["src_country_code"].value_counts().head(15).to_string())
    print("\nProtocol distribution (-> method proxy):")
    print(out_df["method"].value_counts().to_string())
    print("\nTop destination ports (-> endpoint):")
    port_counts = (
        out_df["endpoint"]
        .value_counts()
        .head(15)
    )
    print(port_counts.to_string())
    print("\nAttack category distribution:")
    print(out_df["attack_category"].value_counts().to_string())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Preprocess AWS Honeypot marx-geo dataset for GeoIPAgent verification"
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
    parser.add_argument(
        "--home-country",
        default="US",
        help="ISO-3166-1 alpha-2 country code for the tenant home country "
             "(default: US — AWS groucho-oregon is US-East).",
    )
    args = parser.parse_args()

    out = os.path.join(args.output_dir, args.output_file)
    main(args.input, out, home_country=args.home_country)
