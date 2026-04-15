"""
Abuse Engine — UNSW-NB15 Ingestion Adapter

Loads UNSW-NB15 CSV files and yields LogRecord batches compatible with the
detection pipeline.

Dataset source:
    https://research.unsw.edu.au/projects/unsw-nb15-dataset
    Files: UNSW-NB15_1.csv … UNSW-NB15_4.csv  (plus features CSV for column names)

Key differences from CICIDS 2017:
  - Source IPs are ROUTABLE public addresses → GeoIPAgent produces real geo signals
  - Destination ports are real service ports (not mapped like CICIDS)
  - Attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic,
    Reconnaissance, Shellcode, Worms
  - 'label' column: 0 = normal, 1 = attack
  - 'attack_cat' column: attack category string (empty string for normal traffic)

Column mapping to LogRecord:
    srcip       → ip
    sport       → used for session_id
    dsport      → endpoint (/port_<dsport>)
    dur         → latency (seconds → ms, clipped 10 000ms)
    sbytes      → response_size
    state       → method proxy (REQ/CON/FIN → GET/POST/DELETE)
    label       → is_attack (0/1)
    attack_cat  → attack_category
"""

from __future__ import annotations
import hashlib
import logging
from pathlib import Path
from typing import Generator, List, Optional

import pandas as pd

from schemas.models import LogRecord

logger = logging.getLogger(__name__)

# UNSW-NB15 feature file column names (in order, matching the raw CSVs).
# The raw CSVs have no header row — this list provides it.
UNSWNB15_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur",
    "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service",
    "sload", "dload", "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit",
    "stime", "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login",
    "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "label",
]

# Map UNSW-NB15 attack categories to canonical engine names
_CATEGORY_MAP = {
    "":              "Benign",
    "normal":        "Benign",
    "Normal":        "Benign",
    "Fuzzers":       "Fuzzing",
    "fuzzers":       "Fuzzing",
    "Analysis":      "Analysis",
    "analysis":      "Analysis",
    "Backdoors":     "Backdoor",
    "backdoors":     "Backdoor",
    "backdoor":      "Backdoor",
    "DoS":           "DoS",
    "dos":           "DoS",
    "Exploits":      "Exploit",
    "exploits":      "Exploit",
    "Generic":       "Generic Attack",
    "generic":       "Generic Attack",
    "Reconnaissance":"Reconnaissance",
    "reconnaissance":"Reconnaissance",
    "Shellcode":     "Shellcode",
    "shellcode":     "Shellcode",
    "Worms":         "Worm",
    "worms":         "Worm",
}

# Map protocol/state to synthetic HTTP method
_STATE_TO_METHOD = {
    "REQ": "GET",
    "CON": "POST",
    "FIN": "DELETE",
    "INT": "GET",
    "RST": "GET",
    "CLO": "GET",
}


def _categorize(attack_cat: str) -> str:
    cat = str(attack_cat).strip()
    return _CATEGORY_MAP.get(cat, cat if cat else "Benign")


def _make_session_id(ip: str, sport: str, dsport: str) -> str:
    raw = f"{ip}|{sport}|{dsport}"
    return hashlib.md5(raw.encode()).hexdigest()[:10]


def _row_to_record(row: pd.Series, timestamp_base: pd.Timestamp) -> Optional[LogRecord]:
    try:
        # Use stime (epoch seconds) for timestamp when available
        stime = row.get("stime", 0)
        try:
            ts = pd.Timestamp(float(stime), unit="s")
        except Exception:
            ts = timestamp_base

        src_ip = str(row.get("srcip", "0.0.0.0"))
        dsport = row.get("dsport", 0)
        try:
            port = int(float(dsport)) if pd.notnull(dsport) else 0
        except (ValueError, TypeError):
            port = 0
        endpoint = f"/port_{port}"

        sport_val = str(row.get("sport", "0"))

        # Latency: dur is in seconds → convert to ms, clip at 10 000ms
        try:
            latency = min(float(row.get("dur", 0.0)) * 1000.0, 10_000.0)
        except (ValueError, TypeError):
            latency = 0.0

        try:
            response_size = int(float(row.get("sbytes", 0)))
        except (ValueError, TypeError):
            response_size = 0

        state = str(row.get("state", "REQ")).strip().upper()
        method = _STATE_TO_METHOD.get(state, "GET")

        attack_cat = str(row.get("attack_cat", "")).strip()
        label_val = row.get("label", 0)
        try:
            is_attack_raw = int(float(label_val)) == 1
        except (ValueError, TypeError):
            is_attack_raw = False

        category = _categorize(attack_cat)
        is_attack = is_attack_raw or (category != "Benign")

        return LogRecord(
            timestamp=ts.to_pydatetime(),
            ip=src_ip,
            method=method,
            endpoint=endpoint,
            status=200,           # UNSW-NB15 has no HTTP status — use 200 as default
            response_size=response_size,
            latency=latency,
            user_agent="",        # not present in UNSW-NB15
            label="ATTACK" if is_attack else "BENIGN",
            attack_category=category,
            is_attack=is_attack,
            session_id=_make_session_id(src_ip, sport_val, str(port)),
            endpoint_template=endpoint,
        )
    except Exception as exc:
        logger.debug("Skipping malformed UNSW-NB15 row: %s", exc)
        return None


class UNSWNB15Ingestion:
    """
    Reads UNSW-NB15 CSV files and yields fixed-size batches of LogRecord.

    Usage:
        ingestion = UNSWNB15Ingestion("datasets/UNSW-NB15/", window_size=500)
        for batch in ingestion.batches():
            verdict = orchestrator.run(batch)

    Notes:
        - Raw CSVs have NO header row — column names are injected from UNSWNB15_COLUMNS.
        - Files are sorted alphabetically (UNSW-NB15_1.csv … _4.csv) for determinism.
        - Timestamps are derived from the 'stime' epoch column.
        - GeoIPAgent requires the GeoLite2-City.mmdb file at datasets/GeoLite2-City.mmdb
          (set GEOIP_MMDB_PATH env var to override).
    """

    def __init__(
        self,
        path: str | Path,
        window_size: int = 500,
        max_records: int = 0,
    ):
        self.path = Path(path)
        self.window_size = window_size
        self.max_records = max_records

    def _load_df(self) -> pd.DataFrame:
        if self.path.is_dir():
            csv_files = sorted(self.path.glob("UNSW-NB15*.csv"))
            if not csv_files:
                # Fallback: any CSV in the directory
                csv_files = sorted(self.path.glob("*.csv"))
            dfs = []
            for f in csv_files:
                try:
                    # Try with header first; if columns mismatch, use UNSWNB15_COLUMNS
                    df = pd.read_csv(f, low_memory=False)
                    if len(df.columns) == len(UNSWNB15_COLUMNS):
                        df.columns = UNSWNB15_COLUMNS
                    dfs.append(df)
                    logger.info("Loaded %d rows from %s", len(df), f.name)
                except Exception as exc:
                    logger.warning("Could not read %s: %s", f, exc)
            if not dfs:
                raise FileNotFoundError(f"No UNSW-NB15 CSV files found in {self.path}")
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = pd.read_csv(self.path, low_memory=False)
            if len(df.columns) == len(UNSWNB15_COLUMNS):
                df.columns = UNSWNB15_COLUMNS

        if self.max_records > 0:
            df = df.head(self.max_records)

        # Sort by stime for chronological ordering
        if "stime" in df.columns:
            df = df.sort_values("stime").reset_index(drop=True)

        logger.info("UNSW-NB15: %d total rows | attack=%d | benign=%d",
                    len(df),
                    int((df.get("label", pd.Series([0])) == 1).sum()),
                    int((df.get("label", pd.Series([0])) == 0).sum()))
        return df

    def batches(self) -> Generator[List[LogRecord], None, None]:
        """Yield successive fixed-size batches of LogRecord."""
        df = self._load_df()
        timestamp_base = pd.Timestamp("2015-01-01")
        batch: List[LogRecord] = []

        for _, row in df.iterrows():
            record = _row_to_record(row, timestamp_base)
            if record is None:
                continue
            batch.append(record)
            if len(batch) >= self.window_size:
                yield batch
                batch = []

        if batch:
            yield batch
