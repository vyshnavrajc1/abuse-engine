"""
Abuse Engine Ingestion Pipeline

Loads CICIDS 2017 processed CSVs, yields LogRecord batches.
Handles:
  - Timestamp parsing
  - Endpoint template normalisation (regex)
  - Session-ID heuristic stitching (IP + UA + endpoint prefix)
  - Batch windowing (sliding or fixed)
"""

from __future__ import annotations
import hashlib
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, Iterable, List, Optional

import pandas as pd

from schemas.models import LogRecord


logger = logging.getLogger(__name__)

# Regex: normalise /port_80, /port_443/subpath → /port_{port}
_ENDPOINT_NORMALISER = re.compile(r"(/port_\d+)(/.*)?")

# Sentinel strings that pandas uses when round-tripping Python None/NaN through CSV
_NULL_SENTINELS = frozenset({"nan", "none", "nat", ""})


def _safe_str(val, default: str = "") -> str:
    """Convert *val* to str, mapping NaN / None / empty / null-sentinel to *default*.

    pandas.read_csv silently converts the literal string "None" to a floating-point
    NaN when no explicit ``keep_default_na=False`` is passed.  This helper ensures
    such values are always normalised to the correct *default* label instead of
    leaking as the string ``"nan"`` into the evaluator.
    """
    if val is None:
        return default
    # Numeric NaN check (covers float('nan'))
    try:
        import math
        if math.isnan(float(val)):  # type: ignore[arg-type]
            return default
    except (TypeError, ValueError):
        pass
    s = str(val).strip()
    return default if s.lower() in _NULL_SENTINELS else s


def _normalise_endpoint(endpoint: str) -> str:
    m = _ENDPOINT_NORMALISER.match(endpoint)
    if m:
        return m.group(1)  # e.g. /port_80
    return endpoint


def _make_session_id(ip: str, ua: str, endpoint: str) -> str:
    prefix = _normalise_endpoint(endpoint)
    raw = f"{ip}|{ua}|{prefix}"
    return hashlib.md5(raw.encode()).hexdigest()[:10]


def _row_to_record(row: pd.Series) -> Optional[LogRecord]:
    try:
        ts = pd.to_datetime(row["timestamp"])
        if ts.tzinfo is not None:
            ts = ts.tz_localize(None)
        endpoint = str(row.get("endpoint", "/unknown"))
        # Read tenant_home_country from dataset column (e.g. CTU13 uses 'CZ').
        # This is forwarded to GeoIPAgent via LogRecord so it can compare
        # foreign vs home-country traffic even when --home-country is not passed.
        home_country = str(row.get("tenant_home_country", "") or "")
        return LogRecord(
            timestamp=ts.to_pydatetime(),
            ip=str(row["ip"]),
            method=str(row.get("method", "GET")),
            endpoint=endpoint,
            status=int(row.get("status", 200)),
            response_size=int(row.get("response_size", 0)),
            latency=float(row.get("latency", 0.0)),
            user_agent=str(row.get("user_agent", "")),
            label=str(row.get("label", "BENIGN")),
            attack_category=_safe_str(row.get("attack_category"), default="Benign"),
            is_attack=str(row.get("label", "BENIGN")).upper() != "BENIGN",
            session_id=_make_session_id(
                str(row["ip"]),
                str(row.get("user_agent", "")),
                endpoint,
            ),
            endpoint_template=_normalise_endpoint(endpoint),
            tenant_home_country=home_country,
        )
    except Exception as exc:
        logger.debug("Skipping malformed row: %s", exc)
        return None


class CICIDSIngestion:
    """
    Reads a CICIDS 2017 processed CSV (or folder of CSVs) and yields
    fixed-size time-window batches of LogRecord objects.

    Args:
        path        : Path to a single CSV or directory of CSVs.
        window_size : Number of records per batch (default 500).
        max_records : Cap total records loaded (0 = unlimited).
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
            dfs = [
                pd.read_csv(f)
                for f in sorted(self.path.glob("*.csv"))
            ]
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = pd.read_csv(self.path)

        if self.max_records > 0:
            df = df.head(self.max_records)

        # Sort by timestamp so sliding windows are chronological
        if "timestamp" in df.columns:
            df = df.sort_values("timestamp").reset_index(drop=True)

        logger.info("Loaded %d raw rows from %s", len(df), self.path)
        return df

    def batches(self) -> Generator[List[LogRecord], None, None]:
        """Yield successive fixed-size batches of LogRecord."""
        df = self._load_df()
        batch: List[LogRecord] = []

        for _, row in df.iterrows():
            record = _row_to_record(row)
            if record is None:
                continue
            batch.append(record)
            if len(batch) >= self.window_size:
                yield batch
                batch = []

        if batch:
            yield batch

    def iter_records(self) -> Generator[LogRecord, None, None]:
        """Yield individual LogRecord objects."""
        df = self._load_df()
        for _, row in df.iterrows():
            record = _row_to_record(row)
            if record is not None:
                yield record
