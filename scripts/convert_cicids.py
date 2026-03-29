"""
scripts/convert_cicids.py — CICIDS2017 GeneratedLabelledFlows → cicids_canonical.jsonl

Input:   datasets/CICIDS2017/*.pcap_ISCX.csv   (GeneratedLabelledFlows package from UNB)
Outputs:
  datasets/cicids_canonical.jsonl      — one CanonicalEvent-shaped record per line
                                          includes label/split fields for evaluation;
                                          strip before feeding to the spatiotemporal agent
  datasets/cicids_ground_truth.json    — summary stats + label distribution

Augmentation applied:
  1. Client IP resolution      — swap src/dst if src port is a service port (server→client)
  2. Temporal session windows  — 30-min idle gap resets user_id (mirrors cookie sessions)
  3. Label-conditioned identity perturbation:
       BENIGN          → stable 1:1 IP→user; /24 subnets share a log-normal pool of 25 IDs
       Bot             → 1–2 user_ids shared across all 5 known bot-infected IPs
       Brute Force     → many user_ids per IP, count ∝ Total Fwd Packets (each = 1 attempt)
       Web Attack      → 1 stable user_id per attacker IP (authenticated session exploit)
       DDoS            → 1 shared user_id across all 3 known attacker IPs
       PortScan        → 1 user_id, endpoint = /api/port/{port} (drives ip_endpoint_spread)
       DoS             → 1 user_id, same target endpoint, high volume
  4. Known attacker IP anchoring — flows from 205.174.165.73 always get the same user_id
  5. Port → endpoint mapping    — 80→/api/http, 443→/api/https, 22→/api/ssh, 21→/api/ftp, etc.

Usage:
  python scripts/convert_cicids.py
  python scripts/convert_cicids.py --benign-rate 0.10 --seed 0
  python scripts/convert_cicids.py --input-dir datasets/CICIDS2017 --output datasets/cicids_canonical.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATASET_DIR  = Path("datasets/CICIDS2017")
OUTPUT_FILE  = Path("datasets/cicids_canonical.jsonl")
SUMMARY_FILE = Path("datasets/cicids_ground_truth.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CICIDS2017 uses different timestamp formats across day-files:
#   Monday:   DD/MM/YYYY HH:MM:SS  (leading zeros, has seconds)
#   Tue–Fri:  D/M/YYYY H:MM        (no leading zeros, no seconds)
# Try both formats in order — strptime is flexible with zero-padding on input.
TIMESTAMP_FMTS = [
    "%d/%m/%Y %H:%M:%S",   # 03/07/2017 08:55:58
    "%d/%m/%Y %H:%M",      # 03/07/2017 08:55
    "%m/%d/%Y %H:%M:%S",   # guard against US-ordered variants
    "%m/%d/%Y %H:%M",
]
SESSION_GAP   = timedelta(minutes=30)  # idle gap that resets user_id

# Known IPs from UNB experiment documentation
KALI_ATTACKER_IP  = "205.174.165.73"
DDOS_ATTACKER_IPS = {"205.174.165.69", "205.174.165.70", "205.174.165.71"}
BOT_VICTIM_IPS    = {
    "192.168.10.15", "192.168.10.9",  "192.168.10.14",
    "192.168.10.5",  "192.168.10.8",
}
INTERNAL_SUBNET = "192.168.10."

# Port sets for endpoint mapping
HTTP_PORTS  = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}
SSH_PORTS   = {22}
FTP_PORTS   = {21}
SERVICE_PORTS = HTTP_PORTS | HTTPS_PORTS | SSH_PORTS | FTP_PORTS

# Day-file processing order — maps substring → chronological index
FILE_ORDER: List[str] = [
    "Monday-WorkingHours",
    "Tuesday-WorkingHours",
    "Wednesday-workingHours",
    "Thursday-WorkingHours-Morning-WebAttacks",
    "Thursday-WorkingHours-Afternoon-Infilteration",
    "Friday-WorkingHours-Morning",
    "Friday-WorkingHours-Afternoon-DDos",
    "Friday-WorkingHours-Afternoon-PortScan",
]


# ---------------------------------------------------------------------------
# Label handling
# ---------------------------------------------------------------------------

def normalize_label(raw: str) -> str:
    """Strip whitespace and fix Windows-1252 en-dash artifacts."""
    return raw.strip().replace("\x96", "\u2013").replace("\xe2\x80\x93", "\u2013")


def label_to_attack_class(label: str) -> str:
    """Map raw CICIDS label string to a canonical attack class."""
    l = label.lower().strip()
    if l == "benign":
        return "benign"
    if "patator" in l or ("brute force" in l and "web attack" not in l):
        return "brute_force"
    if l.startswith("dos"):
        return "dos"
    if "heartbleed" in l:
        return "exploit"
    if "web attack" in l and "sql" in l:
        return "web_attack_sqli"
    if "web attack" in l and "xss" in l:
        return "web_attack_xss"
    if "web attack" in l:
        return "web_attack"
    if l == "infiltration":
        return "infiltration"
    if l == "bot":
        return "bot"
    if l == "portscan":
        return "portscan"
    if l == "ddos":
        return "ddos"
    return "unknown"


def is_attack(attack_class: str) -> bool:
    return attack_class != "benign"


# ---------------------------------------------------------------------------
# Port → endpoint / method / response code
# ---------------------------------------------------------------------------

def port_to_endpoint(port: int, attack_class: str) -> str:
    """
    Map service port to a request_path template.
    PortScan uses /api/port/{port} so each scanned port is a distinct endpoint,
    which drives ip_endpoint_spread to spike — the key spatiotemporal signal.
    """
    if attack_class == "portscan":
        return f"/api/port/{port}"
    if port in HTTP_PORTS:
        return "/api/http"
    if port in HTTPS_PORTS:
        return "/api/https"
    if port in SSH_PORTS:
        return "/api/ssh"
    if port in FTP_PORTS:
        return "/api/ftp"
    return f"/api/svc/{port}"


def infer_method(port: int, attack_class: str) -> str:
    """Brute force to HTTP endpoints = POST (login attempts). Everything else = GET."""
    if attack_class in ("brute_force",) and port in (HTTP_PORTS | HTTPS_PORTS):
        return "POST"
    return "GET"


def infer_response_code(attack_class: str) -> Optional[int]:
    mapping = {
        "benign":            200,
        "brute_force":       401,
        "web_attack_sqli":   500,
        "web_attack_xss":    200,
        "web_attack":        200,
        "bot":               200,
        "portscan":          None,
        "ddos":              None,
        "dos":               None,
        "infiltration":      200,
        "exploit":           None,
        "unknown":           None,
    }
    return mapping.get(attack_class)


# ---------------------------------------------------------------------------
# User ID registry — all synthesis logic in one place
# ---------------------------------------------------------------------------

class UserIDRegistry:
    """
    Synthesizes user_ids using the label-conditioned augmentation strategy.
    Seeded RNG ensures the output is fully reproducible.
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        # ip → {"user_id": str, "last_ts": datetime}
        self._sessions: Dict[str, dict] = {}
        # Shared identities for coordinated attack groups
        self._ddos_uid = "atk_ddos_campaign_1"
        self._bot_uids = ["atk_bot_pool_1", "atk_bot_pool_2"]
        self._kali_uid = "atk_kali_1"
        # Per-subnet user pools for BENIGN internal traffic
        self._subnet_pools: Dict[str, List[str]] = {}

    def _new_uid(self, prefix: str = "user") -> str:
        return f"{prefix}_{self._rng.randint(10000, 99999)}"

    def _benign_pool_uid(self, ip: str) -> str:
        """
        For internal 192.168.10.x IPs, draw from a shared pool with log-normal
        weighting to simulate a few heavy users and many light ones on the same subnet.
        """
        subnet = ip.rsplit(".", 1)[0]
        if subnet not in self._subnet_pools:
            pool = [f"user_{subnet.replace('.', '_')}_{i:03d}" for i in range(25)]
            self._rng.shuffle(pool)
            self._subnet_pools[subnet] = pool
        pool = self._subnet_pools[subnet]
        # Log-normal weights: first entries get disproportionately more traffic
        weights = [1.0 / (i + 1) for i in range(len(pool))]
        total = sum(weights)
        r = self._rng.random() * total
        cumulative = 0.0
        for uid, w in zip(pool, weights):
            cumulative += w
            if r <= cumulative:
                return uid
        return pool[-1]

    def get(
        self,
        client_ip: str,
        ts: datetime,
        attack_class: str,
        fwd_packets: int,
        svc_port: int,
    ) -> str:
        # Known attacker — always same identity across all files
        if client_ip == KALI_ATTACKER_IP:
            return self._kali_uid

        # DDoS campaign — three IPs, one actor
        if client_ip in DDOS_ATTACKER_IPS:
            return self._ddos_uid

        # Botnet — five infected machines sharing 1–2 controller accounts
        if client_ip in BOT_VICTIM_IPS and attack_class == "bot":
            return self._rng.choice(self._bot_uids)

        # Brute force — many identities per IP, proportional to packet count
        # Each group of ~5 fwd packets = one credential attempt = one user_id probed
        if attack_class == "brute_force":
            n_attempts = max(1, min(fwd_packets // 5, 50))
            attempt_idx = self._rng.randint(0, n_attempts - 1)
            safe_ip = client_ip.replace(".", "_")
            return f"victim_user_{safe_ip}_{attempt_idx:03d}"

        # Web attacks — single stable authenticated user (exploiting active session)
        if attack_class in ("web_attack_sqli", "web_attack_xss", "web_attack"):
            return f"auth_user_{client_ip.replace('.', '_')}"

        # PortScan — one actor scanning systematically
        if attack_class == "portscan":
            return f"scanner_{client_ip.replace('.', '_')}"

        # DoS — single source, high volume
        if attack_class == "dos":
            return f"dos_src_{client_ip.replace('.', '_')}"

        # BENIGN + everything else — temporal session windowing
        sess = self._sessions.get(client_ip)
        if sess is None or (ts - sess["last_ts"]) > SESSION_GAP:
            if client_ip.startswith(INTERNAL_SUBNET):
                uid = self._benign_pool_uid(client_ip)
            else:
                uid = self._new_uid("user")
            self._sessions[client_ip] = {"user_id": uid, "last_ts": ts}
        else:
            self._sessions[client_ip]["last_ts"] = ts
            uid = self._sessions[client_ip]["user_id"]
        return uid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_timestamp(raw: str) -> datetime:
    """Try each known format in order; raise ValueError if none match."""
    raw = raw.strip()
    for fmt in TIMESTAMP_FMTS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised timestamp format: {raw!r}")


def resolve_client(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> Tuple[str, int]:
    """
    Return (client_ip, service_port).

    CICFlowMeter captures bidirectional flows and sometimes records the server→client
    direction as "forward". Detect this by checking if the source port is a known
    service port — if so, the actual client is the destination.
    """
    if src_port in SERVICE_PORTS:
        return dst_ip, src_port
    return src_ip, dst_port


def sorted_csv_files(dataset_dir: Path) -> List[Path]:
    """Return CSV files sorted in chronological day order."""
    found = {p.stem: p for p in dataset_dir.glob("*.pcap_ISCX.csv")}
    ordered: List[Path] = []
    for key in FILE_ORDER:
        match = next(
            (p for stem, p in found.items() if key.lower() in stem.lower()), None
        )
        if match and match not in ordered:
            ordered.append(match)
    # Append any unrecognised files at the end (safety net)
    ordered_stems = {p.stem for p in ordered}
    for stem, p in found.items():
        if stem not in ordered_stems:
            ordered.append(p)
    return ordered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def convert(
    dataset_dir: Path = DATASET_DIR,
    output_file: Path = OUTPUT_FILE,
    summary_file: Path = SUMMARY_FILE,
    benign_sample_rate: float = 0.15,
    seed: int = 42,
) -> None:
    """
    Stream all CICIDS2017 CSV files and write cicids_canonical.jsonl.

    benign_sample_rate: fraction of BENIGN rows to retain.
      CICIDS2017 is ~80% BENIGN; keeping all of them makes the dataset unusable
      for training. Default 0.15 gives roughly 1:2 benign:attack ratio.
      Monday BENIGN (the clean baseline) is always kept at 100% regardless of
      this setting — it is used for IsolationForest training (split="train").
    """
    rng      = random.Random(seed)
    registry = UserIDRegistry(seed=seed)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    stats: dict = {
        "total_rows_read":     0,
        "rows_skipped":        0,
        "rows_parse_error":    0,
        "events_written":      0,
        "label_counts":        defaultdict(int),
        "attack_class_counts": defaultdict(int),
        "split_counts":        defaultdict(int),
        "files_processed":     [],
        "benign_sample_rate":  benign_sample_rate,
        "seed":                seed,
    }

    csv_files = sorted_csv_files(dataset_dir)
    if not csv_files:
        print(f"ERROR: No CSV files found in {dataset_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(csv_files)} CSV file(s) in {dataset_dir}")
    print(f"BENIGN sample rate : {benign_sample_rate:.0%}  "
          f"(Monday BENIGN kept at 100% for training baseline)")
    print(f"Output             : {output_file}\n")

    with open(output_file, "w", encoding="utf-8") as out_f:
        for csv_path in csv_files:
            is_monday       = "Monday" in csv_path.name
            file_written    = 0
            file_errors     = 0
            first_err_shown = False

            print(f"  {csv_path.name} ... ", end="", flush=True)

            try:
                with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)

                    try:
                        raw_header = next(reader)
                    except StopIteration:
                        print("EMPTY — skipped")
                        continue

                    col = {h.strip(): i for i, h in enumerate(raw_header)}

                    # Verify required columns exist
                    required = {
                        "Source IP", "Source Port", "Destination IP",
                        "Destination Port", "Protocol", "Timestamp",
                        "Total Fwd Packets", "Label",
                    }
                    missing = required - set(col)
                    if missing:
                        print(f"MISSING COLUMNS {missing} — skipped")
                        continue

                    for row in reader:
                        stats["total_rows_read"] += 1
                        try:
                            raw_label   = normalize_label(row[col["Label"]])
                            attack_cls  = label_to_attack_class(raw_label)
                            attack_flag = is_attack(attack_cls)

                            # BENIGN sampling: Monday always kept, others sampled
                            if not attack_flag:
                                if not is_monday and rng.random() > benign_sample_rate:
                                    stats["rows_skipped"] += 1
                                    continue

                            ts = parse_timestamp(row[col["Timestamp"]])

                            src_ip   = row[col["Source IP"]].strip()
                            src_port = int(row[col["Source Port"]].strip())
                            dst_ip   = row[col["Destination IP"]].strip()
                            dst_port = int(row[col["Destination Port"]].strip())
                            flow_id  = row[col.get("Flow ID", 0)].strip() if "Flow ID" in col else f"{src_ip}-{dst_ip}-{src_port}-{dst_port}"
                            fwd_pkts = int(float(row[col["Total Fwd Packets"]].strip()))

                            client_ip, svc_port = resolve_client(
                                src_ip, src_port, dst_ip, dst_port
                            )

                            endpoint = port_to_endpoint(svc_port, attack_cls)
                            method   = infer_method(svc_port, attack_cls)
                            rcode    = infer_response_code(attack_cls)
                            user_id  = registry.get(
                                client_ip, ts, attack_cls, fwd_pkts, svc_port
                            )

                            # Monday BENIGN = train split (IsolationForest baseline)
                            split = "train" if (is_monday and not attack_flag) else "test"

                            record = {
                                "flow_id":      flow_id,
                                "timestamp":    ts.isoformat(),
                                "source_ip":    client_ip,
                                "user_id":      user_id,
                                "request_path": endpoint,
                                "http_method":  method,
                                "response_code": rcode,
                                "bytes_sent":   None,
                                # Evaluation fields — strip before passing to agent
                                "label":        raw_label,
                                "attack_class": attack_cls,
                                "is_attack":    attack_flag,
                                "split":        split,
                            }

                            out_f.write(json.dumps(record) + "\n")
                            file_written += 1
                            stats["events_written"]                  += 1
                            stats["label_counts"][raw_label]         += 1
                            stats["attack_class_counts"][attack_cls] += 1
                            stats["split_counts"][split]             += 1

                        except (ValueError, IndexError, KeyError) as exc:
                            if not first_err_shown:
                                print(f"\n    [first parse error] {type(exc).__name__}: {exc}")
                                print(f"    row sample: {','.join(row[:8])}")
                                first_err_shown = True
                            file_errors += 1
                            stats["rows_parse_error"] += 1
                            continue

            except FileNotFoundError:
                print(f"NOT FOUND — skipped")
                continue

            print(f"{file_written:>8,} events  ({file_errors} parse errors)")
            stats["files_processed"].append(csv_path.name)

    # Serialize stats (convert defaultdicts)
    stats["label_counts"]        = dict(stats["label_counts"])
    stats["attack_class_counts"] = dict(stats["attack_class_counts"])
    stats["split_counts"]        = dict(stats["split_counts"])

    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    total = stats["events_written"]
    print(f"\n{'─'*55}")
    print(f"Total events written  : {total:>10,}")
    print(f"Rows skipped (BENIGN) : {stats['rows_skipped']:>10,}")
    print(f"Rows parse errors     : {stats['rows_parse_error']:>10,}")
    print(f"Train split           : {stats['split_counts'].get('train', 0):>10,}  (Monday BENIGN baseline)")
    print(f"Test split            : {stats['split_counts'].get('test', 0):>10,}")
    print(f"\nAttack class distribution:")
    for cls, cnt in sorted(stats["attack_class_counts"].items(), key=lambda x: -x[1]):
        pct = cnt / total * 100 if total else 0
        bar = "█" * int(pct / 2)
        print(f"  {cls:<25} {cnt:>8,}  {pct:5.1f}%  {bar}")
    print(f"\nSummary written to: {summary_file}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert CICIDS2017 GeneratedLabelledFlows → cicids_canonical.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input-dir", type=Path, default=DATASET_DIR,
        metavar="DIR",
        help=f"CICIDS2017 CSV directory (default: {DATASET_DIR})",
    )
    parser.add_argument(
        "--output", type=Path, default=OUTPUT_FILE,
        metavar="FILE",
        help=f"Output JSONL path (default: {OUTPUT_FILE})",
    )
    parser.add_argument(
        "--summary", type=Path, default=SUMMARY_FILE,
        metavar="FILE",
        help=f"Summary JSON path (default: {SUMMARY_FILE})",
    )
    parser.add_argument(
        "--benign-rate", type=float, default=0.15,
        metavar="RATE",
        help="Fraction of non-Monday BENIGN rows to keep. Default 0.15.",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="RNG seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    convert(
        dataset_dir=args.input_dir,
        output_file=args.output,
        summary_file=args.summary,
        benign_sample_rate=args.benign_rate,
        seed=args.seed,
    )
