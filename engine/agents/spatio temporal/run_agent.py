"""
run_agent.py – Complete runnable demo for the agentic spatio-temporal pipeline.

This is the ONLY file you need to run.  Everything is self-contained:
  • Generates synthetic baseline + attack traffic (no external data needed)
  • Trains the IsolationForest on the baseline
  • Runs the full agentic graph: validate → score → severity → llm_analysis
  • Prints a rich, colour-coded report of what the LLM agent found

HOW TO RUN
----------
1. Install dependencies:
       pip install langchain langchain-google-genai google-generativeai \
                   scikit-learn joblib networkx numpy

2. Set your Gemini API key (get one free at https://aistudio.google.com/app/apikey):
       Option A – edit this file: set GEMINI_API_KEY = "your-key-here"  (line ~40)
       Option B – environment variable: export GEMINI_API_KEY="your-key-here"

3. Run:
       python run_agent.py

   To test a specific attack scenario pass a flag:
       python run_agent.py --attack sync          # synchronised HTTP flood
       python run_agent.py --attack hop           # IP-hopping credential stuffing
       python run_agent.py --attack scan          # coordinated endpoint scan
       python run_agent.py --attack compound      # all three combined (default)
       python run_agent.py --attack none          # normal traffic only (LLM skips)

FILE LAYOUT (all must be in the same directory)
-----------------------------------------------
  run_agent.py               ← this file
  llm_agent_node.py          ← Gemini ReAct node  (new)
  spatio_temporal_agent.py   ← updated pipeline façade  (updated)
  agent_framework.py         ← graph engine  (unchanged)
  model_registry.py          ← IsolationForest registry  (unchanged)
  models.py                  ← data models  (unchanged)
  sliding_window.py          ← sliding window  (unchanged)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import tempfile
from datetime import datetime, timedelta
from typing import List

# ---------------------------------------------------------------------------
# ★  SET YOUR GEMINI API KEY HERE  ★
# ---------------------------------------------------------------------------
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not set")
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.WARNING,   # set to INFO to see per-node trace
    format="%(levelname)s  %(name)s – %(message)s",
)

# Local modules – must be in the same directory
from models import CanonicalEvent, Severity
from spatio_temporal_agent import SpatioTemporalConfig, SpatioTemporalPipeline
from llm_agent_node import LLMConfig

# ---------------------------------------------------------------------------
# ANSI colours for terminal output
# ---------------------------------------------------------------------------
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

SEVERITY_COLOR = {
    "info":     DIM,
    "low":      GREEN,
    "medium":   YELLOW,
    "high":     RED,
    "critical": BOLD + RED,
}

VERDICT_COLOR = {
    "confirmed_threat": BOLD + RED,
    "likely_fp":        GREEN,
    "uncertain":        YELLOW,
}

ENDPOINTS = ["/users", "/orders", "/products", "/reports",
             "/admin", "/search", "/auth", "/feed"]


# ---------------------------------------------------------------------------
# Synthetic traffic generators (copied from tests.py so this file is self-
# contained — no need to import tests.py)
# ---------------------------------------------------------------------------

def _ts(base: datetime, offset_seconds: float) -> datetime:
    return base + timedelta(seconds=offset_seconds)


def make_normal_traffic(base: datetime, n: int = 16_000, seed: int = 0) -> List[CanonicalEvent]:
    """30 users × 1 IP each, named endpoints, events at ~5 s intervals."""
    rng = random.Random(seed)
    n_users = 30
    events: List[CanonicalEvent] = []
    for i in range(n):
        u  = i % n_users
        ep = ENDPOINTS[u % len(ENDPOINTS)] if rng.random() < 0.85 else rng.choice(ENDPOINTS)
        t  = _ts(base, i * 5 + rng.uniform(-2, 2))
        events.append(CanonicalEvent(t, f"192.168.1.{u + 1}", f"u{u}", ep, "GET"))
    return events


def make_synchronised_attack(base: datetime, n_attackers: int = 30,
                              burst_offset_seconds: float = 4_000) -> List[CanonicalEvent]:
    """All attackers hit /target within 0.5 s → request_synchrony ≈ 0.14 s."""
    t0 = _ts(base, burst_offset_seconds)
    return [
        CanonicalEvent(t0 + timedelta(milliseconds=i * 25),
                       f"10.0.{i}.1", f"atk_{i}", "/target", "GET")
        for i in range(n_attackers)
    ]


def make_ip_hopping_attack(base: datetime, n_ips: int = 10,
                            burst_offset_seconds: float = 4_000) -> List[CanonicalEvent]:
    """Single user 'hopper' requests from n_ips IPs → max_user_ip_count spikes."""
    t0 = _ts(base, burst_offset_seconds)
    return [
        CanonicalEvent(t0 + timedelta(seconds=i * 18),
                       f"10.1.{i}.1", "hopper", "/users", "GET")
        for i in range(n_ips)
    ]


def make_coordinated_scan(base: datetime, n_ips: int = 40,
                           burst_offset_seconds: float = 4_000) -> List[CanonicalEvent]:
    """n_ips IPs hit /admin at tight 0.5 s intervals → shared_endpoint_ips + synchrony spike."""
    t0 = _ts(base, burst_offset_seconds)
    return [
        CanonicalEvent(t0 + timedelta(seconds=i * 0.5),
                       f"10.2.{i}.1", f"coord_{i}", "/admin", "GET")
        for i in range(n_ips)
    ]


def build_attack_events(attack_type: str, base: datetime) -> List[CanonicalEvent]:
    """Return the attack event list for a given scenario name."""
    if attack_type == "sync":
        return make_synchronised_attack(base, n_attackers=30)
    elif attack_type == "hop":
        return make_ip_hopping_attack(base, n_ips=10)
    elif attack_type == "scan":
        return make_coordinated_scan(base, n_ips=40)
    elif attack_type == "compound":
        return (
            make_synchronised_attack(base, n_attackers=30, burst_offset_seconds=4_000)
            + make_coordinated_scan(base,  n_ips=60,       burst_offset_seconds=4_060)
            + make_ip_hopping_attack(base, n_ips=10,       burst_offset_seconds=4_120)
        )
    else:  # "none" — normal traffic only
        return []


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _bar(value: float, width: int = 30) -> str:
    """Render a float 0–1 as a filled progress bar."""
    filled = int(value * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {value:.3f}"


def print_header(title: str) -> None:
    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")


def print_section(title: str) -> None:
    print(f"\n{CYAN}{BOLD}── {title} {'─' * (55 - len(title))}{RESET}")


def print_iso_result(risk_score: float, severity: str, flags: List[str],
                     num_windows: int, worst_start: str, worst_end: str) -> None:
    sev_color = SEVERITY_COLOR.get(severity, "")
    print(f"  Risk score  : {BOLD}{_bar(risk_score)}{RESET}")
    print(f"  Severity    : {sev_color}{severity.upper()}{RESET}")
    print(f"  Flags       : {', '.join(flags) if flags else 'none'}")
    print(f"  Windows     : {num_windows} scored")
    print(f"  Worst window: {worst_start}  →  {worst_end}")


def print_llm_result(llm: dict) -> None:
    verdict  = llm.get("verdict", "unknown")
    conf     = llm.get("confidence", 0.0)
    atk_type = llm.get("attack_type") or "—"
    ips      = llm.get("affected_ips", [])
    eps      = llm.get("affected_endpoints", [])
    tools    = llm.get("tool_calls_made", [])
    actions  = llm.get("recommended_actions", [])
    reasoning = llm.get("reasoning", "")

    v_color = VERDICT_COLOR.get(verdict, "")
    print(f"  Verdict     : {v_color}{BOLD}{verdict.upper().replace('_', ' ')}{RESET}")
    print(f"  Confidence  : {_bar(conf)}")
    print(f"  Attack type : {atk_type}")
    print(f"  Affected IPs: {', '.join(ips[:6]) or '—'}"
          + (f"  (+{len(ips)-6} more)" if len(ips) > 6 else ""))
    print(f"  Endpoints   : {', '.join(eps) or '—'}")
    print(f"  Tools used  : {', '.join(tools) or 'none'}")

    if reasoning:
        print_section("LLM Reasoning")
        # Word-wrap at 72 chars
        words = reasoning.split()
        line, lines = [], []
        for w in words:
            if sum(len(x) + 1 for x in line) + len(w) > 72:
                lines.append(" ".join(line))
                line = [w]
            else:
                line.append(w)
        if line:
            lines.append(" ".join(line))
        for l in lines:
            print(f"  {l}")

    if actions:
        print_section("Recommended Actions")
        for i, action in enumerate(actions, 1):
            print(f"  {i}. {action}")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the agentic spatio-temporal anomaly detection pipeline."
    )
    parser.add_argument(
        "--attack",
        choices=["sync", "hop", "scan", "compound", "none"],
        default="compound",
        help=(
            "Attack scenario to inject into the traffic:\n"
            "  sync     – synchronised HTTP flood (30 bots, /target)\n"
            "  hop      – IP-hopping credential stuffing (10 IPs, 1 user)\n"
            "  scan     – coordinated endpoint scan (40 IPs, /admin)\n"
            "  compound – all three combined (default)\n"
            "  none     – normal traffic only (LLM skips; low risk)"
        ),
    )
    args = parser.parse_args()

    # ── Validate API key ─────────────────────────────────────────────────
    if GEMINI_API_KEY in ("", "YOUR_GEMINI_KEY_HERE"):
        print(f"{RED}ERROR: Gemini API key not set.{RESET}")
        print("  Option A: Edit run_agent.py line ~40 and set GEMINI_API_KEY = 'your-key'")
        print("  Option B: export GEMINI_API_KEY='your-key'  then re-run")
        print("  Get a free key at: https://aistudio.google.com/app/apikey")
        sys.exit(1)

    print_header("Agentic Spatio-Temporal Anomaly Detector")
    print(f"  Attack scenario : {BOLD}{args.attack}{RESET}")
    print(f"  LLM model       : gemini-1.5-flash")
    print(f"  LLM threshold   : risk ≥ 0.50  (agent fires above this)")

    base = datetime(2024, 1, 1)

    # ── Step 1: Generate data ─────────────────────────────────────────────
    print_section("Step 1 / 3 — Generating synthetic traffic")
    print("  Building baseline: 16,000 events (~22 hours of normal traffic) …", end=" ", flush=True)
    baseline = make_normal_traffic(base, n=16_000, seed=0)
    print(f"{GREEN}done{RESET}  ({len(baseline):,} events)")

    attack_events = build_attack_events(args.attack, base)
    if attack_events:
        print(f"  Injecting attack: {BOLD}{args.attack}{RESET}  ({len(attack_events)} malicious events)")
    else:
        print("  No attack injected — testing false-positive rate on clean traffic.")

    all_events = baseline + attack_events

    # ── Step 2: Build and train pipeline ─────────────────────────────────
    print_section("Step 2 / 3 — Training IsolationForest baseline model")

    with tempfile.TemporaryDirectory() as tmpdir:
        import os as _os
        model_path = _os.path.join(tmpdir, "isolation_forest.joblib")

        config = SpatioTemporalConfig(
            window_size=timedelta(minutes=5),
            stride=timedelta(minutes=2, seconds=30),
            min_window_events=55,
            min_total_events=10,
            model_path=model_path,
            contamination=0.05,
        )

        llm_config = LLMConfig(
            api_key=GEMINI_API_KEY,
            model_name="gemini-2.5-flash",
            temperature=0.1,
            max_iterations=6,
            high_risk_threshold=0.50,   # LLM fires when risk >= 0.50
        )

        pipeline = SpatioTemporalPipeline(config=config, llm_config=llm_config)

        print("  Training on baseline events …", end=" ", flush=True)
        pipeline.train_baseline(baseline)
        status = pipeline.model_status()
        print(f"{GREEN}done{RESET}  "
              f"(trained_at={status['trained_at'][:19]}, "
              f"samples={status['training_samples']:,})")

        # ── Step 3: Run the agentic pipeline ─────────────────────────────
        print_section("Step 3 / 3 — Running agentic pipeline")
        print("  Graph: validate → score → severity → llm_analysis → END")
        print("  Processing events …", end=" ", flush=True)

        state = pipeline.process(all_events)
        print(f"{GREEN}done{RESET}  ({len(all_events):,} events processed)")

        if state.errors:
            print(f"\n{YELLOW}  Warnings / errors during run:{RESET}")
            for err in state.errors:
                print(f"    • {err}")

        # ── Results: IsolationForest layer ────────────────────────────────
        print_header("IsolationForest Results")
        st_result = next((r for r in state.results if r.agent == "spatio_temporal"), None)
        val_result = next((r for r in state.results if r.agent == "validation"), None)

        if val_result and state.metadata.get("skip_scoring"):
            print(f"  {YELLOW}Pipeline routed to SKIP — too few events.{RESET}")
            print(f"  Risk score: 0.0  (no scoring performed)")
        elif st_result:
            details = st_result.details
            print_iso_result(
                risk_score   = st_result.risk_score,
                severity     = st_result.severity.value,
                flags        = st_result.flags,
                num_windows  = details.get("num_windows_scored", 0),
                worst_start  = details.get("worst_window_start", "?"),
                worst_end    = details.get("worst_window_end", "?"),
            )

            # Print worst-window feature breakdown
            worst_features = details.get("worst_window_features", {})
            if worst_features:
                print_section("Worst-Window Feature Vector")
                for name, val in worst_features.items():
                    bar_val = min(val / 50.0, 1.0) if val > 0 else 0.0  # normalise for display
                    flag = ""
                    if name == "request_synchrony" and val < 20:
                        flag = f" {RED}← suspiciously low (baseline ≥ 32 s){RESET}"
                    elif name == "max_user_ip_count" and val > 3:
                        flag = f" {RED}← IP-hopping signal (baseline = 1){RESET}"
                    elif name == "shared_endpoint_ips" and val > 15:
                        flag = f" {RED}← coordinated scan (baseline ≤ 9){RESET}"
                    print(f"  {name:<26}: {val:>8.2f}{flag}")
        else:
            print(f"  {YELLOW}No spatio_temporal result found in state.{RESET}")

        # ── Results: LLM reasoning layer ──────────────────────────────────
        print_header("Gemini LLM Agent Analysis")
        llm = state.metadata.get("llm_analysis")

        if llm is None:
            print(f"  {DIM}No LLM analysis in metadata.{RESET}")
        elif not llm.get("tool_calls_made") and llm.get("verdict") == "likely_fp":
            # Threshold was not met — LLM was skipped
            risk = st_result.risk_score if st_result else 0.0
            print(f"  {DIM}LLM skipped — risk score {risk:.3f} is below the 0.50 threshold.{RESET}")
            print(f"  Auto-classified as: {GREEN}likely false positive{RESET}")
        else:
            print_llm_result(llm)

        # ── Overall summary ───────────────────────────────────────────────
        print_header("Overall Summary")
        overall_sev = state.metadata.get("overall_severity", Severity.INFO)
        sev_str     = overall_sev.value if isinstance(overall_sev, Severity) else str(overall_sev)
        sev_color   = SEVERITY_COLOR.get(sev_str, "")

        verdict     = (llm or {}).get("verdict", "n/a")
        v_color     = VERDICT_COLOR.get(verdict, "")

        print(f"  Pipeline severity : {sev_color}{BOLD}{sev_str.upper()}{RESET}")
        print(f"  LLM verdict       : {v_color}{BOLD}{verdict.upper().replace('_', ' ')}{RESET}")
        print(f"  Errors/warnings   : {len(state.errors)}")
        print(f"  Finished at       : {state.finished_at}")
        print(f"\n{DIM}Run with --attack {{sync|hop|scan|compound|none}} to test other scenarios.{RESET}\n")


if __name__ == "__main__":
    main()
