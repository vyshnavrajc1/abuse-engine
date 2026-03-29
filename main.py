"""
main.py – Abuse Engine: production runner

Runs all three agents on a batch of events and produces:
  • Per-user risk scores with XAI explanations from each agent
  • Coordinator final verdict (weighted risk score + assembled explanation)

For research validation metrics (F1, AUC, precision/recall, plots) use:
  python evaluation/validate_spatiotemporal.py --save-results
  python evaluation/validate_behavioral.py     --save-results
  python evaluation/validate_combined.py       --save-results

Usage
-----
  # Production mode — CICIDS2017 dataset (requires datasets/cicids_canonical.jsonl)
  python main.py

  # Quick test — synthetic mock logs (no dataset required)
  python main.py --mock

  # Limit events for a fast smoke test
  python main.py --max-events 5000
"""

import argparse
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.ingestion.cicids_loader import load_cicids, DEFAULT_PATH
from engine.normalization.normalizer import normalize
from engine.pipeline.sessionizer import sessionize
from engine.agents.behavioral import analyze as behavioral_analyze
from engine.agents.semantic import SemanticGuardAgent
from engine.agents.spatio_temporal.spatio_temporal_agent import (
    SpatioTemporalPipeline,
    SpatioTemporalConfig,
)
from engine.coordinator.coordinator import Coordinator, CoordinatorLLMConfig

# Optional LLM layer — activates automatically when GEMINI_API_KEY is set
try:
    from engine.agents.spatio_temporal.llm_agent_node import LLMConfig as _LLMConfig
    _LLM_AVAILABLE = True
except ImportError:
    _LLM_AVAILABLE = False
    _LLMConfig = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VERDICT_ICON = {"normal": "✅", "suspicious": "⚠️ ", "attack": "🚨"}


def _section(title: str) -> None:
    print(f"\n{'═' * 65}")
    print(f"  {title}")
    print(f"{'═' * 65}")


def _print_agent_result(result) -> None:
    icon = "🔴" if result.risk_score >= 0.7 else ("🟡" if result.risk_score >= 0.4 else "🟢")
    print(f"    {icon} [{result.agent.upper()}] risk={result.risk_score:.3f}  "
          f"severity={result.severity}  flags={result.flags}")
    if result.explanation:
        for line in result.explanation.split(" | "):
            print(f"       {line}")


def _print_coordinator_result(r) -> None:
    icon = VERDICT_ICON.get(r.verdict, "?")
    print(f"\n  {icon} {r.user_id}")
    print(f"    Verdict     : {r.verdict.upper()}")
    print(f"    Final score : {r.final_score:.3f}   confidence={r.confidence:.2f}")
    print(f"    Agents      : {r.agent_scores}")
    print(f"    Flags       : {r.all_flags[:8]}")
    print(f"    Explanation : {r.explanation[:200]}")
    if r.llm_analysis:
        la = r.llm_analysis
        print(f"    🤖 LLM      : verdict={la.get('verdict')}  "
              f"confidence={la.get('confidence', 0):.2f}  "
              f"type={la.get('attack_type', '?')}  "
              f"MITRE={la.get('mitre_technique', 'N/A')}")
        reasoning = str(la.get("reasoning", ""))
        if reasoning:
            print(f"       Reasoning : {reasoning[:160]}")


# ---------------------------------------------------------------------------
# Mock-log path (small built-in test)
# ---------------------------------------------------------------------------

def run_mock() -> None:
    _section("MOCK MODE — datasets/mock_logs.json")
    mock_path = PROJECT_ROOT / "datasets" / "mock_logs.json"
    if not mock_path.exists():
        print("  mock_logs.json not found — skipping mock mode.")
        return

    with open(mock_path) as f:
        raw = json.load(f)
    from engine.normalization.normalizer import normalize
    events = normalize(raw)
    print(f"  Loaded {len(events)} events from mock_logs.json")
    _run_pipeline(events, train_events=None)


# ---------------------------------------------------------------------------
# Core pipeline  (shared by CICIDS mode and mock mode)
# ---------------------------------------------------------------------------

def _run_pipeline(test_events, train_events=None, max_users: int = 20) -> None:
    # ── 1. Sessionize ──────────────────────────────────────────────────
    sessions = sessionize(test_events)
    print(f"  Sessionized into {len(sessions)} sessions")

    # ── 2. Behavioral agent ────────────────────────────────────────────
    _section("BEHAVIORAL AGENT")
    behavioral_results = behavioral_analyze(sessions)
    print(f"  Analyzed {len(behavioral_results)} sessions")
    top_b = sorted(behavioral_results, key=lambda r: r.risk_score, reverse=True)[:5]
    for r in top_b:
        _print_agent_result(r)

    # ── 3. Semantic agent ──────────────────────────────────────────────
    _section("SEMANTIC AGENT")
    semantic_config = {
        "admin_users": [],
        "weights": {
            "ownership_violation": 0.4,
            "enumeration": 0.2,
            "volume_mismatch": 0.2,
            "parameter_tampering": 0.1,
            "probing": 0.1,
        },
        "volume_low_threshold": 5,
        "volume_medium_threshold": 10,
        "volume_high_threshold": 20,
    }
    semantic_agent = SemanticGuardAgent(
        str(PROJECT_ROOT / "spec.yaml"),
        lambda obj_id, tenant: None,
        semantic_config,
    )
    from datetime import datetime
    if test_events:
        all_ts = [e.timestamp for e in test_events]
        win_start = min(all_ts) - timedelta(minutes=1)
        win_end   = max(all_ts) + timedelta(minutes=1)
    else:
        win_start = win_end = datetime.utcnow()

    semantic_results = semantic_agent.process_window(test_events, win_start, win_end)
    print(f"  Analyzed {len(semantic_results)} users")
    top_s = sorted(semantic_results, key=lambda r: r.risk_score, reverse=True)[:5]
    for r in top_s:
        _print_agent_result(r)

    # ── 4. Spatiotemporal agent ────────────────────────────────────────
    _section("SPATIOTEMPORAL AGENT")
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        config = SpatioTemporalConfig(
            model_path=os.path.join(tmpdir, "isolation_forest.joblib"),
            contamination=0.05,
        )
        # Auto-enable Gemini LLM layer if API key is present
        llm_cfg = None
        if _LLM_AVAILABLE and os.environ.get("GEMINI_API_KEY"):
            llm_cfg = _LLMConfig()
            print("  Gemini LLM layer: ENABLED (GEMINI_API_KEY found)")
        else:
            print("  Gemini LLM layer: DISABLED (set GEMINI_API_KEY to enable)")
        pipeline = SpatioTemporalPipeline(config=config, llm_config=llm_cfg)

        if train_events and len(train_events) >= 50:
            print(f"  Training on {len(train_events):,} baseline events …", end=" ", flush=True)
            try:
                pipeline.train_baseline(train_events)
                print("done")
            except ValueError as exc:
                print(f"skipped ({exc})")

        if pipeline.registry.is_ready:
            state = pipeline.process(test_events)
            spatio_result = next(
                (r for r in state.results if r.agent == "spatio_temporal"), None
            )
            if spatio_result:
                _print_agent_result(spatio_result)
            llm_analysis = state.metadata.get("llm_analysis")
            if llm_analysis:
                print(f"\n  🤖 LLM Analysis:")
                print(f"     Verdict     : {llm_analysis.get('verdict', '?')}")
                print(f"     Confidence  : {llm_analysis.get('confidence', 0):.2f}")
                print(f"     Attack type : {llm_analysis.get('attack_type', 'unknown')}")
                print(f"     MITRE       : {llm_analysis.get('mitre_technique', 'N/A')}")
                print(f"     Reasoning   : {str(llm_analysis.get('reasoning', ''))[:200]}")
                actions = llm_analysis.get("recommended_actions", [])
                if actions:
                    print(f"     Actions     : {actions[0]}")
                print(f"     Tools used  : {llm_analysis.get('tool_calls_made', [])}")
        else:
            spatio_result = None
            print("  Spatiotemporal agent skipped (model not trained).")

        # ── 5. Coordinator ─────────────────────────────────────────────
        _section("COORDINATOR — FINAL VERDICTS")
        # Auto-enable coordinator LLM enrichment if API key is present
        coord_llm_cfg = None
        if _LLM_AVAILABLE and os.environ.get("GEMINI_API_KEY"):
            coord_llm_cfg = CoordinatorLLMConfig()
            print("  Coordinator LLM reasoning: ENABLED")
        coordinator  = Coordinator(llm_config=coord_llm_cfg)
        all_per_user = behavioral_results + semantic_results
        final        = coordinator.combine(all_per_user, spatio_result=spatio_result)

        attacks    = [r for r in final if r.verdict == "attack"]
        suspicious = [r for r in final if r.verdict == "suspicious"]
        normal     = [r for r in final if r.verdict == "normal"]

        print(f"  Showing top {min(max_users, len(final))} users by risk score:\n")
        for r in final[:max_users]:
            _print_coordinator_result(r)

        # ── 6. Summary ─────────────────────────────────────────────────
        _section("SUMMARY")
        print(f"  🚨 Attacks    : {len(attacks)}")
        print(f"  ⚠️  Suspicious : {len(suspicious)}")
        print(f"  ✅ Normal     : {len(normal)}")
        print(f"  Total users  : {len(final)}")
        if attacks:
            print(f"\n  Top attack explanations:")
            for r in attacks[:3]:
                print(f"    • {r.explanation[:160]}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Abuse Engine — production runner")
    parser.add_argument("--mock",       action="store_true",
                        help="Use mock_logs.json instead of CICIDS2017")
    parser.add_argument("--max-events", type=int, default=None,
                        help="Cap number of test events (for quick runs)")
    args = parser.parse_args()

    if args.mock:
        run_mock()
        return

    # ── CICIDS2017 mode ────────────────────────────────────────────────
    _section("ABUSE ENGINE — CICIDS2017 MODE")
    dataset_path = DEFAULT_PATH
    if not dataset_path.exists():
        print(
            f"ERROR: {dataset_path} not found.\n"
            "Run:  python scripts/convert_cicids.py\n"
            "Or use --mock for quick testing.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"  Loading {dataset_path} …")
    train_events, test_events, _, _ = load_cicids(
        dataset_path,
        max_test=args.max_events,
    )
    print(f"  Train events : {len(train_events):>10,}  (Monday BENIGN baseline)")
    print(f"  Test events  : {len(test_events):>10,}")

    _run_pipeline(test_events, train_events=train_events)


if __name__ == "__main__":
    main()
