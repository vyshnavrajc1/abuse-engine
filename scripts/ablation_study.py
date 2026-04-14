"""
Ablation study — Abuse Engine CICIDS 2017
=======================================
Three passes over the same dataset window (max_records=1_400_000):

  Mode A — Rules-only
    • Cold-start (static) thresholds throughout
    • Isolation Forest disabled
    • XGBoost stacking disabled

  Mode B — Rules + adaptive thresholds
    • LTM-derived thresholds active once distribution is stable
    • Isolation Forest enabled
    • XGBoost stacking disabled

  Mode C — Full system
    • All of Mode B
    • XGBoost stacking enabled (trains on accumulated verdicts)

Results are saved to results/ablation_study.json and printed in a summary table.

Usage:
  python3 scripts/ablation_study.py [--max-records N]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import engine.coordinator.meta_agent as _meta_mod
import engine.agents.volume_agent as _vol_mod


def _run_mode(
    label: str,
    data_path: str,
    window_size: int,
    max_records: int,
    disable_adaptive: bool,
    disable_xgb: bool,
) -> Dict[str, Any]:
    """Run a single evaluation pass with specified ablation settings.

    Returns a dict with precision, recall, f1, fp, fn, tp, tn counts, and a
    per-threat breakdown.
    """
    from collections import Counter

    # ── Fresh LTM / memory per run ─────────────────────────────────────────
    from engine.memory.shared_memory import SharedMemory
    from engine.coordinator.meta_agent import MetaAgentOrchestrator
    from engine.ingestion.cicids_ingestion import CICIDSIngestion

    # Reseed global XGB state so each mode starts from scratch
    _meta_mod._xgb_stacker = None
    _meta_mod._xgb_trained_on = 0

    # Reset Isolation Forest state for Volume agent
    _vol_mod._iso_forest = None
    _vol_mod._iso_forest_trained_on = 0

    mem = SharedMemory()

    # ── Ablation patches ────────────────────────────────────────────────────
    _original_stable = mem.ltm.is_distribution_stable

    # Save originals before patching
    _orig_sklearn = _vol_mod._SKLEARN_AVAILABLE
    _orig_xgb = _meta_mod._XGB_AVAILABLE

    if disable_adaptive:
        # Freeze thresholds at cold-start values by reporting "not stable yet"
        mem.ltm.is_distribution_stable = lambda agent_name: False  # type: ignore[method-assign]

        # Also suppress Isolation Forest (relies on LTM history)
        _vol_mod._SKLEARN_AVAILABLE = False

    if disable_xgb:
        _meta_mod._XGB_AVAILABLE = False  # type: ignore[attr-defined]

    orch = MetaAgentOrchestrator(mem)
    ing = CICIDSIngestion(data_path, window_size=window_size, max_records=max_records)

    counts = [0, 0, 0, 0]  # FP, TP, FN, TN
    fp_agents: Counter = Counter()
    fn_labels: Counter = Counter()

    for batch in ing.batches():
        ac = sum(1 for r in batch if r.is_attack)
        v = orch.run(batch)
        p = v.is_attack
        gt = ac > 0

        if not gt and p:
            counts[0] += 1
            for a in v.contributing_agents:
                fp_agents[a] += 1
        elif gt and p:
            counts[1] += 1
        elif gt and not p:
            counts[2] += 1
            for lbl in set(r.label for r in batch if r.is_attack):
                fn_labels[lbl] += 1
        else:
            counts[3] += 1

    # ── Restore patches ─────────────────────────────────────────────────────
    if disable_adaptive:
        mem.ltm.is_distribution_stable = _original_stable  # type: ignore[method-assign]
        _vol_mod._SKLEARN_AVAILABLE = _orig_sklearn

    _meta_mod._XGB_AVAILABLE = _orig_xgb

    fp, tp, fn, tn = counts
    pr = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rc = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * pr * rc / (pr + rc) if (pr + rc) > 0 else 0.0

    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"{'─'*60}")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision={pr:.3f}  Recall={rc:.3f}  F1={f1:.3f}")
    if fp_agents:
        print(f"  FP agents : {dict(fp_agents.most_common())}")
    if fn_labels:
        print(f"  FN types  : {dict(fn_labels.most_common())}")

    return {
        "label": label,
        "disable_adaptive": disable_adaptive,
        "disable_xgb": disable_xgb,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(pr, 4),
        "recall": round(rc, 4),
        "f1": round(f1, 4),
        "fp_agents": dict(fp_agents.most_common()),
        "fn_labels": dict(fn_labels.most_common()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Abuse Engine ablation study")
    parser.add_argument("--data", default="datasets/processed/", help="Data directory")
    parser.add_argument("--window", type=int, default=500, help="Batch window size")
    parser.add_argument("--max-records", type=int, default=1_400_000,
                        help="Records to evaluate (0 = all ~2.8M)")
    parser.add_argument("--output", default="results/ablation_study.json")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("  Abuse Engine — Ablation Study")
    print(f"  max_records={args.max_records or 'ALL'}  window={args.window}")
    print(f"{'='*60}")

    modes = [
        ("Mode A — Rules-only (cold-start, no ML)",
         dict(disable_adaptive=True, disable_xgb=True)),
        ("Mode B — Rules + adaptive thresholds (no XGB)",
         dict(disable_adaptive=False, disable_xgb=True)),
        ("Mode C — Full system (adaptive + XGB stacking)",
         dict(disable_adaptive=False, disable_xgb=False)),
    ]

    results = []
    for label, kwargs in modes:
        res = _run_mode(
            label=label,
            data_path=args.data,
            window_size=args.window,
            max_records=args.max_records,
            **kwargs,
        )
        results.append(res)

    # ── Summary table ────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  ABLATION SUMMARY TABLE")
    print(f"{'='*60}")
    header = f"{'Mode':<45} {'P':>6} {'R':>6} {'F1':>6} {'FP':>5} {'FN':>5}"
    print(header)
    print("─" * len(header))
    for r in results:
        row = (
            f"{r['label']:<45} "
            f"{r['precision']:>6.3f} "
            f"{r['recall']:>6.3f} "
            f"{r['f1']:>6.3f} "
            f"{r['fp']:>5} "
            f"{r['fn']:>5}"
        )
        print(row)

    # ── Save ─────────────────────────────────────────────────────────────────
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_timestamp": datetime.utcnow().isoformat(),
        "config": {
            "data_path": args.data,
            "window_size": args.window,
            "max_records": args.max_records,
        },
        "modes": results,
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nResults saved → {output_path}")


if __name__ == "__main__":
    main()
