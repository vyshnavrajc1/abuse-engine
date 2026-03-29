"""
evaluation/validate_combined.py – Combined (coordinator) F1/AUC validation on CICIDS2017.

Ablation table rows this produces
-----------------------------------
  A. Spatiotemporal alone      (already in validate_spatiotemporal.py)
  B. Behavioral alone          (already in validate_behavioral.py)
  C. Coordinator (all three)   ← this script

How per-user scores are compared to ground truth
-------------------------------------------------
For each user_id in the test set we compute:
  • user_is_attack = True  if any of that user's events are attacks
  • user_score     = coordinator final_score for that user

Then standard precision / recall / F1 / AUC are computed at the user level.

Spatiotemporal contributes one batch-level score (shared across all users).
Behavioral + semantic contribute per-user scores.

Usage
-----
    python evaluation/validate_combined.py
    python evaluation/validate_combined.py --max-events 20000
    python evaluation/validate_combined.py --save-results
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.ingestion.cicids_loader import load_cicids, DEFAULT_PATH
from engine.pipeline.sessionizer import sessionize
from engine.agents.behavioral import analyze as behavioral_analyze
from engine.agents.semantic import SemanticGuardAgent
from engine.agents.spatio_temporal.spatio_temporal_agent import (
    SpatioTemporalConfig,
    SpatioTemporalPipeline,
)
from engine.coordinator.coordinator import Coordinator
from schemas.event_schema import CanonicalEvent

RESULTS_DIR = PROJECT_ROOT / "results"


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def compute_metrics(scores, labels, threshold) -> dict:
    tp = fp = tn = fn = 0
    for s, l in zip(scores, labels):
        pred = s >= threshold
        if pred and l:  tp += 1
        elif pred:      fp += 1
        elif l:         fn += 1
        else:           tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
            "support_pos": tp + fn, "support_neg": fp + tn}


def find_optimal_threshold(scores, labels, steps=200) -> float:
    best_j, best_t = -1.0, 0.5
    for i in range(1, steps):
        t = i / steps
        m = compute_metrics(scores, labels, t)
        j = m["recall"] - m["fpr"]
        if j > best_j:
            best_j, best_t = j, t
    return best_t


def roc_auc(scores, labels, steps=500) -> float:
    pts = []
    for i in range(steps + 1):
        m = compute_metrics(scores, labels, i / steps)
        pts.append((m["fpr"], m["recall"]))
    pts.sort()
    auc = 0.0
    for i in range(1, len(pts)):
        auc += (pts[i][0] - pts[i-1][0]) * (pts[i][1] + pts[i-1][1]) / 2
    return auc


def _bar(v, w=20):
    return "█" * int(v * w) + "░" * (w - int(v * w))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Combined coordinator validation on CICIDS2017")
    parser.add_argument("--dataset",    type=Path, default=DEFAULT_PATH)
    parser.add_argument("--max-events", type=int,  default=None)
    parser.add_argument("--batch-hours", type=float, default=2.0,
                        help="Spatiotemporal batch window size in hours")
    parser.add_argument("--save-results", action="store_true")
    parser.add_argument("--plot",  action="store_true",
                        help="Save all plots (ROC, PRF, CM, ablation) to figures/")
    parser.add_argument("--show",  action="store_true",
                        help="Display plots interactively (requires display)")
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"ERROR: {args.dataset} not found. Run: python scripts/convert_cicids.py",
              file=sys.stderr)
        sys.exit(1)

    # ── 1. Load ────────────────────────────────────────────────────────
    print("\n─── Step 1/5 — Loading dataset ────────────────────────────────")
    train_events, test_events, test_labels_list, test_classes = load_cicids(
        args.dataset, max_test=args.max_events)
    n_attack = sum(test_labels_list)
    print(f"  Train events : {len(train_events):,}")
    print(f"  Test events  : {len(test_events):,}  "
          f"(attack={n_attack:,}  benign={len(test_labels_list)-n_attack:,})")

    # Build per-event label lookup
    label_map: Dict[int, bool] = {
        id(e): l for e, l in zip(test_events, test_labels_list)
    }
    class_map: Dict[int, str] = {
        id(e): c for e, c in zip(test_events, test_classes)
    }

    # ── 2. Train spatiotemporal ────────────────────────────────────────
    print("\n─── Step 2/5 — Training spatiotemporal baseline ───────────────")
    with tempfile.TemporaryDirectory() as tmpdir:
        config   = SpatioTemporalConfig(
            model_path=os.path.join(tmpdir, "isolation_forest.joblib"),
            contamination=0.05,
        )
        pipeline = SpatioTemporalPipeline(config=config)
        print(f"  Training on {len(train_events):,} baseline events …", end=" ", flush=True)
        pipeline.train_baseline(train_events)
        print("done")

        # ── 3. Run all agents ──────────────────────────────────────────
        print("\n─── Step 3/5 — Running all three agents ────────────────────")

        # Sessionize
        sessions = sessionize(test_events)
        print(f"  Sessions            : {len(sessions):,}")

        # Behavioral
        behavioral_results = behavioral_analyze(sessions)
        print(f"  Behavioral results  : {len(behavioral_results):,}")

        # Semantic (very lightweight on CICIDS — spec coverage will be low → low scores)
        semantic_agent = SemanticGuardAgent(
            str(PROJECT_ROOT / "spec.yaml"),
            lambda obj_id, tenant: None,
            {"admin_users": [], "weights": {
                "ownership_violation": 0.4, "enumeration": 0.2,
                "volume_mismatch": 0.2, "parameter_tampering": 0.1, "probing": 0.1}},
        )
        if test_events:
            ts_all = [e.timestamp for e in test_events]
            semantic_results = semantic_agent.process_window(
                test_events, min(ts_all) - timedelta(minutes=1),
                max(ts_all) + timedelta(minutes=1))
        else:
            semantic_results = []
        print(f"  Semantic results    : {len(semantic_results):,} users")

        # Spatiotemporal — process in batches, pick highest batch score
        print(f"  Running spatiotemporal ({args.batch_hours}h batches) …", end=" ", flush=True)
        sorted_test = sorted(test_events, key=lambda e: e.timestamp)
        if sorted_test:
            from datetime import timedelta as td
            batch_delta  = td(hours=args.batch_hours)
            t0, t1       = sorted_test[0].timestamp, sorted_test[-1].timestamp
            cur          = t0
            best_spatio  = None
            while cur <= t1:
                batch = [e for e in sorted_test if cur <= e.timestamp < cur + batch_delta]
                if batch:
                    state  = pipeline.process(batch)
                    result = next((r for r in state.results if r.agent == "spatio_temporal"), None)
                    if result and (best_spatio is None or result.risk_score > best_spatio.risk_score):
                        best_spatio = result
                cur += batch_delta * 0.5
        else:
            best_spatio = None
        spatio_score = best_spatio.risk_score if best_spatio else 0.0
        print(f"done  (max risk={spatio_score:.3f})")

        # ── 4. Coordinator ─────────────────────────────────────────────
        print("\n─── Step 4/5 — Coordinator combination ─────────────────────")
        coordinator   = Coordinator()
        all_per_user  = behavioral_results + semantic_results
        final_results = coordinator.combine(all_per_user, spatio_result=best_spatio)
        print(f"  Users with verdicts : {len(final_results):,}")

        # ── 5. Metrics ─────────────────────────────────────────────────
        print("\n─── Step 5/5 — Computing metrics ────────────────────────────")

        # Build per-user ground truth (attack if ANY event is an attack)
        user_labels: Dict[str, bool] = defaultdict(bool)
        for e in test_events:
            uid = e.user_id or e.source_ip
            if label_map.get(id(e), False):
                user_labels[uid] = True

        # Align coordinator scores with ground-truth labels
        u_scores = [r.final_score for r in final_results]
        u_labels = [user_labels.get(r.user_id, False) for r in final_results]

        n_pos = sum(u_labels)
        n_neg = len(u_labels) - n_pos
        print(f"  Users: {len(u_labels):,}  attack={n_pos:,}  benign={n_neg:,}")

        if n_pos == 0:
            print("  WARNING: No attack users in results — F1 will be 0.")

        auc       = roc_auc(u_scores, u_labels)
        threshold = find_optimal_threshold(u_scores, u_labels)
        print(f"  Optimal threshold   : {threshold:.4f}  (Youden's J)")

        m_fixed   = compute_metrics(u_scores, u_labels, 0.5)
        m_optimal = compute_metrics(u_scores, u_labels, threshold)

        print(f"\n  {'Configuration':<45} {'P':>7}  {'R':>7}  {'F1':>7}  Bar")
        print(f"  {'─'*45} {'─'*7}  {'─'*7}  {'─'*7}  {'─'*22}")

        def row(label, m):
            print(f"  {label:<45} {m['precision']:>7.4f}  {m['recall']:>7.4f}  "
                  f"{m['f1']:>7.4f}  {_bar(m['f1'])}")

        row("Coordinator (t=0.50 fixed)",         m_fixed)
        row(f"Coordinator (t={threshold:.2f} optimal)", m_optimal)

        print(f"\n  Agent weights used : {dict(coordinator.weights)}")
        print(f"  Spatio batch score : {spatio_score:.4f}")
        print(f"\n  Confusion: TP={m_optimal['tp']:,}  FP={m_optimal['fp']:,}  "
              f"FN={m_optimal['fn']:,}  TN={m_optimal['tn']:,}")

        print(f"\n{'═'*65}")
        print(f"  FINAL  F1={m_optimal['f1']:.4f}   AUC={auc:.4f}   threshold={threshold:.4f}")
        print(f"{'═'*65}\n")

        if args.save_results:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            out = {
                "agents": ["behavioral", "semantic", "spatio_temporal"],
                "weights": dict(coordinator.weights),
                "threshold": threshold, "auc": auc,
                "fixed": m_fixed, "optimal": m_optimal,
                "spatio_batch_score": spatio_score,
            }
            p = RESULTS_DIR / "combined_validation.json"
            with open(p, "w") as f:
                json.dump(out, f, indent=2)
            print(f"  Results saved → {p}")

        if args.plot or args.show:
            from evaluation.plot_utils import plot_all, plot_ablation
            print("\n─── Generating plots ──────────────────────────────────────────────")
            # ROC + PRF + CM for the combined coordinator
            plot_all(u_scores, u_labels, auc, threshold, m_optimal,
                     "Coordinator (All Agents)", save=args.plot, show=args.show)
            # Ablation bar chart — reads saved results if available,
            # otherwise uses the coordinator score only
            ablation_configs = []
            import json as _json
            results_dir = RESULTS_DIR
            for fname, label in [
                ("behavioral_validation.json",      "Behavioral alone"),
                ("spatiotemporal_validation.json",  "Spatiotemporal alone"),
                ("combined_validation.json",        "All three (Coordinator)"),
            ]:
                p2 = results_dir / fname
                if p2.exists():
                    with open(p2) as f2:
                        d = _json.load(f2)
                    opt = d.get("optimal") or d.get("spatiotemporal") or {}
                    ablation_configs.append({
                        "label": label,
                        "f1":    opt.get("f1", 0.0),
                        "auc":   d.get("auc", 0.0),
                    })
            if ablation_configs:
                plot_ablation(ablation_configs, save=args.plot, show=args.show)


if __name__ == "__main__":
    main()
