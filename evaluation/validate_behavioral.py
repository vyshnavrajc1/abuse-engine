"""
evaluation/validate_behavioral.py – F1 validation of the behavioral agent on CICIDS2017.

How it works
------------
1. Loads cicids_canonical.jsonl via cicids_loader
2. Sessionizes test events by user_id (30-min gap rule)
3. Runs behavioral.analyze() on all test sessions (unsupervised IsolationForest)
4. Labels a session as "attack" if >50% of its events have is_attack=True
5. Computes precision / recall / F1 / AUC at optimal Youden's-J threshold

Usage
-----
    python evaluation/validate_behavioral.py
    python evaluation/validate_behavioral.py --max-events 50000
    python evaluation/validate_behavioral.py --save-results
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.ingestion.cicids_loader import load_cicids, DEFAULT_PATH
from engine.pipeline.sessionizer import sessionize
from engine.agents.behavioral import analyze as behavioral_analyze, train_model as behavioral_train
from schemas.event_schema import CanonicalEvent

RESULTS_DIR = PROJECT_ROOT / "results"


# ---------------------------------------------------------------------------
# Session labelling
# ---------------------------------------------------------------------------

def label_sessions(
    sessions,
    event_labels: Dict[int, bool],
    attack_threshold: float = 0.5,
    model=None,
) -> Tuple[List[float], List[bool]]:
    """
    Given pre-computed per-event attack labels (keyed by id()), label each
    session as attack/benign and return (session_scores, session_labels).
    Accepts an optional pre-trained IsolationForest to avoid contamination.
    """
    results = behavioral_analyze(sessions, model=model)

    scores  = []
    labels  = []
    for result, session in zip(results, sessions):
        scores.append(result.risk_score)
        # Session is "attack" if more than attack_threshold fraction are attacks
        n_attack = sum(event_labels.get(id(e), False) for e in session.events)
        labels.append(n_attack / max(1, len(session.events)) >= attack_threshold)

    return scores, labels


# ---------------------------------------------------------------------------
# Metrics (shared logic mirrored from validate_spatiotemporal.py)
# ---------------------------------------------------------------------------

def compute_metrics(scores, labels, threshold) -> dict:
    tp = fp = tn = fn = 0
    for s, l in zip(scores, labels):
        pred = s >= threshold
        if pred and l:      tp += 1
        elif pred:          fp += 1
        elif l:             fn += 1
        else:               tn += 1
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
    parser = argparse.ArgumentParser(description="Validate behavioral agent on CICIDS2017")
    parser.add_argument("--dataset",    type=Path, default=DEFAULT_PATH)
    parser.add_argument("--max-events", type=int,  default=None,
                        help="Cap test events (e.g. 50000 for fast run)")
    parser.add_argument("--threshold",  type=float, default=None,
                        help="Fixed threshold (default: auto-tune Youden's J)")
    parser.add_argument("--save-results", action="store_true")
    parser.add_argument("--plot",  action="store_true",
                        help="Save ROC, PRF, and confusion-matrix plots to figures/")
    parser.add_argument("--show",  action="store_true",
                        help="Display plots interactively (requires display)")
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"ERROR: {args.dataset} not found. Run: python scripts/convert_cicids.py",
              file=sys.stderr)
        sys.exit(1)

    # ── Load ──────────────────────────────────────────────────────────────
    print("\n─── Step 1/4 — Loading dataset ────────────────────────────────")
    train_events, test_events, test_labels_list, test_classes = load_cicids(
        args.dataset, max_test=args.max_events)
    print(f"  Train events: {len(train_events):,}")
    print(f"  Test events : {len(test_events):,}  "
          f"(attack={sum(test_labels_list):,}  "
          f"benign={sum(1 for l in test_labels_list if not l):,})")

    # Build per-event id() lookup for fast session labelling
    label_map: Dict[int, bool] = {id(e): l for e, l in zip(test_events, test_labels_list)}

    # ── Sessionize ────────────────────────────────────────────────────────
    print("\n─── Step 2/4 — Sessionizing ────────────────────────────────────")
    train_sessions = sessionize(train_events)
    test_sessions  = sessionize(test_events)
    print(f"  Train sessions: {len(train_sessions):,}")
    print(f"  Test sessions : {len(test_sessions):,}")

    # ── Train baseline model ──────────────────────────────────────────────
    print("\n─── Step 3/4 — Training baseline model ─────────────────────────")
    baseline_model = behavioral_train(train_sessions, contamination=0.05)
    print(f"  Trained IsolationForest on {len(train_sessions):,} baseline sessions")

    # ── Score ─────────────────────────────────────────────────────────────
    print("\n─── Step 4/4 — Scoring & metrics ───────────────────────────────")
    scores, session_labels = label_sessions(test_sessions, label_map, model=baseline_model)

    n_pos = sum(session_labels)
    n_neg = len(session_labels) - n_pos
    print(f"  Sessions    : {len(session_labels):,}  (attack={n_pos:,}  benign={n_neg:,})")

    auc = roc_auc(scores, session_labels)

    threshold = args.threshold if args.threshold else find_optimal_threshold(scores, session_labels)
    if args.threshold:
        print(f"  Threshold   : {threshold}  (fixed)")
    else:
        print(f"  Threshold   : {threshold:.4f}  (Youden's J)")

    m_fixed   = compute_metrics(scores, session_labels, 0.5)
    m_optimal = compute_metrics(scores, session_labels, threshold)

    print(f"\n  {'Configuration':<40} {'P':>8}  {'R':>8}  {'F1':>8}  {'Bar':>22}  AUC")
    print(f"  {'─'*40} {'─'*8}  {'─'*8}  {'─'*8}  {'─'*22}  {'─'*6}")

    def row(label, m, show_auc=False):
        a = f"  AUC={auc:.4f}" if show_auc else ""
        print(f"  {label:<40} {m['precision']:>8.4f}  {m['recall']:>8.4f}  "
              f"{m['f1']:>8.4f}  {_bar(m['f1']):>22}{a}")

    row("Behavioral (t=0.50, raw)", m_fixed)
    row("Behavioral (optimal threshold)", m_optimal, show_auc=True)

    print(f"\n  Confusion: TP={m_optimal['tp']:,}  FP={m_optimal['fp']:,}  "
          f"FN={m_optimal['fn']:,}  TN={m_optimal['tn']:,}")

    print(f"\n{'═'*65}")
    print(f"  FINAL  F1={m_optimal['f1']:.4f}   AUC={auc:.4f}   threshold={threshold:.4f}")
    print(f"{'═'*65}\n")

    if args.save_results:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out = {
            "agent": "behavioral",
            "threshold": threshold, "auc": auc,
            "fixed": m_fixed, "optimal": m_optimal,
        }
        p = RESULTS_DIR / "behavioral_validation.json"
        with open(p, "w") as f:
            json.dump(out, f, indent=2)
        print(f"  Results saved → {p}")

    if args.plot or args.show:
        from evaluation.plot_utils import plot_all
        print("\n─── Generating plots ───────────────────────────────────────────────")
        plot_all(scores, session_labels, auc, threshold, m_optimal,
                 "Behavioral Agent", save=args.plot, show=args.show)


if __name__ == "__main__":
    main()
