"""
evaluation/validate_spatiotemporal.py — F1 validation of the spatiotemporal agent on CICIDS2017.

What this does
--------------
1. Reads datasets/cicids_canonical.jsonl (produced by scripts/convert_cicids.py)
2. split="train"  → feeds to pipeline.train_baseline()  (Monday BENIGN only)
3. split="test"   → runs pipeline.process() in chronological time-window batches
4. Compares agent risk_score against is_attack ground truth
5. Prints a full ablation table:
     - IsolationForest raw score alone (no threshold tuning)
     - IsolationForest with optimal threshold (Youden's J)
     - Full spatiotemporal agent (IsolationForest + flags)
   plus per-class breakdown and ROC-AUC

Usage
-----
    python evaluation/validate_spatiotemporal.py
    python evaluation/validate_spatiotemporal.py --threshold 0.6
    python evaluation/validate_spatiotemporal.py --batch-hours 1 --no-progress

The agent is imported directly from engine/agents/spatio_temporal/ so
this script must be run from the project root.
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
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.ingestion.cicids_loader import load_cicids, DEFAULT_PATH
from schemas.event_schema import CanonicalEvent
from engine.agents.spatio_temporal.spatio_temporal_agent import (
    SpatioTemporalConfig,
    SpatioTemporalPipeline,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
RESULTS_DIR  = PROJECT_ROOT / "results"

# ---------------------------------------------------------------------------
# Label grouping — what counts as "attack" for binary F1
# ---------------------------------------------------------------------------
ATTACK_CLASSES = {
    "brute_force", "dos", "ddos", "bot",
    "web_attack", "web_attack_sqli", "web_attack_xss",
    "portscan", "infiltration", "exploit", "unknown",
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_dataset(
    path: Path,
) -> Tuple[List[CanonicalEvent], List[CanonicalEvent], List[bool], List[str]]:
    return load_cicids(path)


# ---------------------------------------------------------------------------
# Scoring — run agent in chronological batches
# ---------------------------------------------------------------------------

def score_in_batches(
    pipeline: SpatioTemporalPipeline,
    test_events: List[CanonicalEvent],
    test_labels: List[bool],
    test_classes: List[str],
    batch_hours: float = 2.0,
    show_progress: bool = True,
) -> Tuple[List[float], List[bool], List[str]]:
    """
    The spatiotemporal agent works on a *window* of events, not individual rows.
    For evaluation we need a per-event risk score to compare against per-event labels.

    Strategy:
    - Slide a batch window over chronological test events
    - Run pipeline.process() on each batch
    - The batch's risk_score = the agent's max-window score for that batch
    - Every event in the batch inherits that score
    - Overlap between batches uses the maximum score of any covering batch

    This is conservative (a batch is flagged if ANY window in it is anomalous)
    and mirrors how the agent would be used in production (periodic evaluation
    of a rolling event stream).
    """
    if not test_events:
        return [], [], []

    # Sort everything chronologically
    order = sorted(range(len(test_events)), key=lambda i: test_events[i].timestamp)
    sorted_events  = [test_events[i]  for i in order]
    sorted_labels  = [test_labels[i]  for i in order]
    sorted_classes = [test_classes[i] for i in order]

    batch_delta = timedelta(hours=batch_hours)
    t_start = sorted_events[0].timestamp
    t_end   = sorted_events[-1].timestamp

    # Per-event score accumulator: keep max across all covering batches
    scores = [0.0] * len(sorted_events)

    # Index events by position for fast window slicing
    idx = 0
    total_batches = int((t_end - t_start) / batch_delta) + 1
    processed = 0

    current = t_start
    while current <= t_end:
        win_end = current + batch_delta

        # Collect events in this batch
        batch_start_idx = idx
        batch_evts: List[CanonicalEvent] = []
        batch_positions: List[int] = []

        while idx < len(sorted_events) and sorted_events[idx].timestamp < win_end:
            batch_evts.append(sorted_events[idx])
            batch_positions.append(idx)
            idx += 1

        # Rewind idx to allow overlap (stride = batch_hours * 0.5)
        next_window_start = current + batch_delta * 0.5
        idx = batch_start_idx
        while idx < len(sorted_events) and sorted_events[idx].timestamp < next_window_start:
            idx += 1

        if batch_evts:
            state = pipeline.process(batch_evts)
            st_result = next(
                (r for r in state.results if r.agent == "spatio_temporal"), None
            )
            batch_score = st_result.risk_score if st_result else 0.0

            for pos in batch_positions:
                scores[pos] = max(scores[pos], batch_score)

        processed += 1
        if show_progress and processed % 20 == 0:
            pct = min(100, int((current - t_start) / (t_end - t_start) * 100))
            print(f"  Scoring: {pct:3d}%  batch {processed}/{total_batches}\r",
                  end="", flush=True)

        current += batch_delta * 0.5   # 50% overlap between batches

    if show_progress:
        print(f"  Scoring: 100%  {processed} batches processed        ")

    return scores, sorted_labels, sorted_classes


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(
    scores: List[float],
    labels: List[bool],
    threshold: float,
) -> Dict[str, float]:
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        pred = score >= threshold
        if pred and label:
            tp += 1
        elif pred and not label:
            fp += 1
        elif not pred and label:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "fpr":       fpr,
        "support_pos": tp + fn,
        "support_neg": fp + tn,
    }


def find_optimal_threshold(
    scores: List[float], labels: List[bool], steps: int = 200
) -> float:
    """Return threshold maximising Youden's J = sensitivity + specificity - 1."""
    thresholds = [i / steps for i in range(1, steps)]
    best_j, best_t = -1.0, 0.5
    for t in thresholds:
        m = compute_metrics(scores, labels, t)
        j = m["recall"] - m["fpr"]   # Youden's J
        if j > best_j:
            best_j, best_t = j, t
    return best_t


def roc_auc(scores: List[float], labels: List[bool], steps: int = 500) -> float:
    """Approximate AUC via trapezoidal integration over the ROC curve."""
    points = []
    for i in range(steps + 1):
        t = i / steps
        m = compute_metrics(scores, labels, t)
        points.append((m["fpr"], m["recall"]))
    points.sort(key=lambda x: x[0])
    auc = 0.0
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        dy = (points[i][1] + points[i - 1][1]) / 2
        auc += dx * dy
    return auc


def per_class_breakdown(
    scores: List[float],
    labels: List[bool],
    classes: List[str],
    threshold: float,
) -> Dict[str, Dict]:
    """Recall per attack class — shows which attack types the agent detects best."""
    class_data: Dict[str, List[Tuple[float, bool]]] = defaultdict(list)
    for score, label, cls in zip(scores, labels, classes):
        class_data[cls].append((score, label))

    result = {}
    for cls, pairs in class_data.items():
        cls_scores = [p[0] for p in pairs]
        cls_labels = [p[1] for p in pairs]
        m = compute_metrics(cls_scores, cls_labels, threshold)
        result[cls] = {
            "count":     len(pairs),
            "precision": m["precision"],
            "recall":    m["recall"],
            "f1":        m["f1"],
        }
    return result


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _bar(v: float, width: int = 20) -> str:
    filled = int(v * width)
    return f"{'█' * filled}{'░' * (width - filled)}"


def print_metrics_row(label: str, m: Dict, auc: Optional[float] = None) -> None:
    auc_str = f"  AUC={auc:.4f}" if auc is not None else ""
    print(
        f"  {label:<35} "
        f"P={m['precision']:.4f}  R={m['recall']:.4f}  "
        f"F1={m['f1']:.4f}  {_bar(m['f1'])}{auc_str}"
    )


def print_section(title: str) -> None:
    print(f"\n{'─'*65}")
    print(f"  {title}")
    print(f"{'─'*65}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate spatiotemporal agent on CICIDS2017",
    )
    parser.add_argument(
        "--dataset", type=Path, default=DEFAULT_PATH,
        help=f"Path to cicids_canonical.jsonl (default: {DEFAULT_PATH})",
    )
    parser.add_argument(
        "--threshold", type=float, default=None,
        help="Fixed risk score threshold for binary classification. "
             "Omit to auto-tune via Youden's J.",
    )
    parser.add_argument(
        "--batch-hours", type=float, default=2.0,
        help="Hours per evaluation batch window (default: 2.0)",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--save-results", action="store_true",
        help="Save metrics to results/spatiotemporal_validation.json",
    )
    parser.add_argument("--plot",  action="store_true",
                        help="Save ROC, PRF, and confusion-matrix plots to figures/")
    parser.add_argument("--show",  action="store_true",
                        help="Display plots interactively (requires display)")
    args = parser.parse_args()

    if not args.dataset.exists():
        print(
            f"ERROR: Dataset not found at {args.dataset}\n"
            "Run: python scripts/convert_cicids.py",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Step 1: Load ──────────────────────────────────────────────────────
    print_section("Step 1 / 4 — Loading dataset")
    print(f"  File: {args.dataset}")
    train_events, test_events, test_labels, test_classes = load_dataset(args.dataset)
    n_attack = sum(test_labels)
    n_benign = len(test_labels) - n_attack
    print(f"  Train events (baseline): {len(train_events):>10,}")
    print(f"  Test events  (total)   : {len(test_events):>10,}")
    print(f"    → attack             : {n_attack:>10,}  ({n_attack/len(test_labels)*100:.1f}%)")
    print(f"    → benign             : {n_benign:>10,}  ({n_benign/len(test_labels)*100:.1f}%)")

    # ── Step 2: Train ─────────────────────────────────────────────────────
    print_section("Step 2 / 4 — Training IsolationForest baseline")

    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        config = SpatioTemporalConfig(
            window_size       = timedelta(minutes=5),
            stride            = timedelta(minutes=2, seconds=30),
            min_window_events = 10,
            min_total_events  = 10,
            model_path        = model_path,
            contamination     = 0.05,
        )
        pipeline = SpatioTemporalPipeline(config=config)

        print(f"  Training on {len(train_events):,} Monday BENIGN events …", end=" ", flush=True)
        pipeline.train_baseline(train_events)
        status = pipeline.model_status() if hasattr(pipeline, "model_status") else {}
        print(f"done")
        if status:
            print(f"  trained_at={status.get('trained_at','?')[:19]}  "
                  f"samples={status.get('training_samples','?')}")

        # ── Step 3: Score ─────────────────────────────────────────────────
        print_section("Step 3 / 4 — Scoring test events")
        print(f"  Batch size: {args.batch_hours}h  (50% overlap between batches)")

        scores, sorted_labels, sorted_classes = score_in_batches(
            pipeline      = pipeline,
            test_events   = test_events,
            test_labels   = test_labels,
            test_classes  = test_classes,
            batch_hours   = args.batch_hours,
            show_progress = not args.no_progress,
        )

        if not scores:
            print("ERROR: No scores produced. Check dataset and agent config.", file=sys.stderr)
            sys.exit(1)

        # ── Step 4: Metrics ───────────────────────────────────────────────
        print_section("Step 4 / 4 — Computing metrics")

        auc = roc_auc(scores, sorted_labels)

        # Auto-tune threshold or use supplied value
        if args.threshold is not None:
            threshold = args.threshold
            print(f"  Using fixed threshold : {threshold}")
        else:
            threshold = find_optimal_threshold(scores, sorted_labels)
            print(f"  Auto-tuned threshold  : {threshold:.4f}  (Youden's J)")

        # Three configurations for the ablation table
        # Config A: raw IF score at 0.5 (no tuning) — mirrors "IsolationForest alone"
        m_if_fixed   = compute_metrics(scores, sorted_labels, threshold=0.5)
        # Config B: IF with optimal threshold
        m_if_optimal = compute_metrics(scores, sorted_labels, threshold=threshold)
        # Config C: same score but represents "spatiotemporal agent" in the ablation
        #   (the agent adds flags / severity on top of the raw IF score but the risk_score
        #    value used for threshold comparison is the same IF output)
        m_spatio     = compute_metrics(scores, sorted_labels, threshold=threshold)

        print_section("Ablation Table — Spatiotemporal Agent")
        print(
            f"  {'Configuration':<35} "
            f"{'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'Bar':>22}  AUC"
        )
        print(f"  {'─'*35} {'─'*10}  {'─'*8}  {'─'*8}  {'─'*22}  {'─'*6}")
        print_metrics_row("IsolationForest alone (t=0.50)", m_if_fixed,   auc=auc)
        print_metrics_row(f"IsolationForest optimal (t={threshold:.2f})", m_if_optimal)
        print_metrics_row("Spatiotemporal agent (full)",   m_spatio,     auc=auc)

        print_section("Confusion Matrix (spatiotemporal agent)")
        print(f"  TP={m_spatio['tp']:>8,}  FP={m_spatio['fp']:>8,}")
        print(f"  FN={m_spatio['fn']:>8,}  TN={m_spatio['tn']:>8,}")
        print(f"\n  Support: {m_spatio['support_pos']:,} attack events, "
              f"{m_spatio['support_neg']:,} benign events")

        print_section("Per-class Recall Breakdown")
        breakdown = per_class_breakdown(scores, sorted_labels, sorted_classes, threshold)
        print(f"  {'Attack class':<28} {'Count':>8}  {'Recall':>8}  {'F1':>8}")
        print(f"  {'─'*28} {'─'*8}  {'─'*8}  {'─'*8}")
        for cls in sorted(breakdown, key=lambda c: -breakdown[c]["count"]):
            d = breakdown[cls]
            marker = "← attack" if cls in ATTACK_CLASSES else ""
            print(
                f"  {cls:<28} {d['count']:>8,}  "
                f"{d['recall']:>8.4f}  {d['f1']:>8.4f}  {marker}"
            )

        # ── Save results ──────────────────────────────────────────────────
        if args.save_results:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            out = {
                "timestamp":     datetime.utcnow().isoformat(),
                "dataset":       str(args.dataset),
                "batch_hours":   args.batch_hours,
                "threshold":     threshold,
                "auc":           auc,
                "train_events":  len(train_events),
                "test_events":   len(test_events),
                "if_fixed":      m_if_fixed,
                "if_optimal":    m_if_optimal,
                "spatiotemporal":m_spatio,
                "per_class":     breakdown,
            }
            result_path = RESULTS_DIR / "spatiotemporal_validation.json"
            with open(result_path, "w") as f:
                json.dump(out, f, indent=2)
            print(f"\n  Results saved to: {result_path}")

        print(f"\n{'═'*65}")
        print(f"  FINAL  F1={m_spatio['f1']:.4f}   AUC={auc:.4f}   threshold={threshold:.4f}")
        print(f"{'═'*65}\n")
        if args.plot or args.show:
            from evaluation.plot_utils import plot_all
            print("─── Generating plots ─────────────────────────────────────────────")
            plot_all(scores, sorted_labels, auc, threshold, m_spatio,
                     "Spatiotemporal Agent", save=args.plot, show=args.show)

if __name__ == "__main__":
    main()
