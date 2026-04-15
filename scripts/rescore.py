#!/usr/bin/env python3
"""
rescore.py — Re-evaluate an existing results JSON under the secondary ≥5% threshold.

The primary run stores ground_truth_attack_ratio for every batch verdict.
This script reads that JSON and recomputes metrics under both evaluation modes
without re-running the full pipeline.

Usage:
    python scripts/rescore.py results/full_2.8M_phase4.json
    python scripts/rescore.py results/full_2.8M_phase5.json --threshold 0.05
"""

from __future__ import annotations
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Metric helpers (no sklearn dependency)
# ---------------------------------------------------------------------------

def _prf(y_true, y_pred):
    tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 0)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1, tp, fp, fn


def _per_threat(y_true_threat, y_pred_threat):
    cats = sorted(set(y_true_threat))
    out = {}
    for cat in cats:
        y_t = [1 if c == cat else 0 for c in y_true_threat]
        y_p = [1 if c == cat else 0 for c in y_pred_threat]
        p, r, f, tp, fp, fn = _prf(y_t, y_p)
        out[cat] = {"precision": round(p, 3), "recall": round(r, 3),
                    "f1": round(f, 3), "support": sum(y_t)}
    return out


# ---------------------------------------------------------------------------
# Threat label normalisation (mirrors evaluator._THREAT_LABEL_MAP)
# ---------------------------------------------------------------------------
_THREAT_LABEL_MAP = {
    "DOS":                "DoS",
    "DDOS":               "DDoS",
    "PORT_SCAN":          "Port Scan",
    "BRUTE_FORCE":        "Brute Force",
    "CREDENTIAL_STUFFING":"Brute Force",
    "BOT_ACTIVITY":       "Botnet",
    "SCRAPING":           "DoS",
    "UNKNOWN_ABUSE":      "Other",
    "NONE":               "Benign",
}

def _norm(label: str) -> str:
    return _THREAT_LABEL_MAP.get(label, label)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def rescore(results_path: str, threshold: float = 0.05) -> None:
    path = Path(results_path)
    if not path.exists():
        print(f"ERROR: file not found — {results_path}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        data = json.load(f)

    verdicts = data.get("verdicts", [])
    if not verdicts:
        print("ERROR: no verdicts found in results file.", file=sys.stderr)
        sys.exit(1)

    # ── Reconstruct arrays ────────────────────────────────────────────────
    # Primary (majority >50%)
    y_true_50   = [1 if v["majority_label"] == "ATTACK" else 0 for v in verdicts]
    y_pred      = [1 if v["is_attack"] else 0 for v in verdicts]
    y_pred_threat = [_norm(v["threat_type"]) if v["is_attack"] else "Benign" for v in verdicts]

    # Ground-truth threat is the majority category from ground_truth_categories
    # We use the first entry that is not empty; fall back to "Benign"
    def _gt_threat(v):
        cats = v.get("ground_truth_categories", ["Benign"])
        # Filter out Benign if there are attacks, to get the actual threat label
        attack_cats = [c for c in cats if c != "Benign"]
        return attack_cats[0] if attack_cats and v["majority_label"] == "ATTACK" else "Benign"

    y_true_threat_50 = [_gt_threat(v) for v in verdicts]

    # Secondary (≥ threshold %)
    y_true_5 = [
        1 if v.get("ground_truth_attack_ratio", 0.0) >= threshold else 0
        for v in verdicts
    ]

    def _gt_threat_5(v):
        if v.get("ground_truth_attack_ratio", 0.0) >= threshold:
            cats = v.get("ground_truth_categories", ["Benign"])
            attack_cats = [c for c in cats if c != "Benign"]
            return attack_cats[0] if attack_cats else "Benign"
        return "Benign"

    y_true_threat_5 = [_gt_threat_5(v) for v in verdicts]

    # Per-agent accuracy
    agent_stats: dict = defaultdict(lambda: {"tp": 0, "fp": 0})
    for v, gt in zip(verdicts, y_true_50):
        if v["is_attack"]:
            for agent in v.get("contributing_agents", []):
                if gt == 1:
                    agent_stats[agent]["tp"] += 1
                else:
                    agent_stats[agent]["fp"] += 1

    # ── Compute metrics ───────────────────────────────────────────────────
    p50, r50, f50, tp50, fp50, fn50 = _prf(y_true_50, y_pred)
    p5,  r5,  f5,  tp5,  fp5,  fn5  = _prf(y_true_5,  y_pred)
    acc50 = sum(a == b for a, b in zip(y_true_50, y_pred)) / len(y_pred)

    per50 = _per_threat(y_true_threat_50, y_pred_threat)
    per5  = _per_threat(y_true_threat_5,  y_pred_threat)

    n = len(verdicts)
    fpr50 = fp50 / max(1, n - sum(y_true_50))

    # ── Print ─────────────────────────────────────────────────────────────
    print("=" * 64)
    print(f"  Rescore: {path.name}")
    print("=" * 64)
    print(f"  Batches evaluated     : {n}")
    print()
    print(f"  PRIMARY (majority >50%):")
    print(f"    Attack batches      : {sum(y_true_50)}")
    print(f"    TP={tp50}  FP={fp50}  FN={fn50}")
    print(f"    Precision={p50:.4f}  Recall={r50:.4f}  F1={f50:.4f}  Acc={acc50:.4f}")
    print(f"    FPR={fpr50:.2%}")
    print()
    print(f"  SECONDARY (\u2265{threshold*100:.0f}% attack records):")
    print(f"    Attack batches      : {sum(y_true_5)}")
    print(f"    TP={tp5}  FP={fp5}  FN={fn5}")
    print(f"    Precision={p5:.4f}  Recall={r5:.4f}  F1={f5:.4f}")
    print()

    print("  Per-Threat (PRIMARY >50%):")
    for cat, m in per50.items():
        print(f"    {cat:<26} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} (n={m['support']})")
    print()

    print(f"  Per-Threat (SECONDARY \u2265{threshold*100:.0f}%):")
    for cat, m in per5.items():
        print(f"    {cat:<26} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} (n={m['support']})")
    print()

    print("  Agent Contribution Accuracy:")
    for agent, stats in sorted(agent_stats.items(), key=lambda x: -x[1]["tp"]):
        tp = stats["tp"]; fp = stats["fp"]
        total = tp + fp
        prec = tp / total if total > 0 else 0.0
        print(f"    {agent:<20} TP={tp:<5} FP={fp:<5} precision={prec:.3f}")

    print("=" * 64)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rescore results JSON under ≥5% threshold")
    parser.add_argument("results", help="Path to results JSON file")
    parser.add_argument("--threshold", type=float, default=0.05,
                        help="Secondary eval threshold (default: 0.05 = 5%%)")
    args = parser.parse_args()
    rescore(args.results, args.threshold)
