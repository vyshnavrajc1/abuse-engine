"""
APISentry Evaluation Module

Computes detection metrics against ground-truth labels:
  - Overall: Precision, Recall, F1, Accuracy
  - Per threat-type breakdown
  - Confusion matrix
  - Ablation study helpers (compare agent subsets)
"""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from schemas.models import FusionVerdict, ThreatType


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    precision: float
    recall: float
    f1: float
    accuracy: float
    total_samples: int
    true_attacks: int
    detected_attacks: int
    false_positives: int
    false_negatives: int
    per_threat: Dict[str, Dict[str, float]] = field(default_factory=dict)
    confusion: Optional[np.ndarray] = None

    def summary(self) -> str:
        # Derive FP rate and specificity for richer reporting
        tn = self.total_samples - self.true_attacks - self.false_positives - self.false_negatives
        fp_rate = self.false_positives / max(1, self.total_samples - self.true_attacks)
        lines = [
            "=" * 60,
            "  APISentry Detection Evaluation",
            "=" * 60,
            f"  Evaluation units  : {self.total_samples} batches",
            f"  True Attack batches: {self.true_attacks}",
            f"  True Benign batches: {self.total_samples - self.true_attacks}",
            "-" * 60,
            f"  Detected attacks  : {self.detected_attacks}",
            f"  True Positives    : {self.detected_attacks - self.false_positives}",
            f"  False Positives   : {self.false_positives}  (FPR={fp_rate:.2%})",
            f"  False Negatives   : {self.false_negatives}",
            "-" * 60,
            f"  Precision         : {self.precision:.4f}",
            f"  Recall            : {self.recall:.4f}",
            f"  F1 Score          : {self.f1:.4f}",
            f"  Accuracy          : {self.accuracy:.4f}",
        ]
        if self.per_threat:
            lines.append("-" * 60)
            lines.append("  Per-Threat Breakdown (majority-label basis):")
            for threat, metrics in self.per_threat.items():
                lines.append(
                    f"    {threat:<26} P={metrics['precision']:.3f} "
                    f"R={metrics['recall']:.3f} F1={metrics['f1']:.3f} "
                    f"(n={metrics['support']})"
                )
        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class Evaluator:
    """
    Collects (verdict, ground_truth) pairs and computes metrics.

    Supports two evaluation modes:

    1. add_batch() — Majority-label mode (recommended for batch-level systems):
       Computes the majority ground-truth label for the batch and uses that
       single label for one prediction. This is semantically correct for a
       system that produces one verdict per batch.

    2. add() — Per-record mode (legacy):
       Assigns the batch-level verdict to every record individually. Causes
       inflation of FP/FN on mixed batches.
    """

    def __init__(self):
        self._y_true: List[int] = []           # 1=attack, 0=benign
        self._y_pred: List[int] = []           # 1=attack, 0=benign
        self._y_true_threat: List[str] = []    # ground-truth category
        self._y_pred_threat: List[str] = []    # predicted threat type

    def add_batch(
        self,
        verdict: FusionVerdict,
        batch_records,
        attack_threshold: float = 0.5,
    ) -> None:
        """
        Majority-label batch evaluation.

        The ground truth for the batch is determined by whether >\'attack_threshold\'%
        of its records are attacks. The verdict is compared against this single
        majority label — one data point per batch added.

        Args:
            verdict:          The FusionVerdict produced by the orchestrator.
            batch_records:    The List[LogRecord] for this batch.
            attack_threshold: Fraction of attack records required to call batch an attack.
                              Default 0.5 means >50% attack records → batch is attack.
        """
        if not batch_records:
            return
        attack_count = sum(1 for r in batch_records if r.is_attack)
        attack_ratio = attack_count / len(batch_records)
        majority_is_attack = attack_ratio > attack_threshold

        # Dominant ground-truth threat in this batch
        categories = [r.attack_category for r in batch_records]
        from collections import Counter
        majority_category = Counter(categories).most_common(1)[0][0]

        self._y_true.append(int(majority_is_attack))
        self._y_pred.append(int(verdict.is_attack))
        self._y_true_threat.append(majority_category)
        self._y_pred_threat.append(
            verdict.threat_type.value if verdict.is_attack else "Benign"
        )

    def add(
        self,
        verdict: FusionVerdict,
        ground_truth_is_attack: bool,
        ground_truth_category: str = "Benign",
    ) -> None:
        """Legacy per-record evaluation. Prefer add_batch() for batch-level systems."""
        self._y_true.append(int(ground_truth_is_attack))
        self._y_pred.append(int(verdict.is_attack))
        self._y_true_threat.append(ground_truth_category)
        self._y_pred_threat.append(
            verdict.threat_type.value if verdict.is_attack else "Benign"
        )

    def compute(self) -> EvalResult:
        y_true = np.array(self._y_true)
        y_pred = np.array(self._y_pred)

        if len(y_true) == 0:
            raise ValueError("No samples recorded. Call add() before compute().")

        precision = precision_score(y_true, y_pred, zero_division=0)
        recall    = recall_score(y_true, y_pred, zero_division=0)
        f1        = f1_score(y_true, y_pred, zero_division=0)
        accuracy  = float((y_true == y_pred).mean())

        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())

        cm = confusion_matrix(y_true, y_pred)

        # Per-threat breakdown
        per_threat = self._per_threat_metrics()

        return EvalResult(
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            accuracy=round(accuracy, 4),
            total_samples=len(y_true),
            true_attacks=int(y_true.sum()),
            detected_attacks=int(y_pred.sum()),
            false_positives=fp,
            false_negatives=fn,
            per_threat=per_threat,
            confusion=cm,
        )

    def _per_threat_metrics(self) -> Dict[str, Dict[str, float]]:
        """Per ground-truth threat-type precision/recall/F1."""
        from collections import defaultdict
        categories = set(self._y_true_threat)
        out = {}
        for cat in sorted(categories):
            y_t = np.array([1 if c == cat else 0 for c in self._y_true_threat])
            y_p = np.array([1 if c == cat else 0 for c in self._y_pred_threat])
            out[cat] = {
                "precision": round(precision_score(y_t, y_p, zero_division=0), 4),
                "recall":    round(recall_score(y_t, y_p, zero_division=0), 4),
                "f1":        round(f1_score(y_t, y_p, zero_division=0), 4),
                "support":   int(y_t.sum()),
            }
        return out

    def reset(self) -> None:
        self.__init__()


# ---------------------------------------------------------------------------
# Ablation helper
# ---------------------------------------------------------------------------

def run_ablation(
    pipeline_factory,   # callable(agent_names: List[str]) -> pipeline
    records,
    all_agents: List[str],
) -> pd.DataFrame:
    """
    Run all 2^N - 1 non-empty subsets of agents.
    Returns a DataFrame comparing F1 / Precision / Recall per subset.
    """
    from itertools import combinations
    rows = []
    for r in range(1, len(all_agents) + 1):
        for subset in combinations(all_agents, r):
            pipeline = pipeline_factory(list(subset))
            ev = Evaluator()
            for batch in records:
                verdict = pipeline.run(batch)
                for rec in batch:
                    ev.add(verdict, rec.is_attack, rec.attack_category)
            result = ev.compute()
            rows.append({
                "agents": "+".join(subset),
                "n_agents": len(subset),
                "precision": result.precision,
                "recall": result.recall,
                "f1": result.f1,
                "accuracy": result.accuracy,
            })
    return pd.DataFrame(rows).sort_values("f1", ascending=False)
