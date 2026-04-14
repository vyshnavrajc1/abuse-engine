"""
Abuse Engine Evaluation Module

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
            "  Abuse Engine Detection Evaluation",
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
        self._y_prob: List[float] = []         # confidence scores (0-1)
        self._y_true_threat: List[str] = []    # ground-truth category
        self._y_pred_threat: List[str] = []    # predicted threat type
        self._batch_nums: List[int] = []       # batch sequence numbers
        self._contributing: List[List[str]] = []  # contributing agents per batch

    def add_batch(
        self,
        verdict: FusionVerdict,
        batch_records,
        attack_threshold: float = 0.5,
        batch_num: int = 0,
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
        self._y_prob.append(verdict.confidence_score)
        self._y_true_threat.append(majority_category)
        # Normalise predicted threat label to match ground-truth casing
        # (e.g. ThreatType.DOS.value = "DOS" but ground truth is "DoS")
        pred_label = verdict.threat_type.value if verdict.is_attack else "Benign"
        self._y_pred_threat.append(self._normalise_threat_label(pred_label))
        self._batch_nums.append(batch_num)
        self._contributing.append(verdict.contributing_agents or [])

    def add(
        self,
        verdict: FusionVerdict,
        ground_truth_is_attack: bool,
        ground_truth_category: str = "Benign",
    ) -> None:
        """Legacy per-record evaluation. Prefer add_batch() for batch-level systems."""
        self._y_true.append(int(ground_truth_is_attack))
        self._y_pred.append(int(verdict.is_attack))
        self._y_prob.append(verdict.confidence_score)
        self._y_true_threat.append(ground_truth_category)
        pred_label = verdict.threat_type.value if verdict.is_attack else "Benign"
        self._y_pred_threat.append(self._normalise_threat_label(pred_label))

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

    def save_plots(self, output_dir: str | Path) -> None:
        """
        Generate and save Confusion Matrix, ROC, and PR curves.
        """
        import matplotlib.pyplot as plt
        from pathlib import Path
        from sklearn.metrics import (
            ConfusionMatrixDisplay,
            RocCurveDisplay,
            PrecisionRecallDisplay,
        )

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        y_true = np.array(self._y_true)
        y_pred = np.array(self._y_pred)
        y_prob = np.array(self._y_prob)

        # 1. Confusion Matrix
        fig, ax = plt.subplots(figsize=(8, 6))
        ConfusionMatrixDisplay.from_predictions(
            y_true, y_pred,
            display_labels=["Benign", "Attack"],
            cmap=plt.cm.Blues,
            ax=ax
        )
        ax.set_title("Confusion Matrix")
        plt.tight_layout()
        plt.savefig(output_path / "confusion_matrix.png", dpi=150)
        plt.close()

        # 2. ROC Curve
        if len(np.unique(y_true)) > 1:
            fig, ax = plt.subplots(figsize=(8, 6))
            RocCurveDisplay.from_predictions(y_true, y_prob, ax=ax)
            ax.set_title("ROC Curve")
            plt.grid(True, linestyle="--", alpha=0.6)
            plt.tight_layout()
            plt.savefig(output_path / "roc_curve.png", dpi=150)
            plt.close()

        # 3. Precision-Recall Curve
        if len(np.unique(y_true)) > 1:
            fig, ax = plt.subplots(figsize=(8, 6))
            PrecisionRecallDisplay.from_predictions(y_true, y_prob, ax=ax)
            ax.set_title("Precision-Recall Curve")
            plt.grid(True, linestyle="--", alpha=0.6)
            plt.tight_layout()
            plt.savefig(output_path / "precision_recall_curve.png", dpi=150)
            plt.close()

        # 4. Per-Threat F1 Score (Bar Chart)
        metrics = self._per_threat_metrics()
        if metrics:
            fig, ax = plt.subplots(figsize=(10, 6))
            threats = list(metrics.keys())
            f1_scores = [m["f1"] for m in metrics.values()]

            bars = ax.bar(threats, f1_scores, color='skyblue')
            ax.set_title("F1 Score by Threat Category")
            ax.set_ylabel("F1 Score")
            ax.set_ylim(0, 1.1)
            plt.xticks(rotation=45, ha='right')

            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                        f'{height:.2f}', ha='center', va='bottom')

            plt.tight_layout()
            plt.savefig(output_path / "per_threat_f1.png", dpi=150)
            plt.close()

        # 5. Detection Timeline
        if self._batch_nums:
            from matplotlib.patches import Patch
            y_true = np.array(self._y_true)
            y_pred = np.array(self._y_pred)
            batch_nums = np.array(self._batch_nums)

            colors = []
            for gt, pred in zip(y_true, y_pred):
                if   gt == 1 and pred == 1: colors.append('#2ecc71')  # TP green
                elif gt == 0 and pred == 0: colors.append('#dfe6e9')  # TN light grey
                elif gt == 0 and pred == 1: colors.append('#e67e22')  # FP orange
                else:                       colors.append('#e74c3c')  # FN red

            fig, ax = plt.subplots(figsize=(18, 2.5))
            ax.bar(batch_nums, [1] * len(batch_nums), color=colors, width=1.0, linewidth=0)
            ax.set_xlim(batch_nums[0] - 1, batch_nums[-1] + 1)
            ax.set_ylim(0, 1)
            ax.set_xlabel("Batch Number")
            ax.set_yticks([])
            ax.set_title("Detection Timeline")
            ax.legend(
                handles=[
                    Patch(facecolor='#2ecc71', label='TP'),
                    Patch(facecolor='#e67e22', label='FP'),
                    Patch(facecolor='#e74c3c', label='FN'),
                    Patch(facecolor='#dfe6e9', label='TN', edgecolor='#b2bec3'),
                ],
                loc='upper right', ncol=4,
            )
            plt.tight_layout()
            plt.savefig(output_path / "detection_timeline.png", dpi=150)
            plt.close()

        # 6. Agent Contribution (attack verdicts only)
        if self._contributing:
            from collections import Counter
            agent_counts = Counter(
                agent
                for agents, pred in zip(self._contributing, self._y_pred)
                if pred == 1
                for agent in agents
            )
            if agent_counts:
                fig, ax = plt.subplots(figsize=(9, 5))
                names, counts = zip(*sorted(agent_counts.items(), key=lambda x: -x[1]))
                ax.bar(names, counts, color='steelblue')
                ax.set_title("Agent Contribution to Attack Verdicts")
                ax.set_ylabel("Batches flagged")
                plt.xticks(rotation=30, ha='right')
                for i, c in enumerate(counts):
                    ax.text(i, c + 0.3, str(c), ha='center', va='bottom', fontsize=9)
                plt.tight_layout()
                plt.savefig(output_path / "agent_contribution.png", dpi=150)
                plt.close()

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
        self.__init__()  # resets all lists including _batch_nums and _contributing

    # Map ThreatType enum values → CICIDS ground-truth category names
    _THREAT_LABEL_MAP = {
        "DOS": "DoS",
        "PORT_SCAN": "Port Scan",
        "BRUTE_FORCE": "Brute Force",
        "CREDENTIAL_STUFFING": "Brute Force",   # CICIDS has no "credential stuffing" category
        "BOT_ACTIVITY": "Botnet",
        "SCRAPING": "DoS",                       # compound DoS+bot → still DoS in ground truth
        "UNKNOWN_ABUSE": "Other",
        "NONE": "Benign",
    }

    @classmethod
    def _normalise_threat_label(cls, label: str) -> str:
        """Map predicted ThreatType enum values to CICIDS ground-truth casing."""
        return cls._THREAT_LABEL_MAP.get(label, label)


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
