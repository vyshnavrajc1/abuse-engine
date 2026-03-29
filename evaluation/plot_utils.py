"""
evaluation/plot_utils.py — Shared matplotlib helpers for all validate_*.py scripts.

Produces 3 figures per validation run:
  1. ROC curve (FPR vs TPR) with AUC annotation
  2. Precision / Recall / F1 vs threshold sweep
  3. Confusion matrix heatmap at optimal threshold

Optional 4th figure for validate_combined.py:
  4. Ablation bar chart (F1 per agent + combined)

All functions save to figures/ and optionally display interactively.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")          # non-interactive backend — safe on all machines
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

FIGURES_DIR = Path(__file__).resolve().parent.parent / "figures"

_PALETTE = {
    "primary":    "#2563EB",   # blue
    "danger":     "#DC2626",   # red
    "warning":    "#D97706",   # amber
    "success":    "#16A34A",   # green
    "muted":      "#9CA3AF",   # grey
    "background": "#F9FAFB",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _roc_points(scores: List[float], labels: List[bool], steps: int = 500
                ) -> Tuple[List[float], List[float]]:
    fprs, tprs = [], []
    for i in range(steps + 1):
        t = i / steps
        tp = fp = tn = fn = 0
        for s, l in zip(scores, labels):
            pred = s >= t
            if pred and l:      tp += 1
            elif pred:          fp += 1
            elif l:             fn += 1
            else:               tn += 1
        fprs.append(fp / (fp + tn) if (fp + tn) else 0.0)
        tprs.append(tp / (tp + fn) if (tp + fn) else 0.0)
    # sort by FPR for a clean curve
    pts = sorted(zip(fprs, tprs))
    return [p[0] for p in pts], [p[1] for p in pts]


def _prf_vs_threshold(scores: List[float], labels: List[bool], steps: int = 200
                      ) -> Tuple[List[float], List[float], List[float], List[float]]:
    thresholds, precisions, recalls, f1s = [], [], [], []
    for i in range(1, steps):
        t = i / steps
        tp = fp = tn = fn = 0
        for s, l in zip(scores, labels):
            pred = s >= t
            if pred and l:      tp += 1
            elif pred:          fp += 1
            elif l:             fn += 1
            else:               tn += 1
        p  = tp / (tp + fp) if (tp + fp) else 0.0
        r  = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        thresholds.append(t)
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)
    return thresholds, precisions, recalls, f1s


def _style_ax(ax, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_facecolor(_PALETTE["background"])
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def plot_roc(
    scores: List[float],
    labels: List[bool],
    auc: float,
    agent_name: str,
    optimal_threshold: float,
    save: bool = True,
    show: bool = False,
) -> Path:
    """ROC curve with AUC label and optimal-threshold operating point."""
    fprs, tprs = _roc_points(scores, labels)

    fig, ax = plt.subplots(figsize=(6, 6))
    ax.plot(fprs, tprs, color=_PALETTE["primary"], lw=2,
            label=f"ROC (AUC = {auc:.4f})")
    ax.plot([0, 1], [0, 1], color=_PALETTE["muted"], lw=1, linestyle="--",
            label="Random classifier")

    # Mark operating point at optimal threshold
    tp = fp = tn = fn = 0
    for s, l in zip(scores, labels):
        pred = s >= optimal_threshold
        if pred and l:      tp += 1
        elif pred:          fp += 1
        elif l:             fn += 1
        else:               tn += 1
    op_fpr = fp / (fp + tn) if (fp + tn) else 0.0
    op_tpr = tp / (tp + fn) if (tp + fn) else 0.0
    ax.scatter([op_fpr], [op_tpr], color=_PALETTE["danger"], zorder=5, s=80,
               label=f"Optimal t={optimal_threshold:.2f}  (TPR={op_tpr:.3f}, FPR={op_fpr:.3f})")

    _style_ax(ax, f"ROC Curve — {agent_name}", "False Positive Rate", "True Positive Rate")
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.01)
    ax.legend(fontsize=9)

    plt.tight_layout()
    out = _save_or_show(fig, f"roc_{agent_name.lower().replace(' ', '_')}.png", save, show)
    return out


def plot_prf_curve(
    scores: List[float],
    labels: List[bool],
    optimal_threshold: float,
    agent_name: str,
    save: bool = True,
    show: bool = False,
) -> Path:
    """Precision / Recall / F1 vs threshold sweep."""
    ts, ps, rs, f1s = _prf_vs_threshold(scores, labels)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(ts, ps,  color=_PALETTE["primary"],  lw=2, label="Precision")
    ax.plot(ts, rs,  color=_PALETTE["success"],  lw=2, label="Recall")
    ax.plot(ts, f1s, color=_PALETTE["danger"],   lw=2.5, label="F1")
    ax.axvline(optimal_threshold, color=_PALETTE["warning"], lw=1.5, linestyle="--",
               label=f"Optimal threshold = {optimal_threshold:.2f}")

    _style_ax(ax, f"Precision / Recall / F1 vs Threshold — {agent_name}",
              "Threshold", "Score")
    ax.set_xlim(0, 1)
    ax.set_ylim(-0.02, 1.05)
    ax.legend(fontsize=9)

    plt.tight_layout()
    out = _save_or_show(fig, f"prf_{agent_name.lower().replace(' ', '_')}.png", save, show)
    return out


def plot_confusion_matrix(
    tp: int, fp: int, fn: int, tn: int,
    agent_name: str,
    save: bool = True,
    show: bool = False,
) -> Path:
    """2×2 confusion matrix heatmap."""
    total = tp + fp + fn + tn or 1
    cm    = np.array([[tn, fp], [fn, tp]], dtype=float)
    cm_pct = cm / total * 100

    fig, ax = plt.subplots(figsize=(5, 4.5))
    im = ax.imshow(cm_pct, cmap="Blues", vmin=0, vmax=100)
    plt.colorbar(im, ax=ax, label="% of total")

    labels_text = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            count = int(cm[i, j])
            pct   = cm_pct[i, j]
            color = "white" if pct > 50 else "black"
            ax.text(j, i, f"{labels_text[i][j]}\n{count:,}\n({pct:.1f}%)",
                    ha="center", va="center", fontsize=11,
                    fontweight="bold", color=color)

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted\nBenign", "Predicted\nAttack"])
    ax.set_yticklabels(["Actual\nBenign", "Actual\nAttack"])
    ax.set_title(f"Confusion Matrix — {agent_name}", fontsize=12,
                 fontweight="bold", pad=10)

    plt.tight_layout()
    out = _save_or_show(fig, f"cm_{agent_name.lower().replace(' ', '_')}.png", save, show)
    return out


def plot_ablation(
    configs: List[Dict],    # [{"label": str, "f1": float, "auc": float}, ...]
    title: str = "Ablation Study — F1 Score by Configuration",
    save: bool = True,
    show: bool = False,
) -> Path:
    """
    Horizontal bar chart for ablation table.

    configs example:
        [
            {"label": "Behavioral alone",   "f1": 0.72, "auc": 0.81},
            {"label": "Semantic alone",     "f1": 0.55, "auc": 0.67},
            {"label": "Spatiotemporal",     "f1": 0.68, "auc": 0.79},
            {"label": "All three (coord.)", "f1": 0.88, "auc": 0.93},
        ]
    """
    labels = [c["label"] for c in configs]
    f1s    = [c["f1"]    for c in configs]
    aucs   = [c.get("auc", 0) for c in configs]

    x    = np.arange(len(labels))
    w    = 0.38
    fig, ax = plt.subplots(figsize=(9, max(4, len(labels) * 1.1)))

    bars_f1  = ax.barh(x + w/2, f1s,  w, label="F1",  color=_PALETTE["primary"],  alpha=0.85)
    bars_auc = ax.barh(x - w/2, aucs, w, label="AUC", color=_PALETTE["success"],  alpha=0.85)

    # Value annotations
    for bar, val in zip(bars_f1, f1s):
        if val > 0:
            ax.text(val + 0.005, bar.get_y() + bar.get_height()/2,
                    f"{val:.3f}", va="center", fontsize=9)
    for bar, val in zip(bars_auc, aucs):
        if val > 0:
            ax.text(val + 0.005, bar.get_y() + bar.get_height()/2,
                    f"{val:.3f}", va="center", fontsize=9)

    # Highlight the "all agents" row
    if len(configs) > 1:
        ax.axhspan(len(configs) - 1.5, len(configs) - 0.5,
                   alpha=0.08, color=_PALETTE["warning"])

    ax.set_yticks(x)
    ax.set_yticklabels(labels, fontsize=10)
    ax.set_xlim(0, 1.12)
    ax.set_xlabel("Score", fontsize=10)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
    ax.legend(fontsize=9)
    ax.set_facecolor(_PALETTE["background"])
    ax.grid(True, axis="x", linestyle="--", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    out = _save_or_show(fig, "ablation_study.png", save, show)
    return out


def plot_all(
    scores: List[float],
    labels: List[bool],
    auc: float,
    optimal_threshold: float,
    metrics: Dict,       # output of compute_metrics() at optimal threshold
    agent_name: str,
    save: bool = True,
    show: bool = False,
) -> List[Path]:
    """Convenience: produces ROC + PRF + CM in one call. Returns list of saved paths."""
    paths = []
    paths.append(plot_roc(scores, labels, auc, agent_name, optimal_threshold, save, show))
    paths.append(plot_prf_curve(scores, labels, optimal_threshold, agent_name, save, show))
    paths.append(plot_confusion_matrix(
        metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"],
        agent_name, save, show))
    return paths


# ---------------------------------------------------------------------------
# Internal save/show helper
# ---------------------------------------------------------------------------

def _save_or_show(fig, filename: str, save: bool, show: bool) -> Path:
    out = FIGURES_DIR / filename
    if save:
        FIGURES_DIR.mkdir(parents=True, exist_ok=True)
        fig.savefig(out, dpi=150, bbox_inches="tight")
        print(f"  Plot saved → {out}")
    if show:
        matplotlib.use("TkAgg")   # switch to interactive backend if displaying
        plt.show()
    plt.close(fig)
    return out
