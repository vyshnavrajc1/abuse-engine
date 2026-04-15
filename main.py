"""
Abuse Engine Main Runner

Entry point for Phase 1: Volume + Temporal + Auth agents on CICIDS 2017.

Usage:
    python main.py \
        --data datasets/processed/ \
        --window 500 \
        --max-records 50000 \
        --output results/phase1.json \
        --warmup-batches 10

The pipeline:
  1. Ingest CICIDS 2017 processed CSV(s) in sliding windows.
  2. For each window → MetaAgentOrchestrator.run(batch).
  3. Collect FusionVerdicts and evaluate against ground truth.
     Evaluation is BATCH-LEVEL (majority label per batch), not per-record.
  4. Save metrics to results/.
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# ── path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from engine.coordinator.meta_agent import MetaAgentOrchestrator
from engine.ingestion.cicids_ingestion import CICIDSIngestion
from engine.memory.shared_memory import SharedMemory
from evaluation.evaluator import Evaluator
from schemas.models import FusionVerdict


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("abuse_engine.main")


def run(
    data_path: str,
    window_size: int = 500,
    max_records: int = 0,
    output_path: str = "results/phase1.json",
    verbose: bool = False,
    warmup_batches: int = 10,
    llm_url: str = "",
    llm_model: str = "qwen2.5:7b",
    attack_threshold: float = 0.05,
) -> None:

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("  Abuse Engine — CICIDS 2017")
    logger.info("  Agents: Volume | Temporal | Auth | MetaOrchestrator")
    logger.info("  Evaluation: batch-level majority-label")
    logger.info("  Warm-up batches (learn only): %d", warmup_batches)
    logger.info("=" * 60)

    # ── Setup ────────────────────────────────────────────────────────────────
    memory = SharedMemory(window_seconds=60)

    llm_client = None
    if llm_url:
        from engine.llm.client import LLMClient
        llm_client = LLMClient(base_url=llm_url, model=llm_model)
        logger.info("LLM enabled: model=%s endpoint=%s", llm_model, llm_url)
        if not llm_client.is_available():
            logger.warning("LLM endpoint unreachable — falling back to rule-based")
            llm_client = None

    orchestrator = MetaAgentOrchestrator(memory, llm_client=llm_client)
    ingestion = CICIDSIngestion(data_path, window_size=window_size, max_records=max_records)
    evaluator = Evaluator()

    verdicts_log = []
    batch_num = 0

    # ── Main loop ────────────────────────────────────────────────────────────
    for batch in ingestion.batches():
        batch_num += 1
        logger.info("Batch %d | %d records", batch_num, len(batch))

        verdict: FusionVerdict = orchestrator.run(batch)

        # ── Evaluate using majority-label (skip warm-up batches) ─────────────
        # Warm-up batches are still processed (agents build baselines) but
        # they are not scored, since thresholds aren't yet calibrated.
        in_warmup = batch_num <= warmup_batches
        if not in_warmup:
            evaluator.add_batch(verdict, batch, attack_threshold=attack_threshold, batch_num=batch_num)

        # ── Logging ──────────────────────────────────────────────────────────
        attack_count = sum(1 for r in batch if r.is_attack)
        attack_ratio = attack_count / len(batch)
        gt_label = "ATTACK" if attack_ratio > attack_threshold else "BENIGN"
        pred_label = "ATTACK" if verdict.is_attack else "CLEAN"
        correct = (gt_label == "ATTACK") == verdict.is_attack

        status_icon = "✓" if correct else "✗"
        warmup_tag = " [WARMUP]" if in_warmup else ""

        if verdict.is_attack or verbose or not correct:
            logger.info(
                "  %s %s → %s | gt=%s(%d%%) | %s | conf=%.2f%s",
                status_icon,
                pred_label,
                verdict.threat_type.value,
                gt_label,
                int(attack_ratio * 100),
                verdict.compound_signals[0] if verdict.compound_signals else "—",
                verdict.confidence_score,
                warmup_tag,
            )
            if verbose:
                logger.debug(verdict.explanation)

        if not in_warmup:
            verdicts_log.append({
                "batch": batch_num,
                "is_attack": verdict.is_attack,
                "threat_type": verdict.threat_type.value,
                "confidence": verdict.confidence_score,
                "contributing_agents": verdict.contributing_agents,
                "compound_signals": verdict.compound_signals,
                "explanation": verdict.explanation,
                "ground_truth_categories": list({r.attack_category for r in batch}),
                "ground_truth_attack_ratio": round(attack_ratio, 3),
                "majority_label": gt_label,
                "correct": correct,
            })

    # ── Evaluation ───────────────────────────────────────────────────────────
    if evaluator._y_true:
        result = evaluator.compute()
        print("\n" + result.summary())

        # Save results
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_timestamp": datetime.utcnow().isoformat(),
            "config": {
                "data_path": str(data_path),
                "window_size": window_size,
                "max_records": max_records,
                "warmup_batches": warmup_batches,
                "attack_threshold": attack_threshold,
                "evaluation_mode": "batch_5pct_threshold",
                "llm_model": llm_model if llm_url else None,
            },
            "metrics": {
                "precision":         result.precision,
                "recall":            result.recall,
                "f1":                result.f1,
                "accuracy":          result.accuracy,
                "total_batches":     result.total_samples,
                "attack_batches":    result.true_attacks,
                "detected_attacks":  result.detected_attacks,
                "false_positives":   result.false_positives,
                "false_negatives":   result.false_negatives,
            },
            "metrics_5pct": {
                "precision":      result.precision_5pct,
                "recall":         result.recall_5pct,
                "f1":             result.f1_5pct,
                "attack_batches": result.true_attacks_5pct,
            },
            "per_threat": result.per_threat,
            "per_threat_5pct": result.per_threat_5pct,
            "per_agent_accuracy": result.per_agent_accuracy,
            "verdicts": verdicts_log,
        }
        with open(output, "w") as f:
            json.dump(payload, f, indent=2)
        logger.info("Results saved → %s", output)

        # Save plots
        evaluator.save_plots(output.parent)
        logger.info("Plots saved → %s/", output.parent)
    else:
        logger.warning("No records evaluated. Check data path or --warmup-batches value.")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Abuse Engine Runner")
    parser.add_argument(
        "--data",
        default="datasets/processed/",
        help="Path to CICIDS 2017 processed CSV(s)",
    )
    parser.add_argument(
        "--window", type=int, default=500,
        help="Records per batch window (default: 500)",
    )
    parser.add_argument(
        "--max-records", type=int, default=0,
        help="Limit total records (0 = all)",
    )
    parser.add_argument(
        "--output",
        default="results/phase1.json",
        help="Output JSON for metrics",
    )
    parser.add_argument(
        "--warmup-batches", type=int, default=10,
        help="First N batches used only for baseline learning, not scored (default: 10)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging and print all verdicts",
    )
    parser.add_argument(
        "--llm-url",
        default="",
        help="OpenAI-compatible LLM endpoint (e.g. http://localhost:11434/v1). "
             "If omitted, rule-based engine runs without LLM.",
    )
    parser.add_argument(
        "--llm-model",
        default="qwen2.5:7b",
        help="Model name to request from the LLM endpoint (default: qwen2.5:7b)",
    )
    parser.add_argument(
        "--attack-threshold", type=float, default=0.05,
        help="Fraction of attack records required to label a batch as attack (default: 0.05). "
             "≥5%% threshold credits minority attacks in mixed-traffic windows.",
    )
    args = parser.parse_args()

    run(
        data_path=args.data,
        window_size=args.window,
        max_records=args.max_records,
        output_path=args.output,
        verbose=args.verbose,
        warmup_batches=args.warmup_batches,
        llm_url=args.llm_url,
        llm_model=args.llm_model,
        attack_threshold=args.attack_threshold,
    )


if __name__ == "__main__":
    main()
