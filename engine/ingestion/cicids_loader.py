"""
engine/ingestion/cicids_loader.py – Shared CICIDS2017 dataset loader.

Used by all evaluation/validate_*.py scripts to avoid duplicating
the streaming logic.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from schemas.event_schema import CanonicalEvent

DEFAULT_PATH = Path("datasets/cicids_canonical.jsonl")


def load_cicids(
    path: Path = DEFAULT_PATH,
    max_train: Optional[int] = None,
    max_test:  Optional[int] = None,
) -> Tuple[List[CanonicalEvent], List[CanonicalEvent], List[bool], List[str]]:
    """
    Stream cicids_canonical.jsonl and return four parallel lists.

    Returns
    -------
    train_events  : CanonicalEvent list for IsolationForest baseline training
                    (Monday BENIGN events, split="train")
    test_events   : CanonicalEvent list for evaluation (split="test")
    test_labels   : bool per test event — True = is_attack
    test_classes  : str per test event — raw attack_class label

    Parameters
    ----------
    max_train / max_test : optional caps (useful for quick smoke tests)
    """
    train_events: List[CanonicalEvent] = []
    test_events:  List[CanonicalEvent] = []
    test_labels:  List[bool]           = []
    test_classes: List[str]            = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = CanonicalEvent(
                timestamp    = datetime.fromisoformat(rec["timestamp"]),
                source_ip    = rec["source_ip"],
                user_id      = rec.get("user_id"),
                request_path = rec["request_path"],
                http_method  = rec["http_method"],
                response_code= rec.get("response_code"),
                bytes_sent   = rec.get("bytes_sent"),
            )

            if rec.get("split") == "train":
                if max_train is None or len(train_events) < max_train:
                    train_events.append(event)
            else:
                if max_test is None or len(test_events) < max_test:
                    test_events.append(event)
                    test_labels.append(bool(rec.get("is_attack", False)))
                    test_classes.append(rec.get("attack_class", "unknown"))

    return train_events, test_events, test_labels, test_classes
