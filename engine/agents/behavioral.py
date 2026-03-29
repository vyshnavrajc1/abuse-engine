import math
from typing import List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from schemas.agent_result import AgentResult, Severity
from engine.pipeline.sessionizer import Session


def extract_features(session: Session) -> dict:
    events = session.events
    count = len(events)

    if count < 2:
        return {
            "request_count": count,
            "avg_interval": 0,
            "std_interval": 0,
            "endpoint_entropy": 0,
            "error_rate": 0,
            "burstiness": count,
            "unique_endpoints": 1 if count else 0,
            "sequential_id_score": 0,
        }

    # timestamp is already a datetime — no fromisoformat needed
    times = [e.timestamp for e in events]
    intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    avg_interval = sum(intervals) / len(intervals)
    std_interval = (sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5

    endpoints = [e.request_path for e in events]
    freq = {}
    for ep in endpoints:
        freq[ep] = freq.get(ep, 0) + 1
    entropy = -sum((c / count) * math.log2(c / count) for c in freq.values())

    errors = sum(1 for e in events if (e.response_code or 0) >= 400)
    error_rate = errors / count

    burst = 0
    for i, t in enumerate(times):
        window_count = sum(1 for t2 in times if 0 <= (t2 - t).total_seconds() <= 5)
        burst = max(burst, window_count)

    # Sequential ID detection — now uses path_params (new schema field)
    ids = []
    for e in events:
        for val in e.path_params.values():
            if str(val).isdigit():
                ids.append(int(val))
    seq_score = 0.0
    if len(ids) >= 2:
        diffs = [ids[i + 1] - ids[i] for i in range(len(ids) - 1)]
        seq_score = sum(1 for d in diffs if d == 1) / len(diffs)

    return {
        "request_count": count,
        "avg_interval": avg_interval,
        "std_interval": std_interval,
        "endpoint_entropy": entropy,
        "error_rate": error_rate,
        "burstiness": burst,
        "unique_endpoints": len(freq),
        "sequential_id_score": seq_score,
    }


def features_to_vector(features: dict) -> list:
    return [
        features["request_count"],
        features["avg_interval"],
        features["std_interval"],
        features["endpoint_entropy"],
        features["error_rate"],
        features["burstiness"],
        features["unique_endpoints"],
        features["sequential_id_score"],
    ]


def train_model(
    sessions: List[Session],
    contamination: float = 0.05,
) -> IsolationForest:
    """
    Train a behavioral IsolationForest on baseline (benign) sessions.
    Pass the returned model to analyze() to avoid train/test contamination.

    Usage
    -----
        baseline_model = train_model(train_sessions)
        results = analyze(test_sessions, model=baseline_model)
    """
    if not sessions:
        raise ValueError("Need at least one session to train.")
    feature_matrix = np.array([features_to_vector(extract_features(s)) for s in sessions])
    model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
    model.fit(feature_matrix)
    return model


def analyze(
    sessions: List[Session],
    model: Optional[IsolationForest] = None,
) -> List[AgentResult]:
    """
    Score sessions with the behavioral agent.

    Parameters
    ----------
    sessions : List[Session]
        Sessions to score.
    model : IsolationForest, optional
        Pre-trained model from train_model(). When supplied the function
        scores only — no fitting occurs, eliminating train/test contamination.
        When None (default), a fresh model is trained on `sessions` and then
        scored — suitable for smoke tests but NOT for quantitative evaluation.
    """
    if not sessions:
        return []

    all_features = [extract_features(s) for s in sessions]
    feature_matrix = np.array([features_to_vector(f) for f in all_features])

    if model is None:
        # Unsupervised fallback: train and score on the same data.
        # Acceptable for quick runs; use train_model() for real evaluation.
        model = IsolationForest(contamination=0.3, random_state=42, n_estimators=100)
        model.fit(feature_matrix)

    raw_scores = model.decision_function(feature_matrix)
    predictions = model.predict(feature_matrix)

    min_score, max_score = raw_scores.min(), raw_scores.max()
    if max_score - min_score == 0:
        normalized = np.zeros_like(raw_scores)
    else:
        normalized = 1 - (raw_scores - min_score) / (max_score - min_score)

    results = []
    for i, session in enumerate(sessions):
        risk_score = round(float(normalized[i]), 2)
        is_anomaly = predictions[i] == -1
        features = all_features[i]

        flags = []
        if features["avg_interval"] < 1.0 and features["request_count"] > 10:
            flags.append("high_request_rate")
        if features["std_interval"] < 0.2 and features["request_count"] > 10:
            flags.append("consistent_timing")
        if features["sequential_id_score"] > 0.5:
            flags.append("sequential_id_access")
        if features["error_rate"] > 0.5:
            flags.append("high_error_rate")
        if features["burstiness"] > 20:
            flags.append("burst_detected")
        if is_anomaly:
            flags.append("model_anomaly")

        if risk_score >= 0.8:
            sev = Severity.HIGH
        elif risk_score >= 0.6:
            sev = Severity.MEDIUM
        elif risk_score >= 0.3:
            sev = Severity.LOW
        else:
            sev = Severity.INFO

        explanation = (
            f"Session {session.session_id}: risk={risk_score:.2f}. "
            + (f"Signals: {', '.join(flags)}." if flags else "No anomalous signals detected.")
        )

        results.append(AgentResult(
            agent="behavioral",
            risk_score=risk_score,
            severity=sev,
            flags=flags,
            explanation=explanation,
            metadata={
                **features,
                "is_anomaly": is_anomaly,
                "user_id": session.user_id,
            },
        ))

    return results