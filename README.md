# Abuse Engine — Quick Start & Semantic Handoff

Lightweight research pipeline for passive API-abuse detection. This repo implements a behavioral MVP and scaffolds semantic and spatiotemporal agents for later integration.

Repository layout (important files only)
```
.
├─ main.py
├─ README.md
├─ requirements.txt
├─ configs/
├─ datasets/           # generated locally, ignored by git
│  └─ mock_logs.json
├─ engine/
│  ├─ agents/
│  │  ├─ behavioral.py
│  │  ├─ semantic.py
│  │  └─ spatiotemporal.py
│  ├─ normalization/normalizer.py
│  ├─ pipeline/sessionizer.py
│  └─ coordinator/coordinator.py
├─ schemas/
│  ├─ event_schema.py
│  └─ agent_result.py
└─ scripts/
   └─ generate_synthetic_data.py
```

Prerequisites (Linux)
1. Clone repo and change directory:
```sh
cd */abuse-engine
```
2. Create & activate a virtual environment:
```sh
python3 -m venv venv
source venv/bin/activate
```
3. Install minimal dependencies:
```sh
pip install -r requirements.txt
```
(Use `pip freeze > requirements.txt` if you want to capture your venv later.)

Generate synthetic data
1. Create synthetic logs (used for development + handoff):
```sh
python scripts/generate_synthetic_data.py
```
2. This writes `datasets/mock_logs.json` locally. The file is in `.gitignore` so it will not be pushed.

Run the pipeline (behavioral MVP)
1. Ensure `datasets/mock_logs.json` exists (generated above).
2. Run the pipeline end-to-end:
```sh
python main.py
```
3. Output:
- Normalizer converts raw JSON → [`schemas.CanonicalEvent`](schemas/event_schema.py)  
- Sessionizer groups events → sessions  
- Behavioral agent (`engine.agents.behavioral.analyze`) scores sessions and prints `AgentResult` objects

Interpreting results
- Each printed `AgentResult` contains:
  - `risk_score` (0.0–1.0)
  - `flags` (explainable signals, e.g. `high_request_rate`, `sequential_id_access`, `model_anomaly`)
  - `metadata` (feature values used for scoring)
- Use thresholds in `configs/config.yaml` to classify low/medium/high risk.

Semantic handoff (for your teammate)
- Implement: [engine/agents/semantic.py](engine/agents/semantic.py) with function:
```py
def analyze(events: List[schemas.CanonicalEvent]) -> List[schemas.AgentResult]:
    ...
```
- Requirements:
  - Accept normalized `CanonicalEvent` objects (do not re-ingest raw logs).
  - Use an OpenAPI/Swagger spec or heuristic rules to detect contract misuse, endpoint enumeration, invalid parameter combinations, excessive single-object access, etc.
  - Return `AgentResult` objects with `agent="semantic"`.
- Integration:
  - Once semantic is available, call it from `main.py` with the canonical events list.
  - Coordinator will combine behavioral + semantic results (implement `engine/coordinator/coordinator.py`).

Validation & evaluation
- Use the known labels in the synthetic generator for quick validation.
- Add evaluation scripts under `evaluation/` to compute precision, recall, F1, ROC.
- To validate locally:
```sh
python evaluation/validate_behavioral.py
```
- For real validation, convert public datasets (e.g., HTTP CSIC 2010, CICIDS) into the `CanonicalEvent` format and run the same pipeline.

Testing
- Add unit tests to `tests/`:
  - feature extraction edge-cases
  - sessionizer behavior (time gap logic)
  - agent scoring on synthetic sessions
- Run tests:
```sh
pytest -q
```