For LLM reading: This should contain the context of implementation done so far, so always update it with latest implementation changes.

current goal: start with Volume, Temporal, Auth, and the Orchestrator Meta-Agent on CICIDS 2017, then expand.


## Directory Structure

- `datasets/`: Includes raw CICIDS 2017 CSVs and a `processed/` directory for API-normalized logs.
- `engine/`: Core system logic with subdirectories for `agents/`, `coordinator/`, `ingestion/`, `normalization/`, and `pipeline/`.
- `evaluation/`: System validation and benchmarking (currently empty).
- `figures/`: Architecture diagrams and visualizations.
- `results/`: Detection metrics and experiment logs.
- `schemas/`: Data models and validation schemas.
- `scripts/`: Utility scripts, including `prepare_cicids_dataset.py`.
- main.py empty.


**Progress:**
- CICIDS 2017 dataset processed (2.8M records) with derived API‑like fields.
attack_category
Benign          2273097
DoS              380688
Port Scan        158930
Brute Force       15342
Botnet             1966
Web Attack          673
Infiltration         36
Heartbleed           11

Final Columns and How They Are Generated
timestamp
Parsed from original timestamp column
Converted to ISO format (YYYY-MM-DDTHH:MM:SSZ)
ip
Taken directly from source IP column
method (synthetic)
Set to constant value: "GET"
endpoint (synthetic)
Generated from destination port → "/port_<port>"
If missing → set to "/unknown"
status (synthetic)
Based on attack type:
Benign → 200
Brute Force → randomly 200 / 401 / 403
Others → 200
response_size (synthetic)
From total forward packets
If missing → set to 0
latency (synthetic)
From flow duration (µs → ms)
Clipped to max 10000
If missing → set to 0
user_agent (synthetic)
Set to empty string: ""
label
Original raw label from dataset
attack_category (derived)
Mapped from label (e.g., DoS, DDoS, Botnet, etc.)
is_attack (derived)
True if not Benign, else False





