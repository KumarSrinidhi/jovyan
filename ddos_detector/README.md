# Real-Time Flow-Based DDoS Detector (LightGBM)

This project captures packets, builds bidirectional 5-tuple flows, computes CIC-IDS style flow features, and performs real-time inference using a trained LightGBM model.

## Project Layout

- capture.py: Live and offline packet capture with scapy
- flow_builder.py: Flow state and CIC-style feature extraction
- detector.py: LightGBM artifact loading and inference
- alerts.py: Rich terminal alerts + CSV flow logging
- main.py: CLI entry point
- export_model.py: Export model artifacts from training outputs
- model/: Put lgbm_model.pkl, features.json, and optional label_encoder.pkl here

## Requirements

- Python 3.9+
- Linux: root/sudo for live packet capture
- Windows: Npcap installed (WinPcap compatibility mode recommended)

Python packages are listed in requirements.txt.

## Install

### Linux (Ubuntu/Debian)

1. Install system packages:

   sudo apt update
   sudo apt install -y python3 python3-pip libpcap-dev

2. Install Python dependencies:

   pip install -r requirements.txt

### Windows

1. Install Python 3.9+.
2. Install Npcap from https://npcap.com/.
3. Install dependencies in PowerShell or CMD:

   pip install -r requirements.txt

## Export Artifacts From Notebook

Use this in your training notebook after model training.

```python
from export_model import export_from_objects

# Example for binary model
export_from_objects(
    model=lgb_model,
    feature_names=feature_names,
    output_dir="model"
)

# Example for multiclass model with label encoder
export_from_objects(
    model=lgb_multi_model,
    feature_names=feature_names,
    output_dir="model",
    label_encoder=le
)
```

This creates:
- model/lgbm_model.pkl
- model/features.json
- model/label_encoder.pkl (if provided)

## Run Detector

### Live mode (Linux)

sudo python main.py --interface eth0 --mode binary --threshold 0.5

### Live mode (Windows)

python main.py --interface "Wi-Fi" --mode multiclass --threshold 0.6

### Offline mode with pcap

python main.py --pcap sample_traffic.pcap --mode multiclass --threshold 0.5

## Useful Flags

- --interface: Capture interface name for live mode
- --mode: binary or multiclass
- --threshold: confidence threshold (default 0.5)
- --pcap: offline pcap file mode
- --flow-timeout: inactivity timeout in seconds (default 5)
- --max-packets: force export when flow reaches N packets (default 10000)
- --log-file: path for flows CSV (default flows_log.csv)
- --list-interfaces: print interfaces and exit

## Logging and Alerts

- Every exported flow is written to CSV (benign and attack).
- Attack flows are shown in terminal with rich panel output.
- If exported flows exceed 1000/minute, the system prints HIGH TRAFFIC WARNING.

## Notes on Feature Consistency

- Inference order strictly follows model/features.json.
- Missing flow features are filled with 0.0.
- For best accuracy, ensure feature names and preprocessing exactly match training.

## Example

sudo python main.py --interface eth0 --mode binary --threshold 0.5
