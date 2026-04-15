# Real-Time Flow-Based DDoS Detector (LightGBM)

Captures packets, builds bidirectional 5-tuple flows, computes CIC-IDS style features, and runs real-time inference with a trained LightGBM model.

---

## Project Layout

```
ddos_detector/
├── main.py               CLI entry point
├── capture.py            Live and offline packet capture (scapy)
├── flow_builder.py       Flow state + CIC-style feature extraction
├── detector.py           LightGBM artifact loading and inference
├── alerts.py             Rich terminal alerts + CSV flow logging
├── export_model.py       Export artifacts from a training notebook
├── train_from_parquet.py Train from CIC-IDS parquet via KaggleHub
├── model/                Place lgbm_binary_model.pkl, lgbm_multiclass_model.pkl,
│                         features.json, label_encoder.pkl here
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── requirements.txt
```

---

## Platform Prerequisites

| Platform | Requirement |
|---|---|
| Linux | `libpcap-dev`, run live capture with `sudo` |
| macOS | Xcode CLI tools (`xcode-select --install`), live capture needs `sudo` |
| Windows | Python 3.9+, [Npcap](https://npcap.com) (WinPcap-compat mode), run terminal as Administrator for live capture |
| Docker | Docker Desktop (Windows/macOS) or Docker Engine (Linux) |

---

## Quick Start (Local)

### Linux / macOS

```bash
cd ddos_detector
make install          # creates .venv and installs deps
make smoke            # offline test with bundled pcap
make interfaces       # list capture interfaces
make live IFACE=eth0  # live capture (prepend sudo on Linux/macOS)
```

### Windows (PowerShell or CMD)

```powershell
cd ddos_detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Offline smoke test
python main.py --pcap windows_smoke_test.pcap --mode binary --threshold 0.5 --log-file flows_log_smoke.csv

# List interfaces
python main.py --list-interfaces

# Live capture (run terminal as Administrator)
python main.py --interface "\Device\NPF_{GUID}" --mode binary --threshold 0.5
```

### Windows (Git Bash / WSL)

```bash
make install
make smoke
make live IFACE="\Device\NPF_{GUID}"
```

---

## Docker

### Build

```bash
docker build -t ddos-detector:latest ddos_detector/
```

### Offline smoke test

```bash
docker compose -f ddos_detector/docker-compose.yml run --rm offline
```

Or with make:

```bash
make docker-offline
```

### Live capture (Linux host only)

Live capture in Docker requires host networking and `NET_RAW` capability. This works on Linux. On macOS/Windows, Docker Desktop runs inside a VM and cannot see host interfaces — use the local install instead.

```bash
docker compose -f ddos_detector/docker-compose.yml run --rm live --interface eth0 --mode binary
```

Or:

```bash
make docker-live IFACE=eth0 MODE=binary
```

### Training

```bash
docker compose -f ddos_detector/docker-compose.yml run --rm train
```

Model artifacts are written to `./model/` on the host via the volume mount.

---

## CLI Reference

```
python main.py [OPTIONS]

  --interface           Interface name for live capture
  --mode                binary | multiclass  (default: binary)
  --threshold           Confidence threshold (default: 0.5)
  --model-path          Override model .pkl path
  --features-path       Path to features.json (default: model/features.json)
  --label-encoder-path  Path to label_encoder.pkl (multiclass)
  --log-file            CSV output path (default: flows_log.csv)
  --flow-timeout        Inactivity timeout in seconds (default: 5.0)
  --max-packets         Force-export flow at N packets (default: 10000)
  --pcap                Offline mode: path to .pcap/.pcapng
  --bpf                 BPF filter for live capture (default: "tcp or udp")
  --list-interfaces     Print interfaces and exit
```

---

## Exporting Artifacts From a Notebook

```python
from export_model import export_from_objects

# Binary
export_from_objects(model=lgb_binary, feature_names=feature_names, output_dir="model")

# Multiclass with label encoder
export_from_objects(model=lgb_multi, feature_names=feature_names,
                    output_dir="model", label_encoder=le)
```

Produces:
- `model/lgbm_model.pkl`
- `model/features.json`
- `model/label_encoder.pkl` (if provided)

---

## Logging and Alerts

- Every exported flow (benign and attack) is appended to the CSV log.
- Attack flows render a rich panel in the terminal.
- More than 1000 flows/minute triggers a `HIGH TRAFFIC WARNING`.

---

## Notes

- Feature names in `features.json` must exactly match those used during training.
- Missing features at inference time are filled with `0.0`.
- Live capture on Linux/macOS requires root. On Windows, run the terminal as Administrator.
- Docker live capture only works on Linux hosts (host network mode).
