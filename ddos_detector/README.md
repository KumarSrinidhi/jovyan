# DDoS Detector

A real-time, flow-based network intrusion detection system powered by LightGBM. Captures raw packets, reconstructs bidirectional TCP/UDP flows, extracts 57 CIC-IDS style features per flow, and classifies traffic as benign or an attack — all in real time.

Supports both **binary detection** (benign vs. attack) and **multi-class classification** (DDoS, DoS, Botnet, Bruteforce, Infiltration, Portscan, Webattack).

---

## Model Performance

Trained on the [CIC-IDS Collection](https://www.kaggle.com/datasets/dhoogla/cicidscollection) — a combined dataset of CIC-IDS2017, CIC-DoS2017, CSE-CIC-IDS2018, and CIC-DDoS2019 (9.1M flows).

| Task | AUC | F1 | Recall | Precision |
|---|---|---|---|---|
| Binary (Benign vs. Attack) | 0.997 | 0.972 | 0.958 | 0.987 |
| Multi-class (attack family) | — | 0.873 (weighted) | — | — |

---

## How It Works

```
Raw packets (live NIC or .pcap)
        │
        ▼
  capture.py          ← scapy sniff / rdpcap
        │
        ▼
  flow_builder.py     ← 5-tuple bidirectional flow aggregation
                         57 CIC-IDS features per completed flow
        │
        ▼
  detector.py         ← LightGBM inference (binary or multiclass)
        │
        ▼
  alerts.py           ← Rich terminal alert panel + CSV log
```

A flow is exported when it either times out (default: 5 s inactivity) or reaches the packet limit (default: 10 000 packets).

---

## Project Layout

```
ddos_detector/
├── main.py                  CLI entry point
├── capture.py               Live and offline packet capture (scapy)
├── flow_builder.py          Flow state machine + CIC-IDS feature extraction
├── detector.py              LightGBM model loading and inference
├── alerts.py                Rich terminal alerts + CSV flow logging
├── export_model.py          Export trained artifacts for use by the detector
├── train_from_parquet.py    Retrain from CIC-IDS parquet via KaggleHub
├── model/
│   ├── lgbm_binary_model.pkl
│   ├── lgbm_multiclass_model.pkl
│   ├── lgbm_model.pkl           (default: points to multiclass)
│   ├── features.json            (57 feature names, must match training)
│   └── label_encoder.pkl        (multiclass label decoder)
├── logs/                    Runtime CSV logs (git-ignored)
├── windows_smoke_test.pcap  Bundled pcap for offline testing
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── pyproject.toml
└── requirements.txt
```

---

## Prerequisites

| Platform | What you need |
|---|---|
| **Linux** | Python 3.9+, `libpcap-dev`, run live capture with `sudo` |
| **macOS** | Python 3.9+, Xcode CLI tools (`xcode-select --install`), run live capture with `sudo` |
| **Windows** | Python 3.9+, [Npcap](https://npcap.com) with WinPcap-compat mode, run terminal as Administrator for live capture |
| **Docker** | Docker Desktop (Windows/macOS) or Docker Engine (Linux) |

---

## Quick Start

### Linux / macOS

```bash
cd ddos_detector

make install                        # create .venv and install deps
make smoke                          # offline test with bundled pcap
make interfaces                     # list available capture interfaces
sudo make live IFACE=eth0           # live binary detection
sudo make live IFACE=eth0 MODE=multiclass  # live multiclass detection
```

### Windows (PowerShell — run as Administrator for live capture)

```powershell
cd ddos_detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Offline smoke test
python main.py --pcap windows_smoke_test.pcap --mode binary --threshold 0.5

# List interfaces (find your interface name)
python main.py --list-interfaces

# Live capture
python main.py --interface "\Device\NPF_{GUID}" --mode binary --threshold 0.5
```

See [RUN_WINDOWS.md](RUN_WINDOWS.md) for the full Windows guide.

### Windows (Git Bash / WSL)

```bash
make install
make smoke
make live IFACE="\Device\NPF_{GUID}"
```

---

## Docker

### Build the image

```bash
docker build -t ddos-detector:latest .
# or
make docker-build
```

### Offline smoke test (works everywhere)

```bash
docker compose run --rm offline
# or
make docker-offline
```

### Live capture (Linux hosts only)

Live capture in Docker requires `network_mode: host` and `NET_RAW` capability. This only works on Linux. On macOS and Windows, Docker Desktop runs inside a VM and cannot see host network interfaces — use the local install instead.

```bash
docker compose run --rm live --interface eth0 --mode binary
# or
make docker-live IFACE=eth0 MODE=binary
```

### Retrain models

```bash
docker compose run --rm train
```

Artifacts are written back to `./model/` on the host via the volume mount. Requires Kaggle credentials in the environment.

---

## CLI Reference

```
python main.py [OPTIONS]

Options:
  --interface TEXT        Network interface for live capture (e.g. eth0, Wi-Fi)
  --mode TEXT             Detection mode: binary or multiclass  [default: binary]
  --threshold FLOAT       Confidence threshold for attack classification  [default: 0.5]
  --model-path TEXT       Override the model .pkl path
                          (default: model/lgbm_binary_model.pkl or
                                    model/lgbm_multiclass_model.pkl based on --mode)
  --features-path TEXT    Path to features.json  [default: model/features.json]
  --label-encoder-path TEXT  Path to label_encoder.pkl (multiclass only)
  --log-file TEXT         CSV file for flow logs  [default: flows_log.csv]
  --flow-timeout FLOAT    Inactivity timeout in seconds before a flow is exported  [default: 5.0]
  --max-packets INT       Export a flow once it reaches this many packets  [default: 10000]
  --pcap TEXT             Offline mode: path to a .pcap or .pcapng file
  --bpf TEXT              BPF filter for live capture  [default: "tcp or udp"]
  --list-interfaces       Print available network interfaces and exit
  --help                  Show this message and exit
```

**Examples**

```bash
# Offline test
python main.py --pcap windows_smoke_test.pcap --mode binary --threshold 0.5

# Live binary detection on eth0
sudo python main.py --interface eth0 --mode binary --threshold 0.5

# Live multiclass detection, lower threshold, custom log
sudo python main.py --interface eth0 --mode multiclass --threshold 0.4 --log-file /var/log/ddos.csv

# List interfaces
python main.py --list-interfaces
```

---

## Output

### Terminal

Every attack flow triggers a rich panel:

```
╔══════════════════════════════════════════╗
║              ATTACK DETECTED             ║
╠══════════════════════════════════════════╣
║ Time       2024-01-15 14:32:01           ║
║ Flow       192.168.1.5:4444 ->           ║
║            10.0.0.1:80                   ║
║ Type       DDoS                          ║
║ Confidence 97.43%                        ║
║ Stats      Duration: 2.31s | Packets:    ║
║            1842 | Bytes: 1.24 MB         ║
╚══════════════════════════════════════════╝
```

If flow rate exceeds 1000/minute, a `HIGH TRAFFIC WARNING` is printed.

### CSV Log

Every flow (benign and attack) is appended to the log file:

```
timestamp,src_ip,src_port,dst_ip,dst_port,protocol,predicted_label,confidence,is_attack,duration_seconds,packet_count,byte_count
2024-01-15 14:32:01,192.168.1.5,4444,10.0.0.1,80,6,DDoS,0.974300,1,2.310000,1842,1300000
```

---

## Exporting Artifacts From a Training Notebook

After training in a notebook, export artifacts for use by the detector:

```python
from export_model import export_from_objects

# Binary model
export_from_objects(
    model=lgb_binary_model,
    feature_names=X_train.columns.tolist(),
    output_dir="model"
)

# Multiclass model with label encoder
export_from_objects(
    model=lgb_multi_model,
    feature_names=X_train.columns.tolist(),
    output_dir="model",
    label_encoder=le
)
```

This writes `lgbm_model.pkl`, `features.json`, and optionally `label_encoder.pkl` to the `model/` directory.

> **Important:** `features.json` must contain the exact feature names used during training, in the same order. The detector fills any missing features with `0.0`.

---

## Retraining From Scratch

```bash
python train_from_parquet.py \
  --dataset dhoogla/cicidscollection \
  --file-path cic-collection.parquet \
  --output-dir model \
  --max-rows 300000
```

Requires a Kaggle account and `~/.kaggle/kaggle.json` credentials. Downloads ~825 MB. Writes `lgbm_binary_model.pkl`, `lgbm_multiclass_model.pkl`, `lgbm_model.pkl`, `features.json`, and `label_encoder.pkl` to `model/`.

---

## Known Limitations

- **Feature approximation:** The detector reimplements CICFlowMeter-style features from raw packets. Some features (e.g. `fwd_seg_size_min`) may differ slightly from the CICFlowMeter tool used to generate the training data. Real-world accuracy may be slightly below the reported test metrics.
- **Docker live capture:** Only works on Linux hosts. macOS and Windows Docker Desktop run inside a VM with no access to host interfaces.
- **IPv4 only:** Only TCP and UDP over IPv4 are processed. IPv6 and other protocols are ignored.
