# Running on Windows

Complete guide for setting up and running the DDoS Detector on Windows.

---

## Prerequisites

Before you start, install the following:

1. **Python 3.9+** — download from [python.org](https://python.org)
   - During install, check **"Add Python to PATH"**

2. **Npcap** — download from [npcap.com](https://npcap.com)
   - During install, check **"Install Npcap in WinPcap API-compatible Mode"**
   - This is required for live packet capture

3. For **live capture**, open PowerShell or CMD **as Administrator**

---

## Step 1 — Set up the environment

Open PowerShell (or CMD) in the `ddos_detector` folder:

```powershell
cd ddos_detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

You should see `(.venv)` in your prompt once activated.

---

## Step 2 — Run the offline smoke test

This verifies everything is working without needing a network interface or Administrator rights:

```powershell
python main.py `
  --pcap windows_smoke_test.pcap `
  --mode binary `
  --threshold 0.5 `
  --log-file flows_log_smoke.csv
```

Expected output ends with:
```
Detection session complete.
```

Check `flows_log_smoke.csv` to see the flow predictions.

---

## Step 3 — Find your network interface

```powershell
python main.py --list-interfaces
```

Example output:
```
Available interfaces:
- \Device\NPF_{A1B2C3D4-...}
- \Device\NPF_Loopback
```

Copy the interface name you want to capture on.

---

## Step 4 — Run live capture

> **Requires Administrator.** Right-click PowerShell → "Run as administrator", then activate the venv again.

```powershell
.venv\Scripts\activate

python main.py `
  --interface "\Device\NPF_{YOUR-GUID-HERE}" `
  --mode binary `
  --threshold 0.5 `
  --log-file flows_log_live.csv
```

Press `Ctrl+C` to stop. Flows are flushed and the log is saved on exit.

---

## Multiclass mode

To classify attack types (DDoS, DoS, Botnet, etc.) instead of just binary detection:

```powershell
python main.py `
  --interface "\Device\NPF_{YOUR-GUID-HERE}" `
  --mode multiclass `
  --threshold 0.6 `
  --log-file flows_log_live.csv
```

Or offline:

```powershell
python main.py `
  --pcap windows_smoke_test.pcap `
  --mode multiclass `
  --threshold 0.6 `
  --log-file flows_log_multi.csv
```

---

## All CLI options

| Option | Default | Description |
|---|---|---|
| `--interface` | — | Interface name for live capture |
| `--mode` | `binary` | `binary` or `multiclass` |
| `--threshold` | `0.5` | Confidence threshold (0.0–1.0) |
| `--pcap` | — | Offline mode: path to `.pcap` file |
| `--log-file` | `flows_log.csv` | Output CSV path |
| `--flow-timeout` | `5.0` | Seconds of inactivity before a flow is exported |
| `--max-packets` | `10000` | Export flow after this many packets |
| `--bpf` | `tcp or udp` | BPF filter for live capture |
| `--list-interfaces` | — | Print interfaces and exit |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `No interfaces listed` | Reinstall Npcap and check "WinPcap API-compatible Mode" |
| `Access denied` or `Permission denied` on live capture | Run PowerShell as Administrator |
| `python` not found | Use `py` instead, or check "Add Python to PATH" was ticked during install |
| `ModuleNotFoundError` | Make sure the venv is activated (you should see `(.venv)` in the prompt) |
| `InconsistentVersionWarning` from scikit-learn | The model was trained with a different sklearn version — predictions still work but retrain for best accuracy |
| `Ctrl+C` doesn't stop immediately | Wait 1–2 seconds — the detector flushes remaining flows before exiting |
