# Running on Windows

## Prerequisites

- Python 3.9+ from https://python.org
- [Npcap](https://npcap.com) — install with "WinPcap API-compatible mode" checked
- Run PowerShell or CMD **as Administrator** for live capture

---

## Setup

```powershell
cd ddos_detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## Offline smoke test

```powershell
python main.py `
  --pcap windows_smoke_test.pcap `
  --mode binary `
  --threshold 0.5 `
  --log-file flows_log_smoke.csv
```

Expected last line: `Detection session complete.`
Results are in `flows_log_smoke.csv`.

---

## List interfaces

```powershell
python main.py --list-interfaces
```

Pick the interface name from the output (e.g. `\Device\NPF_{GUID}`).

---

## Live capture

```powershell
python main.py `
  --interface "\Device\NPF_{GUID}" `
  --mode binary `
  --threshold 0.5 `
  --log-file flows_log_live.csv
```

Stop with `Ctrl+C`.

---

## Multiclass mode

```powershell
python main.py `
  --pcap windows_smoke_test.pcap `
  --mode multiclass `
  --threshold 0.6 `
  --log-file flows_log_multi.csv
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No interfaces listed | Install/reinstall Npcap with WinPcap-compat mode |
| `Access denied` on live capture | Run terminal as Administrator |
| `InconsistentVersionWarning` from scikit-learn | Align sklearn version with training environment |
| `python` not found | Use `py` instead, or activate the venv first |
