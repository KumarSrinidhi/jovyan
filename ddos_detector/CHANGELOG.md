# Changelog

All notable changes to this project are documented here.

---

## [1.0.0] — Initial release

### Added
- Real-time bidirectional flow builder with 57 CIC-IDS style features
- LightGBM binary detector (benign vs. attack) — AUC 0.997, F1 0.972, Recall 0.958
- LightGBM multiclass detector (8 attack families) — weighted F1 0.873
- Live packet capture via scapy (`capture.py`)
- Offline pcap replay mode
- Rich terminal attack alert panels
- CSV flow logging (persistent file handle, not reopened per flow)
- `export_model.py` — export trained artifacts from a notebook
- `train_from_parquet.py` — retrain from CIC-IDS parquet via KaggleHub
- Dockerfile (multi-stage, non-root runtime)
- `docker-compose.yml` with offline, live, and train services
- `Makefile` for Linux/macOS/Windows Git Bash
- Cross-platform setup: Linux, macOS, Windows, Docker

### Fixed
- Feature name mismatch: `flow_builder.py` now produces lowercase/underscore names matching `features.json` and the trained model (previously all features defaulted to `0.0` at inference)
- `flush_all()` and `_export_timed_out()` no longer mutate the flow dict during iteration
- `assert` statements replaced with proper `if` guards (asserts are stripped by `python -O`)
- CSV log file now kept open for the session lifetime instead of reopened per flow
- `SIGINT` now correctly stops `sniff()` on Windows via `stop_event` / `stop_filter`
- Default model path now correctly resolves to `lgbm_binary_model.pkl` or `lgbm_multiclass_model.pkl` based on `--mode`
- `pickle.load()` now validates file existence and extension before loading
