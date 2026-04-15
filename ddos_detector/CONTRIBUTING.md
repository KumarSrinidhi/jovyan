# Contributing

## Development setup

```bash
cd ddos_detector
make install
```

This creates a `.venv` and installs all dependencies.

## Running the smoke test

Always run this before opening a PR to confirm nothing is broken:

```bash
make smoke
```

Expected last line: `Detection session complete.`

## Code style

- Python 3.9+ compatible
- Type hints on all public functions and methods
- No bare `except` clauses
- Keep functions small and single-purpose

## Project structure

| File | Responsibility |
|---|---|
| `main.py` | CLI parsing and top-level orchestration only |
| `capture.py` | Scapy wrappers — no business logic |
| `flow_builder.py` | Flow state machine and feature extraction |
| `detector.py` | Model loading and inference — no I/O |
| `alerts.py` | Terminal output and CSV logging — no inference |
| `export_model.py` | Artifact export utility |
| `train_from_parquet.py` | Standalone training script |

## Adding or changing features

If you change the features extracted in `flow_builder.py`:

1. Update `FEATURE_COLUMNS` to match
2. Update `to_feature_dict()` to produce the new keys
3. Retrain the model with `train_from_parquet.py` and replace the artifacts in `model/`
4. Update `model/features.json` — this is the source of truth the detector reads at runtime

The feature names in `flow_builder.py`, `features.json`, and the trained model **must all match exactly**.

## Pull requests

- One logical change per PR
- Include a description of what changed and why
- Run `make smoke` and confirm it passes before submitting
