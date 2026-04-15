# Works on Linux/macOS natively.
# On Windows: use Git Bash, WSL, or `winget install GnuWin32.Make`.

PYTHON   ?= python3
VENV     := .venv
PIP      := $(VENV)/bin/pip
PYEXE    := $(VENV)/bin/python

# Windows Git Bash / WSL path adjustment
ifeq ($(OS),Windows_NT)
  PIP    := $(VENV)/Scripts/pip
  PYEXE  := $(VENV)/Scripts/python
endif

.PHONY: venv install smoke live train docker-build docker-offline docker-live clean

## Create virtual environment
venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

## Install all dependencies into venv
install: venv
	$(PIP) install -r requirements.txt

## Run offline smoke test with the bundled pcap
smoke: install
	$(PYEXE) main.py \
		--pcap windows_smoke_test.pcap \
		--mode binary \
		--threshold 0.5 \
		--log-file flows_log_smoke.csv

## List available capture interfaces
interfaces: install
	$(PYEXE) main.py --list-interfaces

## Live capture — set IFACE and MODE as needed:
##   make live IFACE=eth0 MODE=binary
IFACE ?= eth0
MODE  ?= binary
live: install
	$(PYEXE) main.py --interface $(IFACE) --mode $(MODE) --threshold 0.5

## Train models from parquet (requires Kaggle credentials)
train: install
	$(PYEXE) train_from_parquet.py --output-dir model --max-rows 300000

## Docker targets
docker-build:
	docker build -t ddos-detector:latest .

docker-offline: docker-build
	docker compose run --rm offline

docker-live: docker-build
	docker compose run --rm live --interface $(IFACE) --mode $(MODE)

## Remove venv and cached files
clean:
	rm -rf $(VENV) __pycache__ *.pyc flows_log_smoke.csv
