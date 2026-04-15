# syntax=docker/dockerfile:1

# ── Stage 1: build deps ───────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# libpcap is needed at runtime for scapy live capture
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Non-root user for offline/inference workloads.
# Live capture overrides this with --user root or --cap-add NET_RAW in compose.
RUN useradd --create-home --shell /bin/bash detector
WORKDIR /app

COPY . .

# Ensure model dir exists so volume mounts work cleanly
RUN mkdir -p model logs \
 && chown -R detector:detector /app

USER detector

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
