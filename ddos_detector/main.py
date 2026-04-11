"""Entry point for real-time/offline DDoS and attack flow detection."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from typing import Dict, Optional

from rich.console import Console

from alerts import AlertManager
from capture import capture_live, capture_offline, list_interfaces
from detector import LGBMFlowDetector
from flow_builder import FlowBuilder


def build_parser() -> argparse.ArgumentParser:
    """Build command-line arguments parser."""
    parser = argparse.ArgumentParser(
        description="Real-time flow-based DDoS/attack detector using LightGBM",
    )
    parser.add_argument("--interface", type=str, default=None, help="Capture interface for live mode")
    parser.add_argument(
        "--mode",
        type=str,
        default="binary",
        choices=["binary", "multiclass"],
        help="Detection mode",
    )
    parser.add_argument("--threshold", type=float, default=0.5, help="Confidence threshold")
    parser.add_argument(
        "--model-path",
        type=str,
        default="model/lgbm_model.pkl",
        help="Path to pickled LightGBM model",
    )
    parser.add_argument(
        "--features-path",
        type=str,
        default="model/features.json",
        help="Path to ordered feature name list",
    )
    parser.add_argument(
        "--label-encoder-path",
        type=str,
        default="model/label_encoder.pkl",
        help="Path to pickled label encoder for multiclass mode",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="flows_log.csv",
        help="CSV file to log all flow decisions",
    )
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=5.0,
        help="Flow export timeout in seconds (inactivity)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=10_000,
        help="Export flow once packet count reaches this limit",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Offline mode: read packets from pcap/pcapng",
    )
    parser.add_argument(
        "--bpf",
        type=str,
        default="tcp or udp",
        help="Optional BPF filter for live capture",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available interfaces and exit",
    )
    return parser


def _resolve_path(path: str, base_dir: str) -> str:
    return path if os.path.isabs(path) else os.path.join(base_dir, path)


def run(args: argparse.Namespace) -> int:
    """Run live or offline detection loop."""
    console = Console()

    if args.list_interfaces:
        interfaces = list_interfaces()
        if not interfaces:
            console.print("No interfaces found.")
            return 1
        console.print("Available interfaces:")
        for iface in interfaces:
            console.print(f"- {iface}")
        return 0

    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = _resolve_path(args.model_path, base_dir)
    features_path = _resolve_path(args.features_path, base_dir)
    label_encoder_path = _resolve_path(args.label_encoder_path, base_dir)
    log_path = _resolve_path(args.log_file, base_dir)

    if args.mode == "multiclass" and not os.path.exists(label_encoder_path):
        console.print(
            "[yellow]Label encoder not found. Multiclass labels will be numeric.[/yellow]"
        )
        label_encoder_path = None

    detector = LGBMFlowDetector(
        model_path=model_path,
        features_path=features_path,
        mode=args.mode,
        threshold=args.threshold,
        label_encoder_path=label_encoder_path,
    )
    flow_builder = FlowBuilder(timeout_seconds=args.flow_timeout, max_packets=args.max_packets)
    alerts = AlertManager(log_path=log_path, high_traffic_threshold_per_min=1000)

    running = True

    def _signal_handler(signum: int, frame: Optional[object]) -> None:
        nonlocal running
        running = False
        console.print("\nStopping capture and flushing flows...")

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    def handle_completed_flow(flow_record: Dict[str, object]) -> None:
        pred = detector.predict(flow_record["features"])
        alerts.record_flow_rate(float(flow_record["timestamp"]))
        alerts.log_flow(flow_record, pred)
        if pred.is_attack:
            alerts.show_attack(flow_record, pred)

    def packet_handler(packet: object) -> None:
        nonlocal running
        if not running:
            return
        completed = flow_builder.process_packet(packet)  # type: ignore[arg-type]
        for flow_record in completed:
            handle_completed_flow(flow_record)

    if args.pcap:
        pcap_path = _resolve_path(args.pcap, base_dir)
        console.print(f"Running offline mode with pcap: {pcap_path}")
        capture_offline(packet_handler, pcap_path)
        running = False
    else:
        if not args.interface:
            console.print(
                "[red]Live mode requires --interface. Use --list-interfaces to inspect options.[/red]"
            )
            return 2

        console.print(
            "Starting live capture: "
            f"interface={args.interface} mode={args.mode} threshold={args.threshold}"
        )
        console.print("Tip: Linux live capture typically requires sudo/root.")
        capture_live(packet_handler, interface=args.interface, bpf_filter=args.bpf)

    for flow_record in flow_builder.flush_all():
        handle_completed_flow(flow_record)

    console.print("Detection session complete.")
    return 0


def main() -> None:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
