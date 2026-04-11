"""Alert display and CSV logging utilities."""

from __future__ import annotations

import csv
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from detector import PredictionResult


@dataclass
class AlertManager:
    """Print attack alerts and persist per-flow records."""

    log_path: str = "flows_log.csv"
    high_traffic_threshold_per_min: int = 1000

    def __post_init__(self) -> None:
        self.console = Console()
        self._flow_events: Deque[float] = deque()
        self._init_log()

    def _init_log(self) -> None:
        path = Path(self.log_path)
        parent = path.parent
        if str(parent) and str(parent) != ".":
            parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            return

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._csv_columns())
            writer.writeheader()

    @staticmethod
    def _csv_columns() -> list[str]:
        return [
            "timestamp",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "predicted_label",
            "confidence",
            "is_attack",
            "duration_seconds",
            "packet_count",
            "byte_count",
        ]

    def record_flow_rate(self, event_ts: float) -> None:
        """Update flow/minute tracking and print high-traffic warning."""
        self._flow_events.append(event_ts)
        one_minute_ago = event_ts - 60.0
        while self._flow_events and self._flow_events[0] < one_minute_ago:
            self._flow_events.popleft()

        if len(self._flow_events) > self.high_traffic_threshold_per_min:
            self.console.print(
                "[bold yellow]HIGH TRAFFIC WARNING[/bold yellow] "
                f"- {len(self._flow_events)} flows/min observed"
            )

    def log_flow(self, flow_record: Dict[str, object], pred: PredictionResult) -> None:
        """Append one flow outcome to CSV log."""
        row = {
            "timestamp": self._fmt_ts(float(flow_record["timestamp"])),
            "src_ip": flow_record["src_ip"],
            "src_port": flow_record["src_port"],
            "dst_ip": flow_record["dst_ip"],
            "dst_port": flow_record["dst_port"],
            "protocol": flow_record["protocol"],
            "predicted_label": pred.label,
            "confidence": f"{pred.confidence:.6f}",
            "is_attack": int(pred.is_attack),
            "duration_seconds": f"{float(flow_record['duration_seconds']):.6f}",
            "packet_count": int(flow_record["packet_count"]),
            "byte_count": int(flow_record["byte_count"]),
        }

        with open(self.log_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._csv_columns())
            writer.writerow(row)

    def show_attack(self, flow_record: Dict[str, object], pred: PredictionResult) -> None:
        """Render a rich attack alert panel."""
        mb = float(flow_record["byte_count"]) / (1024.0 * 1024.0)

        table = Table.grid(expand=True)
        table.add_row("Time", self._fmt_ts(float(flow_record["timestamp"])))
        table.add_row(
            "Flow",
            f"{flow_record['src_ip']}:{flow_record['src_port']} -> "
            f"{flow_record['dst_ip']}:{flow_record['dst_port']}",
        )
        table.add_row("Type", pred.label)
        table.add_row("Confidence", f"{pred.confidence * 100.0:.2f}%")
        table.add_row(
            "Stats",
            "Duration: "
            f"{float(flow_record['duration_seconds']):.2f}s | "
            f"Packets: {flow_record['packet_count']} | "
            f"Bytes: {mb:.2f} MB",
        )

        self.console.print(
            Panel(
                table,
                title="ATTACK DETECTED",
                border_style="bold red",
            )
        )

    @staticmethod
    def _fmt_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
