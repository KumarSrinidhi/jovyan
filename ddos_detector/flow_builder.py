"""Flow aggregation and CIC-IDS style feature extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import numpy as np
from scapy.all import IP, TCP, UDP, Packet


# Feature names must exactly match those in model/features.json (lowercase/underscore).
FEATURE_COLUMNS: list[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "fwd_packets_length_total",
    "bwd_packets_length_total",
    "fwd_packet_length_max",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes/s",
    "flow_packets/s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "fwd_psh_flags",
    "fwd_header_length",
    "bwd_header_length",
    "fwd_packets/s",
    "bwd_packets/s",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "syn_flag_count",
    "urg_flag_count",
    "avg_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "subflow_fwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_packets",
    "subflow_bwd_bytes",
    "init_fwd_win_bytes",
    "init_bwd_win_bytes",
    "fwd_act_data_packets",
    "fwd_seg_size_min",
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min",
]


def _safe_float(value: float) -> float:
    if not np.isfinite(value):
        return 0.0
    return float(value)


def _stats(values: List[float]) -> tuple[float, float, float, float]:
    """Return mean, std, max, min for a list, or zeros if empty."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    return (
        _safe_float(arr.mean()),
        _safe_float(arr.std(ddof=0)),
        _safe_float(arr.max()),
        _safe_float(arr.min()),
    )


def _iat_stats(times: List[float]) -> tuple[float, float, float, float, float]:
    """Return total, mean, std, max, min IAT in microseconds."""
    if len(times) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    iats = np.diff(np.asarray(times, dtype=np.float64)) * 1e6
    return (
        _safe_float(iats.sum()),
        _safe_float(iats.mean()),
        _safe_float(iats.std(ddof=0)),
        _safe_float(iats.max()),
        _safe_float(iats.min()),
    )


@dataclass(frozen=True)
class FlowKey:
    """Bidirectional flow key in canonical forward direction."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FlowKey":
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )


@dataclass
class PacketInfo:
    """Normalized packet fields required by feature extraction."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    header_length: int
    payload_length: int
    flags: str
    window_size: Optional[int]


@dataclass
class _BulkState:
    """Tracks burst state for CIC-like bulk metrics."""

    start_ts: Optional[float] = None
    last_ts: Optional[float] = None
    packet_count: int = 0
    byte_count: int = 0
    bulk_count: int = 0
    bulk_packets: int = 0
    bulk_bytes: int = 0
    bulk_duration: float = 0.0


@dataclass
class FlowAccumulator:
    """Holds packet-level state and computes CIC-style features."""

    key: FlowKey
    start_time: float
    last_seen: float

    total_packets: int = 0
    total_bytes: int = 0

    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    all_timestamps: List[float] = field(default_factory=list)

    fwd_lengths: List[float] = field(default_factory=list)
    bwd_lengths: List[float] = field(default_factory=list)
    all_lengths: List[float] = field(default_factory=list)

    fwd_header_lengths: List[float] = field(default_factory=list)
    bwd_header_lengths: List[float] = field(default_factory=list)

    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    fwd_psh_count: int = 0
    bwd_psh_count: int = 0
    fwd_urg_count: int = 0
    bwd_urg_count: int = 0

    first_fwd_window: Optional[int] = None
    first_bwd_window: Optional[int] = None

    act_data_pkt_fwd: int = 0
    min_seg_size_forward_values: List[int] = field(default_factory=list)

    active_periods: List[float] = field(default_factory=list)
    idle_periods: List[float] = field(default_factory=list)
    current_active_start: Optional[float] = None
    previous_packet_ts: Optional[float] = None

    fwd_bulk: _BulkState = field(default_factory=_BulkState)
    bwd_bulk: _BulkState = field(default_factory=_BulkState)

    active_gap_threshold: float = 1.0

    def add_packet(self, packet: PacketInfo, forward: bool) -> None:
        """Update flow state with one packet."""
        self.total_packets += 1
        self.total_bytes += packet.length

        self.last_seen = packet.timestamp
        self.all_timestamps.append(packet.timestamp)
        self.all_lengths.append(packet.length)

        self._update_activity(packet.timestamp)

        flags = set(packet.flags)
        self.fin_count += int("F" in flags)
        self.syn_count += int("S" in flags)
        self.rst_count += int("R" in flags)
        self.psh_count += int("P" in flags)
        self.ack_count += int("A" in flags)
        self.urg_count += int("U" in flags)
        self.cwe_count += int("C" in flags)
        self.ece_count += int("E" in flags)

        if forward:
            self.fwd_timestamps.append(packet.timestamp)
            self.fwd_lengths.append(packet.length)
            self.fwd_header_lengths.append(packet.header_length)
            self.fwd_psh_count += int("P" in flags)
            self.fwd_urg_count += int("U" in flags)

            if packet.payload_length > 0:
                self.act_data_pkt_fwd += 1
            if packet.header_length > 0:
                self.min_seg_size_forward_values.append(packet.header_length)
            if packet.window_size is not None and self.first_fwd_window is None:
                self.first_fwd_window = int(packet.window_size)
            self._update_bulk(self.fwd_bulk, packet.timestamp, packet.payload_length)
        else:
            self.bwd_timestamps.append(packet.timestamp)
            self.bwd_lengths.append(packet.length)
            self.bwd_header_lengths.append(packet.header_length)
            self.bwd_psh_count += int("P" in flags)
            self.bwd_urg_count += int("U" in flags)

            if packet.window_size is not None and self.first_bwd_window is None:
                self.first_bwd_window = int(packet.window_size)
            self._update_bulk(self.bwd_bulk, packet.timestamp, packet.payload_length)

    def _update_activity(self, ts: float) -> None:
        if self.current_active_start is None:
            self.current_active_start = ts
            self.previous_packet_ts = ts
            return

        if self.previous_packet_ts is None:
            self.previous_packet_ts = ts
            return
        gap = ts - self.previous_packet_ts
        if gap > self.active_gap_threshold:
            active_dur = max(0.0, self.previous_packet_ts - self.current_active_start)
            self.active_periods.append(active_dur * 1e6)
            self.idle_periods.append(gap * 1e6)
            self.current_active_start = ts

        self.previous_packet_ts = ts

    def _close_activity(self) -> None:
        if self.current_active_start is None or self.previous_packet_ts is None:
            return
        active_dur = max(0.0, self.previous_packet_ts - self.current_active_start)
        self.active_periods.append(active_dur * 1e6)

    def _update_bulk(self, state: _BulkState, ts: float, payload_len: int) -> None:
        # CIC bulk requires payload packets in a short contiguous burst.
        if payload_len <= 0:
            self._close_bulk_if_needed(state)
            return

        if state.start_ts is None:
            state.start_ts = ts
            state.last_ts = ts
            state.packet_count = 1
            state.byte_count = payload_len
            return

        if state.last_ts is None:
            self._close_bulk_if_needed(state)
            return
        if ts - state.last_ts <= 1.0:
            state.packet_count += 1
            state.byte_count += payload_len
            state.last_ts = ts
            return

        self._close_bulk_if_needed(state)
        state.start_ts = ts
        state.last_ts = ts
        state.packet_count = 1
        state.byte_count = payload_len

    def _close_bulk_if_needed(self, state: _BulkState) -> None:
        if state.start_ts is None or state.last_ts is None:
            state.start_ts = None
            state.last_ts = None
            state.packet_count = 0
            state.byte_count = 0
            return

        if state.packet_count >= 4:
            state.bulk_count += 1
            state.bulk_packets += state.packet_count
            state.bulk_bytes += state.byte_count
            state.bulk_duration += max(0.0, state.last_ts - state.start_ts)

        state.start_ts = None
        state.last_ts = None
        state.packet_count = 0
        state.byte_count = 0

    def _bulk_features(self, state: _BulkState) -> tuple[float, float, float]:
        if state.bulk_count == 0:
            return 0.0, 0.0, 0.0
        avg_bytes = state.bulk_bytes / state.bulk_count
        avg_pkts = state.bulk_packets / state.bulk_count
        avg_rate = state.bulk_bytes / state.bulk_duration if state.bulk_duration > 0 else 0.0
        return _safe_float(avg_bytes), _safe_float(avg_pkts), _safe_float(avg_rate)

    def to_feature_dict(self) -> Dict[str, float]:
        """Compute all required CIC-style features for this flow."""
        self._close_bulk_if_needed(self.fwd_bulk)
        self._close_bulk_if_needed(self.bwd_bulk)
        self._close_activity()

        duration_s = max(0.0, self.last_seen - self.start_time)
        duration_us = duration_s * 1e6

        fwd_pkts = len(self.fwd_lengths)
        bwd_pkts = len(self.bwd_lengths)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_bytes = float(np.sum(self.fwd_lengths)) if self.fwd_lengths else 0.0
        bwd_bytes = float(np.sum(self.bwd_lengths)) if self.bwd_lengths else 0.0
        total_bytes = fwd_bytes + bwd_bytes

        fwd_mean, fwd_std, fwd_max, fwd_min = _stats(self.fwd_lengths)
        bwd_mean, bwd_std, bwd_max, bwd_min = _stats(self.bwd_lengths)
        flow_iat_total, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(self.all_timestamps)
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(self.fwd_timestamps)
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(self.bwd_timestamps)
        pkt_mean, pkt_std, pkt_max, pkt_min = _stats(self.all_lengths)

        flow_bytes_s = total_bytes / duration_s if duration_s > 0 else 0.0
        flow_pkts_s = total_pkts / duration_s if duration_s > 0 else 0.0
        fwd_pkts_s = fwd_pkts / duration_s if duration_s > 0 else 0.0
        bwd_pkts_s = bwd_pkts / duration_s if duration_s > 0 else 0.0

        fwd_header_len = float(np.sum(self.fwd_header_lengths)) if self.fwd_header_lengths else 0.0
        bwd_header_len = float(np.sum(self.bwd_header_lengths)) if self.bwd_header_lengths else 0.0

        down_up_ratio = (bwd_pkts / fwd_pkts) if fwd_pkts > 0 else 0.0
        avg_pkt_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        avg_fwd_seg_size = (fwd_bytes / fwd_pkts) if fwd_pkts > 0 else 0.0
        avg_bwd_seg_size = (bwd_bytes / bwd_pkts) if bwd_pkts > 0 else 0.0

        fwd_bulk_avg_bytes, fwd_bulk_avg_pkts, fwd_bulk_avg_rate = self._bulk_features(self.fwd_bulk)
        bwd_bulk_avg_bytes, bwd_bulk_avg_pkts, bwd_bulk_avg_rate = self._bulk_features(self.bwd_bulk)

        active_mean, active_std, active_max, active_min = _stats(self.active_periods)
        idle_mean, idle_std, idle_max, idle_min = _stats(self.idle_periods)

        pkt_variance = _safe_float(float(np.var(np.asarray(self.all_lengths, dtype=np.float64), ddof=0))) if self.all_lengths else 0.0

        min_seg_size_forward = float(min(self.min_seg_size_forward_values)) if self.min_seg_size_forward_values else 0.0

        features: Dict[str, float] = {
            "flow_duration": _safe_float(duration_us),
            "total_fwd_packets": float(fwd_pkts),
            "total_backward_packets": float(bwd_pkts),
            "fwd_packets_length_total": _safe_float(fwd_bytes),
            "bwd_packets_length_total": _safe_float(bwd_bytes),
            "fwd_packet_length_max": _safe_float(fwd_max),
            "fwd_packet_length_mean": _safe_float(fwd_mean),
            "fwd_packet_length_std": _safe_float(fwd_std),
            "bwd_packet_length_max": _safe_float(bwd_max),
            "bwd_packet_length_mean": _safe_float(bwd_mean),
            "bwd_packet_length_std": _safe_float(bwd_std),
            "flow_bytes/s": _safe_float(flow_bytes_s),
            "flow_packets/s": _safe_float(flow_pkts_s),
            "flow_iat_mean": _safe_float(flow_iat_mean),
            "flow_iat_std": _safe_float(flow_iat_std),
            "flow_iat_max": _safe_float(flow_iat_max),
            "flow_iat_min": _safe_float(flow_iat_min),
            "fwd_iat_total": _safe_float(fwd_iat_total),
            "fwd_iat_mean": _safe_float(fwd_iat_mean),
            "fwd_iat_std": _safe_float(fwd_iat_std),
            "fwd_iat_max": _safe_float(fwd_iat_max),
            "fwd_iat_min": _safe_float(fwd_iat_min),
            "bwd_iat_total": _safe_float(bwd_iat_total),
            "bwd_iat_mean": _safe_float(bwd_iat_mean),
            "bwd_iat_std": _safe_float(bwd_iat_std),
            "bwd_iat_max": _safe_float(bwd_iat_max),
            "bwd_iat_min": _safe_float(bwd_iat_min),
            "fwd_psh_flags": float(self.fwd_psh_count),
            "fwd_header_length": _safe_float(fwd_header_len),
            "bwd_header_length": _safe_float(bwd_header_len),
            "fwd_packets/s": _safe_float(fwd_pkts_s),
            "bwd_packets/s": _safe_float(bwd_pkts_s),
            "packet_length_max": _safe_float(pkt_max),
            "packet_length_mean": _safe_float(pkt_mean),
            "packet_length_std": _safe_float(pkt_std),
            "packet_length_variance": _safe_float(pkt_variance),
            "syn_flag_count": float(self.syn_count),
            "urg_flag_count": float(self.urg_count),
            "avg_packet_size": _safe_float(avg_pkt_size),
            "avg_fwd_segment_size": _safe_float(avg_fwd_seg_size),
            "avg_bwd_segment_size": _safe_float(avg_bwd_seg_size),
            "subflow_fwd_packets": float(fwd_pkts),
            "subflow_fwd_bytes": _safe_float(fwd_bytes),
            "subflow_bwd_packets": float(bwd_pkts),
            "subflow_bwd_bytes": _safe_float(bwd_bytes),
            "init_fwd_win_bytes": float(self.first_fwd_window or 0),
            "init_bwd_win_bytes": float(self.first_bwd_window or 0),
            "fwd_act_data_packets": float(self.act_data_pkt_fwd),
            "fwd_seg_size_min": _safe_float(min_seg_size_forward),
            "active_mean": _safe_float(active_mean),
            "active_std": _safe_float(active_std),
            "active_max": _safe_float(active_max),
            "active_min": _safe_float(active_min),
            "idle_mean": _safe_float(idle_mean),
            "idle_std": _safe_float(idle_std),
            "idle_max": _safe_float(idle_max),
            "idle_min": _safe_float(idle_min),
        }

        for col in FEATURE_COLUMNS:
            features.setdefault(col, 0.0)

        return features


def parse_packet(packet: Packet) -> Optional[PacketInfo]:
    """Normalize a Scapy packet into PacketInfo.

    Only IPv4 TCP/UDP packets are used for 5-tuple flow tracking.
    """
    if IP not in packet:
        return None

    ip = packet[IP]
    protocol = int(ip.proto)
    src_ip = str(ip.src)
    dst_ip = str(ip.dst)
    timestamp = float(getattr(packet, "time", 0.0))

    ip_header_len = int(getattr(ip, "ihl", 5)) * 4

    sport = 0
    dport = 0
    header_length = ip_header_len
    payload_length = 0
    flags = ""
    window_size: Optional[int] = None

    if TCP in packet:
        tcp = packet[TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        tcp_header_len = int(getattr(tcp, "dataofs", 5)) * 4
        header_length = ip_header_len + tcp_header_len
        payload_length = len(bytes(tcp.payload))
        flags = str(tcp.flags)
        window_size = int(getattr(tcp, "window", 0))
    elif UDP in packet:
        udp = packet[UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)
        header_length = ip_header_len + 8
        payload_length = len(bytes(udp.payload))
        flags = ""
    else:
        return None

    packet_len = int(getattr(ip, "len", len(bytes(packet))))

    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        protocol=protocol,
        length=packet_len,
        header_length=header_length,
        payload_length=payload_length,
        flags=flags,
        window_size=window_size,
    )


class FlowBuilder:
    """Build bidirectional flows and export completed feature rows."""

    def __init__(self, timeout_seconds: float = 5.0, max_packets: int = 10_000) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_packets = max_packets
        self._flows: Dict[FlowKey, FlowAccumulator] = {}

    def process_packet(self, packet: Packet) -> List[Dict[str, object]]:
        """Process one packet and return any completed flow records."""
        parsed = parse_packet(packet)
        if parsed is None:
            return []

        completed = self._export_timed_out(parsed.timestamp)

        direct_key = FlowKey(
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            protocol=parsed.protocol,
        )
        reverse_key = direct_key.reverse()

        if direct_key in self._flows:
            key = direct_key
            forward = True
        elif reverse_key in self._flows:
            key = reverse_key
            forward = False
        else:
            key = direct_key
            forward = True
            self._flows[key] = FlowAccumulator(
                key=key,
                start_time=parsed.timestamp,
                last_seen=parsed.timestamp,
            )

        flow = self._flows[key]
        flow.add_packet(parsed, forward=forward)

        if flow.total_packets >= self.max_packets:
            completed.append(self._export_key(key))

        return completed

    def flush_all(self) -> List[Dict[str, object]]:
        """Export and clear all active flows."""
        keys = list(self._flows.keys())
        records = [self._export_key(key) for key in keys]
        return records

    def _export_timed_out(self, now_ts: float) -> List[Dict[str, object]]:
        expired: List[FlowKey] = [
            key for key, flow in self._flows.items()
            if now_ts - flow.last_seen >= self.timeout_seconds
        ]
        return [self._export_key(key) for key in expired]

    def _export_key(self, key: FlowKey) -> Dict[str, object]:
        flow = self._flows.pop(key)
        features = flow.to_feature_dict()
        duration_seconds = features["flow_duration"] / 1e6

        return {
            "timestamp": flow.last_seen,
            "src_ip": key.src_ip,
            "dst_ip": key.dst_ip,
            "src_port": key.src_port,
            "dst_port": key.dst_port,
            "protocol": key.protocol,
            "packet_count": flow.total_packets,
            "byte_count": flow.total_bytes,
            "duration_seconds": duration_seconds,
            "features": features,
        }

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    @staticmethod
    def feature_columns() -> Iterable[str]:
        return FEATURE_COLUMNS
