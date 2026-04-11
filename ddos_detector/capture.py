"""Packet capture helpers for live and offline processing."""

from __future__ import annotations

from typing import Callable, Optional

from scapy.all import Packet, get_if_list, rdpcap, sniff

PacketHandler = Callable[[Packet], None]


def list_interfaces() -> list[str]:
    """Return available network interfaces on this host."""
    return list(get_if_list())


def capture_live(
    packet_handler: PacketHandler,
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
) -> None:
    """Capture packets from a live interface and forward to handler.

    Args:
        packet_handler: Callback invoked once per packet.
        interface: Interface name such as eth0, wlan0, or Wi-Fi.
        bpf_filter: Optional BPF expression, e.g. "tcp or udp".
    """

    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=packet_handler,
        store=False,
    )


def capture_offline(packet_handler: PacketHandler, pcap_path: str) -> None:
    """Replay packets from a pcap file through the same handler.

    Args:
        packet_handler: Callback invoked once per packet.
        pcap_path: Path to .pcap/.pcapng file.
    """

    packets = rdpcap(pcap_path)
    for packet in packets:
        packet_handler(packet)
