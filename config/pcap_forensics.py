"""
NIDS — PCAP Forensics Module
===========================
PCAP capture for HIGH/CRITICAL events and PCAP analysis utilities.
"""

from __future__ import annotations

import logging
import os
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger("NIDS.PCAPForensics")

PCAP_DIR = Path("logs/pcap")
PCAP_DIR.mkdir(parents=True, exist_ok=True)

# PCAP global header magic numbers
PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4


# ---------------------------------------------------------------------------
# PCAP file format helpers
# ---------------------------------------------------------------------------

def _write_pcap_global_header(f: BinaryIO, linktype: int = 1) -> None:
    """Write PCAP global header (24 bytes)."""
    f.write(struct.pack("<I", PCAP_MAGIC))          # magic
    f.write(struct.pack("<H", PCAP_VERSION_MAJOR))   # version major
    f.write(struct.pack("<H", PCAP_VERSION_MINOR))  # version minor
    f.write(struct.pack("<i", 0))                    # thiszone
    f.write(struct.pack("<I", 0))                    # sigfigs
    f.write(struct.pack("<I", 65535))               # snaplen
    f.write(struct.pack("<I", linktype))             # linktype


def _write_pcap_packet_header(f: BinaryIO, timestamp: float, captured_len: int, original_len: int) -> None:
    """Write PCAP packet record header (16 bytes)."""
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    f.write(struct.pack("<I", ts_sec))
    f.write(struct.pack("<I", ts_usec))
    f.write(struct.pack("<I", captured_len))
    f.write(struct.pack("<I", original_len))


def _read_pcap_packet_header(f: BinaryIO) -> tuple[float, int, int]:
    """Read and return (timestamp, captured_len, original_len)."""
    data = f.read(16)
    if len(data) < 16:
        return 0.0, 0, 0
    ts_sec, ts_usec, captured_len, original_len = struct.unpack("<IIII", data)
    timestamp = ts_sec + ts_usec / 1_000_000
    return timestamp, captured_len, original_len


# ---------------------------------------------------------------------------
# PCAP capture context manager
# ---------------------------------------------------------------------------

@dataclass
class CaptureContext:
    """Context for capturing packets surrounding an event."""
    event_id: int
    pcap_path: Path
    _f: BinaryIO | None = None
    _packet_count: int = 0


class PCAPCapture:
    """
    Captures packets to a PCAP file for forensic analysis.
    When a HIGH/CRITICAL event is triggered, surrounding packets
    (the N packets before and after) are saved.
    """

    def __init__(self, pcap_dir: Path | None = None, packets_before: int = 5, packets_after: int = 5):
        self.pcap_dir = pcap_dir or PCAP_DIR
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.packets_before = packets_before
        self.packets_after = packets_after
        self._buffers: dict[int, list] = {}  # event_id -> list of (timestamp, raw_packet)
        self._buffering_events: set[int] = set()  # event_ids currently being buffered

    def start_buffering(self, event_id: int) -> None:
        """Start buffering packets for an event."""
        if event_id not in self._buffers:
            self._buffers[event_id] = []
            self._buffering_events.add(event_id)
        logger.debug(f"PCAP buffering started for event {event_id}")

    def capture_packet(self, event_id: int, raw_packet: bytes, timestamp: float | None = None) -> None:
        """Add a packet to the buffer for an event."""
        if event_id not in self._buffering_events:
            return
        if timestamp is None:
            timestamp = time.time()
        self._buffers[event_id].append((timestamp, raw_packet))

    def flush(self, event_id: int, trigger_timestamp: float) -> Path | None:
        """
        Write buffered packets to a PCAP file for an event.
        Returns the path to the PCAP file, or None if no packets.
        """
        if event_id not in self._buffers or not self._buffers[event_id]:
            return None

        packets = self._buffers[event_id]
        pcap_path = self.pcap_dir / f"event_{event_id}.pcap"

        try:
            with open(pcap_path, "wb") as f:
                _write_pcap_global_header(f, linktype=1)  # LINKTYPE_ETHERNET

                for ts, raw in packets:
                    _write_pcap_packet_header(f, ts, len(raw), len(raw))
                    f.write(raw)

            logger.info(f"PCAP saved for event {event_id}: {pcap_path} ({len(packets)} packets)")
        except Exception as e:
            logger.error(f"Failed to write PCAP for event {event_id}: {e}")
            return None
        finally:
            del self._buffers[event_id]
            self._buffering_events.discard(event_id)

        return pcap_path

    def stop_buffering(self, event_id: int) -> None:
        """Stop buffering for an event without flushing."""
        self._buffering_events.discard(event_id)
        if event_id in self._buffers:
            del self._buffers[event_id]


# ---------------------------------------------------------------------------
# PCAP analysis
# ---------------------------------------------------------------------------

@dataclass
class FlowSummary:
    """Summary of a network flow extracted from PCAP."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    bytes_sent: int
    bytes_recv: int
    duration_seconds: float
    start_time: str
    end_time: str


def analyze_pcap(pcap_path: Path) -> list[FlowSummary]:
    """
    Parse a PCAP file and extract flow summaries.
    Returns a list of FlowSummary objects.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    except ImportError:
        logger.error("Scapy not installed — PCAP analysis unavailable")
        return []

    if not pcap_path.exists():
        logger.warning(f"PCAP file not found: {pcap_path}")
        return []

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        logger.error(f"Failed to read PCAP {pcap_path}: {e}")
        return []

    # Group by flow (src_ip, dst_ip, protocol, src_port, dst_port)
    flows: dict = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        proto = ip.proto
        src_ip = ip.src
        dst_ip = ip.dst

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto_name = "TCP"
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto_name = "UDP"
        elif pkt.haslayer(ICMP):
            sport = dport = 0
            proto_name = "ICMP"
        else:
            sport = dport = 0
            proto_name = str(proto)

        key = (src_ip, dst_ip, sport, dport, proto_name)
        if key not in flows:
            flows[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto_name,
                "packets": [],
                "bytes_sent": 0,
                "bytes_recv": 0,
            }
        flows[key]["packets"].append(pkt)
        flows[key]["bytes_sent"] += len(pkt)

    # Build summaries
    summaries = []
    for flow_data in flows.values():
        pkts = flow_data["packets"]
        if not pkts:
            continue
        first_ts = pkts[0].time
        last_ts = pkts[-1].time

        summaries.append(FlowSummary(
            src_ip=flow_data["src_ip"],
            dst_ip=flow_data["dst_ip"],
            src_port=flow_data["src_port"],
            dst_port=flow_data["dst_port"],
            protocol=flow_data["protocol"],
            packet_count=len(pkts),
            bytes_sent=flow_data["bytes_sent"],
            bytes_recv=0,  # Would need bidirectional tracking
            duration_seconds=last_ts - first_ts,
            start_time=datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat(),
            end_time=datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat(),
        ))

    summaries.sort(key=lambda s: s.start_time)
    return summaries


def print_flow_summary(pcap_path: Path) -> None:
    """Print a human-readable flow summary for a PCAP file."""
    summaries = analyze_pcap(pcap_path)
    if not summaries:
        print(f"No flows found in {pcap_path}")
        return
    print(f"\n{'='*80}")
    print(f"PCAP Analysis: {pcap_path}")
    print(f"{'='*80}")
    print(f"{'Src IP':<18} {'Dst IP':<18} {'Sport':>6} {'Dport':>6} {'Proto':<6} "
          f"{'Pkts':>6} {'Bytes':>10} {'Duration':>10}")
    print("-" * 80)
    for s in summaries:
        print(
            f"{s.src_ip:<18} {s.dst_ip:<18} {s.src_port:>6} {s.dst_port:>6} "
            f"{s.protocol:<6} {s.packet_count:>6} {s.bytes_sent:>10} {s.duration_seconds:>10.3f}s"
        )
    print(f"\nTotal flows: {len(summaries)}")
