"""
NIDS — ML Anomaly Detection Engine v2
====================================
Ensemble anomaly detection using three models:
  1. IsolationForest (original)
  2. RandomForestClassifier (supervised, trained on CICIDS2017/NSL-KDD features)
  3. LocalOutlierFactor (density-based)

An event is flagged only if 2 of 3 models agree (ensemble voting).

New features added:
  - bytes_per_second
  - packets_per_second
  - connection_duration
  - unique_ports_accessed
  - reverse_dns_failed

Supports online learning (retrain on recent labeled traffic).
Model versioning: models/v{timestamp}/
"""

from __future__ import annotations

import json
import logging
import os
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP

logger = logging.getLogger("NIDS.AnomalyDetection")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
VERSIONS_DIR = MODELS_DIR / "versions"
VERSIONS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Feature names (must stay in sync with train_model.py and extract_features)
# ---------------------------------------------------------------------------
BASE_FEATURES = [
    "packet_length",
    "protocol",
    "src_port",
    "dst_port",
    "tcp_flags",
    "icmp_type",
    "payload_length",
    "is_fragmented",
    "ttl",
    "header_length",
]

EXTENDED_FEATURES = [
    "bytes_per_second",
    "packets_per_second",
    "connection_duration",
    "unique_ports_accessed",
    "reverse_dns_failed",
]

ALL_FEATURES = BASE_FEATURES + EXTENDED_FEATURES


# ---------------------------------------------------------------------------
# Traffic state tracker (for computing flow features)
# ---------------------------------------------------------------------------

@dataclass
class FlowState:
    """Tracks state for a flow (src_ip, dst_ip, protocol) to compute features."""
    src_ip: str
    dst_ip: str
    protocol: int
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    bytes_total: int = 0
    packets_total: int = 0
    dst_ports: set = field(default_factory=set)
    dns_failures: int = 0
    closed: bool = False


class FlowTracker:
    """
    Tracks per-flow statistics for computing connection-level features.
    Thread-safe.
    """

    def __init__(self, flow_timeout: float = 300.0):
        self._flows: dict[tuple, FlowState] = defaultdict(FlowState)
        self._lock = threading.Lock()
        self._flow_timeout = flow_timeout

    def _make_key(self, src_ip: str, dst_ip: str, protocol: int) -> tuple:
        return (src_ip, dst_ip, protocol)

    def update(self, packet) -> None:
        """Update flow state for a packet."""
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        proto = ip.proto
        key = self._make_key(ip.src, ip.dst, proto)

        with self._lock:
            flow = self._flows[key]
            now = time.time()
            if flow.first_seen == 0:
                flow.first_seen = now
            flow.last_seen = now
            flow.bytes_total += len(packet)
            flow.packets_total += 1

            if packet.haslayer(TCP):
                flow.dst_ports.add(packet[TCP].dport)
            elif packet.haslayer(UDP):
                flow.dst_ports.add(packet[UDP].dport)

            # Expire old flows
            expired = [k for k, f in self._flows.items() if now - f.last_seen > self._flow_timeout]
            for k in expired:
                del self._flows[k]

    def record_dns_failure(self, src_ip: str) -> None:
        """Record a reverse DNS lookup failure for an IP."""
        with self._lock:
            for flow in self._flows.values():
                if flow.src_ip == src_ip:
                    flow.dns_failures += 1

    def get_flow_stats(self, src_ip: str, dst_ip: str, protocol: int) -> dict:
        """Get flow statistics for a given connection."""
        key = self._make_key(src_ip, dst_ip, protocol)
        with self._lock:
            flow = self._flows.get(key)
            if not flow:
                return {
                    "bytes_per_second": 0.0,
                    "packets_per_second": 0.0,
                    "connection_duration": 0.0,
                    "unique_ports_accessed": 0,
                    "reverse_dns_failed": 0,
                }
            duration = max(flow.last_seen - flow.first_seen, 0.001)
            return {
                "bytes_per_second": flow.bytes_total / duration,
                "packets_per_second": flow.packets_total / duration,
                "connection_duration": duration,
                "unique_ports_accessed": len(flow.dst_ports),
                "reverse_dns_failed": flow.dns_failures,
            }


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(packet, flow_stats: dict | None = None) -> np.ndarray | None:
    """
    Extract all features from a Scapy packet.

    Extended features (require flow_stats):
        bytes_per_second, packets_per_second, connection_duration,
        unique_ports_accessed, reverse_dns_failed
    """
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    packet_length = len(packet)
    protocol = ip.proto
    ttl = ip.ttl
    header_length = ip.ihl * 4
    is_fragmented = 1 if (ip.flags.MF or ip.frag > 0) else 0

    src_port = dst_port = tcp_flags = 0
    icmp_type = 0
    payload_length = 0

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        tcp_flags = int(tcp.flags)
        payload_length = len(tcp.payload)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        payload_length = len(udp.payload)
    elif packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        payload_length = len(packet[ICMP].payload)

    # Extended features from flow stats
    flow = flow_stats or {}
    bytes_per_second = flow.get("bytes_per_second", 0.0)
    packets_per_second = flow.get("packets_per_second", 0.0)
    connection_duration = flow.get("connection_duration", 0.0)
    unique_ports_accessed = flow.get("unique_ports_accessed", 0)
    reverse_dns_failed = flow.get("reverse_dns_failed", 0)

    features = np.array([[
        packet_length,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        icmp_type,
        payload_length,
        is_fragmented,
        ttl,
        header_length,
        bytes_per_second,
        packets_per_second,
        connection_duration,
        unique_ports_accessed,
        reverse_dns_failed,
    ]], dtype=np.float64)

    return features


# ---------------------------------------------------------------------------
# Ensemble model wrapper
# ---------------------------------------------------------------------------

@dataclass
class ModelInfo:
    """Metadata about a loaded model version."""
    version: str
    path: Path
    created_at: str
    feature_count: int
    model_type: str
    metrics: dict | None = None


class EnsembleAnomalyDetector:
    """
    Ensemble anomaly detector using 3 models with voting.
    Flags anomaly only if >= 2 models agree.
    """

    def __init__(self, model_dir: Path | None = None, contamination: float = 0.05):
        self.model_dir = model_dir or VERSIONS_DIR
        self.contamination = contamination
        self.is_loaded = False

        self.isolation_forest = None
        self.random_forest = None
        self.local_outlier_factor = None
        self._current_version: str | None = None
        self._feature_count = 10  # Start with base features

        self._flow_tracker = FlowTracker()

    def load(self, version: str | None = None) -> bool:
        """
        Load the latest or a specific model version.
        Returns True if models were loaded successfully.
        """
        if version:
            model_path = self.model_dir / f"v{version}"
        else:
            # Load latest version
            versions = sorted(
                [d for d in self.model_dir.iterdir() if d.is_dir() and d.name.startswith("v")],
                key=lambda d: d.name,
            )
            if not versions:
                logger.warning("No model versions found.")
                return False
            model_path = versions[-1]

        try:
            meta_path = model_path / "metadata.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    self._metadata = json.load(f)
            else:
                self._metadata = {}

            self.isolation_forest = joblib.load(model_path / "isolation_forest.joblib")
            self._feature_count = self._metadata.get("feature_count", 10)
            self._current_version = model_path.name
            self.is_loaded = True

            # Try to load optional models
            rf_path = model_path / "random_forest.joblib"
            if rf_path.exists():
                self.random_forest = joblib.load(rf_path)

            lof_path = model_path / "local_outlier_factor.joblib"
            if lof_path.exists():
                self.local_outlier_factor = joblib.load(lof_path)

            logger.info(
                f"Ensemble models loaded from {model_path.name} "
                f"(IF={'Y' if self.isolation_forest else 'N'}, "
                f"RF={'Y' if self.random_forest else 'N'}, "
                f"LOF={'Y' if self.local_outlier_factor else 'N'})"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to load models from {model_path}: {e}")
            self.is_loaded = False
            return False

    def get_current_version(self) -> str | None:
        return self._current_version

    def get_metadata(self) -> dict:
        return getattr(self, "_metadata", {})

    def predict(self, features: np.ndarray) -> tuple[int, dict]:
        """
        Run ensemble prediction on a feature vector.

        Returns:
            (prediction, details) where prediction is 1=normal, -1=anomaly
            and details contains per-model scores.
        """
        if not self.is_loaded:
            return 1, {"error": "models not loaded"}

        scores = {}
        votes = 0
        n_models = 0

        # 1. IsolationForest
        if self.isolation_forest is not None:
            n_models += 1
            pred_if = self.isolation_forest.predict(features)[0]
            scores["isolation_forest"] = pred_if
            if pred_if == -1:
                votes += 1

        # 2. RandomForest (score via predict_proba for anomaly class)
        if self.random_forest is not None:
            n_models += 1
            try:
                proba = self.random_forest.predict_proba(features)[0]
                # Assuming class 1 = anomaly in supervised training
                rf_score = 1 if proba[1] > self.contamination else -1
            except Exception:
                rf_score = 1
            scores["random_forest"] = rf_score
            if rf_score == 1:
                votes += 1

        # 3. LocalOutlierFactor
        if self.local_outlier_factor is not None:
            n_models += 1
            pred_lof = self.local_outlier_factor.predict(features)[0]
            scores["local_outlier_factor"] = pred_lof
            if pred_lof == -1:
                votes += 1

        # Ensemble: flag anomaly if 2+ models agree
        threshold = max(2, n_models // 2 + 1)
        if votes >= threshold:
            final_prediction = -1
        else:
            final_prediction = 1

        scores["votes"] = votes
        scores["threshold"] = threshold
        scores["n_models"] = n_models

        return final_prediction, scores

    def predict_batch(self, features_list: list) -> list[tuple[int, dict]]:
        """Run ensemble prediction on a batch of feature vectors."""
        return [self.predict(f) for f in features_list]


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def load_model(model_path=None) -> EnsembleAnomalyDetector | None:
    """Load the ensemble anomaly detection model."""
    detector = EnsembleAnomalyDetector()
    if detector.load():
        return detector
    return None


def perform_anomaly_detection(packets, model: EnsembleAnomalyDetector | None = None,
                               thresholds: dict | None = None) -> list[dict]:
    """
    Run anomaly detection on a list of packets.

    For live mode, pass a configured EnsembleAnomalyDetector.
    """
    if model is None or not model.is_loaded:
        logger.error("No model loaded — skipping anomaly detection.")
        return []

    anomalies = []
    for pkt in packets:
        # Update flow tracking
        model._flow_tracker.update(pkt)

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        flow_stats = model._flow_tracker.get_flow_stats(ip.src, ip.dst, ip.proto)
        features = extract_features(pkt, flow_stats)
        if features is None:
            continue

        try:
            prediction, scores = model.predict(features)
        except Exception as e:
            logger.debug(f"Prediction error on packet: {e}")
            continue

        if prediction == -1:
            record = {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": ip.proto,
                "packet_length": int(features[0][0]),
                "tcp_flags": int(features[0][4]),
                "ttl": int(features[0][8]),
                "ml_score": scores,
            }
            logger.warning(
                f"Anomaly detected | src={record['src_ip']} "
                f"dst={record['dst_ip']} proto={record['protocol']} "
                f"len={record['packet_length']} | scores={scores}"
            )
            anomalies.append(record)

    if len(packets) > 1:
        logger.info(
            f"Anomaly detection complete: {len(anomalies)} anomaly/ies "
            f"found in {len(packets)} packets."
        )
    return anomalies
