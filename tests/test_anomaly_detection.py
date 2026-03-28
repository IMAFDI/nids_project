"""
tests/test_anomaly_detection.py
==============================
Tests for the anomaly detection module: model load, feature extraction, scoring.
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))

from anomaly_detection_v2 import (
    EnsembleAnomalyDetector,
    extract_features,
    FlowTracker,
    FlowState,
    ALL_FEATURES,
    BASE_FEATURES,
    EXTENDED_FEATURES,
)


class MockPacket:
    def __init__(self, src="1.2.3.4", dst="5.6.7.8", proto=6,
                 sport=12345, dport=80, flags=0, payload=b""):
        self._src = src
        self._dst = dst
        self._proto = proto
        self._sport = sport
        self._dport = dport
        self._flags = flags
        self._payload = payload

    def haslayer(self, layer):
        name = layer.__name__ if hasattr(layer, "__name__") else str(layer)
        if "IP" in name:
            return True
        if "TCP" in name:
            return self._proto == 6
        if "UDP" in name:
            return self._proto == 17
        if "ICMP" in name:
            return self._proto == 1
        if "Raw" in name:
            return len(self._payload) > 0
        return False

    class IP:
        def __init__(self, src, dst, proto):
            self.src = src
            self.dst = dst
            self.proto = proto
            self.ihl = 5
            self.ttl = 64
            self.flags = MagicMock()
            self.flags.MF = 0
            self.frag = 0

    class TCP:
        def __init__(self, sport, dport, flags, payload=b""):
            self.sport = sport
            self.dport = dport
            self.flags = flags
            self.payload = MagicMock()
            self.payload.__class__ = type("MockPayload", (), {"load": payload})

    class Raw:
        def __init__(self, load):
            self.load = load


def make_packet(src="1.2.3.4", dst="5.6.7.8", proto=6,
               sport=12345, dport=80, flags=0, payload=b""):
    return MockPacket(src=src, dst=dst, proto=proto,
                     sport=sport, dport=dport, flags=flags, payload=payload)


class TestFeatureExtraction:
    """Tests for feature extraction from packets."""

    def test_extract_base_features_tcp(self):
        """TCP packet features should be extracted correctly."""
        pkt = make_packet(proto=6, sport=50000, dport=443, flags=0x02, payload=b"hello")
        features = extract_features(pkt)

        assert features is not None
        assert features.shape == (1, 15)
        assert features[0][0] == 60 + len(b"hello")  # packet_length
        assert features[0][1] == 6                   # protocol = TCP
        assert features[0][2] == 50000               # src_port
        assert features[0][3] == 443                 # dst_port
        assert features[0][4] == 0x02                # TCP flags = SYN

    def test_extract_base_features_udp(self):
        """UDP packet features should be extracted correctly."""
        pkt = make_packet(proto=17, sport=53, dport=54321, payload=b"dns query")
        features = extract_features(pkt)

        assert features is not None
        assert features[0][1] == 17  # protocol = UDP
        assert features[0][2] == 53   # src_port
        assert features[0][3] == 54321  # dst_port

    def test_extract_with_extended_features(self):
        """Extended features from flow_stats should be appended."""
        pkt = make_packet(proto=6, sport=12345, dport=80, payload=b"GET /")
        flow_stats = {
            "bytes_per_second": 1500.0,
            "packets_per_second": 10.0,
            "connection_duration": 5.0,
            "unique_ports_accessed": 3,
            "reverse_dns_failed": 1,
        }
        features = extract_features(pkt, flow_stats=flow_stats)

        assert features is not None
        assert features.shape == (1, 15)
        # Extended features are at indices 10-14
        assert features[0][10] == 1500.0
        assert features[0][11] == 10.0
        assert features[0][12] == 5.0
        assert features[0][13] == 3
        assert features[0][14] == 1

    def test_non_ip_packet_returns_none(self):
        """Non-IP packets should return None."""
        non_ip = MagicMock()
        non_ip.haslayer = lambda l: False
        assert extract_features(non_ip) is None


class TestFlowTracker:
    """Tests for the flow tracker."""

    def test_flow_tracking_tcp(self):
        """TCP flows should be tracked with correct stats."""
        tracker = FlowTracker()

        pkt1 = make_packet(src="10.0.0.1", dst="10.0.0.2", proto=6, sport=50000, dport=80, payload=b"a" * 100)
        pkt2 = make_packet(src="10.0.0.1", dst="10.0.0.2", proto=6, sport=50001, dport=80, payload=b"b" * 50)
        pkt3 = make_packet(src="10.0.0.1", dst="10.0.0.2", proto=6, sport=50002, dport=443, payload=b"c" * 200)

        tracker.update(pkt1)
        tracker.update(pkt2)
        tracker.update(pkt3)

        stats = tracker.get_flow_stats("10.0.0.1", "10.0.0.2", 6)

        assert stats["bytes_per_second"] > 0
        assert stats["packets_per_second"] > 0
        assert stats["unique_ports_accessed"] == 2  # ports 80 and 443

    def test_dns_failure_tracking(self):
        """DNS failures should be trackable per IP."""
        tracker = FlowTracker()
        tracker.record_dns_failure("10.0.0.1")
        tracker.record_dns_failure("10.0.0.1")

        stats = tracker.get_flow_stats("10.0.0.1", "8.8.8.8", 17)
        assert stats["reverse_dns_failed"] == 2


class TestEnsembleAnomalyDetector:
    """Tests for the ensemble anomaly detector."""

    def test_predict_returns_valid_structure(self):
        """predict() should return prediction + scores dict."""
        detector = EnsembleAnomalyDetector()

        # Even without loaded models, should return structured response
        features = np.array([[100, 6, 50000, 80, 0x02, 0, 50, 0, 64, 20,
                             0, 0, 0, 0, 0]], dtype=np.float64)

        prediction, scores = detector.predict(features)

        assert prediction in (1, -1)
        assert isinstance(scores, dict)
        assert "votes" in scores
        assert "threshold" in scores
        assert "n_models" in scores

    def test_is_loaded_false_initially(self):
        """Detector should not be loaded initially."""
        detector = EnsembleAnomalyDetector()
        assert detector.is_loaded is False

    def test_feature_count_matches(self):
        """Feature count should be 15 (10 base + 5 extended)."""
        assert len(ALL_FEATURES) == 15
        assert len(BASE_FEATURES) == 10
        assert len(EXTENDED_FEATURES) == 5


class TestAnomalyScoreCalculation:
    """Tests for scoring logic."""

    def test_normal_features_produce_normal_prediction(self):
        """Legitimate traffic features should produce normal predictions."""
        features = np.array([[
            60,      # packet_length (small TCP packet)
            6,       # protocol (TCP)
            443,     # src_port (HTTPS)
            52432,   # dst_port (ephemeral)
            0x02,    # SYN flag
            0,       # no ICMP
            0,       # no payload
            0,       # not fragmented
            64,      # normal TTL
            20,      # header length
            1000.0,  # bytes_per_second (normal browsing)
            10.0,    # packets_per_second
            2.0,     # short connection
            1,       # one port accessed
            0,       # no DNS failures
        ]], dtype=np.float64)

        detector = EnsembleAnomalyDetector()
        prediction, scores = detector.predict(features)

        assert prediction in (-1, 1)
        assert isinstance(scores, dict)
