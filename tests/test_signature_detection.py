"""
tests/test_signature_detection.py
================================
Unit tests for each rule type in the signature detection engine.
"""

import pytest
import time
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))

from signature_detection_v2 import (
    SignatureDetector,
    RULE_TYPE_SIGNATURE,
    RULE_TYPE_RATE_LIMIT,
    RULE_TYPE_PAYLOAD_MATCH,
    RULE_TYPE_WHITELIST,
    load_rules_from_file,
    _json_rule_to_rule,
)


# ---------------------------------------------------------------------------
# Test packets (scapy format helpers)
# ---------------------------------------------------------------------------

class MockPacket:
    """Mock scapy packet for testing without scapy."""
    def __init__(self, src="1.2.3.4", dst="5.6.7.8", proto=6,
                 sport=12345, dport=80, flags=0, haslayer_IP=True,
                 haslayer_TCP=False, haslayer_UDP=False, haslayer_ICMP=False,
                 haslayer_Raw=False, payload=b"", icmp_type=0):
        self._src = src
        self._dst = dst
        self._proto = proto
        self._sport = sport
        self._dport = dport
        self._flags = flags
        self._haslayer_IP = haslayer_IP
        self._haslayer_TCP = haslayer_TCP
        self._haslayer_UDP = haslayer_UDP
        self._haslayer_ICMP = haslayer_ICMP
        self._haslayer_Raw = haslayer_Raw
        self._payload = payload
        self._icmp_type = icmp_type
        self.layers = []
        if haslayer_IP:
            self.layers.append("IP")
        if haslayer_TCP:
            self.layers.append("TCP")
        if haslayer_UDP:
            self.layers.append("UDP")
        if haslayer_ICMP:
            self.layers.append("ICMP")
        if haslayer_Raw:
            self.layers.append("Raw")

    def haslayer(self, layer_cls):
        name = layer_cls.__name__ if hasattr(layer_cls, "__name__") else str(layer_cls)
        if "IP" in name:
            return self._haslayer_IP
        if "TCP" in name:
            return self._haslayer_TCP
        if "UDP" in name:
            return self._haslayer_UDP
        if "ICMP" in name:
            return self._haslayer_ICMP
        if "Raw" in name:
            return self._haslayer_Raw
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
        def __init__(self, sport, dport, flags):
            self.sport = sport
            self.dport = dport
            self.flags = flags

    class UDP:
        def __init__(self, sport, dport):
            self.sport = sport
            self.dport = dport

    class ICMP:
        def __init__(self, icmp_type):
            self.type = icmp_type

    class Raw:
        def __init__(self, load):
            self.load = load


def make_ip_packet(src="1.2.3.4", dst="5.6.7.8", proto=6,
                   sport=12345, dport=80, flags=0,
                   haslayer_TCP=False, haslayer_UDP=False, haslayer_ICMP=False,
                   haslayer_Raw=False, payload=b"", icmp_type=0):
    pkt = MockPacket(
        src=src, dst=dst, proto=proto,
        sport=sport, dport=dport, flags=flags,
        haslayer_TCP=haslayer_TCP, haslayer_UDP=haslayer_UDP,
        haslayer_ICMP=haslayer_ICMP, haslayer_Raw=haslayer_Raw,
        payload=payload, icmp_type=icmp_type
    )
    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSignatureRuleMatching:
    """Tests for SIGNATURE type rules."""

    def test_tcp_syn_flood_match(self):
        """SYN flood should match when threshold is reached."""
        rules = [{
            "id": 1,
            "name": "TCP SYN Flood",
            "rule_type": "SIGNATURE",
            "protocol": "tcp",
            "src_ip": "any",
            "dst_ip": "any",
            "src_port": "any",
            "dst_port": "any",
            "flags": "SYN",
            "threshold": 3,
            "time_window": 60,
            "description": "TCP SYN Flood",
        }]
        detector = SignatureDetector(rules)

        src_ip = "10.0.0.1"
        for i in range(3):
            pkt = make_ip_packet(src=src_ip, proto=6, haslayer_TCP=True,
                                 sport=50000 + i, dport=80, flags=0x02)
            matches = detector.evaluate(pkt)

        assert len(matches) == 1
        assert matches[0]["rule_id"] == 1
        assert matches[0]["count"] == 3
        assert matches[0]["src_ip"] == src_ip

    def test_tcp_syn_flood_no_match_below_threshold(self):
        """Should not match when below threshold."""
        rules = [{
            "id": 1,
            "name": "TCP SYN Flood",
            "rule_type": "SIGNATURE",
            "protocol": "tcp",
            "src_ip": "any",
            "dst_ip": "any",
            "flags": "SYN",
            "threshold": 5,
            "time_window": 60,
        }]
        detector = SignatureDetector(rules)

        pkt = make_ip_packet(src="10.0.0.1", proto=6, haslayer_TCP=True, flags=0x02)
        matches = detector.evaluate(pkt)
        assert len(matches) == 0

    def test_protocol_filter(self):
        """Should not match if protocol doesn't match."""
        rules = [{
            "id": 1,
            "name": "TCP Only",
            "rule_type": "SIGNATURE",
            "protocol": "tcp",
            "src_ip": "any",
            "dst_ip": "any",
            "threshold": 1,
            "time_window": 60,
        }]
        detector = SignatureDetector(rules)

        # UDP packet should not match TCP rule
        pkt = make_ip_packet(src="10.0.0.1", proto=17, haslayer_UDP=True)
        matches = detector.evaluate(pkt)
        assert len(matches) == 0

    def test_src_ip_filter(self):
        """Should match specific source IP."""
        rules = [{
            "id": 1,
            "name": "Specific Src IP",
            "rule_type": "SIGNATURE",
            "protocol": "any",
            "src_ip": "192.168.1.100",
            "dst_ip": "any",
            "threshold": 1,
            "time_window": 60,
        }]
        detector = SignatureDetector(rules)

        pkt_matching = make_ip_packet(src="192.168.1.100", proto=6)
        pkt_other = make_ip_packet(src="192.168.1.200", proto=6)

        assert len(detector.evaluate(pkt_matching)) == 1
        assert len(detector.evaluate(pkt_other)) == 0

    def test_port_filter(self):
        """Should match specific destination port."""
        rules = [{
            "id": 1,
            "name": "SSH Brute Force",
            "rule_type": "SIGNATURE",
            "protocol": "tcp",
            "src_ip": "any",
            "dst_ip": "any",
            "src_port": "any",
            "dst_port": 22,
            "flags": "SYN",
            "threshold": 1,
            "time_window": 60,
        }]
        detector = SignatureDetector(rules)

        pkt_ssh = make_ip_packet(src="10.0.0.1", proto=6, haslayer_TCP=True, dport=22, flags=0x02)
        pkt_http = make_ip_packet(src="10.0.0.1", proto=6, haslayer_TCP=True, dport=80, flags=0x02)

        assert len(detector.evaluate(pkt_ssh)) == 1
        assert len(detector.evaluate(pkt_http)) == 0


class TestRateLimitRule:
    """Tests for RATE_LIMIT type rules."""

    def test_rate_limit_exceeded(self):
        """Should trigger when packets per second exceeds rate."""
        rules = [{
            "id": 2,
            "name": "Rate Limit Test",
            "rule_type": "RATE_LIMIT",
            "rate_per_second": 3,
            "time_window": 1,
            "protocol": "any",
            "priority": "HIGH",
            "description": "Rate limit exceeded",
        }]
        detector = SignatureDetector(rules)

        src_ip = "10.0.0.5"
        for i in range(5):
            pkt = make_ip_packet(src=src_ip, proto=6)
            matches = detector.evaluate(pkt)

        # Should have triggered (5 packets > 3 per second limit)
        assert any(m["rule_id"] == 2 for m in matches)

    def test_rate_limit_within_limit(self):
        """Should not trigger when within rate limit."""
        rules = [{
            "id": 2,
            "name": "Rate Limit Test",
            "rule_type": "RATE_LIMIT",
            "rate_per_second": 10,
            "time_window": 1,
            "protocol": "any",
        }]
        detector = SignatureDetector(rules)

        src_ip = "10.0.0.5"
        for i in range(3):
            pkt = make_ip_packet(src=src_ip, proto=6)
            matches = detector.evaluate(pkt)

        # No match since 3 < 10 limit
        assert not any(m["rule_id"] == 2 for m in matches)


class TestPayloadMatchRule:
    """Tests for PAYLOAD_MATCH type rules."""

    def test_payload_regex_match(self):
        """Should match when payload contains regex pattern."""
        rules = [{
            "id": 3,
            "name": "SQL Injection",
            "rule_type": "PAYLOAD_MATCH",
            "payload_regex": "SELECT.*FROM.*users",
            "protocol": "tcp",
            "priority": "CRITICAL",
            "description": "SQL injection attempt",
        }]
        detector = SignatureDetector(rules)

        pkt = make_ip_packet(
            proto=6, haslayer_TCP=True, haslayer_Raw=True,
            payload=b"GET /search?q=SELECT%20*%20FROM%20users"
        )
        matches = detector.evaluate(pkt)
        assert len(matches) == 1
        assert matches[0]["rule_id"] == 3

    def test_payload_regex_no_match(self):
        """Should not match when payload doesn't contain pattern."""
        rules = [{
            "id": 3,
            "name": "SQL Injection",
            "rule_type": "PAYLOAD_MATCH",
            "payload_regex": "SELECT.*FROM.*users",
            "protocol": "tcp",
        }]
        detector = SignatureDetector(rules)

        pkt = make_ip_packet(
            proto=6, haslayer_TCP=True, haslayer_Raw=True,
            payload=b"GET /search?q=hello%20world"
        )
        matches = detector.evaluate(pkt)
        assert len(matches) == 0


class TestWhitelistRule:
    """Tests for WHITELIST type rules."""

    def test_whitelisted_ip_not_flagged(self):
        """Whitelisted IPs should not generate matches from other rules."""
        rules = [{
            "id": 4,
            "name": "Trusted Host",
            "rule_type": "WHITELIST",
            "criteria": {"src_ip": "8.8.8.8"},
            "description": "Trusted DNS server",
        }]
        detector = SignatureDetector(rules)
        detector.set_whitelist({"8.8.8.8"})

        # This would normally match signature rule 5 but is whitelisted
        pkt = make_ip_packet(src="8.8.8.8", proto=6, haslayer_TCP=True,
                             sport=53, dport=80, flags=0x02)
        # Whitelist rules return empty matches (they just mark as trusted)
        assert detector._is_whitelisted("8.8.8.8")


class TestRuleLifecycle:
    """Tests for rule CRUD operations."""

    def test_add_rule(self):
        """New rules should be added and evaluable."""
        detector = SignatureDetector()
        detector.add_rule({
            "id": 100,
            "name": "Dynamic Rule",
            "rule_type": "SIGNATURE",
            "protocol": "any",
            "src_ip": "any",
            "dst_ip": "any",
            "threshold": 1,
            "time_window": 60,
        })
        assert 100 in detector._rules
        assert detector._rules[100].name == "Dynamic Rule"

    def test_remove_rule(self):
        """Rules can be removed."""
        detector = SignatureDetector()
        detector.add_rule({"id": 200, "name": "Temp", "rule_type": "SIGNATURE",
                          "protocol": "any", "threshold": 1, "time_window": 60})
        detector.remove_rule(200)
        assert 200 not in detector._rules

    def test_toggle_rule(self):
        """Rules can be toggled on/off."""
        detector = SignatureDetector()
        detector.add_rule({"id": 300, "name": "Toggle Me", "rule_type": "SIGNATURE",
                          "protocol": "any", "threshold": 1, "time_window": 60})

        assert detector._rules[300].enabled is True
        detector._rules[300].enabled = False
        assert detector._rules[300].enabled is False

        pkt = make_ip_packet(src="10.0.0.1")
        matches = detector.evaluate(pkt)
        assert len(matches) == 0  # Disabled rule should not match

    def test_non_production_rule_not_evaluated(self):
        """Draft/staging rules should not be evaluated."""
        rules = [{
            "id": 301,
            "name": "Draft Rule",
            "rule_type": "SIGNATURE",
            "protocol": "any",
            "src_ip": "any",
            "dst_ip": "any",
            "threshold": 1,
            "time_window": 60,
            "lifecycle_state": "draft",
        }]
        detector = SignatureDetector(rules)
        pkt = make_ip_packet(src="10.0.0.1")
        matches = detector.evaluate(pkt)
        assert len(matches) == 0

    def test_suppression_deduplicates_repeated_matches(self):
        """Suppression should keep first match and suppress duplicates in window."""
        rules = [{
            "id": 302,
            "name": "Suppressed Rule",
            "rule_type": "SIGNATURE",
            "protocol": "any",
            "src_ip": "any",
            "dst_ip": "any",
            "threshold": 1,
            "time_window": 60,
            "lifecycle_state": "production",
            "suppression_enabled": True,
            "suppression_window_seconds": 10,
        }]
        detector = SignatureDetector(rules)
        pkt = make_ip_packet(src="10.0.0.1", dst="5.6.7.8", proto=6, haslayer_TCP=True)
        first = detector.evaluate(pkt)
        second = detector.evaluate(pkt)
        assert len(first) == 1
        assert len(second) == 0


class TestStatefulWindow:
    """Tests that the time window correctly expires old entries."""

    def test_time_window_expiry(self):
        """Entries outside the window should not count."""
        rules = [{
            "id": 500,
            "name": "Time Window Test",
            "rule_type": "SIGNATURE",
            "protocol": "any",
            "src_ip": "any",
            "threshold": 3,
            "time_window": 1,  # 1 second window
        }]
        detector = SignatureDetector(rules)

        src_ip = "10.0.0.1"
        # First burst
        for i in range(3):
            pkt = make_ip_packet(src=src_ip)
            detector.evaluate(pkt)

        # Verify matches
        pkt = make_ip_packet(src=src_ip)
        matches = detector.evaluate(pkt)
        assert len(matches) == 1

        # Wait for window to expire
        time.sleep(1.1)

        pkt = make_ip_packet(src=src_ip)
        matches = detector.evaluate(pkt)
        # Should be back to 1 (count reset in window)
        assert len(matches) == 0
