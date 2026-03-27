"""
tests/test_threat_intel.py
=======================
Tests for the threat intelligence engine — mocks AbuseIPDB API responses.
"""

import pytest
from unittest.mock import patch, MagicMock
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))

from threat_intel import (
    ThreatIntelEngine,
    ThreatIntelResult,
    TTLCache,
    BlocklistLoader,
    AbuseIPDBClient,
)


class TestTTLCache:
    """Tests for the in-memory TTL cache."""

    def test_cache_set_and_get(self):
        """Should store and retrieve values."""
        cache = TTLCache(ttl_seconds=3600)
        result = ThreatIntelResult(
            ip="1.2.3.4",
            score=50,
            source="abuseipdb",
            is_malicious=False,
        )
        cache.set("1.2.3.4", result)
        retrieved = cache.get("1.2.3.4")
        assert retrieved is not None
        assert retrieved.ip == "1.2.3.4"
        assert retrieved.score == 50
        assert retrieved.cached is True

    def test_cache_expiry(self):
        """Values should expire after TTL."""
        import time
        cache = TTLCache(ttl_seconds=1)
        result = ThreatIntelResult(
            ip="1.2.3.4",
            score=50,
            source="abuseipdb",
            is_malicious=False,
        )
        cache.set("1.2.3.4", result)
        time.sleep(1.1)
        assert cache.get("1.2.3.4") is None

    def test_cache_miss(self):
        """Cache miss should return None."""
        cache = TTLCache(ttl_seconds=3600)
        assert cache.get("nonexistent") is None

    def test_cache_clear(self):
        """Clear should remove all entries."""
        cache = TTLCache(ttl_seconds=3600)
        result = ThreatIntelResult(
            ip="1.2.3.4",
            score=50,
            source="abuseipdb",
            is_malicious=False,
        )
        cache.set("1.2.3.4", result)
        cache.clear()
        assert cache.get("1.2.3.4") is None


class TestBlocklistLoader:
    """Tests for blocklist loading."""

    def test_load_blocklist_file(self, tmp_path):
        """Should load IPs and CIDRs from a blocklist file."""
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()

        blocklist_file = blocklist_dir / "test_blocklist.txt"
        blocklist_file.write_text("# Comment\n1.2.3.4\n10.0.0.0/8\n192.168.1.0/24\n")

        loader = BlocklistLoader(blocklist_dir)
        loader.load()

        assert loader.is_blocked("1.2.3.4") is True
        assert loader.is_blocked("10.0.5.5") is True  # Within 10.0.0.0/8
        assert loader.is_blocked("192.168.1.100") is True  # Within /24
        assert loader.is_blocked("8.8.8.8") is False

    def test_get_blocked_entries(self, tmp_path):
        """Should return all blocked entries."""
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()

        blocklist_file = blocklist_dir / "test.txt"
        blocklist_file.write_text("1.2.3.4\n10.0.0.0/8\n")

        loader = BlocklistLoader(blocklist_dir)
        loader.load()

        entries = loader.get_blocked_entries()
        assert len(entries) == 2
        assert any(e["ip"] == "1.2.3.4" and e["type"] == "ip" for e in entries)
        assert any(e["ip"] == "10.0.0.0/8" and e["type"] == "cidr" for e in entries)


class TestAbuseIPDBClient:
    """Tests for AbuseIPDB API client."""

    @patch("threat_intel.urllib.request.urlopen")
    def test_check_ip_returns_data(self, mock_urlopen):
        """Should parse and return AbuseIPDB response data."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 75,
                "countryCode": "US",
                "isp": "Example ISP",
                "domain": "example.com",
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        client = AbuseIPDBClient(api_key="test_key")
        result = client.check_ip("1.2.3.4")

        assert result is not None
        assert result["abuseConfidenceScore"] == 75
        assert result["countryCode"] == "US"

    @patch("threat_intel.urllib.request.urlopen")
    def test_check_ip_handles_error(self, mock_urlopen):
        """Should return None on HTTP error."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=None,
        )

        client = AbuseIPDBClient(api_key="test_key")
        result = client.check_ip("1.2.3.4")

        assert result is None

    def test_check_ip_no_api_key(self):
        """Should return None if no API key configured."""
        client = AbuseIPDBClient(api_key="")
        result = client.check_ip("1.2.3.4")
        assert result is None


class TestThreatIntelEngine:
    """Tests for the unified ThreatIntelEngine."""

    def test_engine_initialization(self):
        """Engine should initialize with correct defaults."""
        engine = ThreatIntelEngine(
            abuseipdb_api_key="test_key",
            blocklist_dir=None,
            cache_ttl_seconds=1800,
            escalation_threshold=50,
        )
        assert engine.abuseipdb is not None
        assert engine.cache is not None
        assert engine.blocklist is not None
        assert engine.escalation_threshold == 50

    @patch("threat_intel._get_country_code")
    def test_check_ip_blocklist_hit(self, mock_geo, tmp_path):
        """Should return malicious if IP is in blocklist."""
        mock_geo.return_value = "US"
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()
        blocklist_file = blocklist_dir / "test.txt"
        blocklist_file.write_text("5.6.7.8\n")

        engine = ThreatIntelEngine(
            blocklist_dir=blocklist_dir,
            cache_ttl_seconds=3600,
        )
        engine.start()

        result = engine.check_ip("5.6.7.8")

        assert result.is_malicious is True
        assert result.score == 100
        assert result.source == "blocklist"

    @patch("threat_intel._get_country_code")
    def test_check_ip_clean(self, mock_geo, tmp_path):
        """Should return non-malicious for clean IP."""
        mock_geo.return_value = "CA"
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()

        engine = ThreatIntelEngine(
            blocklist_dir=blocklist_dir,
            cache_ttl_seconds=3600,
        )
        engine.start()

        result = engine.check_ip("8.8.8.8")

        assert result.is_malicious is False
        assert result.score == 0
        assert result.source == "none"

    def test_should_escalate_malicious_ip(self, tmp_path):
        """Should escalate severity for high-confidence malicious IPs."""
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()
        blocklist_file = blocklist_dir / "test.txt"
        blocklist_file.write_text("5.6.7.8\n")

        engine = ThreatIntelEngine(
            blocklist_dir=blocklist_dir,
            cache_ttl_seconds=3600,
            escalation_threshold=50,
        )
        engine.start()

        should_escalate, score = engine.should_escalate("5.6.7.8", "MEDIUM")

        assert should_escalate is True
        assert score == 100

    def test_should_not_escalate_clean_ip(self, tmp_path):
        """Should not escalate for clean IPs."""
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()

        engine = ThreatIntelEngine(
            blocklist_dir=blocklist_dir,
            cache_ttl_seconds=3600,
            escalation_threshold=50,
        )
        engine.start()

        should_escalate, score = engine.should_escalate("8.8.8.8", "MEDIUM")

        assert should_escalate is False
        assert score == 0

    def test_add_to_blocklist(self, tmp_path):
        """Should add IP to manual blocklist file."""
        blocklist_dir = tmp_path / "blocklists"
        blocklist_dir.mkdir()

        engine = ThreatIntelEngine(blocklist_dir=blocklist_dir)
        engine.start()

        success = engine.add_to_blocklist("1.2.3.4", source="manual")
        assert success is True
        assert engine.blocklist.is_blocked("1.2.3.4") is True
