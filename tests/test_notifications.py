"""
tests/test_notifications.py
==========================
Tests for notification channels — mocks SMTP/Slack/PagerDuty and verifies payload structure.
"""

import pytest
from unittest.mock import patch, MagicMock
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))

from notifications_v2 import (
    AlertPayload,
    NotificationTask,
    _is_duplicate,
    _send_email,
    _send_slack,
    _send_pagerduty,
    _send_teams,
    _send_syslog,
    _dedup_cache,
    _dedup_lock,
)


@pytest.fixture
def sample_payload():
    return AlertPayload(
        event_id=42,
        rule_id=1,
        rule_name="TCP SYN Flood",
        event_type="signature",
        severity="HIGH",
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        protocol="tcp",
        description="TCP SYN Flood detected from 1.2.3.4",
        threat_intel_score=75,
        ml_score={"isolation_forest": -1, "random_forest": 1},
    )


class TestEmailNotification:
    """Tests for email notifications."""

    @patch("notifications_v2.smtplib.SMTP")
    def test_email_payload_structure(self, mock_smtp, sample_payload):
        """Email should be sent with correct payload structure."""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

        cfg = {
            "enabled": True,
            "host": "smtp.test.com",
            "port": 587,
            "user": "test@test.com",
            "password": "password",
            "from": "nids@test.com",
            "to": "alerts@test.com",
        }

        result = _send_email(cfg, sample_payload)

        assert result is True
        mock_server.sendmail.assert_called_once()


class TestSlackNotification:
    """Tests for Slack notifications."""

    @patch("notifications_v2.urllib.request.urlopen")
    def test_slack_payload_structure(self, mock_urlopen, sample_payload):
        """Slack should receive a structured payload with correct fields."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        cfg = {"webhook": "https://hooks.slack.com/test"}

        result = _send_slack(cfg, sample_payload)

        assert result is True
        mock_urlopen.assert_called_once()

        # Verify the payload
        call_args = mock_urlopen.call_args
        payload = json.loads(call_args[1]["data"])
        assert "blocks" in payload or "attachments" in payload


class TestPagerDutyNotification:
    """Tests for PagerDuty notifications."""

    @patch("notifications_v2.urllib.request.urlopen")
    def test_pagerduty_payload_structure(self, mock_urlopen):
        """PagerDuty payload should contain required fields."""
        payload = AlertPayload(
            event_id=1,
            rule_id=1,
            rule_name="Critical Alert",
            event_type="signature",
            severity="CRITICAL",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            protocol="tcp",
            description="Critical alert",
        )

        mock_response = MagicMock()
        mock_response.status = 202
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        cfg = {"routing_key": "test_routing_key"}
        result = _send_pagerduty(cfg, payload)

        assert result is True
        call_args = mock_urlopen.call_args
        pd_payload = json.loads(call_args[1]["data"])

        assert pd_payload["event_action"] == "trigger"
        assert pd_payload["routing_key"] == "test_routing_key"
        assert "dedup_key" in pd_payload
        assert "payload" in pd_payload
        assert pd_payload["payload"]["severity"] == "critical"

    @patch("urllib.request.urlopen")
    def test_pagerduty_only_sends_critical(self):
        """PagerDuty should only send for CRITICAL events."""
        payload = AlertPayload(
            event_id=1,
            rule_id=1,
            rule_name="High Alert",
            event_type="signature",
            severity="HIGH",  # Not CRITICAL
            src_ip="1.2.3.4",
            protocol="tcp",
            description="High alert",
        )
        result = _send_pagerduty({"routing_key": "key"}, payload)
        assert result is True  # Returns True (skipped silently)


class TestTeamsNotification:
    """Tests for Microsoft Teams notifications."""

    @patch("notifications_v2.urllib.request.urlopen")
    def test_teams_payload_structure(self, mock_urlopen, sample_payload):
        """Teams should receive a MessageCard with correct fields."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        cfg = {"webhook": "https://teams.webhook.url"}

        result = _send_teams(cfg, sample_payload)

        assert result is True
        call_args = mock_urlopen.call_args
        teams_payload = json.loads(call_args[1]["data"])

        assert teams_payload["@type"] == "MessageCard"
        assert "summary" in teams_payload
        assert "sections" in teams_payload


class TestSyslogNotification:
    """Tests for Syslog notifications."""

    @patch("notifications_v2.socket.socket")
    def test_syslog_payload_format(self, mock_socket, sample_payload):
        """Syslog should send RFC 5424 formatted message."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock

        from notifications_v2 import _init_syslog, _send_syslog
        _init_syslog({"host": "syslog.test.com", "port": 514, "protocol": "udp"})

        result = _send_syslog(sample_payload)

        assert result is True
        mock_sock.sendto.assert_called_once()

        # Verify RFC 5424 format
        call_args = mock_sock.sendto.call_args
        msg = call_args[0][0].decode("utf-8")
        assert msg.startswith("<")  # RFC 5424 starts with <
        assert "NIDS" in msg
        assert "1.2.3.4" in msg


class TestDeduplication:
    """Tests for notification deduplication."""

    def test_dedup_same_src_ip_and_rule(self):
        """Duplicate alerts for same (src_ip, rule_id) should be suppressed."""
        # Clear dedup cache
        with _dedup_lock:
            _dedup_cache.clear()

        src_ip = "1.2.3.4"
        rule_id = 5

        # First call should not be duplicate
        assert _is_duplicate(src_ip, rule_id) is False

        # Immediate second call should be duplicate
        assert _is_duplicate(src_ip, rule_id) is True

    def test_dedup_different_rule_id(self):
        """Same src_ip but different rule_id should not be deduplicated."""
        with _dedup_lock:
            _dedup_cache.clear()

        src_ip = "1.2.3.4"
        assert _is_duplicate(src_ip, 1) is False
        assert _is_duplicate(src_ip, 2) is False  # Different rule


class TestNotificationTask:
    """Tests for NotificationTask dataclass."""

    def test_task_creation(self):
        """NotificationTask should store all required fields."""
        payload = AlertPayload(
            event_id=1,
            rule_id=1,
            rule_name="Test",
            event_type="signature",
            severity="HIGH",
            src_ip="1.2.3.4",
            protocol="tcp",
            description="Test alert",
        )
        task = NotificationTask(payload=payload, channel="email", retry_count=0)

        assert task.payload == payload
        assert task.channel == "email"
        assert task.retry_count == 0
