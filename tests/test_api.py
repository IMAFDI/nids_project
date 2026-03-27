"""
tests/test_api.py
================
Integration tests for all FastAPI endpoints.
"""

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

# Add config to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """Mock database functions."""
    with patch("api.main.init_db") as mock_init, \
         patch("api.main.get_recent_events") as mock_recent, \
         patch("api.main.get_stats") as mock_stats, \
         patch("api.main.search_events") as mock_search, \
         patch("api.main.acknowledge_event") as mock_ack, \
         patch("api.main.delete_event") as mock_delete, \
         patch("api.main.clear_events") as mock_clear, \
         patch("api.main.get_rules") as mock_get_rules, \
         patch("api.main.get_rule") as mock_get_rule, \
         patch("api.main.create_rule") as mock_create_rule, \
         patch("api.main.update_rule") as mock_update_rule, \
         patch("api.main.delete_rule") as mock_delete_rule, \
         patch("api.main.toggle_rule") as mock_toggle_rule, \
         patch("api.main.log_audit") as mock_audit, \
         patch("api.main.get_threat_intel_engine") as mock_ti:
        yield {
            "init": mock_init,
            "recent": mock_recent,
            "stats": mock_stats,
            "search": mock_search,
            "ack": mock_ack,
            "delete": mock_delete,
            "clear": mock_clear,
            "get_rules": mock_get_rules,
            "get_rule": mock_get_rule,
            "create_rule": mock_create_rule,
            "update_rule": mock_update_rule,
            "delete_rule": mock_delete_rule,
            "toggle_rule": mock_toggle_rule,
            "audit": mock_audit,
            "threat_intel": mock_ti,
        }


@pytest.fixture
def mock_settings():
    """Mock settings."""
    with patch("api.main.get_settings") as mock:
        settings = MagicMock()
        settings.api.jwt.secret = "test-secret-key"
        settings.api.jwt.algorithm = "HS256"
        settings.api.jwt.expiry_hours = 24
        settings.api.jwt.rate_limit_per_minute = 100
        settings.database.url = "sqlite:///:memory:"
        mock.return_value = settings
        yield mock


@pytest.fixture
def client(mock_db, mock_settings):
    """Create a test client."""
    from fastapi.testclient import TestClient
    from api.main import app

    # Skip lifespan (no real DB)
    app.router.lifespan_context = MagicMock(return_value=None)

    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_token(client):
    """Get an auth token."""
    with patch.dict(os.environ, {"NIDS_API_USER": "admin", "NIDS_API_PASSWORD": "admin"}):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        assert resp.status_code == 200
        return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Health endpoint (no auth)
# ---------------------------------------------------------------------------

def test_health_no_auth(client, mock_db):
    """Health endpoint should not require authentication."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "version" in data
    assert "uptime_seconds" in data


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def test_login_success(client, mock_db):
    """Valid credentials should return a token."""
    with patch.dict(os.environ, {"NIDS_API_USER": "admin", "NIDS_API_PASSWORD": "admin"}):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"


def test_login_invalid_credentials(client, mock_db):
    """Invalid credentials should return 401."""
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Events (protected)
// ---------------------------------------------------------------------------

def test_list_events_requires_auth(client, mock_db):
    """Events endpoint should require authentication."""
    resp = client.get("/api/v1/events")
    assert resp.status_code == 403  # No auth header


def test_list_events_with_auth(client, mock_db, auth_token):
    """Events endpoint should return paginated events with auth."""
    mock_db["search"].return_value = ([
        {"id": 1, "timestamp": "2026-01-01T00:00:00Z", "event_type": "signature",
         "severity": "HIGH", "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
         "protocol": "tcp", "description": "Test event", "rule_id": 1,
         "acknowledged": False, "acknowledged_by": None, "acknowledged_at": None,
         "raw_message": "Test"}
    ], 1)

    resp = client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "total" in data
    assert data["total"] == 1


def test_acknowledge_event(client, mock_db, auth_token):
    """Should be able to acknowledge an event."""
    mock_db["ack"].return_value = True

    resp = client.post(
        "/api/v1/events/1/acknowledge",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"acknowledged_by": "analyst"}
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_delete_event(client, mock_db, auth_token):
    """Should be able to delete an event."""
    mock_db["delete"].return_value = True

    resp = client.delete(
        "/api/v1/events/1",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200


def test_get_single_event(client, mock_db, auth_token):
    """Should retrieve a single event by ID."""
    mock_db["search"].return_value = ([
        {"id": 5, "timestamp": "2026-01-01T00:00:00Z", "event_type": "anomaly",
         "severity": "CRITICAL", "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
         "protocol": "udp", "description": "Anomaly event", "rule_id": None,
         "acknowledged": False, "acknowledged_by": None, "acknowledged_at": None,
         "raw_message": "Anomaly"}
    ], 1)

    resp = client.get(
        "/api/v1/events/5",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200


def test_stats_endpoint(client, mock_db, auth_token):
    """Stats endpoint should return aggregated stats."""
    mock_db["stats"].return_value = {
        "total": 100,
        "low": 30,
        "medium": 40,
        "high": 20,
        "critical": 10,
        "recent_24h": 50,
        "recent_1h": 5,
        "top_sources": [{"src_ip": "1.2.3.4", "count": 20}],
    }

    resp = client.get(
        "/api/v1/stats",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 100
    assert data["critical"] == 10


# ---------------------------------------------------------------------------
# Rules (protected)
// ---------------------------------------------------------------------------

def test_list_rules(client, mock_db, auth_token):
    """Rules endpoint should list all rules."""
    mock_db["get_rules"].return_value = [
        {"id": 1, "name": "SYN Flood", "rule_type": "SIGNATURE", "enabled": True,
         "version": 1, "priority": "HIGH", "description": "TCP SYN flood",
         "criteria": {}, "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-01-01T00:00:00Z", "last_matched": None, "match_count": 0}
    ]

    resp = client.get(
        "/api/v1/rules",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "SYN Flood"


def test_create_rule(client, mock_db, auth_token):
    """Should be able to create a new rule."""
    mock_db["create_rule"].return_value = 10
    mock_db["get_rule"].return_value = {
        "id": 10, "name": "New Rule", "rule_type": "SIGNATURE", "enabled": True,
        "version": 1, "priority": "MEDIUM", "description": "A new rule",
        "criteria": {"protocol": "tcp", "threshold": 5},
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "last_matched": None, "match_count": 0
    }

    resp = client.post(
        "/api/v1/rules",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "New Rule",
            "rule_type": "SIGNATURE",
            "criteria": {"protocol": "tcp", "threshold": 5},
            "description": "A new rule",
        }
    )
    assert resp.status_code == 201
    assert resp.json()["id"] == 10


def test_update_rule(client, mock_db, auth_token):
    """Should be able to update a rule."""
    mock_db["update_rule"].return_value = True
    mock_db["get_rule"].return_value = {
        "id": 1, "name": "Updated Rule", "rule_type": "SIGNATURE", "enabled": False,
        "version": 2, "priority": "HIGH", "description": "Updated",
        "criteria": {},
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "last_matched": None, "match_count": 0
    }

    resp = client.put(
        "/api/v1/rules/1",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"name": "Updated Rule", "enabled": False}
    )
    assert resp.status_code == 200


def test_delete_rule(client, mock_db, auth_token):
    """Should be able to delete a rule."""
    mock_db["delete_rule"].return_value = True

    resp = client.delete(
        "/api/v1/rules/1",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200


def test_toggle_rule(client, mock_db, auth_token):
    """Should be able to toggle a rule's enabled status."""
    mock_db["toggle_rule"].return_value = True
    mock_db["get_rule"].return_value = {
        "id": 1, "name": "Toggled Rule", "rule_type": "SIGNATURE", "enabled": False,
        "version": 1, "priority": "MEDIUM", "description": "Toggled",
        "criteria": {},
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "last_matched": None, "match_count": 0
    }

    resp = client.post(
        "/api/v1/rules/1/toggle",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Blocklist (protected)
// ---------------------------------------------------------------------------

def test_get_blocklist(client, mock_db, auth_token):
    """Should retrieve the blocklist."""
    mock_engine = MagicMock()
    mock_engine.get_blocklist.return_value = [
        {"ip": "1.2.3.4", "type": "ip"},
        {"ip": "192.168.0.0/24", "type": "cidr"},
    ]
    mock_db["threat_intel"].return_value = mock_engine

    resp = client.get(
        "/api/v1/alerts/blocklist",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


def test_add_to_blocklist(client, mock_db, auth_token):
    """Should add an IP to the blocklist."""
    mock_engine = MagicMock()
    mock_engine.add_to_blocklist.return_value = True
    mock_db["threat_intel"].return_value = mock_engine

    resp = client.post(
        "/api/v1/alerts/blocklist",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"ip": "1.2.3.4", "source": "manual"}
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Export
// ---------------------------------------------------------------------------

def test_export_events_csv(client, mock_db, auth_token):
    """Should export events as CSV."""
    mock_db["search"].return_value = ([
        {"id": 1, "timestamp": "2026-01-01", "event_type": "signature",
         "severity": "HIGH", "src_ip": "1.2.3.4"}
    ], 1)

    resp = client.get(
        "/api/v1/export/events?format=csv",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]


def test_export_events_json(client, mock_db, auth_token):
    """Should export events as JSON."""
    mock_db["search"].return_value = ([
        {"id": 1, "timestamp": "2026-01-01", "event_type": "signature",
         "severity": "HIGH", "src_ip": "1.2.3.4"}
    ], 1)

    resp = client.get(
        "/api/v1/export/events?format=json",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# System / reload
// ---------------------------------------------------------------------------

def test_reload_rules(client, mock_db, auth_token):
    """Hot reload should reload rules and blocklists."""
    mock_engine = MagicMock()
    mock_db["threat_intel"].return_value = mock_engine

    resp = client.post(
        "/api/v1/system/reload",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
