"""
tests/test_api.py
================
Integration tests for all FastAPI endpoints.
"""

import pytest
import os
import sys
from contextlib import ExitStack
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
    with ExitStack() as stack:
        mock_init = stack.enter_context(patch("api.main.init_db"))
        mock_recent = stack.enter_context(patch("api.main.get_recent_events"))
        mock_stats = stack.enter_context(patch("api.main.get_stats"))
        mock_search = stack.enter_context(patch("api.main.search_events"))
        mock_ack = stack.enter_context(patch("api.main.acknowledge_event"))
        mock_delete = stack.enter_context(patch("api.main.delete_event"))
        mock_clear = stack.enter_context(patch("api.main.clear_events"))
        mock_get_rules = stack.enter_context(patch("api.main.get_rules"))
        mock_get_rule = stack.enter_context(patch("api.main.get_rule"))
        mock_create_rule = stack.enter_context(patch("api.main.create_rule"))
        mock_update_rule = stack.enter_context(patch("api.main.update_rule"))
        mock_delete_rule = stack.enter_context(patch("api.main.delete_rule"))
        mock_toggle_rule = stack.enter_context(patch("api.main.toggle_rule"))
        mock_rules_mitre = stack.enter_context(patch("api.main.get_rules_by_mitre"))
        mock_audit = stack.enter_context(patch("api.main.log_audit"))
        mock_ti = stack.enter_context(patch("api.main.get_threat_intel_engine"))
        mock_list_retention_policies = stack.enter_context(patch("api.main.list_retention_policies"))
        mock_create_retention_policy = stack.enter_context(patch("api.main.create_retention_policy"))
        mock_get_retention_policy = stack.enter_context(patch("api.main.get_retention_policy"))
        mock_update_retention_policy = stack.enter_context(patch("api.main.update_retention_policy"))
        mock_delete_retention_policy = stack.enter_context(patch("api.main.delete_retention_policy"))
        mock_retention_preview = stack.enter_context(patch("api.main.retention_maintenance_preview"))
        mock_retention_execute = stack.enter_context(patch("api.main.execute_retention_maintenance"))
        mock_create_slo_snapshot = stack.enter_context(patch("api.main.create_slo_snapshot"))
        mock_list_slo_snapshots = stack.enter_context(patch("api.main.list_slo_snapshots"))
        mock_create_backup_operation = stack.enter_context(patch("api.main.create_backup_operation"))
        mock_list_backup_operations = stack.enter_context(patch("api.main.list_backup_operations"))
        mock_raw_connection = stack.enter_context(patch("api.main.get_raw_connection"))
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
            "rules_mitre": mock_rules_mitre,
            "audit": mock_audit,
            "threat_intel": mock_ti,
            "list_retention_policies": mock_list_retention_policies,
            "create_retention_policy": mock_create_retention_policy,
            "get_retention_policy": mock_get_retention_policy,
            "update_retention_policy": mock_update_retention_policy,
            "delete_retention_policy": mock_delete_retention_policy,
            "retention_preview": mock_retention_preview,
            "retention_execute": mock_retention_execute,
            "create_slo_snapshot": mock_create_slo_snapshot,
            "list_slo_snapshots": mock_list_slo_snapshots,
            "create_backup_operation": mock_create_backup_operation,
            "list_backup_operations": mock_list_backup_operations,
            "raw_connection": mock_raw_connection,
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
# ---------------------------------------------------------------------------

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
# ---------------------------------------------------------------------------

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


def test_filter_rules_by_mitre(client, mock_db, auth_token):
    """Should filter rules by MITRE technique."""
    mock_db["rules_mitre"].return_value = [
        {"id": 1, "name": "MITRE Rule", "rule_type": "SIGNATURE", "enabled": True,
         "version": 1, "priority": "HIGH", "description": "Mapped rule", "criteria": {},
         "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
         "last_matched": None, "match_count": 0, "lifecycle_state": "production",
         "mitre_tactics": ["credential-access"], "mitre_techniques": ["T1110"],
         "suppression_enabled": False, "suppression_window_seconds": 0}
    ]
    resp = client.get(
        "/api/v1/rules/mitre?technique=T1110",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_promote_rule_lifecycle(client, mock_db, auth_token):
    """Should promote rule lifecycle state."""
    mock_db["update_rule"].return_value = True
    mock_db["get_rule"].return_value = {
        "id": 1, "name": "Rule", "rule_type": "SIGNATURE", "enabled": True,
        "version": 2, "priority": "MEDIUM", "description": "Rule", "criteria": {},
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "last_matched": None, "match_count": 0, "lifecycle_state": "staging",
        "mitre_tactics": [], "mitre_techniques": [], "suppression_enabled": False,
        "suppression_window_seconds": 0
    }
    resp = client.post(
        "/api/v1/rules/1/lifecycle",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"lifecycle_state": "staging"},
    )
    assert resp.status_code == 200
    assert resp.json()["lifecycle_state"] == "staging"


# ---------------------------------------------------------------------------
# Blocklist (protected)
# ---------------------------------------------------------------------------

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
# ---------------------------------------------------------------------------

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
# ---------------------------------------------------------------------------

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


def test_slo_summary_shape(client, mock_db, auth_token):
    mock_db["list_slo_snapshots"].return_value = [{
        "id": 1,
        "tenant_id": None,
        "ingestion_availability": 100,
        "latency_p50_ms": 1,
        "latency_p95_ms": 2,
        "queue_depth": 0,
        "queue_trend": "stable",
        "broker_state": "disabled",
        "db_state": "up",
        "cache_state": "degraded",
        "error_budget_remaining": 100,
        "created_at": "2026-01-01T00:00:00Z",
    }]
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)
    mock_conn.cursor.return_value = mock_cursor
    mock_db["raw_connection"].return_value = mock_conn

    resp = client.get(
        "/api/v1/system/slo",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "ingestion_availability" in data
    assert "event_processing_latency_ms" in data
    assert "queue_depth_trend" in data
    assert "connectivity" in data
    assert "error_budget_remaining" in data


def test_retention_delete_confirmation_required(client, mock_db, auth_token):
    resp = client.post(
        "/api/v1/system/retention/execute",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"apply_delete": True, "confirm_delete": False},
    )
    assert resp.status_code == 400


def test_backup_hooks_admin(client, mock_db, auth_token):
    mock_db["create_backup_operation"].return_value = {
        "id": 7,
        "operation_type": "backup_start",
        "status": "success",
        "duration_ms": 10,
        "artifact_path": "logs/backups/test.meta",
        "operation_metadata": {"dry_run": True},
        "initiated_by": "admin",
        "source_ip": "127.0.0.1",
        "tenant_id": None,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }

    start_resp = client.post(
        "/api/v1/system/backup/start",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"dry_run": True},
    )
    assert start_resp.status_code == 200

    restore_resp = client.post(
        "/api/v1/system/backup/restore-test",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"dry_run": True},
    )
    assert restore_resp.status_code == 200


def test_backup_start_requires_auth(client, mock_db):
    resp = client.post("/api/v1/system/backup/start", json={"dry_run": True})
    assert resp.status_code == 403
