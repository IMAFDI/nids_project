"""
tests/test_playbooks.py
=======================
Playbook API and engine tests with mocked persistence/integrations.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))


@pytest.fixture
def playbook_client():
    from api.main import app, verify_token

    app.router.lifespan_context = MagicMock(return_value=None)
    app.dependency_overrides[verify_token] = lambda: {"uid": 1}

    with patch("api.main.get_user_by_id") as mock_user:
        mock_user.return_value = {
            "id": 1,
            "username": "admin",
            "email": "admin@test.local",
            "role": "admin",
            "is_active": True,
        }
        with TestClient(app) as client:
            yield client
    app.dependency_overrides.clear()


def _auth_headers():
    return {"Authorization": "Bearer test-token"}


def test_list_playbooks_endpoint(playbook_client):
    with patch("api.main.list_playbooks") as mock_list:
        mock_list.return_value = [
            {
                "id": 10,
                "name": "Critical Event Auto-response",
                "description": "Handles critical alerts",
                "trigger_severities": ["CRITICAL"],
                "trigger_rule_ids": [],
                "trigger_event_types": ["signature"],
                "enabled": True,
                "actions": [{"type": "notify_channel"}],
                "last_run_at": None,
                "success_count": 0,
                "failure_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        ]

        resp = playbook_client.get("/api/v1/playbooks", headers=_auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "Critical Event Auto-response"


def test_create_playbook_endpoint(playbook_client):
    row = {
        "id": 11,
        "name": "Ticket on High",
        "description": "Open a ticket for high severity",
        "trigger_severities": ["HIGH", "CRITICAL"],
        "trigger_rule_ids": [],
        "trigger_event_types": ["signature", "anomaly"],
        "enabled": True,
        "actions": [{"type": "create_ticket", "provider_type": "jira"}],
        "last_run_at": None,
        "success_count": 0,
        "failure_count": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    with patch("api.main.create_playbook") as mock_create, patch("api.main.log_audit"):
        mock_create.return_value = row
        resp = playbook_client.post(
            "/api/v1/playbooks",
            headers=_auth_headers(),
            json={
                "name": "Ticket on High",
                "trigger_severities": ["HIGH", "CRITICAL"],
                "trigger_event_types": ["signature", "anomaly"],
                "actions": [{"type": "create_ticket", "config": {"provider_type": "jira"}}],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["id"] == 11


def test_test_playbook_endpoint_executes(playbook_client):
    playbook = {
        "id": 5,
        "name": "PB",
        "description": None,
        "trigger_severities": ["HIGH"],
        "trigger_rule_ids": [],
        "trigger_event_types": ["signature"],
        "enabled": True,
        "actions": [{"type": "notify_channel"}],
        "last_run_at": None,
        "success_count": 0,
        "failure_count": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    with patch("api.main.get_playbook") as mock_get, patch("api.main.run_playbook") as mock_run, patch("api.main.log_audit"):
        mock_get.return_value = playbook
        mock_run.return_value = {"playbook_id": 5, "summary": {"success": 1, "failed": 0, "skipped": 0}, "executions": []}

        resp = playbook_client.post(
            "/api/v1/playbooks/5/test",
            headers=_auth_headers(),
            json={"sample_payload": {"severity": "HIGH", "event_type": "signature"}},
        )
        assert resp.status_code == 200
        assert resp.json()["summary"]["success"] == 1


def test_playbook_engine_execution_path():
    from api.playbook_engine import run_playbook

    playbook = {
        "id": 3,
        "name": "Escalate Event",
        "actions": [{"type": "escalate_event_severity", "target_severity": "CRITICAL"}],
        "success_count": 1,
        "failure_count": 0,
    }
    context = {"event_id": 44, "severity": "HIGH"}

    with patch("api.playbook_engine.set_event_severity") as mock_set_sev, \
         patch("api.playbook_engine.create_playbook_execution") as mock_exec, \
         patch("api.playbook_engine.update_playbook") as mock_update, \
         patch("api.playbook_engine.log_audit"):
        mock_set_sev.return_value = {"id": 44, "severity": "CRITICAL"}
        mock_exec.return_value = {
            "id": 100,
            "status": "success",
            "action": "escalate_event_severity",
            "playbook_id": 3,
        }
        mock_update.return_value = {
            "id": 3,
            "name": "Escalate Event",
        }

        result = run_playbook(playbook, context=context, actor="tester", actor_type="user")
        assert result["summary"]["success"] == 1
        assert result["summary"]["failed"] == 0
