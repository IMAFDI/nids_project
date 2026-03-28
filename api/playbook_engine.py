from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from config.database_v2 import (
    create_playbook_execution,
    get_event_by_id,
    get_playbook,
    get_ticket_integration_config,
    list_playbooks,
    set_event_severity,
    update_playbook,
    get_case,
    log_audit,
)
from config.notifications_v2 import send_notification
from config.settings import get_settings
from config.threat_intel import get_threat_intel_engine

logger = logging.getLogger("NIDS.Playbooks")

SAFE_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _action_safety_enabled(action_type: str) -> bool:
    flag = f"NIDS_PLAYBOOK_ALLOW_{action_type.upper()}"
    value = str(__import__("os").environ.get(flag, "false")).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _severity_gte(lhs: str, rhs: str) -> bool:
    try:
        return SEVERITY_ORDER.index(lhs.upper()) >= SEVERITY_ORDER.index(rhs.upper())
    except ValueError:
        return False


def event_matches_playbook(playbook: dict[str, Any], event: dict[str, Any]) -> bool:
    severities = [str(s).upper() for s in (playbook.get("trigger_severities") or [])]
    rule_ids = [int(r) for r in (playbook.get("trigger_rule_ids") or []) if str(r).isdigit()]
    event_types = [str(t).lower() for t in (playbook.get("trigger_event_types") or [])]
    if severities and str(event.get("severity", "")).upper() not in severities:
        return False
    if rule_ids:
        event_rule_id = event.get("rule_id")
        if event_rule_id is None or int(event_rule_id) not in rule_ids:
            return False
    if event_types and str(event.get("event_type", "")).lower() not in event_types:
        return False
    return True


def _build_ticket_payload(action_cfg: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    provider = str(action_cfg.get("provider_type", "generic")).lower()
    title = str(action_cfg.get("title") or f"NIDS Alert - {context.get('severity', 'MEDIUM')}")
    body = str(action_cfg.get("body") or context.get("description") or "NIDS playbook ticket")
    payload = {
        "provider_type": provider,
        "title": title,
        "body": body,
        "severity": context.get("severity"),
        "event_id": context.get("event_id"),
        "case_id": context.get("case_id"),
        "rule_id": context.get("rule_id"),
        "src_ip": context.get("src_ip"),
        "dst_ip": context.get("dst_ip"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    payload.update(action_cfg.get("payload", {}))
    return payload


def _run_single_action(
    playbook: dict[str, Any],
    action_cfg: dict[str, Any],
    context: dict[str, Any],
    actor: str,
    actor_type: str,
) -> dict[str, Any]:
    action_type = str(action_cfg.get("type", "")).strip()
    if not action_type:
        raise ValueError("playbook action missing type")

    started_at = datetime.now(timezone.utc)
    status = "success"
    payload: dict[str, Any] = {}
    error_text: str | None = None

    try:
        if action_type == "add_to_blocklist":
            if not _action_safety_enabled("add_to_blocklist"):
                raise PermissionError("Action add_to_blocklist is disabled by safety flag")
            target_ip = action_cfg.get("ip") or context.get("src_ip")
            if not target_ip:
                raise ValueError("No IP available for add_to_blocklist action")
            source = str(action_cfg.get("source", "playbook"))
            ok = get_threat_intel_engine().add_to_blocklist(str(target_ip), source=source)
            if not ok:
                raise RuntimeError("Threat intel engine failed to add IP to blocklist")
            payload = {"blocked_ip": str(target_ip), "source": source}

        elif action_type == "escalate_event_severity":
            event_id = context.get("event_id")
            if not event_id:
                raise ValueError("No event_id available for escalate_event_severity action")
            current_sev = str(context.get("severity", "LOW")).upper()
            target_sev = str(action_cfg.get("target_severity", "HIGH")).upper()
            if target_sev not in SAFE_SEVERITIES:
                raise ValueError("Invalid target_severity")
            if _severity_gte(current_sev, target_sev):
                status = "skipped"
                payload = {"message": "Event already at equal/higher severity", "current": current_sev, "target": target_sev}
            else:
                updated = set_event_severity(int(event_id), target_sev)
                if not updated:
                    raise RuntimeError("Failed to update event severity")
                context["severity"] = target_sev
                payload = {"event_id": int(event_id), "old_severity": current_sev, "new_severity": target_sev}

        elif action_type == "create_ticket":
            ticket_payload = _build_ticket_payload(action_cfg, context)
            provider = ticket_payload["provider_type"]
            config_row = get_ticket_integration_config(provider)
            if not config_row or not config_row.get("enabled"):
                raise RuntimeError(f"Ticket integration provider '{provider}' is not configured/enabled")
            payload = {
                "provider_type": provider,
                "request_payload": ticket_payload,
                "result": "stub_created",
            }

        elif action_type == "notify_channel":
            description = str(action_cfg.get("description") or context.get("description") or "Playbook notification")
            send_notification(
                severity=str(context.get("severity") or "HIGH"),
                description=description,
                event_type=str(context.get("event_type") or "signature"),
                src_ip=context.get("src_ip"),
                dst_ip=context.get("dst_ip"),
                protocol=context.get("protocol"),
                rule_id=context.get("rule_id"),
                rule_name=str(action_cfg.get("rule_name") or playbook.get("name") or "Playbook"),
                event_id=context.get("event_id"),
                threat_intel_score=context.get("threat_intel_score"),
            )
            payload = {"queued": True, "channel_mode": "notifications_v2_default_fanout"}

        else:
            raise ValueError(f"Unsupported playbook action: {action_type}")

    except Exception as exc:
        status = "failed"
        error_text = str(exc)
        payload = {"action_type": action_type}
        logger.error("Playbook action failed: playbook=%s action=%s err=%s", playbook.get("id"), action_type, exc)

    finished_at = datetime.now(timezone.utc)
    execution = create_playbook_execution(
        playbook_id=int(playbook["id"]),
        event_id=context.get("event_id"),
        case_id=context.get("case_id"),
        action=action_type,
        status=status,
        response_payload=payload,
        error_details=error_text,
        actor=actor,
        actor_type=actor_type,
        started_at=started_at,
        finished_at=finished_at,
    )
    log_audit(
        action="PLAYBOOK_ACTION_EXECUTED",
        resource_type="playbook_execution",
        resource_id=int(execution["id"]),
        user=actor,
        details={
            "playbook_id": int(playbook["id"]),
            "action": action_type,
            "status": status,
            "event_id": context.get("event_id"),
            "case_id": context.get("case_id"),
        },
    )
    return execution


def run_playbook(
    playbook: dict[str, Any],
    context: dict[str, Any],
    actor: str = "system",
    actor_type: str = "system",
) -> dict[str, Any]:
    actions = playbook.get("actions") or []
    if not isinstance(actions, list) or not actions:
        raise ValueError("Playbook has no actions")

    results: list[dict[str, Any]] = []
    success_count = 0
    failure_count = 0
    skipped_count = 0

    for action_cfg in actions:
        if not isinstance(action_cfg, dict):
            raise ValueError("Playbook action definition must be an object")
        result = _run_single_action(playbook, action_cfg, context, actor=actor, actor_type=actor_type)
        results.append(result)
        status = result.get("status")
        if status == "success":
            success_count += 1
        elif status == "failed":
            failure_count += 1
        else:
            skipped_count += 1

    update_playbook(
        int(playbook["id"]),
        last_run_at=datetime.now(timezone.utc),
        success_count=int(playbook.get("success_count", 0)) + success_count,
        failure_count=int(playbook.get("failure_count", 0)) + failure_count,
    )

    return {
        "playbook_id": int(playbook["id"]),
        "executions": results,
        "summary": {
            "success": success_count,
            "failed": failure_count,
            "skipped": skipped_count,
        },
    }


def run_playbooks_for_event(event_id: int, actor: str = "system", actor_type: str = "system") -> list[dict[str, Any]]:
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    enabled_playbooks = list_playbooks(enabled=True)
    matching = [pb for pb in enabled_playbooks if event_matches_playbook(pb, event)]
    results = []
    context = {
        "event_id": event.get("id"),
        "case_id": None,
        "event_type": event.get("event_type"),
        "severity": event.get("severity"),
        "rule_id": event.get("rule_id"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "protocol": event.get("protocol"),
        "description": event.get("description"),
        "threat_intel_score": event.get("threat_intel_score"),
    }
    for playbook in matching:
        results.append(run_playbook(playbook, context=dict(context), actor=actor, actor_type=actor_type))
    return results


def run_playbook_for_case(playbook: dict[str, Any], case_id: int, actor: str = "system", actor_type: str = "system") -> dict[str, Any]:
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    context = {
        "event_id": None,
        "case_id": case_id,
        "event_type": "case",
        "severity": case.get("severity", "MEDIUM"),
        "rule_id": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "description": case.get("title", f"Case #{case_id}"),
    }
    return run_playbook(playbook, context=context, actor=actor, actor_type=actor_type)


def queue_playbook_execution_for_event(event_id: int, actor: str = "system", actor_type: str = "system") -> None:
    async def _run() -> None:
        await asyncio.to_thread(run_playbooks_for_event, event_id, actor, actor_type)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_run())
    except RuntimeError:
        run_playbooks_for_event(event_id, actor=actor, actor_type=actor_type)
