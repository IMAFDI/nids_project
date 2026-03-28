"""
NIDS — FastAPI REST API
=======================
All endpoints under /api/v1/* with JWT authentication, rate limiting,
correlation IDs, real-time WebSocket streaming, and full OpenAPI documentation.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import smtplib
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

import psutil
from fastapi import FastAPI, Request, HTTPException, Depends, status, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import jwt

from config.database_v2 import (
    init_db,
    get_recent_events,
    get_stats,
    search_events,
    acknowledge_event,
    delete_event,
    clear_events,
    log_intrusion_event,
    get_rules,
    get_rule,
    create_rule,
    update_rule,
    delete_rule,
    toggle_rule,
    get_rules_by_mitre,
    update_rule_last_trigger,
    log_audit,
    upsert_threat_intel,
    get_threat_intel,
    get_user_by_identifier,
    get_user_by_id,
    get_user_by_email,
    create_user,
    update_user_profile,
    update_user_password,
    create_password_reset_token,
    consume_password_reset_token,
    verify_password,
    touch_user_last_login,
    create_case,
    list_cases,
    get_case_detail,
    update_case,
    add_case_note,
    link_case_event,
    unlink_case_event,
    create_playbook,
    list_playbooks,
    get_playbook,
    update_playbook,
    delete_playbook,
    toggle_playbook,
    list_playbook_executions,
    get_event_by_id,
    upsert_ticket_integration_config,
    get_ticket_integration_config,
    list_retention_policies,
    create_retention_policy,
    get_retention_policy,
    update_retention_policy,
    delete_retention_policy,
    retention_maintenance_preview,
    execute_retention_maintenance,
    create_slo_snapshot,
    list_slo_snapshots,
    create_backup_operation,
    list_backup_operations,
    get_raw_connection,
)
from config.threat_intel import ThreatIntelEngine, get_threat_intel_engine
from config.settings import get_settings
from api.detection_engine import get_detection_engine, PacketData
from api.traffic_simulator import get_traffic_simulator
from api.websocket import (
    handle_events_websocket,
    handle_metrics_websocket,
    broadcast_event,
    broadcast_metrics,
    broadcast_alert,
    manager as ws_manager,
)
from api.message_broker import RabbitMQBroker
from api.playbook_engine import (
    run_playbook,
    run_playbooks_for_event,
    run_playbook_for_case,
    queue_playbook_execution_for_event,
)

logger = logging.getLogger("NIDS.API")

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

security = HTTPBearer()
VALID_ROLES = {"admin", "analyst", "viewer"}


def create_access_token(username: str) -> str:
    """Create a JWT access token."""
    settings = get_settings()
    user = get_user_by_identifier(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    expiry = datetime.now(timezone.utc) + timedelta(hours=settings.api.jwt.expiry_hours)
    payload = {
        "sub": username,
        "uid": user.get("id"),
        "email": user.get("email"),
        "role": user.get("role", "analyst"),
        "exp": expiry,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.api.jwt.secret, algorithm=settings.api.jwt.algorithm)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify a JWT token and return the payload."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.api.jwt.secret,
            algorithms=[settings.api.jwt.algorithm],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(payload: dict = Depends(verify_token)) -> dict:
    user_id = payload.get("uid")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = get_user_by_id(int(user_id))
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def require_roles(*roles: str):
    """Dependency factory to enforce role-based access."""
    allowed_roles = {role.lower() for role in roles}
    if not allowed_roles.issubset(VALID_ROLES):
        invalid = sorted(allowed_roles.difference(VALID_ROLES))
        raise ValueError(f"Invalid RBAC role(s): {', '.join(invalid)}")

    def _require(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = str(current_user.get("role", "viewer")).lower()
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Insufficient permissions for this operation. "
                    f"Required role: {', '.join(sorted(allowed_roles))}"
                ),
            )
        return current_user

    return _require


def _request_ip(request: Request | None) -> str:
    return request.client.host if request and request.client else "unknown"


def _audit_user(current_user: dict | None = None, fallback: str = "system") -> str:
    if not current_user:
        return fallback
    return str(current_user.get("username") or current_user.get("email") or current_user.get("id") or fallback)


def audit_action(
    *,
    request: Request | None,
    action: str,
    resource_type: str,
    resource_id: int | None = None,
    details: dict | None = None,
    current_user: dict | None = None,
    fallback_user: str = "system",
) -> None:
    log_audit(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        user=_audit_user(current_user, fallback=fallback_user),
        details=details or {},
        ip_address=_request_ip(request),
    )


def _send_password_reset_email(email: str, token: str) -> None:
    settings = get_settings()
    email_cfg = settings.notifications.email
    if not email_cfg.enabled:
        logger.warning("Password reset email disabled; request for %s accepted but not sent", email)
        return
    if not (email_cfg.host and email_cfg.port and email_cfg.user and email_cfg.password and email_cfg.from_addr):
        logger.error("Password reset email config incomplete; cannot send reset email to %s", email)
        return

    msg = EmailMessage()
    msg["Subject"] = "NIDS Password Reset"
    msg["From"] = email_cfg.from_addr
    msg["To"] = email
    msg.set_content(
        "A password reset was requested for your NIDS account.\n\n"
        f"Reset token: {token}\n"
        "This token expires in 30 minutes.\n"
        "If you did not request this, you can ignore this email."
    )
    with smtplib.SMTP(email_cfg.host, email_cfg.port, timeout=10) as server:
        server.starttls()
        server.login(email_cfg.user, email_cfg.password)
        server.send_message(msg)


def get_tenant_id(request: Request) -> str | None:
    tenant = request.headers.get("X-Tenant-ID")
    if tenant is None:
        return None
    tenant = tenant.strip()
    return tenant or None


def _normalize_playbook_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for action in actions or []:
        if not isinstance(action, dict):
            raise HTTPException(status_code=400, detail="Each playbook action must be an object")
        action_type = str(action.get("type", "")).strip()
        if not action_type:
            raise HTTPException(status_code=400, detail="Each playbook action requires a type")
        config = action.get("config")
        if config is not None and not isinstance(config, dict):
            raise HTTPException(status_code=400, detail="Action config must be an object")
        normalized_action = {"type": action_type}
        if isinstance(config, dict):
            normalized_action.update(config)
        for key, value in action.items():
            if key not in {"type", "config"}:
                normalized_action[key] = value
        normalized.append(normalized_action)
    return normalized


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str = Field(min_length=8)
    full_name: str | None = None


class UserProfileResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: str
    updated_at: str
    last_login: str | None = None


class UpdateProfileRequest(BaseModel):
    email: str | None = None
    full_name: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetConfirmRequest(BaseModel):
    email: str
    token: str = Field(min_length=16)
    new_password: str = Field(min_length=8)


class RuleCreate(BaseModel):
    name: str
    rule_type: str
    criteria: dict
    description: str | None = None
    priority: str = "MEDIUM"
    lifecycle_state: str = Field(default="production", pattern="^(draft|staging|production)$")
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    suppression_enabled: bool = False
    suppression_window_seconds: int = 0


class RuleUpdate(BaseModel):
    name: str | None = None
    criteria: dict | None = None
    description: str | None = None
    priority: str | None = None
    enabled: bool | None = None
    lifecycle_state: str | None = Field(default=None, pattern="^(draft|staging|production)$")
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    suppression_enabled: bool | None = None
    suppression_window_seconds: int | None = None


class BlocklistEntry(BaseModel):
    ip: str
    source: str = "manual"


class AckRequest(BaseModel):
    acknowledged_by: str = "api"


class StatsResponse(BaseModel):
    total: int
    low: int
    medium: int
    high: int
    critical: int
    recent_24h: int
    recent_1h: int
    top_sources: list[dict[str, Any]]
    by_type: dict[str, int] | None = None
    timeline: list[dict[str, Any]] | None = None


class EventResponse(BaseModel):
    id: int
    timestamp: str
    event_type: str
    severity: str
    src_ip: str | None
    dst_ip: str | None
    protocol: str | None
    src_port: int | None = None
    dst_port: int | None = None
    description: str | None
    rule_id: int | None
    acknowledged: bool
    acknowledged_by: str | None
    acknowledged_at: str | None
    raw_message: str | None
    ml_score: float | None = None
    threat_intel_score: float | None = None
    country_code: str | None = None


class PaginatedEventsResponse(BaseModel):
    events: list[EventResponse]
    total: int
    limit: int
    offset: int


class RuleResponse(BaseModel):
    id: int
    name: str
    rule_type: str
    enabled: bool
    version: int
    priority: str
    description: str | None
    criteria: dict
    lifecycle_state: str = "production"
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    suppression_enabled: bool = False
    suppression_window_seconds: int = 0
    last_trigger_fingerprint: str | None = None
    last_trigger_at: str | None = None
    created_at: str
    updated_at: str
    last_matched: str | None
    match_count: int


class SystemMetrics(BaseModel):
    uptime_seconds: float
    packets_received: int
    packets_processed: int
    packets_dropped: int
    queue_depth: int
    avg_processing_time_ms: float
    packets_per_second: float = 0.0
    events_per_minute: int = 0
    events_detected: int = 0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    websocket_connections: int = 0
    detection_engine_status: str = "running"
    simulator_status: str = "running"
    broker_status: str = "disabled"


class RetentionPolicyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scope: str = Field(default="global", pattern="^(global|severity|tenant)$")
    hot_days: int = Field(default=7, ge=0)
    warm_days: int = Field(default=30, ge=0)
    cold_days: int = Field(default=90, ge=0)
    archive_enabled: bool = True
    delete_after_days: int = Field(default=365, ge=0)
    enabled: bool = True
    severity: str | None = None


class RetentionPolicyUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    scope: str | None = Field(default=None, pattern="^(global|severity|tenant)$")
    hot_days: int | None = Field(default=None, ge=0)
    warm_days: int | None = Field(default=None, ge=0)
    cold_days: int | None = Field(default=None, ge=0)
    archive_enabled: bool | None = None
    delete_after_days: int | None = Field(default=None, ge=0)
    enabled: bool | None = None
    severity: str | None = None


class RetentionPolicyResponse(BaseModel):
    id: int
    name: str
    scope: str
    hot_days: int
    warm_days: int
    cold_days: int
    archive_enabled: bool
    delete_after_days: int
    enabled: bool
    severity: str | None = None
    tenant_id: str | None = None
    created_at: str
    updated_at: str


class RetentionDryRunResponse(BaseModel):
    evaluated_events: int
    archive_candidates: int
    delete_candidates: int
    matched_policy_ids: list[int]


class RetentionExecuteRequest(BaseModel):
    apply_delete: bool = False
    confirm_delete: bool = False


class RetentionExecuteResponse(BaseModel):
    evaluated_events: int
    archived_count: int
    deleted_count: int
    delete_applied: bool
    matched_policy_ids: list[int]


class ConnectivityState(BaseModel):
    broker: str
    database: str
    cache: str


class SLOSummaryResponse(BaseModel):
    window_minutes: int
    ingestion_availability: float
    event_processing_latency_ms: dict[str, float]
    queue_depth_trend: dict[str, Any]
    connectivity: ConnectivityState
    error_budget_remaining: float
    snapshots_recorded: int
    generated_at: str


class SLOSnapshotResponse(BaseModel):
    id: int
    tenant_id: str | None = None
    ingestion_availability: int
    latency_p50_ms: int
    latency_p95_ms: int
    queue_depth: int
    queue_trend: str
    broker_state: str
    db_state: str
    cache_state: str
    error_budget_remaining: int
    created_at: str


class BackupStartRequest(BaseModel):
    target: str = Field(default="database")
    dry_run: bool = True
    include_events: bool = True
    include_rules: bool = True
    include_cases: bool = True


class BackupRestoreTestRequest(BaseModel):
    backup_id: int | None = None
    artifact_path: str | None = None
    dry_run: bool = True


class BackupOperationResponse(BaseModel):
    id: int
    operation_type: str
    status: str
    duration_ms: int | None = None
    artifact_path: str | None = None
    operation_metadata: dict[str, Any] | None = None
    initiated_by: str | None = None
    source_ip: str | None = None
    tenant_id: str | None = None
    created_at: str
    updated_at: str


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    severity: str = "MEDIUM"
    priority: str = "MEDIUM"
    owner_user_id: int | None = None
    event_ids: list[int] = Field(default_factory=list)


class CaseUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    status: str | None = None
    priority: str | None = None
    owner_user_id: int | None = None


class CaseNoteCreateRequest(BaseModel):
    note: str = Field(min_length=1)


class CaseNoteResponse(BaseModel):
    id: int
    case_id: int
    author_user_id: int
    note: str
    created_at: str


class CaseResponse(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    priority: str
    owner_user_id: int | None
    created_by_user_id: int
    created_at: str
    updated_at: str
    closed_at: str | None


class CaseDetailResponse(CaseResponse):
    events: list[EventResponse] = Field(default_factory=list)
    notes: list[CaseNoteResponse] = Field(default_factory=list)


class PaginatedCasesResponse(BaseModel):
    cases: list[CaseResponse]
    total: int
    limit: int
    offset: int


class PlaybookAction(BaseModel):
    type: str
    config: dict[str, Any] = Field(default_factory=dict)


class PlaybookCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    trigger_severities: list[str] = Field(default_factory=list)
    trigger_rule_ids: list[int] = Field(default_factory=list)
    trigger_event_types: list[str] = Field(default_factory=list)
    enabled: bool = True
    actions: list[dict[str, Any]] = Field(default_factory=list)


class PlaybookUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    trigger_severities: list[str] | None = None
    trigger_rule_ids: list[int] | None = None
    trigger_event_types: list[str] | None = None
    enabled: bool | None = None
    actions: list[dict[str, Any]] | None = None


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: str | None = None
    trigger_severities: list[str] = Field(default_factory=list)
    trigger_rule_ids: list[int] = Field(default_factory=list)
    trigger_event_types: list[str] = Field(default_factory=list)
    enabled: bool
    actions: list[dict[str, Any]] = Field(default_factory=list)
    last_run_at: str | None = None
    success_count: int
    failure_count: int
    created_at: str
    updated_at: str


class PlaybookExecutionResponse(BaseModel):
    id: int
    playbook_id: int
    event_id: int | None = None
    case_id: int | None = None
    action: str
    status: str
    response_payload: dict[str, Any] | None = None
    error_details: str | None = None
    actor: str | None = None
    actor_type: str
    started_at: str
    finished_at: str | None = None
    created_at: str


class PaginatedPlaybookExecutionsResponse(BaseModel):
    executions: list[PlaybookExecutionResponse]
    total: int
    limit: int
    offset: int


class PlaybookTestRequest(BaseModel):
    sample_payload: dict[str, Any] = Field(default_factory=dict)


class TicketIntegrationRequest(BaseModel):
    provider_type: str = Field(min_length=1, max_length=50)
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)


class TicketIntegrationResponse(BaseModel):
    id: int
    provider_type: str
    enabled: bool
    config: dict[str, Any]
    created_at: str
    updated_at: str


# ---------------------------------------------------------------------------
# Correlation ID middleware
# ---------------------------------------------------------------------------

async def correlation_id_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id

    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

_start_time = time.time()
_pipeline_metrics = {
    "packets_received": 0,
    "packets_processed": 0,
    "packets_dropped": 0,
    "queue_depth": 0,
    "avg_processing_time_ms": 0.0,
}
_broker: RabbitMQBroker | None = None
_broker_enabled = False
_pipeline_history = {
    "metrics_ts": deque(maxlen=720),
    "queue_depth": deque(maxlen=720),
    "processing_latency_ms": deque(maxlen=720),
}


async def on_event_detected(event_data: dict):
    """Callback when detection engine detects an event."""
    # Log to database
    try:
        details = {
            "src_ip": event_data.get("src_ip"),
            "dst_ip": event_data.get("dst_ip"),
            "protocol": event_data.get("protocol"),
            "src_port": event_data.get("src_port"),
            "dst_port": event_data.get("dst_port"),
            "description": event_data.get("description"),
            "rule_id": event_data.get("rule_id"),
            "packet_length": event_data.get("packet_length"),
            "ml_score": event_data.get("ml_score"),
            "country_code": event_data.get("country_code"),
        }
        event_id = log_intrusion_event(
            event_type=event_data.get("event_type", "signature"),
            severity=event_data.get("severity", "MEDIUM"),
            message=event_data.get("description", "Detection event"),
            details=details,
            tenant_id=event_data.get("tenant_id"),
        )
        if event_data.get("rule_id") and event_data.get("rule_fingerprint"):
            update_rule_last_trigger(
                int(event_data["rule_id"]),
                event_data["rule_fingerprint"],
            )
        if event_id and str(event_data.get("severity", "")).upper() in {"HIGH", "CRITICAL"}:
            queue_playbook_execution_for_event(int(event_id), actor="detection-engine", actor_type="system")
    except Exception as e:
        logger.error(f"Failed to log event: {e}")
    
    # Broadcast via WebSocket
    await broadcast_event(event_data)
    
    # Send alert for high severity
    if event_data.get("severity") in ("HIGH", "CRITICAL"):
        await broadcast_alert(event_data)


async def on_metrics_update(metrics_data: dict):
    """Callback for engine metrics updates."""
    global _pipeline_metrics
    _pipeline_metrics = metrics_data
    now_ts = time.time()
    _pipeline_history["metrics_ts"].append(now_ts)
    _pipeline_history["queue_depth"].append(int(metrics_data.get("queue_depth", 0) or 0))
    _pipeline_history["processing_latency_ms"].append(float(metrics_data.get("avg_processing_time_ms", 0.0) or 0.0))
    await broadcast_metrics(metrics_data)


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return float(ordered[low] * (1 - weight) + ordered[high] * weight)


def _compute_queue_trend_snapshot() -> dict[str, Any]:
    series = list(_pipeline_history["queue_depth"])
    if not series:
        return {"current": 0, "avg_5m": 0.0, "direction": "stable", "recent": []}
    current = int(series[-1])
    tail = series[-60:] if len(series) >= 60 else series
    avg_5m = float(sum(tail) / len(tail))
    if len(tail) >= 2:
        delta = tail[-1] - tail[0]
    else:
        delta = 0
    if delta > 5:
        direction = "rising"
    elif delta < -5:
        direction = "falling"
    else:
        direction = "stable"
    return {
        "current": current,
        "avg_5m": round(avg_5m, 2),
        "direction": direction,
        "recent": tail[-10:],
    }


def _check_db_connectivity() -> str:
    try:
        conn = get_raw_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        return "up"
    except Exception:
        return "down"


def _check_cache_connectivity() -> str:
    try:
        engine = get_threat_intel_engine()
        if getattr(engine, "_redis_available", False):
            return "up"
        return "degraded"
    except Exception:
        return "unknown"


def _compute_slo_summary(window_minutes: int = 15) -> dict[str, Any]:
    metrics_ts = list(_pipeline_history["metrics_ts"])
    queue_depth = list(_pipeline_history["queue_depth"])
    latency = list(_pipeline_history["processing_latency_ms"])
    if not metrics_ts:
        ingestion_availability = 100.0
        p50 = 0.0
        p95 = 0.0
    else:
        now_ts = time.time()
        window_start = now_ts - (window_minutes * 60)
        in_window_indices = [idx for idx, ts in enumerate(metrics_ts) if ts >= window_start]
        observed = len(in_window_indices)
        expected = max(1, window_minutes * 12)
        ingestion_availability = min(100.0, round((observed / expected) * 100.0, 2))
        latency_in_window = [latency[idx] for idx in in_window_indices] if in_window_indices else latency
        p50 = round(_percentile(latency_in_window, 0.50), 2)
        p95 = round(_percentile(latency_in_window, 0.95), 2)

    queue_trend = _compute_queue_trend_snapshot()
    broker_state = "up" if _broker_enabled else "disabled"
    db_state = _check_db_connectivity()
    cache_state = _check_cache_connectivity()
    if queue_depth:
        recent_depth = queue_depth[-1]
    else:
        recent_depth = 0

    latency_budget_ms = 500.0
    availability_budget = max(0.0, 100.0 - ingestion_availability)
    latency_penalty = max(0.0, p95 - latency_budget_ms) / latency_budget_ms * 100.0
    queue_penalty = min(30.0, max(0.0, recent_depth - 100) / 10.0)
    error_budget_remaining = max(0.0, round(100.0 - availability_budget - latency_penalty - queue_penalty, 2))

    return {
        "window_minutes": window_minutes,
        "ingestion_availability": ingestion_availability,
        "event_processing_latency_ms": {"p50": p50, "p95": p95},
        "queue_depth_trend": queue_trend,
        "connectivity": {
            "broker": broker_state,
            "database": db_state,
            "cache": cache_state,
        },
        "error_budget_remaining": error_budget_remaining,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _on_broker_event(loop: asyncio.AbstractEventLoop, event_data: dict):
    """Bridge synchronous broker callback to async event handler."""
    asyncio.run_coroutine_threadsafe(on_event_detected(event_data), loop)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise database, detection engine, and traffic simulator on startup."""
    global _start_time
    _start_time = time.time()
    settings = get_settings()
    
    # Initialize database
    init_db(settings.database.url)
    logger.info("Database initialized.")
    
    # Initialize and start detection engine
    engine = get_detection_engine()
    
    # Load rules from database
    try:
        rules = get_rules()
        engine.load_rules(rules)
    except Exception as e:
        logger.warning(f"Could not load rules: {e}")
    
    # Register callbacks (direct mode by default)
    engine.set_event_publisher(None)
    engine.remove_event_callback(on_event_detected)
    engine.add_event_callback(on_event_detected)
    engine.add_metrics_callback(on_metrics_update)

    # Optional RabbitMQ event bus
    global _broker, _broker_enabled
    _broker = None
    _broker_enabled = False
    if settings.broker.enabled and settings.broker.backend == "rabbitmq":
        try:
            loop = asyncio.get_running_loop()
            _broker = RabbitMQBroker(
                url=settings.broker.rabbitmq_url,
                exchange=settings.broker.exchange,
                queue=settings.broker.queue,
                routing_key=settings.broker.routing_key,
                prefetch_count=settings.broker.prefetch_count,
            )
            _broker.start_consumer(lambda payload: _on_broker_event(loop, payload))
            engine.set_event_publisher(_broker.publish)
            engine.remove_event_callback(on_event_detected)
            _broker_enabled = True
            logger.info("RabbitMQ broker mode enabled.")
        except Exception as e:
            logger.error(f"Failed to initialize RabbitMQ broker mode: {e}")
            _broker = None
            _broker_enabled = False
    
    # Start engine
    await engine.start()
    logger.info("Detection engine started.")
    
    # Start traffic simulator (for demo mode)
    simulator = get_traffic_simulator()
    await simulator.start()
    logger.info("Traffic simulator started.")
    
    logger.info("NIDS API started - Real-time detection active.")
    
    yield
    
    # Shutdown
    if _broker:
        _broker.stop_consumer()
        _broker = None
    await simulator.stop()
    await engine.stop()
    logger.info("NIDS API shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NIDS API",
    description="Network Intrusion Detection System REST API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(correlation_id_middleware)


# ---------------------------------------------------------------------------
# WebSocket endpoints
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await handle_events_websocket(websocket)


@app.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    """WebSocket endpoint for real-time metrics streaming."""
    await handle_metrics_websocket(websocket)


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth/login", response_model=LoginResponse, tags=["auth"])
async def login(req: LoginRequest, request: Request) -> LoginResponse:
    """
    Authenticate and receive a JWT token.
    Default credentials are admin/admin (override via NIDS_JWT_SECRET env var).
    """
    settings = get_settings()

    user = get_user_by_identifier(req.username)
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User account is disabled")

    touch_user_last_login(int(user["id"]))
    audit_action(
        request=request,
        action="LOGIN_SUCCESS",
        resource_type="user_account",
        resource_id=int(user["id"]),
        details={"username": user.get("username"), "role": user.get("role")},
        current_user=user,
        fallback_user="anonymous",
    )
    token = create_access_token(user["username"])
    return LoginResponse(access_token=token)


@app.post("/api/v1/auth/register", response_model=UserProfileResponse, tags=["auth"])
async def register(
    req: RegisterRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> UserProfileResponse:
    """Register a new user account."""
    try:
        user = create_user(
            username=req.username.strip(),
            email=req.email.strip().lower(),
            password=req.password,
            full_name=req.full_name.strip() if req.full_name else None,
            role="analyst",
        )
    except ValueError as e:
        if str(e) == "username_or_email_exists":
            raise HTTPException(status_code=409, detail="Username or email already exists")
        raise
    audit_action(
        request=request,
        action="REGISTER_USER",
        resource_type="user_account",
        resource_id=int(user["id"]),
        details={"username": user.get("username"), "email": user.get("email"), "role": user.get("role")},
        current_user=current_user,
    )
    return UserProfileResponse(**user)


@app.get("/api/v1/auth/me", response_model=UserProfileResponse, tags=["auth"])
async def me(current_user: dict = Depends(get_current_user)) -> UserProfileResponse:
    """Get current authenticated user profile."""
    return UserProfileResponse(**current_user)


@app.put("/api/v1/auth/me", response_model=UserProfileResponse, tags=["auth"])
async def update_me(
    req: UpdateProfileRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> UserProfileResponse:
    """Update current user profile."""
    try:
        updated = update_user_profile(
            user_id=int(current_user["id"]),
            full_name=req.full_name,
            email=req.email.strip().lower() if req.email else None,
        )
    except ValueError as e:
        if str(e) == "email_exists":
            raise HTTPException(status_code=409, detail="Email already in use")
        raise
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    audit_action(
        request=request,
        action="UPDATE_PROFILE",
        resource_type="user_account",
        resource_id=int(current_user["id"]),
        details={"updated_fields": [k for k, v in {"email": req.email, "full_name": req.full_name}.items() if v is not None]},
        current_user=current_user,
    )
    return UserProfileResponse(**updated)


@app.post("/api/v1/auth/change-password", tags=["auth"])
async def change_password(
    req: ChangePasswordRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Change current user password."""
    if not verify_password(req.current_password, current_user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if req.current_password == req.new_password:
        raise HTTPException(status_code=400, detail="New password must be different")
    ok = update_user_password(int(current_user["id"]), req.new_password)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    audit_action(
        request=request,
        action="CHANGE_PASSWORD",
        resource_type="user_account",
        resource_id=int(current_user["id"]),
        details={"password_changed": True},
        current_user=current_user,
    )
    return {"ok": True}


@app.post("/api/v1/auth/forgot-password", tags=["auth"])
async def forgot_password(req: PasswordResetRequest, request: Request) -> dict:
    """Request a password reset token (sent to the user's email)."""
    email = req.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    user = get_user_by_email(email)
    if user and user.get("is_active", True):
        token = create_password_reset_token(
            user_id=int(user["id"]),
            expires_in_minutes=30,
            requested_ip=_request_ip(request),
        )
        _send_password_reset_email(email, token)
        audit_action(
            request=request,
            action="PASSWORD_RESET_REQUESTED",
            resource_type="user_account",
            resource_id=int(user["id"]),
            details={"email": email},
            current_user=user,
            fallback_user="anonymous",
        )
    else:
        audit_action(
            request=request,
            action="PASSWORD_RESET_REQUESTED_UNKNOWN",
            resource_type="user_account",
            resource_id=None,
            details={"email": email},
            current_user=None,
            fallback_user="anonymous",
        )
    return {"ok": True, "message": "If the account exists, a reset email has been sent"}


@app.post("/api/v1/auth/reset-password", tags=["auth"])
async def reset_password(req: PasswordResetConfirmRequest, request: Request) -> dict:
    """Reset password using email + reset token."""
    email = req.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    updated = consume_password_reset_token(
        email=email,
        token=req.token.strip(),
        new_password=req.new_password,
    )
    if not updated:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user = get_user_by_email(email)
    audit_action(
        request=request,
        action="PASSWORD_RESET_COMPLETED",
        resource_type="user_account",
        resource_id=int(user["id"]) if user else None,
        details={"email": email},
        current_user=user,
        fallback_user="anonymous",
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", tags=["system"])
async def health():
    """System health check — no auth required."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "uptime_seconds": round(time.time() - _start_time, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@app.get("/api/v1/events", response_model=PaginatedEventsResponse, tags=["events"])
async def list_events(
    request: Request,
    severity: str | None = None,
    src_ip: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
    page: int | None = None,
    per_page: int | None = None,
    offset: int = 0,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> PaginatedEventsResponse:
    """List intrusion events with pagination and filtering."""
    if per_page is not None:
        limit = max(1, per_page)
    if page is not None and per_page is not None:
        offset = max(0, (page - 1) * per_page)

    events, total = search_events(
        severity=severity,
        event_type=event_type,
        src_ip=src_ip,
        limit=limit,
        offset=offset,
    )
    return PaginatedEventsResponse(
        events=[EventResponse(**e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get("/api/v1/events/{event_id}", response_model=EventResponse, tags=["events"])
async def get_event(event_id: int, _: dict = Depends(require_roles("admin", "analyst", "viewer"))) -> EventResponse:
    """Get a single event by ID."""
    events, total = search_events(limit=1)
    matching = [e for e in events if e.get("id") == event_id]
    if not matching:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventResponse(**matching[0])


@app.post("/api/v1/events/{event_id}/acknowledge", tags=["events"])
async def acknowledge_event_endpoint(
    event_id: int,
    req: AckRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Mark an event as acknowledged."""
    success = acknowledge_event(event_id, req.acknowledged_by)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")

    audit_action(
        request=request,
        action="ACK_EVENT",
        resource_type="intrusion_event",
        resource_id=event_id,
        details={"acknowledged_by": req.acknowledged_by},
        current_user=current_user,
    )
    return {"ok": True, "event_id": event_id}


@app.delete("/api/v1/events/{event_id}", tags=["events"])
async def delete_event_endpoint(
    event_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> dict:
    """Delete a single event."""
    success = delete_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    audit_action(
        request=request,
        action="DELETE_EVENT",
        resource_type="intrusion_event",
        resource_id=event_id,
        details={"deleted": True},
        current_user=current_user,
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@app.post("/api/v1/cases", response_model=CaseResponse, status_code=201, tags=["cases"])
async def create_case_endpoint(
    payload: CaseCreateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> CaseResponse:
    """Create a case and optionally attach intrusion events."""
    severity = (payload.severity or "MEDIUM").upper()
    priority = (payload.priority or "MEDIUM").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="Invalid severity")
    if priority not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="Invalid priority")
    if payload.owner_user_id is not None and not get_user_by_id(payload.owner_user_id):
        raise HTTPException(status_code=404, detail="Owner user not found")

    created = create_case(
        title=payload.title.strip(),
        severity=severity,
        priority=priority,
        owner_user_id=payload.owner_user_id,
        created_by_user_id=int(current_user["id"]),
        event_ids=payload.event_ids,
    )
    audit_action(
        request=request,
        action="CREATE_CASE",
        resource_type="case",
        resource_id=int(created["id"]),
        details={
            "title": created["title"],
            "severity": created["severity"],
            "priority": created["priority"],
            "owner_user_id": created.get("owner_user_id"),
            "linked_event_ids": payload.event_ids,
        },
        current_user=current_user,
    )
    return CaseResponse(**created)


@app.get("/api/v1/cases", response_model=PaginatedCasesResponse, tags=["cases"])
async def list_cases_endpoint(
    status: str | None = None,
    owner_user_id: int | None = None,
    severity: str | None = None,
    page: int | None = None,
    per_page: int | None = None,
    limit: int = 50,
    offset: int = 0,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> PaginatedCasesResponse:
    """List cases with pagination and filtering."""
    if per_page is not None:
        limit = max(1, per_page)
    if page is not None and per_page is not None:
        offset = max(0, (page - 1) * per_page)
    status = status.upper() if status else None
    severity = severity.upper() if severity else None
    rows, total = list_cases(
        status=status,
        owner_user_id=owner_user_id,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return PaginatedCasesResponse(cases=[CaseResponse(**row) for row in rows], total=total, limit=limit, offset=offset)


@app.get("/api/v1/cases/{case_id}", response_model=CaseDetailResponse, tags=["cases"])
async def get_case_endpoint(
    case_id: int,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> CaseDetailResponse:
    """Get case detail with linked events and notes."""
    case = get_case_detail(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return CaseDetailResponse(**case)


@app.put("/api/v1/cases/{case_id}", response_model=CaseResponse, tags=["cases"])
async def update_case_endpoint(
    case_id: int,
    payload: CaseUpdateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> CaseResponse:
    """Update mutable case fields (title, status, priority, owner)."""
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    if "title" in fields:
        fields["title"] = (fields["title"] or "").strip()
        if not fields["title"]:
            raise HTTPException(status_code=400, detail="Title cannot be empty")
    if "status" in fields:
        fields["status"] = str(fields["status"]).upper()
        if fields["status"] not in {"OPEN", "IN_PROGRESS", "ON_HOLD", "CLOSED"}:
            raise HTTPException(status_code=400, detail="Invalid status")
    if "priority" in fields:
        fields["priority"] = str(fields["priority"]).upper()
        if fields["priority"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=400, detail="Invalid priority")
    if "owner_user_id" in fields and fields["owner_user_id"] is not None and not get_user_by_id(fields["owner_user_id"]):
        raise HTTPException(status_code=404, detail="Owner user not found")

    updated = update_case(case_id, **fields)
    if not updated:
        raise HTTPException(status_code=404, detail="Case not found")
    audit_action(
        request=request,
        action="UPDATE_CASE",
        resource_type="case",
        resource_id=case_id,
        details=fields,
        current_user=current_user,
    )
    return CaseResponse(**updated)


@app.post("/api/v1/cases/{case_id}/notes", response_model=CaseNoteResponse, status_code=201, tags=["cases"])
async def add_case_note_endpoint(
    case_id: int,
    payload: CaseNoteCreateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> CaseNoteResponse:
    """Add an investigation note to a case."""
    note_text = payload.note.strip()
    if not note_text:
        raise HTTPException(status_code=400, detail="Note cannot be empty")
    note = add_case_note(case_id=case_id, author_user_id=int(current_user["id"]), note=note_text)
    if not note:
        raise HTTPException(status_code=404, detail="Case not found")
    audit_action(
        request=request,
        action="ADD_CASE_NOTE",
        resource_type="case_note",
        resource_id=int(note["id"]),
        details={"case_id": case_id, "note_length": len(note_text)},
        current_user=current_user,
    )
    return CaseNoteResponse(**note)


@app.post("/api/v1/cases/{case_id}/events/{event_id}", tags=["cases"])
async def link_case_event_endpoint(
    case_id: int,
    event_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Link an event to an investigation case."""
    linked = link_case_event(case_id=case_id, event_id=event_id)
    if not linked:
        raise HTTPException(status_code=404, detail="Case or event not found")
    audit_action(
        request=request,
        action="LINK_CASE_EVENT",
        resource_type="case_event",
        details={"case_id": case_id, "event_id": event_id},
        current_user=current_user,
    )
    return {"ok": True, "case_id": case_id, "event_id": event_id}


@app.delete("/api/v1/cases/{case_id}/events/{event_id}", tags=["cases"])
async def unlink_case_event_endpoint(
    case_id: int,
    event_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Unlink an event from an investigation case."""
    unlinked = unlink_case_event(case_id=case_id, event_id=event_id)
    if not unlinked:
        raise HTTPException(status_code=404, detail="Case or event link not found")
    audit_action(
        request=request,
        action="UNLINK_CASE_EVENT",
        resource_type="case_event",
        details={"case_id": case_id, "event_id": event_id},
        current_user=current_user,
    )
    return {"ok": True, "case_id": case_id, "event_id": event_id}


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

@app.get("/api/v1/playbooks", response_model=list[PlaybookResponse], tags=["playbooks"])
async def list_playbooks_endpoint(
    enabled: bool | None = None,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[PlaybookResponse]:
    rows = list_playbooks(enabled=enabled)
    return [PlaybookResponse(**row) for row in rows]


@app.post("/api/v1/playbooks", response_model=PlaybookResponse, status_code=201, tags=["playbooks"])
async def create_playbook_endpoint(
    payload: PlaybookCreateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> PlaybookResponse:
    try:
        row = create_playbook(
            name=payload.name.strip(),
            description=payload.description,
            trigger_severities=[str(s).upper() for s in payload.trigger_severities],
            trigger_rule_ids=[int(r) for r in payload.trigger_rule_ids],
            trigger_event_types=[str(t).lower() for t in payload.trigger_event_types],
            enabled=payload.enabled,
            actions=_normalize_playbook_actions(payload.actions),
        )
    except ValueError as exc:
        if str(exc) == "playbook_name_exists":
            raise HTTPException(status_code=409, detail="Playbook name already exists")
        raise HTTPException(status_code=400, detail=str(exc))
    audit_action(
        request=request,
        action="CREATE_PLAYBOOK",
        resource_type="playbook",
        resource_id=int(row["id"]),
        details={"name": row["name"], "enabled": row["enabled"]},
        current_user=current_user,
    )
    return PlaybookResponse(**row)


@app.get("/api/v1/playbooks/{playbook_id}", response_model=PlaybookResponse, tags=["playbooks"])
async def get_playbook_endpoint(
    playbook_id: int,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> PlaybookResponse:
    row = get_playbook(playbook_id)
    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return PlaybookResponse(**row)


@app.put("/api/v1/playbooks/{playbook_id}", response_model=PlaybookResponse, tags=["playbooks"])
async def update_playbook_endpoint(
    playbook_id: int,
    payload: PlaybookUpdateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> PlaybookResponse:
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    if "name" in fields:
        fields["name"] = str(fields["name"]).strip()
        if not fields["name"]:
            raise HTTPException(status_code=400, detail="Playbook name cannot be empty")
    if "trigger_severities" in fields and fields["trigger_severities"] is not None:
        fields["trigger_severities"] = [str(s).upper() for s in fields["trigger_severities"]]
    if "trigger_event_types" in fields and fields["trigger_event_types"] is not None:
        fields["trigger_event_types"] = [str(t).lower() for t in fields["trigger_event_types"]]
    if "actions" in fields and fields["actions"] is not None:
        fields["actions"] = _normalize_playbook_actions(fields["actions"])
    updated = update_playbook(playbook_id, **fields)
    if not updated:
        raise HTTPException(status_code=404, detail="Playbook not found")
    audit_action(
        request=request,
        action="UPDATE_PLAYBOOK",
        resource_type="playbook",
        resource_id=playbook_id,
        details={"changed_fields": list(fields.keys())},
        current_user=current_user,
    )
    return PlaybookResponse(**updated)


@app.delete("/api/v1/playbooks/{playbook_id}", tags=["playbooks"])
async def delete_playbook_endpoint(
    playbook_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> dict:
    ok = delete_playbook(playbook_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Playbook not found")
    audit_action(
        request=request,
        action="DELETE_PLAYBOOK",
        resource_type="playbook",
        resource_id=playbook_id,
        details={"deleted": True},
        current_user=current_user,
    )
    return {"ok": True}


@app.post("/api/v1/playbooks/{playbook_id}/toggle", response_model=PlaybookResponse, tags=["playbooks"])
async def toggle_playbook_endpoint(
    playbook_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> PlaybookResponse:
    updated = toggle_playbook(playbook_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Playbook not found")
    audit_action(
        request=request,
        action="TOGGLE_PLAYBOOK",
        resource_type="playbook",
        resource_id=playbook_id,
        details={"enabled": updated.get("enabled")},
        current_user=current_user,
    )
    return PlaybookResponse(**updated)


@app.post("/api/v1/playbooks/{playbook_id}/test", tags=["playbooks"])
async def test_playbook_endpoint(
    playbook_id: int,
    payload: PlaybookTestRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    playbook = get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    context = {
        "event_id": payload.sample_payload.get("event_id"),
        "case_id": payload.sample_payload.get("case_id"),
        "event_type": payload.sample_payload.get("event_type", "signature"),
        "severity": str(payload.sample_payload.get("severity", "HIGH")).upper(),
        "rule_id": payload.sample_payload.get("rule_id"),
        "src_ip": payload.sample_payload.get("src_ip"),
        "dst_ip": payload.sample_payload.get("dst_ip"),
        "protocol": payload.sample_payload.get("protocol"),
        "description": payload.sample_payload.get("description", f"Playbook test run #{playbook_id}"),
        "threat_intel_score": payload.sample_payload.get("threat_intel_score"),
    }
    result = await asyncio.to_thread(
        run_playbook,
        playbook,
        context,
        _audit_user(current_user),
        "user",
    )
    audit_action(
        request=request,
        action="TEST_PLAYBOOK",
        resource_type="playbook",
        resource_id=playbook_id,
        details={"summary": result.get("summary", {})},
        current_user=current_user,
    )
    return result


@app.get("/api/v1/playbooks/{playbook_id}/executions", response_model=PaginatedPlaybookExecutionsResponse, tags=["playbooks"])
async def list_playbook_executions_endpoint(
    playbook_id: int,
    page: int | None = None,
    per_page: int | None = None,
    limit: int = 50,
    offset: int = 0,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> PaginatedPlaybookExecutionsResponse:
    if per_page is not None:
        limit = max(1, per_page)
    if page is not None and per_page is not None:
        offset = max(0, (page - 1) * per_page)
    if not get_playbook(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    rows, total = list_playbook_executions(playbook_id=playbook_id, limit=limit, offset=offset)
    return PaginatedPlaybookExecutionsResponse(
        executions=[PlaybookExecutionResponse(**row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.post("/api/v1/playbooks/execute/event/{event_id}", tags=["playbooks"])
async def execute_playbooks_for_event_endpoint(
    event_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    if not get_event_by_id(event_id):
        raise HTTPException(status_code=404, detail="Event not found")
    results = await asyncio.to_thread(
        run_playbooks_for_event,
        event_id,
        _audit_user(current_user),
        "user",
    )
    audit_action(
        request=request,
        action="MANUAL_EXECUTE_PLAYBOOKS_EVENT",
        resource_type="intrusion_event",
        resource_id=event_id,
        details={"executed_playbooks": len(results)},
        current_user=current_user,
    )
    return {"event_id": event_id, "results": results, "count": len(results)}


@app.post("/api/v1/playbooks/execute/case/{case_id}", tags=["playbooks"])
async def execute_playbooks_for_case_endpoint(
    case_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    enabled_playbooks = list_playbooks(enabled=True)
    results: list[dict[str, Any]] = []
    for playbook in enabled_playbooks:
        result = await asyncio.to_thread(
            run_playbook_for_case,
            playbook,
            case_id,
            _audit_user(current_user),
            "user",
        )
        results.append(result)
    audit_action(
        request=request,
        action="MANUAL_EXECUTE_PLAYBOOKS_CASE",
        resource_type="case",
        resource_id=case_id,
        details={"executed_playbooks": len(results)},
        current_user=current_user,
    )
    return {"case_id": case_id, "results": results, "count": len(results)}


@app.post("/api/v1/playbooks/integrations/ticket", response_model=TicketIntegrationResponse, tags=["playbooks"])
async def upsert_ticket_integration_endpoint(
    payload: TicketIntegrationRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> TicketIntegrationResponse:
    provider_type = payload.provider_type.strip().lower()
    if not provider_type:
        raise HTTPException(status_code=400, detail="provider_type is required")
    row = upsert_ticket_integration_config(provider_type=provider_type, enabled=payload.enabled, config=payload.config)
    audit_action(
        request=request,
        action="UPSERT_TICKET_INTEGRATION",
        resource_type="ticket_integration",
        resource_id=int(row["id"]),
        details={"provider_type": provider_type, "enabled": payload.enabled},
        current_user=current_user,
    )
    return TicketIntegrationResponse(**row)


@app.get("/api/v1/playbooks/integrations/ticket/{provider_type}", response_model=TicketIntegrationResponse, tags=["playbooks"])
async def get_ticket_integration_endpoint(
    provider_type: str,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> TicketIntegrationResponse:
    row = get_ticket_integration_config(provider_type.strip().lower())
    if not row:
        raise HTTPException(status_code=404, detail="Integration config not found")
    return TicketIntegrationResponse(**row)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@app.get("/api/v1/stats", response_model=StatsResponse, tags=["stats"])
async def get_stats_endpoint(
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> StatsResponse:
    """Get aggregated statistics."""
    return get_stats()


@app.get("/api/v1/stats/top-attackers", tags=["stats"])
async def top_attackers(
    request: Request,
    n: int = 10,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    """Get top N source IPs by event count."""
    stats = get_stats()
    return stats.get("top_sources", [])[:n]


@app.get("/api/v1/stats/timeline", tags=["stats"])
async def timeline(
    request: Request,
    hours: int = 24,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    """Get events per hour/day for the specified window."""
    stats = get_stats()
    return stats.get("timeline", [])[:hours]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@app.get("/api/v1/rules", response_model=list[RuleResponse], tags=["rules"])
async def list_rules(
    request: Request,
    enabled: bool | None = None,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[RuleResponse]:
    """List all detection rules."""
    rules = get_rules(enabled=enabled)
    return [RuleResponse(**r) for r in rules]


@app.get("/api/v1/rules/mitre", response_model=list[RuleResponse], tags=["rules"])
async def list_rules_by_mitre(
    technique: str | None = None,
    tactic: str | None = None,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[RuleResponse]:
    """List rules filtered by MITRE technique and/or tactic."""
    rules = get_rules_by_mitre(technique=technique, tactic=tactic)
    return [RuleResponse(**r) for r in rules]


@app.post("/api/v1/rules", response_model=RuleResponse, status_code=201, tags=["rules"])
async def create_rule_endpoint(
    rule: RuleCreate,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RuleResponse:
    """Create a new detection rule."""
    rule_id = create_rule(
        name=rule.name,
        rule_type=rule.rule_type,
        criteria=rule.criteria,
        description=rule.description,
        priority=rule.priority,
        lifecycle_state=rule.lifecycle_state,
        mitre_tactics=rule.mitre_tactics,
        mitre_techniques=rule.mitre_techniques,
        suppression_enabled=rule.suppression_enabled,
        suppression_window_seconds=rule.suppression_window_seconds,
    )
    created = get_rule(rule_id)
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create rule")

    audit_action(
        request=request,
        action="CREATE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={
            "name": rule.name,
            "rule_type": rule.rule_type,
            "lifecycle_state": rule.lifecycle_state,
            "mitre_tactics": rule.mitre_tactics,
            "mitre_techniques": rule.mitre_techniques,
            "suppression_enabled": rule.suppression_enabled,
            "suppression_window_seconds": rule.suppression_window_seconds,
        },
        current_user=current_user,
    )
    return RuleResponse(**created)


@app.get("/api/v1/rules/{rule_id}", response_model=RuleResponse, tags=["rules"])
async def get_rule_endpoint(rule_id: int, _: dict = Depends(require_roles("admin", "analyst", "viewer"))) -> RuleResponse:
    """Get a single rule by ID."""
    rule = get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return RuleResponse(**rule)


@app.put("/api/v1/rules/{rule_id}", response_model=RuleResponse, tags=["rules"])
async def update_rule_endpoint(
    rule_id: int,
    rule_update: RuleUpdate,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RuleResponse:
    """Update a rule."""
    fields = {k: v for k, v in rule_update.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    success = update_rule(rule_id, **fields)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")

    updated = get_rule(rule_id)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update rule")

    audit_action(
        request=request,
        action="UPDATE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={
            "changed_fields": fields,
            "lifecycle_state": fields.get("lifecycle_state"),
            "mitre_tactics": fields.get("mitre_tactics"),
            "mitre_techniques": fields.get("mitre_techniques"),
            "suppression_enabled": fields.get("suppression_enabled"),
            "suppression_window_seconds": fields.get("suppression_window_seconds"),
        },
        current_user=current_user,
    )
    return RuleResponse(**updated)


@app.delete("/api/v1/rules/{rule_id}", tags=["rules"])
async def delete_rule_endpoint(
    rule_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> dict:
    """Delete a rule."""
    success = delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    audit_action(
        request=request,
        action="DELETE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={"deleted": True},
        current_user=current_user,
    )
    return {"ok": True}


@app.post("/api/v1/rules/{rule_id}/toggle", response_model=RuleResponse, tags=["rules"])
async def toggle_rule_endpoint(
    rule_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RuleResponse:
    """Enable or disable a rule."""
    success = toggle_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    updated = get_rule(rule_id)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to toggle rule")
    audit_action(
        request=request,
        action="TOGGLE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={"enabled": updated.get("enabled")},
        current_user=current_user,
    )
    return RuleResponse(**updated)


@app.post("/api/v1/rules/{rule_id}/lifecycle", response_model=RuleResponse, tags=["rules"])
async def promote_rule_lifecycle(
    rule_id: int,
    payload: dict[str, str],
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RuleResponse:
    """Promote rule lifecycle state explicitly."""
    lifecycle_state = payload.get("lifecycle_state")
    if lifecycle_state not in {"draft", "staging", "production"}:
        raise HTTPException(status_code=400, detail="Invalid lifecycle_state")
    success = update_rule(rule_id, lifecycle_state=lifecycle_state)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    updated = get_rule(rule_id)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update lifecycle")
    audit_action(
        request=request,
        action="PROMOTE_RULE_LIFECYCLE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={"lifecycle_state": lifecycle_state},
        current_user=current_user,
    )
    return RuleResponse(**updated)


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------

@app.get("/api/v1/alerts/blocklist", tags=["alerts"])
async def get_blocklist(_: dict = Depends(require_roles("admin", "analyst", "viewer"))) -> list[dict]:
    """Get current IP blocklist."""
    engine = get_threat_intel_engine()
    return engine.get_blocklist()


@app.post("/api/v1/alerts/blocklist", status_code=201, tags=["alerts"])
async def add_to_blocklist(
    entry: BlocklistEntry,
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Add an IP or CIDR to the blocklist."""
    engine = get_threat_intel_engine()
    success = engine.add_to_blocklist(entry.ip, entry.source)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add to blocklist")
    audit_action(
        request=request,
        action="ADD_TO_BLOCKLIST",
        resource_type="blocklist",
        details={"ip": entry.ip, "source": entry.source},
        current_user=current_user,
    )
    return {"ok": True, "ip": entry.ip}


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

@app.get("/api/v1/system/metrics", response_model=SystemMetrics, tags=["system"])
async def system_metrics(_: dict = Depends(require_roles("admin", "analyst", "viewer"))) -> SystemMetrics:
    """Get system metrics (CPU, memory, queue depth, packets/sec)."""
    engine = get_detection_engine()
    simulator = get_traffic_simulator()
    
    return SystemMetrics(
        uptime_seconds=round(time.time() - _start_time, 2),
        packets_received=_pipeline_metrics.get("packets_received", 0),
        packets_processed=_pipeline_metrics.get("packets_processed", 0),
        packets_dropped=_pipeline_metrics.get("packets_dropped", 0),
        queue_depth=_pipeline_metrics.get("queue_depth", 0),
        avg_processing_time_ms=_pipeline_metrics.get("avg_processing_time_ms", 0.0),
        packets_per_second=_pipeline_metrics.get("packets_per_second", 0.0),
        events_per_minute=_pipeline_metrics.get("events_per_minute", 0),
        events_detected=_pipeline_metrics.get("events_detected", 0),
        cpu_percent=psutil.cpu_percent(),
        memory_percent=psutil.virtual_memory().percent,
        websocket_connections=sum(ws_manager.get_all_connection_counts().values()),
        detection_engine_status="running" if engine.running else "stopped",
        simulator_status="running" if simulator.running else "stopped",
        broker_status="running" if _broker_enabled else "disabled",
    )


@app.get("/api/v1/system/slo", response_model=SLOSummaryResponse, tags=["system"])
async def system_slo(
    request: Request,
    window_minutes: int = 15,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> SLOSummaryResponse:
    tenant_id = get_tenant_id(request)
    summary = _compute_slo_summary(window_minutes=max(1, min(window_minutes, 120)))
    create_slo_snapshot(
        ingestion_availability=summary["ingestion_availability"],
        latency_p50_ms=summary["event_processing_latency_ms"]["p50"],
        latency_p95_ms=summary["event_processing_latency_ms"]["p95"],
        queue_depth=summary["queue_depth_trend"]["current"],
        queue_trend=summary["queue_depth_trend"]["direction"],
        broker_state=summary["connectivity"]["broker"],
        db_state=summary["connectivity"]["database"],
        cache_state=summary["connectivity"]["cache"],
        error_budget_remaining=summary["error_budget_remaining"],
        tenant_id=tenant_id,
    )
    snapshots = list_slo_snapshots(limit=1, tenant_id=tenant_id)
    summary["snapshots_recorded"] = len(snapshots)
    return SLOSummaryResponse(**summary)


@app.get("/api/v1/system/slo/history", response_model=list[SLOSnapshotResponse], tags=["system"])
async def system_slo_history(
    request: Request,
    limit: int = 48,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[SLOSnapshotResponse]:
    tenant_id = get_tenant_id(request)
    rows = list_slo_snapshots(limit=max(1, min(limit, 240)), tenant_id=tenant_id)
    return [SLOSnapshotResponse(**row) for row in rows]


@app.get("/api/v1/system/retention/policies", response_model=list[RetentionPolicyResponse], tags=["system"])
async def get_retention_policies(
    request: Request,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[RetentionPolicyResponse]:
    tenant_id = get_tenant_id(request)
    rows = list_retention_policies(tenant_id=tenant_id)
    return [RetentionPolicyResponse(**row) for row in rows]


@app.post("/api/v1/system/retention/policies", response_model=RetentionPolicyResponse, status_code=201, tags=["system"])
async def create_retention_policy_endpoint(
    payload: RetentionPolicyCreateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RetentionPolicyResponse:
    tenant_id = get_tenant_id(request)
    if payload.scope == "severity" and not payload.severity:
        raise HTTPException(status_code=400, detail="severity is required for severity scope")
    row = create_retention_policy(
        name=payload.name,
        scope=payload.scope,
        hot_days=payload.hot_days,
        warm_days=payload.warm_days,
        cold_days=payload.cold_days,
        archive_enabled=payload.archive_enabled,
        delete_after_days=payload.delete_after_days,
        enabled=payload.enabled,
        severity=payload.severity,
        tenant_id=tenant_id,
    )
    audit_action(
        request=request,
        action="CREATE_RETENTION_POLICY",
        resource_type="retention_policy",
        resource_id=int(row["id"]),
        details={"name": row.get("name"), "scope": row.get("scope"), "tenant_id": tenant_id},
        current_user=current_user,
    )
    return RetentionPolicyResponse(**row)


@app.put("/api/v1/system/retention/policies/{policy_id}", response_model=RetentionPolicyResponse, tags=["system"])
async def update_retention_policy_endpoint(
    policy_id: int,
    payload: RetentionPolicyUpdateRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RetentionPolicyResponse:
    tenant_id = get_tenant_id(request)
    current = get_retention_policy(policy_id)
    if not current:
        raise HTTPException(status_code=404, detail="Retention policy not found")
    if tenant_id and current.get("tenant_id") not in {tenant_id, None}:
        raise HTTPException(status_code=404, detail="Retention policy not found")
    updated = update_retention_policy(policy_id, **payload.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update retention policy")
    audit_action(
        request=request,
        action="UPDATE_RETENTION_POLICY",
        resource_type="retention_policy",
        resource_id=policy_id,
        details={"updated_fields": list(payload.model_dump(exclude_unset=True).keys())},
        current_user=current_user,
    )
    return RetentionPolicyResponse(**updated)


@app.delete("/api/v1/system/retention/policies/{policy_id}", tags=["system"])
async def delete_retention_policy_endpoint(
    policy_id: int,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> dict:
    tenant_id = get_tenant_id(request)
    current = get_retention_policy(policy_id)
    if not current:
        raise HTTPException(status_code=404, detail="Retention policy not found")
    if tenant_id and current.get("tenant_id") not in {tenant_id, None}:
        raise HTTPException(status_code=404, detail="Retention policy not found")
    deleted = delete_retention_policy(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Retention policy not found")
    audit_action(
        request=request,
        action="DELETE_RETENTION_POLICY",
        resource_type="retention_policy",
        resource_id=policy_id,
        details={"deleted": True},
        current_user=current_user,
    )
    return {"ok": True}


@app.post("/api/v1/system/retention/dry-run", response_model=RetentionDryRunResponse, tags=["system"])
async def retention_dry_run(
    request: Request,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> RetentionDryRunResponse:
    tenant_id = get_tenant_id(request)
    result = retention_maintenance_preview(tenant_id=tenant_id)
    return RetentionDryRunResponse(**result)


@app.post("/api/v1/system/retention/execute", response_model=RetentionExecuteResponse, tags=["system"])
async def retention_execute(
    payload: RetentionExecuteRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> RetentionExecuteResponse:
    tenant_id = get_tenant_id(request)
    if payload.apply_delete and not payload.confirm_delete:
        raise HTTPException(status_code=400, detail="confirm_delete=true is required when apply_delete=true")
    result = execute_retention_maintenance(tenant_id=tenant_id, apply_delete=payload.apply_delete)
    audit_action(
        request=request,
        action="EXECUTE_RETENTION_MAINTENANCE",
        resource_type="retention_policy",
        details=result | {"tenant_id": tenant_id},
        current_user=current_user,
    )
    return RetentionExecuteResponse(**result)


@app.post("/api/v1/system/backup/start", response_model=BackupOperationResponse, tags=["system"])
async def start_backup(
    payload: BackupStartRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> BackupOperationResponse:
    tenant_id = get_tenant_id(request)
    started = time.time()
    status_value = "success" if payload.dry_run else "queued"
    artifact_path = f"logs/backups/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{payload.target}.meta"
    duration_ms = int((time.time() - started) * 1000)
    row = create_backup_operation(
        operation_type="backup_start",
        status=status_value,
        duration_ms=duration_ms,
        artifact_path=artifact_path,
        operation_metadata={
            "target": payload.target,
            "dry_run": payload.dry_run,
            "include_events": payload.include_events,
            "include_rules": payload.include_rules,
            "include_cases": payload.include_cases,
            "note": "Safe operational stub; no DB dump executed in this environment.",
        },
        initiated_by=_audit_user(current_user),
        source_ip=_request_ip(request),
        tenant_id=tenant_id,
    )
    audit_action(
        request=request,
        action="START_BACKUP",
        resource_type="backup_operation",
        resource_id=int(row["id"]),
        details={"status": row.get("status"), "dry_run": payload.dry_run, "tenant_id": tenant_id},
        current_user=current_user,
    )
    return BackupOperationResponse(**row)


@app.get("/api/v1/system/backup/history", response_model=list[BackupOperationResponse], tags=["system"])
async def backup_history(
    request: Request,
    limit: int = 50,
    _: dict = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[BackupOperationResponse]:
    tenant_id = get_tenant_id(request)
    rows = list_backup_operations(limit=max(1, min(limit, 200)), tenant_id=tenant_id)
    return [BackupOperationResponse(**row) for row in rows]


@app.post("/api/v1/system/backup/restore-test", response_model=BackupOperationResponse, tags=["system"])
async def backup_restore_test(
    payload: BackupRestoreTestRequest,
    request: Request,
    current_user: dict = Depends(require_roles("admin")),
) -> BackupOperationResponse:
    tenant_id = get_tenant_id(request)
    started = time.time()
    status_value = "success" if payload.dry_run else "queued"
    duration_ms = int((time.time() - started) * 1000)
    artifact_path = payload.artifact_path or "logs/backups/restore-test.validation"
    row = create_backup_operation(
        operation_type="restore_test",
        status=status_value,
        duration_ms=duration_ms,
        artifact_path=artifact_path,
        operation_metadata={
            "backup_id": payload.backup_id,
            "dry_run": payload.dry_run,
            "note": "Restore validation stub only; no destructive restore executed.",
        },
        initiated_by=_audit_user(current_user),
        source_ip=_request_ip(request),
        tenant_id=tenant_id,
    )
    audit_action(
        request=request,
        action="RESTORE_TEST_BACKUP",
        resource_type="backup_operation",
        resource_id=int(row["id"]),
        details={"status": row.get("status"), "backup_id": payload.backup_id, "tenant_id": tenant_id},
        current_user=current_user,
    )
    return BackupOperationResponse(**row)


@app.post("/api/v1/system/reload", tags=["system"])
async def reload_rules(
    request: Request,
    current_user: dict = Depends(require_roles("admin", "analyst")),
) -> dict:
    """Hot-reload rules from database and blocklists without restart."""
    # Reload detection engine rules
    engine = get_detection_engine()
    rules = get_rules()
    engine.load_rules(rules)
    
    # Reload threat intel blocklists
    threat_engine = get_threat_intel_engine()
    threat_engine.reload_blocklists()
    
    audit_action(
        request=request,
        action="RELOAD_RULES",
        resource_type="system",
        details={"rules_loaded": len(rules)},
        current_user=current_user,
    )
    return {"ok": True, "message": f"Reloaded {len(rules)} rules and blocklists"}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@app.get("/api/v1/export/events", tags=["export"])
async def export_events(
    request: Request,
    format: str = "csv",
    severity: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    current_user: dict = Depends(require_roles("admin")),
) -> Response:
    """
    Export events as CSV or JSON.
    Query param: format=csv|json
    """
    events, _ = search_events(severity=severity, limit=100000)

    if format == "json":
        audit_action(
            request=request,
            action="EXPORT_EVENTS",
            resource_type="intrusion_event",
            details={"format": "json", "severity": severity, "count": len(events)},
            current_user=current_user,
        )
        import json
        return Response(
            content=json.dumps(events, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=nids_events.json"},
        )

    # CSV
    output = io.StringIO()
    if events:
        writer = csv.DictWriter(output, fieldnames=events[0].keys())
        writer.writeheader()
        writer.writerows(events)
    audit_action(
        request=request,
        action="EXPORT_EVENTS",
        resource_type="intrusion_event",
        details={"format": "csv", "severity": severity, "count": len(events)},
        current_user=current_user,
    )
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=nids_events.csv"},
    )


# ---------------------------------------------------------------------------
# PCAP download
# ---------------------------------------------------------------------------

@app.get("/api/v1/events/{event_id}/pcap", tags=["forensics"])
async def download_pcap(event_id: int, _: dict = Depends(require_roles("admin", "analyst", "viewer"))) -> Response:
    """
    Download PCAP file for an event if it exists.
    PCAPs are captured for HIGH/CRITICAL events and stored in logs/pcap/.
    """
    pcap_dir = Path("logs/pcap")
    pcap_file = pcap_dir / f"{event_id}.pcap"

    if not pcap_file.exists():
        raise HTTPException(status_code=404, detail="PCAP not found for this event")

    with open(pcap_file, "rb") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f"attachment; filename=event_{event_id}.pcap"},
    )


# ---------------------------------------------------------------------------
# Threat intel lookup
# ---------------------------------------------------------------------------

@app.get("/api/v1/threat-intel/{ip}", tags=["threat_intel"])
async def threat_intel_lookup(ip: str, _: dict = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    """Lookup threat intelligence for a specific IP."""
    engine = get_threat_intel_engine()
    result = engine.check_ip(ip)
    return {
        "ip": result.ip,
        "score": result.score,
        "source": result.source,
        "is_malicious": result.is_malicious,
        "country_code": result.country_code,
        "isp": result.isp,
        "cached": result.cached,
    }


# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory, per-IP)
# ---------------------------------------------------------------------------

from collections import defaultdict
from datetime import datetime, timezone as tz2

_rate_limit_store: dict[str, list[float]] = defaultdict(list)


async def rate_limit_middleware(request: Request, call_next):
    settings = get_settings()
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = 60.0
    limit = settings.api.jwt.rate_limit_per_minute

    _rate_limit_store[client_ip] = [
        t for t in _rate_limit_store[client_ip] if now - t < window
    ]
    if len(_rate_limit_store[client_ip]) >= limit:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": "60"},
        )
    _rate_limit_store[client_ip].append(now)

    return await call_next(request)


# Import os for auth
import os
from pathlib import Path
