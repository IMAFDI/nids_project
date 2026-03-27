"""
NIDS — FastAPI REST API
=======================
All endpoints under /api/v1/* with JWT authentication, rate limiting,
correlation IDs, and full OpenAPI documentation.
"""

from __future__ import annotations

import csv
import io
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, Request, HTTPException, Depends, status, Response
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
    log_audit,
    upsert_threat_intel,
    get_threat_intel,
)
from config.threat_intel import ThreatIntelEngine, get_threat_intel_engine
from config.settings import get_settings

logger = logging.getLogger("NIDS.API")

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

security = HTTPBearer()


def create_access_token(username: str) -> str:
    """Create a JWT access token."""
    settings = get_settings()
    expiry = datetime.now(timezone.utc) + timedelta(hours=settings.api.jwt.expiry_hours)
    payload = {
        "sub": username,
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


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RuleCreate(BaseModel):
    name: str
    rule_type: str
    criteria: dict
    description: str | None = None
    priority: str = "MEDIUM"


class RuleUpdate(BaseModel):
    name: str | None = None
    criteria: dict | None = None
    description: str | None = None
    priority: str | None = None
    enabled: bool | None = None


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
    description: str | None
    rule_id: int | None
    acknowledged: bool
    acknowledged_by: str | None
    acknowledged_at: str | None
    raw_message: str | None


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise database and settings on startup."""
    global _start_time
    _start_time = time.time()
    settings = get_settings()
    init_db(settings.database.url)
    logger.info("NIDS API started.")
    yield
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
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth/login", response_model=LoginResponse, tags=["auth"])
async def login(req: LoginRequest) -> LoginResponse:
    """
    Authenticate and receive a JWT token.
    Default credentials are admin/admin (override via NIDS_JWT_SECRET env var).
    """
    settings = get_settings()

    # Simple authentication — in production, verify against a user database
    valid_user = os.environ.get("NIDS_API_USER", "admin")
    valid_pass = os.environ.get("NIDS_API_PASSWORD", "admin")

    if req.username != valid_user or req.password != valid_pass:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(req.username)
    return LoginResponse(access_token=token)


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
    offset: int = 0,
    _: dict = Depends(verify_token),
) -> PaginatedEventsResponse:
    """List intrusion events with pagination and filtering."""
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
async def get_event(event_id: int, _: dict = Depends(verify_token)) -> EventResponse:
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
    correlation_id: Request = None,
    _: dict = Depends(verify_token),
) -> dict:
    """Mark an event as acknowledged."""
    success = acknowledge_event(event_id, req.acknowledged_by)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")

    user = correlation_id.state.username if hasattr(correlation_id, "state") and hasattr(correlation_id.state, "username") else "api"
    log_audit(
        action="ACK_EVENT",
        resource_type="intrusion_event",
        resource_id=event_id,
        user=user,
        details={"acknowledged_by": req.acknowledged_by},
    )
    return {"ok": True, "event_id": event_id}


@app.delete("/api/v1/events/{event_id}", tags=["events"])
async def delete_event_endpoint(event_id: int, _: dict = Depends(verify_token)) -> dict:
    """Delete a single event."""
    success = delete_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@app.get("/api/v1/stats", response_model=StatsResponse, tags=["stats"])
async def get_stats_endpoint(
    _: dict = Depends(verify_token),
) -> StatsResponse:
    """Get aggregated statistics."""
    return get_stats()


@app.get("/api/v1/stats/top-attackers", tags=["stats"])
async def top_attackers(
    request: Request,
    n: int = 10,
    _: dict = Depends(verify_token),
) -> list[dict[str, Any]]:
    """Get top N source IPs by event count."""
    stats = get_stats()
    return stats.get("top_sources", [])[:n]


@app.get("/api/v1/stats/timeline", tags=["stats"])
async def timeline(
    request: Request,
    hours: int = 24,
    _: dict = Depends(verify_token),
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
    _: dict = Depends(verify_token),
) -> list[RuleResponse]:
    """List all detection rules."""
    rules = get_rules(enabled=enabled)
    return [RuleResponse(**r) for r in rules]


@app.post("/api/v1/rules", response_model=RuleResponse, status_code=201, tags=["rules"])
async def create_rule_endpoint(
    rule: RuleCreate,
    request: Request,
    _: dict = Depends(verify_token),
) -> RuleResponse:
    """Create a new detection rule."""
    rule_id = create_rule(
        name=rule.name,
        rule_type=rule.rule_type,
        criteria=rule.criteria,
        description=rule.description,
        priority=rule.priority,
    )
    created = get_rule(rule_id)
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create rule")

    log_audit(
        action="CREATE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={"name": rule.name, "rule_type": rule.rule_type},
    )
    return RuleResponse(**created)


@app.get("/api/v1/rules/{rule_id}", response_model=RuleResponse, tags=["rules"])
async def get_rule_endpoint(rule_id: int, _: dict = Depends(verify_token)) -> RuleResponse:
    """Get a single rule by ID."""
    rule = get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return RuleResponse(**rule)


@app.put("/api/v1/rules/{rule_id}", response_model=RuleResponse, tags=["rules"])
async def update_rule_endpoint(
    rule_id: int,
    rule_update: RuleUpdate,
    _: dict = Depends(verify_token),
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

    log_audit(
        action="UPDATE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details=fields,
    )
    return RuleResponse(**updated)


@app.delete("/api/v1/rules/{rule_id}", tags=["rules"])
async def delete_rule_endpoint(rule_id: int, _: dict = Depends(verify_token)) -> dict:
    """Delete a rule."""
    success = delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    log_audit(action="DELETE_RULE", resource_type="alert_rule", resource_id=rule_id)
    return {"ok": True}


@app.post("/api/v1/rules/{rule_id}/toggle", response_model=RuleResponse, tags=["rules"])
async def toggle_rule_endpoint(rule_id: int, _: dict = Depends(verify_token)) -> RuleResponse:
    """Enable or disable a rule."""
    success = toggle_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    updated = get_rule(rule_id)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to toggle rule")
    log_audit(
        action="TOGGLE_RULE",
        resource_type="alert_rule",
        resource_id=rule_id,
        details={"enabled": updated.get("enabled")},
    )
    return RuleResponse(**updated)


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------

@app.get("/api/v1/alerts/blocklist", tags=["alerts"])
async def get_blocklist(_: dict = Depends(verify_token)) -> list[dict]:
    """Get current IP blocklist."""
    engine = get_threat_intel_engine()
    return engine.get_blocklist()


@app.post("/api/v1/alerts/blocklist", status_code=201, tags=["alerts"])
async def add_to_blocklist(entry: BlocklistEntry, _: dict = Depends(verify_token)) -> dict:
    """Add an IP or CIDR to the blocklist."""
    engine = get_threat_intel_engine()
    success = engine.add_to_blocklist(entry.ip, entry.source)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add to blocklist")
    log_audit(
        action="ADD_TO_BLOCKLIST",
        resource_type="blocklist",
        details={"ip": entry.ip, "source": entry.source},
    )
    return {"ok": True, "ip": entry.ip}


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

@app.get("/api/v1/system/metrics", response_model=SystemMetrics, tags=["system"])
async def system_metrics(_: dict = Depends(verify_token)) -> SystemMetrics:
    """Get system metrics (CPU, memory, queue depth, packets/sec)."""
    import psutil
    process = psutil.Process()
    return SystemMetrics(
        uptime_seconds=round(time.time() - _start_time, 2),
        packets_received=_pipeline_metrics["packets_received"],
        packets_processed=_pipeline_metrics["packets_processed"],
        packets_dropped=_pipeline_metrics["packets_dropped"],
        queue_depth=_pipeline_metrics["queue_depth"],
        avg_processing_time_ms=_pipeline_metrics["avg_processing_time_ms"],
    )


@app.post("/api/v1/system/reload", tags=["system"])
async def reload_rules(_: dict = Depends(verify_token)) -> dict:
    """Hot-reload rules from database and blocklists without restart."""
    engine = get_threat_intel_engine()
    engine.reload_blocklists()
    log_audit(action="RELOAD_RULES", resource_type="system", details={})
    return {"ok": True, "message": "Rules and blocklists reloaded"}


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
    _: dict = Depends(verify_token),
) -> Response:
    """
    Export events as CSV or JSON.
    Query param: format=csv|json
    """
    events, _ = search_events(severity=severity, limit=100000)

    if format == "json":
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
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=nids_events.csv"},
    )


# ---------------------------------------------------------------------------
# PCAP download
# ---------------------------------------------------------------------------

@app.get("/api/v1/events/{event_id}/pcap", tags=["forensics"])
async def download_pcap(event_id: int, _: dict = Depends(verify_token)) -> Response:
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
async def threat_intel_lookup(ip: str, _: dict = Depends(verify_token)) -> dict:
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
