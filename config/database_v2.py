"""
NIDS — Database Module (SQLAlchemy / PostgreSQL with SQLite fallback)
======================================================================
Supports PostgreSQL (preferred) with SQLite as fallback via config flag.

Schema tables:
  - intrusion_events
  - system_events
  - alert_rules
  - threat_intel
  - audit_log
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator, Any

from sqlalchemy import (
    Column, Integer, BigInteger, String, Text, DateTime,
    Index, ForeignKey, Boolean, JSON, create_engine,
    event, text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker, relationship
from sqlalchemy.pool import QueuePool, StaticPool

from config.settings import get_settings

logger = logging.getLogger("NIDS.Database")


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class IntrusionEvent(Base):
    __tablename__ = "intrusion_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    event_type = Column(String(20), nullable=False)  # 'signature' | 'anomaly'
    severity = Column(String(20), nullable=False)    # LOW | MEDIUM | HIGH | CRITICAL
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    protocol = Column(String(10), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    rule_id = Column(Integer, nullable=True)
    packet_length = Column(Integer, nullable=True)
    tcp_flags = Column(Integer, nullable=True)
    ttl = Column(Integer, nullable=True)
    count = Column(Integer, nullable=True)
    threshold = Column(Integer, nullable=True)
    raw_message = Column(Text, nullable=True)
    ml_score = Column(String(10), nullable=True)  # e.g. "0.85"
    threat_intel_score = Column(Integer, nullable=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    country_code = Column(String(2), nullable=True)

    # Relationships
    rule = relationship("AlertRule", back_populates="events", foreign_keys="IntrusionEvent.rule_id")

    __table_args__ = (
        Index("idx_intrusion_timestamp", "timestamp"),
        Index("idx_intrusion_severity", "severity"),
        Index("idx_intrusion_src_ip", "src_ip"),
        Index("idx_intrusion_rule_id", "rule_id"),
        Index("idx_intrusion_event_type", "event_type"),
    )


class SystemEvent(Base):
    __tablename__ = "system_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    level = Column(String(20), nullable=False)   # DEBUG | INFO | WARNING | ERROR | CRITICAL
    message = Column(Text, nullable=False)
    component = Column(String(100), nullable=True)


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(30), nullable=False)  # SIGNATURE | RATE_LIMIT | PAYLOAD_MATCH | GEO_BLOCK | WHITELIST
    enabled = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    priority = Column(String(10), default="MEDIUM")  # LOW | MEDIUM | HIGH | CRITICAL

    # JSON fields for flexible rule definitions
    criteria = Column(JSON, nullable=False)  # rule-specific criteria (protocol, ports, regex, etc.)
    metadata = Column(JSON, nullable=True)   # additional metadata

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_matched = Column(DateTime(timezone=True), nullable=True)
    match_count = Column(BigInteger, default=0)

    # Relationships
    events = relationship("IntrusionEvent", back_populates="rule", foreign_keys="IntrusionEvent.rule_id")

    __table_args__ = (
        Index("idx_rules_enabled", "enabled"),
        Index("idx_rules_type", "rule_type"),
    )


class ThreatIntelEntry(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True)
    source = Column(String(50), nullable=False)  # 'abuseipdb' | 'blocklist' | 'manual'
    score = Column(Integer, nullable=True)       # 0-100 abuse score
    country_code = Column(String(2), nullable=True)
    isp = Column(String(200), nullable=True)
    domain = Column(String(200), nullable=True)
    reported_at = Column(DateTime(timezone=True), nullable=True)
    last_checked = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    cached_until = Column(DateTime(timezone=True), nullable=True)
    raw_data = Column(JSON, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    user = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)   # 'CREATE_RULE' | 'UPDATE_RULE' | 'DELETE_RULE' | 'ACK_EVENT' | etc.
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)


# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------

_engine: Engine | None = None
_SessionFactory: sessionmaker | None = None
_is_sqlite = False


def _create_engine(url: str, echo: bool = False) -> Engine:
    global _is_sqlite
    parsed = make_url(url)
    if parsed.driver == "sqlite":
        _is_sqlite = True
        engine = create_engine(
            url,
            echo=echo,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
        return engine
    else:
        _is_sqlite = False
        settings = get_settings()
        return create_engine(
            url,
            echo=echo,
            poolclass=QueuePool,
            pool_size=settings.database.pool_size,
            max_overflow=settings.database.max_overflow,
        )


def init_db(connection_url: str | None = None) -> None:
    """
    Initialise the database engine and create all tables.
    """
    global _engine, _SessionFactory
    settings = get_settings()
    url = connection_url or settings.database.url

    logger.info(f"Connecting to database: {url}")
    _engine = _create_engine(url, echo=settings.database.echo)
    _SessionFactory = sessionmaker(bind=_engine)

    # Create all tables
    Base.metadata.create_all(_engine)
    logger.info(f"Database initialised ({'SQLite' if _is_sqlite else 'PostgreSQL'}).")


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.
    Automatically handles commit/rollback.
    """
    if _SessionFactory is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_raw_connection():
    """Return a raw DBAPI connection for special operations."""
    if _engine is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _engine.raw_connection()


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def log_intrusion_event(
    event_type: str,
    severity: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> int | None:
    """Persist an intrusion event. Returns the event ID."""
    with get_session() as session:
        event = IntrusionEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            src_ip=details.get("src_ip"),
            dst_ip=details.get("dst_ip"),
            protocol=str(details.get("protocol", "")),
            src_port=details.get("src_port"),
            dst_port=details.get("dst_port"),
            description=details.get("description", message),
            rule_id=details.get("rule_id"),
            packet_length=details.get("packet_length"),
            tcp_flags=details.get("tcp_flags"),
            ttl=details.get("ttl"),
            count=details.get("count"),
            threshold=details.get("threshold"),
            raw_message=message,
            ml_score=details.get("ml_score"),
            threat_intel_score=details.get("threat_intel_score"),
            country_code=details.get("country_code"),
        )
        session.add(event)
        session.commit()
        session.refresh(event)
        return event.id


def log_system_event(level: str, message: str, component: str | None = None) -> None:
    """Persist a system event."""
    with get_session() as session:
        event = SystemEvent(
            timestamp=datetime.now(timezone.utc),
            level=level,
            message=message,
            component=component,
        )
        session.add(event)


def get_recent_events(limit: int = 100, severity: str | None = None) -> list[dict[str, Any]]:
    """Fetch recent intrusion events."""
    with get_session() as session:
        query = session.query(IntrusionEvent).order_by(IntrusionEvent.timestamp.desc())
        if severity:
            query = query.where(IntrusionEvent.severity == severity)
        rows = query.limit(limit).all()
        return [_row_to_dict(r) for r in rows]


def get_stats() -> dict[str, Any]:
    """Return summary statistics for the dashboard."""
    with get_session() as session:
        total = session.query(IntrusionEvent).count()
        severity_counts = {}
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            severity_counts[sev.lower()] = session.query(IntrusionEvent).filter(
                IntrusionEvent.severity == sev
            ).count()

        top_sources = session.query(
            IntrusionEvent.src_ip,
            func.count(IntrusionEvent.id).label("count"),
        ).filter(
            IntrusionEvent.src_ip.isnot(None)
        ).group_by(
            IntrusionEvent.src_ip
        ).order_by(
            func.count(IntrusionEvent.id).desc()
        ).limit(10).all()

        recent_24h = session.query(IntrusionEvent).filter(
            IntrusionEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
        ).count()

        recent_1h = session.query(IntrusionEvent).filter(
            IntrusionEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=1)
        ).count()

        return {
            "total": total,
            **severity_counts,
            "recent_24h": recent_24h,
            "recent_1h": recent_1h,
            "top_sources": [{"src_ip": r[0], "count": r[1]} for r in top_sources],
        }


def search_events(
    query: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Search intrusion events with filters. Returns (events, total_count)."""
    with get_session() as session:
        q = session.query(IntrusionEvent)
        if query:
            q = q.filter(
                IntrusionEvent.description.ilike(f"%{query}%") |
                IntrusionEvent.src_ip.ilike(f"%{query}%") |
                IntrusionEvent.dst_ip.ilike(f"%{query}%")
            )
        if severity:
            q = q.filter(IntrusionEvent.severity == severity)
        if event_type:
            q = q.filter(IntrusionEvent.event_type == event_type)
        if src_ip:
            q = q.filter(IntrusionEvent.src_ip == src_ip)

        total = q.count()
        rows = q.order_by(IntrusionEvent.timestamp.desc()).offset(offset).limit(limit).all()
        return [_row_to_dict(r) for r in rows], total


def acknowledge_event(event_id: int, acknowledged_by: str = "system") -> bool:
    """Mark an event as acknowledged."""
    with get_session() as session:
        event = session.query(IntrusionEvent).filter(IntrusionEvent.id == event_id).first()
        if not event:
            return False
        event.acknowledged = True
        event.acknowledged_by = acknowledged_by
        event.acknowledged_at = datetime.now(timezone.utc)
        return True


def delete_event(event_id: int) -> bool:
    """Delete an intrusion event by ID."""
    with get_session() as session:
        event = session.query(IntrusionEvent).filter(IntrusionEvent.id == event_id).first()
        if not event:
            return False
        session.delete(event)
        return True


def clear_events() -> None:
    """Clear all intrusion events."""
    with get_session() as session:
        session.query(IntrusionEvent).delete()


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------

def create_rule(
    name: str,
    rule_type: str,
    criteria: dict,
    description: str | None = None,
    priority: str = "MEDIUM",
    metadata: dict | None = None,
) -> int:
    """Create a new alert rule. Returns the rule ID."""
    with get_session() as session:
        rule = AlertRule(
            name=name,
            rule_type=rule_type,
            criteria=criteria,
            description=description,
            priority=priority,
            metadata=metadata,
        )
        session.add(rule)
        session.commit()
        session.refresh(rule)
        return rule.id


def get_rules(enabled: bool | None = None) -> list[dict[str, Any]]:
    """Get all rules, optionally filtered by enabled status."""
    with get_session() as session:
        q = session.query(AlertRule)
        if enabled is not None:
            q = q.filter(AlertRule.enabled == enabled)
        rows = q.order_by(AlertRule.id).all()
        return [_row_to_dict(r) for r in rows]


def get_rule(rule_id: int) -> dict[str, Any] | None:
    """Get a single rule by ID."""
    with get_session() as session:
        rule = session.query(AlertRule).filter(AlertRule.id == rule_id).first()
        return _row_to_dict(rule) if rule else None


def update_rule(rule_id: int, **fields) -> bool:
    """Update a rule's fields. Returns True if found and updated."""
    with get_session() as session:
        rule = session.query(AlertRule).filter(AlertRule.id == rule_id).first()
        if not rule:
            return False
        for key, value in fields.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.updated_at = datetime.now(timezone.utc)
        rule.version = (rule.version or 0) + 1
        return True


def delete_rule(rule_id: int) -> bool:
    """Delete a rule."""
    with get_session() as session:
        rule = session.query(AlertRule).filter(AlertRule.id == rule_id).first()
        if not rule:
            return False
        session.delete(rule)
        return True


def toggle_rule(rule_id: int) -> bool:
    """Toggle a rule's enabled status."""
    with get_session() as session:
        rule = session.query(AlertRule).filter(AlertRule.id == rule_id).first()
        if not rule:
            return False
        rule.enabled = not rule.enabled
        rule.updated_at = datetime.now(timezone.utc)
        return True


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_audit(
    action: str,
    resource_type: str,
    resource_id: int | None = None,
    user: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Log an audit entry."""
    with get_session() as session:
        entry = AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user=user,
            details=details,
            ip_address=ip_address,
        )
        session.add(entry)


# ---------------------------------------------------------------------------
# Threat intel helpers
# ---------------------------------------------------------------------------

def upsert_threat_intel(ip_address: str, source: str, score: int | None = None, **fields) -> None:
    """Insert or update a threat intel entry."""
    with get_session() as session:
        existing = session.query(ThreatIntelEntry).filter(
            ThreatIntelEntry.ip_address == ip_address
        ).first()
        if existing:
            if score is not None:
                existing.score = score
            for k, v in fields.items():
                if hasattr(existing, k):
                    setattr(existing, k, v)
            existing.last_checked = datetime.now(timezone.utc)
        else:
            entry = ThreatIntelEntry(
                ip_address=ip_address,
                source=source,
                score=score,
                last_checked=datetime.now(timezone.utc),
                **fields,
            )
            session.add(entry)


def get_threat_intel(ip_address: str) -> dict[str, Any] | None:
    """Get threat intel for an IP if cached and not expired."""
    with get_session() as session:
        entry = session.query(ThreatIntelEntry).filter(
            ThreatIntelEntry.ip_address == ip_address
        ).first()
        if entry and entry.cached_until and entry.cached_until > datetime.now(timezone.utc):
            return _row_to_dict(entry)
        return None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _row_to_dict(row) -> dict[str, Any]:
    """Convert a SQLAlchemy model row to a dict."""
    result = {}
    for col in row.__table__.columns:
        val = getattr(row, col.name)
        if isinstance(val, datetime):
            val = val.isoformat() if val else None
        result[col.name] = val
    return result


# Import these at the bottom to avoid circular imports
from datetime import timedelta
from sqlalchemy import func
