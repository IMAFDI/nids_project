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
import os
import time
import hashlib
import hmac
import secrets
import json
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Generator, Any

from sqlalchemy import (
    Column, Integer, BigInteger, String, Text, DateTime,
    Index, ForeignKey, Boolean, JSON, UniqueConstraint, create_engine,
    event, text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy import inspect
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
    rule_id = Column(Integer, ForeignKey("alert_rules.id"), nullable=True)
    packet_length = Column(Integer, nullable=True)
    tcp_flags = Column(Integer, nullable=True)
    ttl = Column(Integer, nullable=True)
    count = Column(Integer, nullable=True)
    threshold = Column(Integer, nullable=True)
    raw_message = Column(Text, nullable=True)
    ml_score = Column(String(10), nullable=True)  # e.g. "0.85"
    threat_intel_score = Column(Integer, nullable=True)
    acknowledged = Column(Boolean, default=False, nullable=False, server_default="false")
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    country_code = Column(String(2), nullable=True)
    tenant_id = Column(String(100), nullable=True)
    archived_at = Column(DateTime(timezone=True), nullable=True)

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
    lifecycle_state = Column(String(20), nullable=False, default="production", server_default="production")
    version = Column(Integer, default=1)
    priority = Column(String(10), default="MEDIUM")  # LOW | MEDIUM | HIGH | CRITICAL

    # JSON fields for flexible rule definitions
    criteria = Column(JSON, nullable=False)  # rule-specific criteria (protocol, ports, regex, etc.)
    rule_metadata = Column(JSON, nullable=True)   # additional metadata
    mitre_tactics = Column(JSON, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)
    suppression_enabled = Column(Boolean, nullable=False, default=False, server_default="false")
    suppression_window_seconds = Column(Integer, nullable=False, default=0, server_default="0")
    last_trigger_fingerprint = Column(String(255), nullable=True)
    last_trigger_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_matched = Column(DateTime(timezone=True), nullable=True)
    match_count = Column(BigInteger, default=0)

    # Relationships
    events = relationship("IntrusionEvent", back_populates="rule", foreign_keys="IntrusionEvent.rule_id")

    __table_args__ = (
        Index("idx_rules_enabled", "enabled"),
        Index("idx_rules_lifecycle_state", "lifecycle_state"),
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


class UserAccount(Base):
    __tablename__ = "user_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False, default="analyst")
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    password_hash = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_user_accounts_username", "username"),
        Index("idx_user_accounts_email", "email"),
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    requested_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_password_reset_user_id", "user_id"),
        Index("idx_password_reset_expires_at", "expires_at"),
        Index("idx_password_reset_consumed_at", "consumed_at"),
    )


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    status = Column(String(30), nullable=False, default="OPEN")
    severity = Column(String(20), nullable=False, default="MEDIUM")
    priority = Column(String(20), nullable=False, default="MEDIUM")
    owner_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_cases_status", "status"),
        Index("idx_cases_severity", "severity"),
        Index("idx_cases_owner", "owner_user_id"),
        Index("idx_cases_created_by", "created_by_user_id"),
    )


class CaseEvent(Base):
    __tablename__ = "case_events"

    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True, nullable=False)
    event_id = Column(Integer, ForeignKey("intrusion_events.id", ondelete="CASCADE"), primary_key=True, nullable=False)

    __table_args__ = (
        UniqueConstraint("case_id", "event_id", name="uq_case_events_case_event"),
        Index("idx_case_events_case_id", "case_id"),
        Index("idx_case_events_event_id", "event_id"),
    )


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    author_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_case_notes_case_id", "case_id"),
        Index("idx_case_notes_author_user_id", "author_user_id"),
        Index("idx_case_notes_created_at", "created_at"),
    )


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    trigger_severities = Column(JSON, nullable=False, default=list)
    trigger_rule_ids = Column(JSON, nullable=False, default=list)
    trigger_event_types = Column(JSON, nullable=False, default=list)
    enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    actions = Column(JSON, nullable=False, default=list)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    success_count = Column(BigInteger, nullable=False, default=0, server_default="0")
    failure_count = Column(BigInteger, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_playbooks_enabled", "enabled"),
        Index("idx_playbooks_name", "name"),
        Index("idx_playbooks_updated_at", "updated_at"),
    )


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    event_id = Column(Integer, ForeignKey("intrusion_events.id", ondelete="SET NULL"), nullable=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False)
    status = Column(String(30), nullable=False)  # success | failed | skipped
    response_payload = Column(JSON, nullable=True)
    error_details = Column(Text, nullable=True)
    actor = Column(String(100), nullable=True)
    actor_type = Column(String(20), nullable=False, default="system", server_default="system")
    started_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_playbook_exec_playbook_id", "playbook_id"),
        Index("idx_playbook_exec_event_id", "event_id"),
        Index("idx_playbook_exec_case_id", "case_id"),
        Index("idx_playbook_exec_created_at", "created_at"),
    )


class TicketIntegrationConfig(Base):
    __tablename__ = "ticket_integration_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider_type = Column(String(50), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=False, server_default="false")
    config = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_ticket_integration_provider", "provider_type"),
        Index("idx_ticket_integration_enabled", "enabled"),
    )


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    scope = Column(String(30), nullable=False, default="global", server_default="global")
    hot_days = Column(Integer, nullable=False, default=7, server_default="7")
    warm_days = Column(Integer, nullable=False, default=30, server_default="30")
    cold_days = Column(Integer, nullable=False, default=90, server_default="90")
    archive_enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    delete_after_days = Column(Integer, nullable=False, default=365, server_default="365")
    enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    severity = Column(String(20), nullable=True)
    tenant_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_retention_scope", "scope"),
        Index("idx_retention_enabled", "enabled"),
        Index("idx_retention_tenant_id", "tenant_id"),
        Index("idx_retention_severity", "severity"),
    )


class SLOSnapshot(Base):
    __tablename__ = "slo_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=True)
    ingestion_availability = Column(Integer, nullable=False, default=100, server_default="100")
    latency_p50_ms = Column(Integer, nullable=False, default=0, server_default="0")
    latency_p95_ms = Column(Integer, nullable=False, default=0, server_default="0")
    queue_depth = Column(Integer, nullable=False, default=0, server_default="0")
    queue_trend = Column(String(20), nullable=False, default="stable", server_default="stable")
    broker_state = Column(String(20), nullable=False, default="unknown", server_default="unknown")
    db_state = Column(String(20), nullable=False, default="unknown", server_default="unknown")
    cache_state = Column(String(20), nullable=False, default="unknown", server_default="unknown")
    error_budget_remaining = Column(Integer, nullable=False, default=100, server_default="100")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_slo_snapshots_created_at", "created_at"),
        Index("idx_slo_snapshots_tenant_id", "tenant_id"),
    )


class BackupOperation(Base):
    __tablename__ = "backup_operations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    operation_type = Column(String(30), nullable=False)
    status = Column(String(20), nullable=False, default="pending", server_default="pending")
    duration_ms = Column(Integer, nullable=True)
    artifact_path = Column(Text, nullable=True)
    operation_metadata = Column(JSON, nullable=True)
    initiated_by = Column(String(100), nullable=True)
    source_ip = Column(String(45), nullable=True)
    tenant_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_backup_operations_created_at", "created_at"),
        Index("idx_backup_operations_status", "status"),
        Index("idx_backup_operations_tenant_id", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------

_engine: Engine | None = None
_SessionFactory: sessionmaker | None = None
_is_sqlite = False


def _create_engine(url: str, echo: bool = False) -> Engine:
    global _is_sqlite
    parsed = make_url(url)
    # SQLAlchemy 2.0 uses drivername instead of driver
    if parsed.drivername.startswith("sqlite"):
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
    _ensure_alert_rule_columns()
    _ensure_playbook_columns()
    _ensure_intrusion_event_columns()
    _ensure_retention_tables()
    _ensure_slo_snapshot_table()
    _ensure_backup_operations_table()
    _ensure_default_user()
    logger.info(f"Database initialised ({'SQLite' if _is_sqlite else 'PostgreSQL'}).")


def _ensure_alert_rule_columns() -> None:
    """
    Ensure additive alert_rules columns exist for backward-compatible upgrades.
    """
    if _engine is None:
        return
    inspector = inspect(_engine)
    existing = {c["name"] for c in inspector.get_columns("alert_rules")}
    missing = {
        "lifecycle_state": "TEXT NOT NULL DEFAULT 'production'",
        "mitre_tactics": "TEXT",
        "mitre_techniques": "TEXT",
        "suppression_enabled": "BOOLEAN NOT NULL DEFAULT 0",
        "suppression_window_seconds": "INTEGER NOT NULL DEFAULT 0",
        "last_trigger_fingerprint": "TEXT",
        "last_trigger_at": "TIMESTAMP",
    }
    with _engine.begin() as conn:
        for col, ddl in missing.items():
            if col in existing:
                continue
            conn.execute(text(f"ALTER TABLE alert_rules ADD COLUMN {col} {ddl}"))


def _ensure_playbook_columns() -> None:
    """
    Ensure additive playbook columns exist for backward-compatible upgrades.
    """
    if _engine is None:
        return
    inspector = inspect(_engine)

    if "playbooks" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("playbooks")}
        missing = {
            "trigger_severities": "TEXT",
            "trigger_rule_ids": "TEXT",
            "trigger_event_types": "TEXT",
            "enabled": "BOOLEAN NOT NULL DEFAULT 1",
            "actions": "TEXT",
            "last_run_at": "TIMESTAMP",
            "success_count": "BIGINT NOT NULL DEFAULT 0",
            "failure_count": "BIGINT NOT NULL DEFAULT 0",
            "created_at": "TIMESTAMP",
            "updated_at": "TIMESTAMP",
        }
        with _engine.begin() as conn:
            for col, ddl in missing.items():
                if col in existing:
                    continue
                conn.execute(text(f"ALTER TABLE playbooks ADD COLUMN {col} {ddl}"))

    if "playbook_executions" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("playbook_executions")}
        missing = {
            "response_payload": "TEXT",
            "error_details": "TEXT",
            "actor": "TEXT",
            "actor_type": "TEXT NOT NULL DEFAULT 'system'",
            "started_at": "TIMESTAMP",
            "finished_at": "TIMESTAMP",
            "created_at": "TIMESTAMP",
        }
        with _engine.begin() as conn:
            for col, ddl in missing.items():
                if col in existing:
                    continue
                conn.execute(text(f"ALTER TABLE playbook_executions ADD COLUMN {col} {ddl}"))

    if "ticket_integration_configs" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("ticket_integration_configs")}
        missing = {
            "enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "config": "TEXT",
            "created_at": "TIMESTAMP",
            "updated_at": "TIMESTAMP",
        }
        with _engine.begin() as conn:
            for col, ddl in missing.items():
                if col in existing:
                    continue
                conn.execute(text(f"ALTER TABLE ticket_integration_configs ADD COLUMN {col} {ddl}"))


def _ensure_intrusion_event_columns() -> None:
    if _engine is None:
        return
    inspector = inspect(_engine)
    if "intrusion_events" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("intrusion_events")}
    missing = {
        "tenant_id": "TEXT",
        "archived_at": "TIMESTAMP",
    }
    with _engine.begin() as conn:
        for col, ddl in missing.items():
            if col in existing:
                continue
            conn.execute(text(f"ALTER TABLE intrusion_events ADD COLUMN {col} {ddl}"))


def _ensure_retention_tables() -> None:
    if _engine is None:
        return
    Base.metadata.tables["retention_policies"].create(bind=_engine, checkfirst=True)


def _ensure_slo_snapshot_table() -> None:
    if _engine is None:
        return
    Base.metadata.tables["slo_snapshots"].create(bind=_engine, checkfirst=True)


def _ensure_backup_operations_table() -> None:
    if _engine is None:
        return
    Base.metadata.tables["backup_operations"].create(bind=_engine, checkfirst=True)


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

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, iter_str, salt_hex, digest_hex = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations)
        return hmac.compare_digest(check.hex(), digest_hex)
    except Exception:
        return False


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _ensure_default_user() -> None:
    """Ensure a default admin user exists for first login."""
    username = os.environ.get("NIDS_API_USER", "admin").strip() or "admin"
    password = os.environ.get("NIDS_API_PASSWORD", "admin")
    email = os.environ.get("NIDS_API_EMAIL", "admin@nids.local").strip() or "admin@nids.local"

    with get_session() as session:
        existing = session.query(UserAccount).filter(UserAccount.username == username).first()
        if existing:
            return
        user = UserAccount(
            username=username,
            email=email,
            full_name="Administrator",
            role="admin",
            is_active=True,
            password_hash=_hash_password(password),
        )
        session.add(user)
        logger.info("Created default admin account: %s", username)


def create_user(
    username: str,
    email: str,
    password: str,
    full_name: str | None = None,
    role: str = "analyst",
) -> dict[str, Any]:
    with get_session() as session:
        exists = session.query(UserAccount).filter(
            (UserAccount.username == username) | (UserAccount.email == email)
        ).first()
        if exists:
            raise ValueError("username_or_email_exists")
        user = UserAccount(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            is_active=True,
            password_hash=_hash_password(password),
        )
        session.add(user)
        session.flush()
        session.refresh(user)
        return _row_to_dict(user)


def get_user_by_identifier(identifier: str) -> dict[str, Any] | None:
    ident = (identifier or "").strip()
    if not ident:
        return None
    with get_session() as session:
        user = session.query(UserAccount).filter(
            (UserAccount.username == ident) | (UserAccount.email == ident)
        ).first()
        return _row_to_dict(user) if user else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with get_session() as session:
        user = session.query(UserAccount).filter(UserAccount.id == user_id).first()
        return _row_to_dict(user) if user else None


def get_user_by_email(email: str) -> dict[str, Any] | None:
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    with get_session() as session:
        user = session.query(UserAccount).filter(UserAccount.email == normalized).first()
        return _row_to_dict(user) if user else None


def update_user_profile(user_id: int, full_name: str | None = None, email: str | None = None) -> dict[str, Any] | None:
    with get_session() as session:
        user = session.query(UserAccount).filter(UserAccount.id == user_id).first()
        if not user:
            return None
        if email and email != user.email:
            dupe = session.query(UserAccount).filter(UserAccount.email == email, UserAccount.id != user_id).first()
            if dupe:
                raise ValueError("email_exists")
            user.email = email
        if full_name is not None:
            user.full_name = full_name
        user.updated_at = datetime.now(timezone.utc)
        session.flush()
        session.refresh(user)
        return _row_to_dict(user)


def update_user_password(user_id: int, new_password: str) -> bool:
    with get_session() as session:
        user = session.query(UserAccount).filter(UserAccount.id == user_id).first()
        if not user:
            return False
        user.password_hash = _hash_password(new_password)
        user.updated_at = datetime.now(timezone.utc)
        return True


def touch_user_last_login(user_id: int) -> None:
    with get_session() as session:
        user = session.query(UserAccount).filter(UserAccount.id == user_id).first()
        if user:
            user.last_login = datetime.now(timezone.utc)


def create_password_reset_token(
    user_id: int,
    expires_in_minutes: int = 30,
    requested_ip: str | None = None,
) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = _hash_reset_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=max(1, expires_in_minutes))
    now = datetime.now(timezone.utc)
    with get_session() as session:
        session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.consumed_at.is_(None),
        ).update({"consumed_at": now}, synchronize_session=False)
        row = PasswordResetToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            requested_ip=requested_ip,
            created_at=now,
        )
        session.add(row)
    return token


def consume_password_reset_token(email: str, token: str, new_password: str) -> bool:
    normalized = (email or "").strip().lower()
    token_hash = _hash_reset_token(token or "")
    now = datetime.now(timezone.utc)
    with get_session() as session:
        user = session.query(UserAccount).filter(UserAccount.email == normalized).first()
        if not user or not user.is_active:
            return False
        row = session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.expires_at > now,
        ).first()
        if not row:
            return False
        user.password_hash = _hash_password(new_password)
        user.updated_at = now
        row.consumed_at = now
        session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.id != row.id,
        ).update({"consumed_at": now}, synchronize_session=False)
        return True

def log_intrusion_event(
    event_type: str,
    severity: str,
    message: str,
    details: dict[str, Any] | None = None,
    tenant_id: str | None = None,
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
            tenant_id=tenant_id,
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


def list_retention_policies(tenant_id: str | None = None) -> list[dict[str, Any]]:
    with get_session() as session:
        q = session.query(RetentionPolicy)
        if tenant_id:
            q = q.filter(
                (RetentionPolicy.tenant_id == tenant_id) |
                (RetentionPolicy.tenant_id.is_(None))
            )
        rows = q.order_by(RetentionPolicy.id.asc()).all()
        return [_row_to_dict(r) for r in rows]


def create_retention_policy(
    name: str,
    scope: str,
    hot_days: int,
    warm_days: int,
    cold_days: int,
    archive_enabled: bool,
    delete_after_days: int,
    enabled: bool = True,
    severity: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    with get_session() as session:
        row = RetentionPolicy(
            name=name.strip(),
            scope=scope,
            hot_days=hot_days,
            warm_days=warm_days,
            cold_days=cold_days,
            archive_enabled=archive_enabled,
            delete_after_days=delete_after_days,
            enabled=enabled,
            severity=severity,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.flush()
        session.refresh(row)
        return _row_to_dict(row)


def get_retention_policy(policy_id: int) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
        return _row_to_dict(row) if row else None


def update_retention_policy(policy_id: int, **fields) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
        if not row:
            return None
        allowed = {
            "name",
            "scope",
            "hot_days",
            "warm_days",
            "cold_days",
            "archive_enabled",
            "delete_after_days",
            "enabled",
            "severity",
            "tenant_id",
        }
        for key, value in fields.items():
            if key in allowed:
                setattr(row, key, value)
        row.updated_at = datetime.now(timezone.utc)
        session.flush()
        session.refresh(row)
        return _row_to_dict(row)


def delete_retention_policy(policy_id: int) -> bool:
    with get_session() as session:
        row = session.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
        if not row:
            return False
        session.delete(row)
        return True


def retention_maintenance_preview(
    *,
    tenant_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    with get_session() as session:
        policies_q = session.query(RetentionPolicy).filter(RetentionPolicy.enabled.is_(True))
        if tenant_id:
            policies_q = policies_q.filter(
                (RetentionPolicy.tenant_id == tenant_id) |
                (RetentionPolicy.tenant_id.is_(None))
            )
        policies = policies_q.order_by(RetentionPolicy.scope.desc(), RetentionPolicy.id.asc()).all()

        if not policies:
            return {"evaluated_events": 0, "archive_candidates": 0, "delete_candidates": 0, "matched_policy_ids": []}

        events_q = session.query(IntrusionEvent)
        if tenant_id:
            events_q = events_q.filter(
                (IntrusionEvent.tenant_id == tenant_id) |
                (IntrusionEvent.tenant_id.is_(None))
            )
        events = events_q.all()

        archive_candidates = 0
        delete_candidates = 0
        matched_policy_ids: set[int] = set()
        for event in events:
            policy = _select_retention_policy_for_event(event, policies)
            if not policy:
                continue
            matched_policy_ids.add(policy.id)
            event_ts = _ensure_utc(event.timestamp)
            age_days = max(0, int((current - event_ts).total_seconds() // 86400))
            if policy.archive_enabled and event.archived_at is None and age_days >= policy.cold_days:
                archive_candidates += 1
            if policy.delete_after_days > 0 and age_days >= policy.delete_after_days:
                delete_candidates += 1

        return {
            "evaluated_events": len(events),
            "archive_candidates": archive_candidates,
            "delete_candidates": delete_candidates,
            "matched_policy_ids": sorted(matched_policy_ids),
        }


def execute_retention_maintenance(
    *,
    tenant_id: str | None = None,
    apply_delete: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    with get_session() as session:
        policies_q = session.query(RetentionPolicy).filter(RetentionPolicy.enabled.is_(True))
        if tenant_id:
            policies_q = policies_q.filter(
                (RetentionPolicy.tenant_id == tenant_id) |
                (RetentionPolicy.tenant_id.is_(None))
            )
        policies = policies_q.order_by(RetentionPolicy.scope.desc(), RetentionPolicy.id.asc()).all()
        if not policies:
            return {
                "evaluated_events": 0,
                "archived_count": 0,
                "deleted_count": 0,
                "delete_applied": apply_delete,
                "matched_policy_ids": [],
            }

        events_q = session.query(IntrusionEvent)
        if tenant_id:
            events_q = events_q.filter(
                (IntrusionEvent.tenant_id == tenant_id) |
                (IntrusionEvent.tenant_id.is_(None))
            )
        events = events_q.all()

        archived_count = 0
        deleted_ids: list[int] = []
        matched_policy_ids: set[int] = set()
        for event in events:
            policy = _select_retention_policy_for_event(event, policies)
            if not policy:
                continue
            matched_policy_ids.add(policy.id)
            event_ts = _ensure_utc(event.timestamp)
            age_days = max(0, int((current - event_ts).total_seconds() // 86400))
            if policy.archive_enabled and event.archived_at is None and age_days >= policy.cold_days:
                event.archived_at = current
                archived_count += 1
            if apply_delete and policy.delete_after_days > 0 and age_days >= policy.delete_after_days:
                deleted_ids.append(event.id)

        deleted_count = 0
        if deleted_ids:
            deleted_count = (
                session.query(IntrusionEvent)
                .filter(IntrusionEvent.id.in_(deleted_ids))
                .delete(synchronize_session=False)
            )

        return {
            "evaluated_events": len(events),
            "archived_count": archived_count,
            "deleted_count": deleted_count,
            "delete_applied": apply_delete,
            "matched_policy_ids": sorted(matched_policy_ids),
        }


def create_slo_snapshot(
    *,
    ingestion_availability: float,
    latency_p50_ms: float,
    latency_p95_ms: float,
    queue_depth: int,
    queue_trend: str,
    broker_state: str,
    db_state: str,
    cache_state: str,
    error_budget_remaining: float,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    with get_session() as session:
        row = SLOSnapshot(
            tenant_id=tenant_id,
            ingestion_availability=int(round(ingestion_availability)),
            latency_p50_ms=int(round(latency_p50_ms)),
            latency_p95_ms=int(round(latency_p95_ms)),
            queue_depth=queue_depth,
            queue_trend=queue_trend,
            broker_state=broker_state,
            db_state=db_state,
            cache_state=cache_state,
            error_budget_remaining=int(round(error_budget_remaining)),
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.flush()
        session.refresh(row)
        return _row_to_dict(row)


def list_slo_snapshots(limit: int = 48, tenant_id: str | None = None) -> list[dict[str, Any]]:
    with get_session() as session:
        q = session.query(SLOSnapshot)
        if tenant_id:
            q = q.filter(
                (SLOSnapshot.tenant_id == tenant_id) |
                (SLOSnapshot.tenant_id.is_(None))
            )
        rows = q.order_by(SLOSnapshot.created_at.desc()).limit(limit).all()
        return [_row_to_dict(r) for r in rows]


def create_backup_operation(
    *,
    operation_type: str,
    status: str,
    duration_ms: int | None = None,
    artifact_path: str | None = None,
    operation_metadata: dict[str, Any] | None = None,
    initiated_by: str | None = None,
    source_ip: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    with get_session() as session:
        row = BackupOperation(
            operation_type=operation_type,
            status=status,
            duration_ms=duration_ms,
            artifact_path=artifact_path,
            operation_metadata=operation_metadata or {},
            initiated_by=initiated_by,
            source_ip=source_ip,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.flush()
        session.refresh(row)
        return _row_to_dict(row)


def list_backup_operations(limit: int = 50, tenant_id: str | None = None) -> list[dict[str, Any]]:
    with get_session() as session:
        q = session.query(BackupOperation)
        if tenant_id:
            q = q.filter(
                (BackupOperation.tenant_id == tenant_id) |
                (BackupOperation.tenant_id.is_(None))
            )
        rows = q.order_by(BackupOperation.created_at.desc()).limit(limit).all()
        return [_row_to_dict(r) for r in rows]


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
    lifecycle_state: str = "production",
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    suppression_enabled: bool = False,
    suppression_window_seconds: int = 0,
) -> int:
    """Create a new alert rule. Returns the rule ID."""
    with get_session() as session:
        rule = AlertRule(
            name=name,
            rule_type=rule_type,
            criteria=criteria,
            description=description,
            priority=priority,
            rule_metadata=metadata,
            lifecycle_state=lifecycle_state,
            mitre_tactics=mitre_tactics or [],
            mitre_techniques=mitre_techniques or [],
            suppression_enabled=suppression_enabled,
            suppression_window_seconds=suppression_window_seconds,
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


def get_rules_by_mitre(technique: str | None = None, tactic: str | None = None) -> list[dict[str, Any]]:
    """Get rules filtered by MITRE technique and/or tactic."""
    with get_session() as session:
        rows = session.query(AlertRule).order_by(AlertRule.id).all()
        rules = [_row_to_dict(r) for r in rows]

    def _norm(values: Any) -> list[str]:
        if values is None:
            return []
        if isinstance(values, list):
            return [str(v).strip() for v in values if str(v).strip()]
        if isinstance(values, str):
            txt = values.strip()
            if not txt:
                return []
            if txt.startswith("["):
                try:
                    parsed = json.loads(txt)
                    if isinstance(parsed, list):
                        return [str(v).strip() for v in parsed if str(v).strip()]
                except Exception:
                    pass
            return [v.strip() for v in txt.split(",") if v.strip()]
        return [str(values).strip()]

    filtered = rules
    if technique:
        t = technique.strip().upper()
        filtered = [
            r for r in filtered
            if any(x.upper() == t for x in _norm(r.get("mitre_techniques")))
        ]
    if tactic:
        t = tactic.strip().lower()
        filtered = [
            r for r in filtered
            if any(x.lower() == t for x in _norm(r.get("mitre_tactics")))
        ]
    return filtered


def update_rule_last_trigger(
    rule_id: int,
    fingerprint: str,
    triggered_at: datetime | None = None,
) -> bool:
    """Update rule trigger tracking fields used for suppression."""
    with get_session() as session:
        rule = session.query(AlertRule).filter(AlertRule.id == rule_id).first()
        if not rule:
            return False
        rule.last_trigger_fingerprint = fingerprint
        rule.last_trigger_at = triggered_at or datetime.now(timezone.utc)
        rule.updated_at = datetime.now(timezone.utc)
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


def create_case(
    title: str,
    created_by_user_id: int,
    severity: str = "MEDIUM",
    priority: str = "MEDIUM",
    status: str = "OPEN",
    owner_user_id: int | None = None,
    event_ids: list[int] | None = None,
) -> dict[str, Any]:
    with get_session() as session:
        case = Case(
            title=title,
            status=status,
            severity=severity,
            priority=priority,
            owner_user_id=owner_user_id,
            created_by_user_id=created_by_user_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(case)
        session.flush()
        if event_ids:
            existing_ids = {
                row[0]
                for row in session.query(IntrusionEvent.id)
                .filter(IntrusionEvent.id.in_(list(set(event_ids))))
                .all()
            }
            for event_id in existing_ids:
                session.add(CaseEvent(case_id=case.id, event_id=event_id))
        session.flush()
        session.refresh(case)
        return _row_to_dict(case)


def list_cases(
    status: str | None = None,
    owner_user_id: int | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    with get_session() as session:
        q = session.query(Case)
        if status:
            q = q.filter(Case.status == status)
        if owner_user_id is not None:
            q = q.filter(Case.owner_user_id == owner_user_id)
        if severity:
            q = q.filter(Case.severity == severity)
        total = q.count()
        rows = q.order_by(Case.updated_at.desc(), Case.id.desc()).offset(offset).limit(limit).all()
        return [_row_to_dict(r) for r in rows], total


def get_case(case_id: int) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(Case).filter(Case.id == case_id).first()
        return _row_to_dict(row) if row else None


def update_case(case_id: int, **fields) -> dict[str, Any] | None:
    with get_session() as session:
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            return None
        allowed = {"title", "status", "priority", "owner_user_id", "severity"}
        changed_status = None
        for key, value in fields.items():
            if key in allowed:
                setattr(case, key, value)
                if key == "status":
                    changed_status = str(value).upper() if value is not None else None
        case.updated_at = datetime.now(timezone.utc)
        if changed_status == "CLOSED":
            case.closed_at = datetime.now(timezone.utc)
        elif changed_status and case.closed_at is not None:
            case.closed_at = None
        session.flush()
        session.refresh(case)
        return _row_to_dict(case)


def add_case_note(case_id: int, author_user_id: int, note: str) -> dict[str, Any] | None:
    with get_session() as session:
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            return None
        note_row = CaseNote(
            case_id=case_id,
            author_user_id=author_user_id,
            note=note,
            created_at=datetime.now(timezone.utc),
        )
        case.updated_at = datetime.now(timezone.utc)
        session.add(note_row)
        session.flush()
        session.refresh(note_row)
        return _row_to_dict(note_row)


def list_case_notes(case_id: int) -> list[dict[str, Any]]:
    with get_session() as session:
        rows = (
            session.query(CaseNote)
            .filter(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at.asc(), CaseNote.id.asc())
            .all()
        )
        return [_row_to_dict(r) for r in rows]


def list_case_events(case_id: int) -> list[dict[str, Any]]:
    with get_session() as session:
        rows = (
            session.query(IntrusionEvent)
            .join(CaseEvent, CaseEvent.event_id == IntrusionEvent.id)
            .filter(CaseEvent.case_id == case_id)
            .order_by(IntrusionEvent.timestamp.desc())
            .all()
        )
        return [_row_to_dict(r) for r in rows]


def link_case_event(case_id: int, event_id: int) -> bool:
    with get_session() as session:
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            return False
        intrusion_event = session.query(IntrusionEvent).filter(IntrusionEvent.id == event_id).first()
        if not intrusion_event:
            return False
        existing = session.query(CaseEvent).filter(CaseEvent.case_id == case_id, CaseEvent.event_id == event_id).first()
        if existing:
            return True
        session.add(CaseEvent(case_id=case_id, event_id=event_id))
        case.updated_at = datetime.now(timezone.utc)
        return True


def unlink_case_event(case_id: int, event_id: int) -> bool:
    with get_session() as session:
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            return False
        link = session.query(CaseEvent).filter(CaseEvent.case_id == case_id, CaseEvent.event_id == event_id).first()
        if not link:
            return False
        session.delete(link)
        case.updated_at = datetime.now(timezone.utc)
        return True


def get_case_detail(case_id: int) -> dict[str, Any] | None:
    case = get_case(case_id)
    if not case:
        return None
    case["events"] = list_case_events(case_id)
    case["notes"] = list_case_notes(case_id)
    return case


# ---------------------------------------------------------------------------
# Playbook CRUD and execution persistence
# ---------------------------------------------------------------------------

def _normalize_json_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def _normalize_json_object(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _normalise_playbook_dict(row_dict: dict[str, Any]) -> dict[str, Any]:
    row_dict["trigger_severities"] = _normalize_json_list(row_dict.get("trigger_severities"))
    row_dict["trigger_rule_ids"] = _normalize_json_list(row_dict.get("trigger_rule_ids"))
    row_dict["trigger_event_types"] = _normalize_json_list(row_dict.get("trigger_event_types"))
    row_dict["actions"] = _normalize_json_list(row_dict.get("actions"))
    return row_dict


def _normalise_execution_dict(row_dict: dict[str, Any]) -> dict[str, Any]:
    row_dict["response_payload"] = _normalize_json_object(row_dict.get("response_payload"))
    return row_dict


def create_playbook(
    name: str,
    description: str | None = None,
    trigger_severities: list[str] | None = None,
    trigger_rule_ids: list[int] | None = None,
    trigger_event_types: list[str] | None = None,
    enabled: bool = True,
    actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    with get_session() as session:
        existing = session.query(Playbook).filter(Playbook.name == name).first()
        if existing:
            raise ValueError("playbook_name_exists")
        row = Playbook(
            name=name.strip(),
            description=description,
            trigger_severities=trigger_severities or [],
            trigger_rule_ids=trigger_rule_ids or [],
            trigger_event_types=trigger_event_types or [],
            enabled=enabled,
            actions=actions or [],
            success_count=0,
            failure_count=0,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.flush()
        session.refresh(row)
        return _normalise_playbook_dict(_row_to_dict(row))


def list_playbooks(enabled: bool | None = None) -> list[dict[str, Any]]:
    with get_session() as session:
        q = session.query(Playbook)
        if enabled is not None:
            q = q.filter(Playbook.enabled == enabled)
        rows = q.order_by(Playbook.updated_at.desc(), Playbook.id.desc()).all()
        return [_normalise_playbook_dict(_row_to_dict(r)) for r in rows]


def get_playbook(playbook_id: int) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(Playbook).filter(Playbook.id == playbook_id).first()
        return _normalise_playbook_dict(_row_to_dict(row)) if row else None


def update_playbook(playbook_id: int, **fields) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not row:
            return None
        allowed = {
            "name",
            "description",
            "trigger_severities",
            "trigger_rule_ids",
            "trigger_event_types",
            "enabled",
            "actions",
            "last_run_at",
            "success_count",
            "failure_count",
        }
        for key, value in fields.items():
            if key in allowed:
                setattr(row, key, value)
        row.updated_at = datetime.now(timezone.utc)
        session.flush()
        session.refresh(row)
        return _normalise_playbook_dict(_row_to_dict(row))


def delete_playbook(playbook_id: int) -> bool:
    with get_session() as session:
        row = session.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not row:
            return False
        session.delete(row)
        return True


def toggle_playbook(playbook_id: int) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not row:
            return None
        row.enabled = not row.enabled
        row.updated_at = datetime.now(timezone.utc)
        session.flush()
        session.refresh(row)
        return _normalise_playbook_dict(_row_to_dict(row))


def get_event_by_id(event_id: int) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(IntrusionEvent).filter(IntrusionEvent.id == event_id).first()
        return _row_to_dict(row) if row else None


def set_event_severity(event_id: int, severity: str) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(IntrusionEvent).filter(IntrusionEvent.id == event_id).first()
        if not row:
            return None
        row.severity = severity
        session.flush()
        session.refresh(row)
        return _row_to_dict(row)


def create_playbook_execution(
    playbook_id: int,
    action: str,
    status: str,
    event_id: int | None = None,
    case_id: int | None = None,
    response_payload: dict[str, Any] | None = None,
    error_details: str | None = None,
    actor: str | None = None,
    actor_type: str = "system",
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> dict[str, Any]:
    with get_session() as session:
        row = PlaybookExecution(
            playbook_id=playbook_id,
            event_id=event_id,
            case_id=case_id,
            action=action,
            status=status,
            response_payload=response_payload or {},
            error_details=error_details,
            actor=actor,
            actor_type=actor_type,
            started_at=started_at or datetime.now(timezone.utc),
            finished_at=finished_at,
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.flush()
        session.refresh(row)
        return _normalise_execution_dict(_row_to_dict(row))


def list_playbook_executions(
    playbook_id: int,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    with get_session() as session:
        q = session.query(PlaybookExecution).filter(PlaybookExecution.playbook_id == playbook_id)
        total = q.count()
        rows = q.order_by(PlaybookExecution.created_at.desc(), PlaybookExecution.id.desc()).offset(offset).limit(limit).all()
        return ([_normalise_execution_dict(_row_to_dict(r)) for r in rows], total)


def get_ticket_integration_config(provider_type: str) -> dict[str, Any] | None:
    with get_session() as session:
        row = session.query(TicketIntegrationConfig).filter(TicketIntegrationConfig.provider_type == provider_type).first()
        if not row:
            return None
        data = _row_to_dict(row)
        data["config"] = _normalize_json_object(data.get("config"))
        return data


def upsert_ticket_integration_config(provider_type: str, enabled: bool, config: dict[str, Any]) -> dict[str, Any]:
    with get_session() as session:
        row = session.query(TicketIntegrationConfig).filter(TicketIntegrationConfig.provider_type == provider_type).first()
        if not row:
            row = TicketIntegrationConfig(
                provider_type=provider_type,
                enabled=enabled,
                config=config,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(row)
        else:
            row.enabled = enabled
            row.config = config
            row.updated_at = datetime.now(timezone.utc)
        session.flush()
        session.refresh(row)
        data = _row_to_dict(row)
        data["config"] = _normalize_json_object(data.get("config"))
        return data


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


def _ensure_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _select_retention_policy_for_event(event: IntrusionEvent, policies: list[RetentionPolicy]) -> RetentionPolicy | None:
    event_severity = (event.severity or "").upper()
    for policy in policies:
        if not policy.enabled:
            continue
        if policy.tenant_id and policy.tenant_id != event.tenant_id:
            continue
        if policy.scope == "severity":
            if (policy.severity or "").upper() == event_severity:
                return policy
            continue
        if policy.scope == "tenant":
            if policy.tenant_id and policy.tenant_id == event.tenant_id:
                return policy
            continue
        if policy.scope == "global":
            return policy
    return None


# Import these at the bottom to avoid circular imports
from sqlalchemy import func
