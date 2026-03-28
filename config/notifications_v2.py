"""
NIDS — Notifications Module v2
==============================
Supports:
  - Email (SMTP)
  - Slack (Incoming Webhooks)
  - PagerDuty (Events API v2)
  - Microsoft Teams (Incoming Webhooks)
  - Syslog (UDP/TCP, RFC 5424)

Features:
  - Structured alert payload
  - Async background worker with retry (max 3 retries, exponential backoff)
  - Deduplication: suppress duplicate alerts for same (src_ip, rule_id) within window
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import urllib.request
import urllib.error

logger = logging.getLogger("NIDS.Notifications")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE = "config/notification_config.json"
NOTIFY_SEVERITIES = {"HIGH", "CRITICAL"}
DEDUP_WINDOW_SECONDS = 300
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AlertPayload:
    """Structured alert payload sent to all notification channels."""
    event_id: int | None
    rule_id: int | str | None
    rule_name: str
    event_type: str  # 'signature' | 'anomaly'
    severity: str
    src_ip: str | None
    dst_ip: str | None
    protocol: str | None
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    threat_intel_score: int | None = None
    ml_score: dict | None = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class NotificationTask:
    """A notification task in the background queue."""
    payload: AlertPayload
    channel: str  # 'email' | 'slack' | 'pagerduty' | 'teams' | 'syslog'
    retry_count: int = 0
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load notification config from JSON file, then override with env vars."""
    import os as _os

    cfg = {
        "email": {
            "enabled": False,
            "host": "smtp.gmail.com",
            "port": 587,
            "user": "",
            "password": "",
            "from": "",
            "to": "",
        },
        "slack": {
            "enabled": False,
            "webhook": "",
        },
        "pagerduty": {
            "enabled": False,
            "routing_key": "",
        },
        "teams": {
            "enabled": False,
            "webhook": "",
        },
        "syslog": {
            "enabled": False,
            "host": "localhost",
            "port": 514,
            "protocol": "udp",
        },
    }

    if _os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                file_cfg = json.load(f)
            for section in cfg:
                if section in file_cfg:
                    cfg[section].update(file_cfg[section])
        except Exception:
            pass

    # Environment variable overrides
    env_map = {
        "email": {
            "enabled": ("NIDS_EMAIL_ENABLED", lambda v: v.lower() == "true"),
            "host": ("NIDS_EMAIL_HOST", str),
            "port": ("NIDS_EMAIL_PORT", int),
            "user": ("NIDS_EMAIL_USER", str),
            "password": ("NIDS_EMAIL_PASSWORD", str),
            "from": ("NIDS_EMAIL_FROM", str),
            "to": ("NIDS_EMAIL_TO", str),
        },
        "slack": {
            "enabled": ("NIDS_SLACK_ENABLED", lambda v: v.lower() == "true"),
            "webhook": ("NIDS_SLACK_WEBHOOK", str),
        },
        "pagerduty": {
            "enabled": ("NIDS_PAGERDUTY_ENABLED", lambda v: v.lower() == "true"),
            "routing_key": ("NIDS_PAGERDUTY_ROUTING_KEY", str),
        },
        "teams": {
            "enabled": ("NIDS_TEAMS_ENABLED", lambda v: v.lower() == "true"),
            "webhook": ("NIDS_TEAMS_WEBHOOK", str),
        },
        "syslog": {
            "enabled": ("NIDS_SYSLOG_ENABLED", lambda v: v.lower() == "true"),
            "host": ("NIDS_SYSLOG_HOST", str),
            "port": ("NIDS_SYSLOG_PORT", int),
            "protocol": ("NIDS_SYSLOG_PROTOCOL", str),
        },
    }

    for section, keys in env_map.items():
        for key, (env_var, cast) in keys.items():
            val = _os.environ.get(env_var)
            if val:
                cfg[section][key] = cast(val)

    return cfg


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

_dedup_cache: dict[str, float] = {}
_dedup_lock = threading.Lock()


def _is_duplicate(src_ip: str | None, rule_id: int | str | None, window: int = DEDUP_WINDOW_SECONDS) -> bool:
    if not src_ip or not rule_id:
        return False
    key = f"{src_ip}:{rule_id}"
    now = time.time()
    with _dedup_lock:
        last = _dedup_cache.get(key)
        if last and (now - last) < window:
            return True
        _dedup_cache[key] = now
        return False


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def _send_email(cfg: dict, payload: AlertPayload) -> bool:
    """Send an HTML email alert. Returns True on success."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[NIDS {payload.severity}] {payload.description[:80]}"
        msg["From"] = cfg.get("from") or cfg.get("user", "nids@localhost")
        msg["To"] = cfg.get("to", "")

        body_lines = [
            f"Severity    : {payload.severity}",
            f"Time        : {payload.timestamp}",
            f"Event Type  : {payload.event_type}",
            f"Source IP   : {payload.src_ip or 'N/A'}",
            f"Dest IP     : {payload.dst_ip or 'N/A'}",
            f"Protocol    : {payload.protocol or 'N/A'}",
            f"Rule        : {payload.rule_name}",
            f"Description : {payload.description}",
        ]
        if payload.threat_intel_score:
            body_lines.append(f"Threat Score: {payload.threat_intel_score}")
        if payload.ml_score:
            body_lines.append(f"ML Score     : {payload.ml_score}")

        body = "\n".join(body_lines)

        html = f"""
        <html><body>
        <h2 style="color:#cc0000;">NIDS Security Alert [{payload.severity}]</h2>
        <pre style="background:#f4f4f4;padding:12px;border-left:4px solid #cc0000;">{body}</pre>
        <p style="color:#888;font-size:11px;">
            Generated by NIDS at {payload.timestamp}<br/>
            Correlation ID: {payload.correlation_id}
        </p>
        </body></html>
        """
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            if cfg.get("user"):
                server.login(cfg["user"], cfg["password"])
            server.sendmail(msg["From"], [msg["To"]], msg.as_string())

        logger.info(f"Email notification sent: [{payload.severity}] {payload.correlation_id}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email notification: {e}")
        return False


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def _send_slack(cfg: dict, payload: AlertPayload) -> bool:
    """Send a Slack message via Incoming Webhook."""
    colour_map = {
        "LOW": "#36a64f",
        "MEDIUM": "#ffcc00",
        "HIGH": "#ff6600",
        "CRITICAL": "#cc0000",
    }
    colour = colour_map.get(payload.severity, "#aaaaaa")

    fields = [
        {"title": "Source IP", "value": payload.src_ip or "N/A", "short": True},
        {"title": "Dest IP", "value": payload.dst_ip or "N/A", "short": True},
        {"title": "Protocol", "value": payload.protocol or "N/A", "short": True},
        {"title": "Event Type", "value": payload.event_type, "short": True},
    ]
    if payload.threat_intel_score:
        fields.append({"title": "Threat Score", "value": str(payload.threat_intel_score), "short": True})

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"NIDS Alert [{payload.severity}]"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{payload.description}*"},
            "fields": fields,
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Rule: {payload.rule_name} | ID: {payload.correlation_id}"},
            ],
        },
    ]

    slack_payload = {
        "blocks": blocks,
        "attachments": [{"color": colour, "blocks": blocks}],
    }

    try:
        data = json.dumps(slack_payload).encode("utf-8")
        req = urllib.request.Request(
            cfg["webhook"],
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info(f"Slack notification sent: [{payload.severity}] {payload.correlation_id}")
                return True
            logger.warning(f"Slack returned status {resp.status}")
            return False
    except urllib.error.URLError as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Slack notification: {e}")
        return False


# ---------------------------------------------------------------------------
# PagerDuty
# ---------------------------------------------------------------------------

def _send_pagerduty(cfg: dict, payload: AlertPayload) -> bool:
    """
    Send a PagerDuty Events API v2 notification.
    Only triggered for CRITICAL events.
    """
    if payload.severity != "CRITICAL":
        return True  # Skip silently

    pd_payload = {
        "routing_key": cfg["routing_key"],
        "event_action": "trigger",
        "dedup_key": f"nids-{payload.correlation_id}",
        "payload": {
            "summary": f"[{payload.severity}] {payload.description}",
            "source": "NIDS",
            "severity": "critical",
            "timestamp": payload.timestamp,
            "component": payload.event_type,
            "group": "security",
            "class": "network_intrusion",
            "custom_details": {
                "src_ip": payload.src_ip,
                "dst_ip": payload.dst_ip,
                "protocol": payload.protocol,
                "rule_name": payload.rule_name,
                "rule_id": payload.rule_id,
                "event_id": payload.event_id,
                "threat_intel_score": payload.threat_intel_score,
            },
        },
    }

    try:
        data = json.dumps(pd_payload).encode("utf-8")
        req = urllib.request.Request(
            "https://events.pagerduty.com/v2/enqueue",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 202:
                logger.info(f"PagerDuty notification sent: [{payload.severity}] {payload.correlation_id}")
                return True
            logger.warning(f"PagerDuty returned status {resp.status}")
            return False
    except urllib.error.URLError as e:
        logger.error(f"Failed to send PagerDuty notification: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending PagerDuty notification: {e}")
        return False


# ---------------------------------------------------------------------------
# Microsoft Teams
# ---------------------------------------------------------------------------

def _send_teams(cfg: dict, payload: AlertPayload) -> bool:
    """Send a Microsoft Teams message via Incoming Webhook."""
    colour_map = {
        "LOW": "36a64f",
        "MEDIUM": "ffcc00",
        "HIGH": "ff6600",
        "CRITICAL": "cc0000",
    }
    colour = colour_map.get(payload.severity, "aaaaaa")

    teams_payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": colour,
        "summary": f"[{payload.severity}] {payload.description}",
        "title": f"NIDS Alert [{payload.severity}]",
        "sections": [
            {
                "facts": [
                    {"name": "Description", "value": payload.description},
                    {"name": "Source IP", "value": payload.src_ip or "N/A"},
                    {"name": "Dest IP", "value": payload.dst_ip or "N/A"},
                    {"name": "Protocol", "value": payload.protocol or "N/A"},
                    {"name": "Event Type", "value": payload.event_type},
                    {"name": "Rule", "value": payload.rule_name},
                ],
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "View in Dashboard",
                "targets": [{"os": "default", "uri": f"/api/v1/events/{payload.event_id}"}],
            }
        ],
    }

    if payload.threat_intel_score:
        teams_payload["sections"][0]["facts"].append(
            {"name": "Threat Score", "value": str(payload.threat_intel_score)}
        )

    try:
        data = json.dumps(teams_payload).encode("utf-8")
        req = urllib.request.Request(
            cfg["webhook"],
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info(f"Teams notification sent: [{payload.severity}] {payload.correlation_id}")
                return True
            logger.warning(f"Teams returned status {resp.status}")
            return False
    except urllib.error.URLError as e:
        logger.error(f"Failed to send Teams notification: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Teams notification: {e}")
        return False


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------

_syslog_socket: socket.socket | None = None
_syslog_config: dict = {}


def _init_syslog(cfg: dict) -> socket.socket:
    global _syslog_socket, _syslog_config
    _syslog_config = cfg
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if cfg.get("protocol") == "udp" else socket.SOCK_STREAM)
        sock.settimeout(5)
        if cfg.get("protocol") == "tcp":
            sock.connect((cfg["host"], cfg["port"]))
        _syslog_socket = sock
    except Exception as e:
        logger.error(f"Failed to create syslog socket: {e}")
    return _syslog_socket


def _send_syslog(payload: AlertPayload) -> bool:
    """Send a Syslog message (RFC 5424 format)."""
    global _syslog_socket, _syslog_config

    if _syslog_socket is None:
        _init_syslog(_syslog_config)

    if _syslog_socket is None:
        return False

    # RFC 5424 structured data
    sd = json.dumps({
        "nids": {
            "event_id": payload.event_id,
            "rule_id": payload.rule_id,
            "rule_name": payload.rule_name,
            "event_type": payload.event_type,
            "src_ip": payload.src_ip,
            "dst_ip": payload.dst_ip,
            "protocol": payload.protocol,
            "threat_intel_score": payload.threat_intel_score,
        }
    })

    # RFC 5424: PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, SD, MSG
    pri = 16 * 2 + 3  # severity=err(3) + facility=local2(16)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    hostname = socket.gethostname()
    msg = f"<{pri}>1 {timestamp} {hostname} NIDS 1 {payload.correlation_id} {sd} [{payload.severity}] {payload.description}"

    try:
        if _syslog_config.get("protocol") == "tcp":
            _syslog_socket.sendall(msg.encode("utf-8") + b"\n")
        else:
            _syslog_socket.sendto(msg.encode("utf-8"), (_syslog_config["host"], _syslog_config["port"]))
        logger.debug(f"Syslog notification sent: {payload.correlation_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to send syslog notification: {e}")
        _syslog_socket = None  # Force reconnect on next attempt
        return False


# ---------------------------------------------------------------------------
# Notification worker
# ---------------------------------------------------------------------------

_notification_queue: queue.Queue[NotificationTask] = queue.Queue(maxsize=1000)
_worker_thread: threading.Thread | None = None
_shutdown = threading.Event()


def _worker_loop() -> None:
    """Background worker that processes the notification queue with retry logic."""
    global _shutdown
    logger.info("Notification worker started.")

    while not _shutdown.is_set():
        try:
            task = _notification_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        cfg = _load_config()
        payload = task.payload
        success = False

        try:
            if task.channel == "email" and cfg["email"]["enabled"]:
                success = _send_email(cfg["email"], payload)
            elif task.channel == "slack" and cfg["slack"]["enabled"]:
                success = _send_slack(cfg["slack"], payload)
            elif task.channel == "pagerduty" and cfg["pagerduty"]["enabled"]:
                success = _send_pagerduty(cfg["pagerduty"], payload)
            elif task.channel == "teams" and cfg["teams"]["enabled"]:
                success = _send_teams(cfg["teams"], payload)
            elif task.channel == "syslog" and cfg["syslog"]["enabled"]:
                success = _send_syslog(payload)
        except Exception as e:
            logger.error(f"Notification error ({task.channel}): {e}")
            success = False

        # Retry with exponential backoff
        if not success and task.retry_count < MAX_RETRIES:
            backoff = RETRY_BACKOFF_BASE ** task.retry_count
            logger.warning(
                f"Notification failed ({task.channel}), retrying in {backoff}s "
                f"(attempt {task.retry_count + 1}/{MAX_RETRIES})"
            )
            time.sleep(backoff)
            task.retry_count += 1
            _notification_queue.put_nowait(task)
        elif not success:
            logger.error(f"Notification permanently failed after {MAX_RETRIES} retries: {payload.correlation_id}")

        _notification_queue.task_done()


def _start_worker() -> None:
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="NotificationWorker")
        _worker_thread.start()


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def send_notification(
    severity: str,
    description: str,
    event_type: str = "signature",
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    rule_id: int | str | None = None,
    rule_name: str = "",
    event_id: int | None = None,
    threat_intel_score: int | None = None,
    ml_score: dict | None = None,
) -> None:
    """
    Send notifications to all configured channels.
    Dispatches to background workers to avoid blocking packet processing.
    """
    if severity not in NOTIFY_SEVERITIES:
        return

    # Build payload
    payload = AlertPayload(
        event_id=event_id,
        rule_id=rule_id,
        rule_name=rule_name or description,
        event_type=event_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        description=description,
        threat_intel_score=threat_intel_score,
        ml_score=ml_score,
    )

    # Check deduplication
    dedup_key = f"{src_ip}:{rule_id}"
    if _is_duplicate(src_ip, rule_id):
        logger.debug(f"Notification deduplicated: {dedup_key}")
        return

    _start_worker()

    channels = ["email", "slack", "pagerduty", "teams", "syslog"]
    for channel in channels:
        _notification_queue.put_nowait(NotificationTask(payload=payload, channel=channel))


def shutdown_notifications() -> None:
    """Gracefully shutdown the notification worker."""
    global _shutdown
    _shutdown.set()
    if _worker_thread:
        _worker_thread.join(timeout=5)
