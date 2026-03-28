# NIDS — Network Intrusion Detection System

[![Build Status](https://img.shields.io/github/actions/workflow/status/IMAFDI/nids_project/ci.yml?branch=main)](https://github.com/IMAFDI/nids_project/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A real-time, industry-grade Network Intrusion Detection System built with Python, Scapy, scikit-learn, and FastAPI. Detects network threats using signature-based rules and ML anomaly detection with ensemble voting.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NIDS Pipeline                                 │
│                                                                      │
│  ┌──────────┐    ┌────────────┐    ┌────────────────────────────┐  │
│  │  Scapy   │───▶│  Async     │───▶│  Detection Engine           │  │
│  │  Packet  │    │  Queue     │    │  ┌──────────┐ ┌─────────┐  │  │
│  │  Capture │    │  (depth    │    │  │Signature │ │   ML    │  │  │
│  │          │    │   10k)     │    │  │ Rules   │ │Anomaly  │  │  │
│  └──────────┘    └────────────┘    │  │          │ │Ensemble │  │  │
│                                     │  └──────────┘ └─────────┘  │  │
│                                     └────────────┬───────────────┘  │
│                                                  │                   │
│                                     ┌────────────▼───────────────┐  │
│                                     │  Threat Intel Engine        │  │
│                                     │  AbuseIPDB + Blocklists    │  │
│                                     └────────────┬───────────────┘  │
│                                                  │                   │
│  ┌──────────────────────────────────────────────▼───────────────┐  │
│  │  Notification Engine                                          │  │
│  │  Email | Slack | PagerDuty | Teams | Syslog                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  FastAPI     │    │ PostgreSQL   │    │  React Dashboard      │  │
│  │  REST API    │    │  (SQLite)    │    │  (Vite + Tailwind)   │  │
│  │  :8000      │    │              │    │  :3000               │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Features

- **Signature Detection** — Stateful rule engine with protocol, IP, port, TCP flags, time-window, and threshold matching
- **ML Anomaly Detection** — Ensemble voting (IsolationForest + RandomForest + LOF) with 15 features
- **Threat Intelligence** — AbuseIPDB API + local blocklists with Redis caching
- **Async Pipeline** — asyncio-based producer/consumer with backpressure handling
- **Message Broker** — RabbitMQ event bus (optional, production decoupling)
- **REST API** — FastAPI with JWT auth, rate limiting, correlation IDs, OpenAPI docs
- **Rich Notifications** — Email, Slack, PagerDuty, Teams, Syslog (RFC 5424)
- **PCAP Forensics** — Capture surrounding packets for HIGH/CRITICAL events
- **Case Management** — Track investigations with case records, notes, and linked intrusion events
- **Docker Ready** — Multi-stage builds, docker-compose with PostgreSQL + Redis
- **CI/CD** — GitHub Actions with lint, test, security scan, and build

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/IMAFDI/nids_project.git
cd nids_project
pip install -r config/requirements.txt
```

### 2. Train the ML Model

```bash
python models/train_model.py
```

### 3. Configure

```bash
cp .env.example .env
# Edit .env with your settings
```

### 4. Run

**Batch mode** (capture N packets, analyse, exit):
```bash
sudo python config/main.py
```

**Live mode** (real-time detection):
```bash
sudo python config/main.py --live
```

**With web dashboard**:
```bash
sudo python config/main.py --live --dashboard
# Open: http://localhost:5000
```

**With FastAPI REST API**:
```bash
# Terminal 1: Start API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Start NIDS
sudo python config/main.py --live
```

---

## Docker Compose (Production)

```bash
cp .env.example .env
# Fill in .env with your credentials

docker-compose up -d
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
# Dashboard: http://localhost:3000
# RabbitMQ UI: http://localhost:15672 (guest/guest)
```

---

## CLI Reference

```bash
python config/cli.py start [OPTIONS]     # Start NIDS
python config/cli.py stop                  # Stop running NIDS
python config/cli.py configure             # Show config
python config/cli.py interfaces            # List network interfaces
python config/cli.py dashboard --port 5000 # Launch dashboard
python config/cli.py events --limit 20     # Show recent events
```

### Start Options

| Option | Description |
|--------|-------------|
| `-i, --interface` | Network interface (default: auto-detect) |
| `-c, --count` | Packets per batch (default: 200) |
| `-t, --timeout` | Capture timeout in seconds (default: 60) |
| `-f, --filter` | BPF filter e.g. `tcp`, `not arp` |
| `--live` | Real-time mode (infinite capture) |
| `--dashboard` | Start web dashboard alongside NIDS |
| `--dashboard-port` | Dashboard port (default: 5000) |

---

## Configuration

All settings via environment variables (see `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `NIDS_DB__URL` | Database URL | `sqlite:///logs/nids.db` |
| `NIDS_JWT__SECRET` | JWT signing secret | auto-generated |
| `NIDS_EMAIL_*` | Email notification settings | disabled |
| `NIDS_SLACK_*` | Slack webhook settings | disabled |
| `NIDS_PAGERDUTY_*` | PagerDuty routing key | disabled |
| `NIDS_TEAMS_*` | Microsoft Teams webhook | disabled |
| `NIDS_SYSLOG_*` | Syslog host/port | disabled |
| `NIDS_THREATINTEL__ABUSEIPDB_API_KEY` | AbuseIPDB API key | none |
| `NIDS_BROKER_ENABLED` | Enable broker transport | `true` |
| `NIDS_BROKER_BACKEND` | Broker backend (`rabbitmq`/`none`) | `rabbitmq` |
| `NIDS_BROKER_RABBITMQ_URL` | AMQP URL | `amqp://guest:guest@rabbitmq:5672/` |

---

## REST API

Full API docs at `/docs` (Swagger UI) or `/redoc`.

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"strongpass123"}'

# Request password reset token
curl -X POST http://localhost:8000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'

# Reset password using token from email
curl -X POST http://localhost:8000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","token":"<token-from-email>","new_password":"newStrongPass123"}'

# Use token
TOKEN="your-jwt-token"
curl http://localhost:8000/api/v1/events \
  -H "Authorization: Bearer $TOKEN"
```

### Roles & Permissions (RBAC)

- **viewer**: read-only access (events/cases read, stats, rules read, metrics, threat intel, blocklist read)
- **analyst**: viewer + case create/update/notes/event-linking, event acknowledge, blocklist add, system reload, profile update/password change
- **admin**: full access, including rule CRUD/toggle, event delete/export, user registration/admin actions

Unauthorized role access returns **403 Forbidden** with a clear permission message.  
`/api/v1/health` remains public (no auth required).

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Login and receive JWT |
| POST | `/api/v1/auth/register` | Create user account (admin only) |
| POST | `/api/v1/auth/forgot-password` | Request password reset token (email delivery) |
| POST | `/api/v1/auth/reset-password` | Reset password using email + token |
| GET | `/api/v1/auth/me` | Current user profile |
| PUT | `/api/v1/auth/me` | Update user profile |
| POST | `/api/v1/auth/change-password` | Change current user password |
| GET | `/api/v1/health` | System health (no auth) |
| GET | `/api/v1/events` | Paginated events |
| GET | `/api/v1/events/{id}` | Single event |
| POST | `/api/v1/events/{id}/acknowledge` | Acknowledge event (analyst/admin) |
| POST | `/api/v1/cases` | Create case (analyst/admin) |
| GET | `/api/v1/cases` | List/filter cases (viewer+) |
| GET | `/api/v1/cases/{id}` | Case detail with notes + linked events (viewer+) |
| PUT | `/api/v1/cases/{id}` | Update case (analyst/admin) |
| POST | `/api/v1/cases/{id}/notes` | Add case note (analyst/admin) |
| POST | `/api/v1/cases/{id}/events/{event_id}` | Link event to case (analyst/admin) |
| DELETE | `/api/v1/cases/{id}/events/{event_id}` | Unlink event from case (analyst/admin) |
| GET | `/api/v1/stats` | Aggregated statistics |
| GET | `/api/v1/rules` | List detection rules |
| POST | `/api/v1/rules` | Create new rule (admin only) |
| PUT | `/api/v1/rules/{id}` | Update rule (admin only) |
| POST | `/api/v1/rules/{id}/toggle` | Enable/disable rule (admin only) |
| GET | `/api/v1/playbooks` | List response playbooks |
| POST | `/api/v1/playbooks` | Create playbook (admin only) |
| GET | `/api/v1/playbooks/{id}` | Get playbook details |
| PUT | `/api/v1/playbooks/{id}` | Update playbook (admin only) |
| DELETE | `/api/v1/playbooks/{id}` | Delete playbook (admin only) |
| POST | `/api/v1/playbooks/{id}/toggle` | Enable/disable playbook (admin only) |
| POST | `/api/v1/playbooks/{id}/test` | Run test execution with sample payload |
| GET | `/api/v1/playbooks/{id}/executions` | List playbook execution records |
| POST | `/api/v1/playbooks/execute/event/{event_id}` | Manually execute matching playbooks for an event |
| POST | `/api/v1/playbooks/execute/case/{case_id}` | Manually execute enabled playbooks for a case |
| POST | `/api/v1/playbooks/integrations/ticket` | Upsert ticket provider config (admin only) |
| GET | `/api/v1/playbooks/integrations/ticket/{provider}` | Read ticket provider config |
| GET | `/api/v1/alerts/blocklist` | Current blocklist |
| POST | `/api/v1/alerts/blocklist` | Add IP to blocklist (analyst/admin) |
| GET | `/api/v1/system/metrics` | CPU, memory, queue depth |
| GET | `/api/v1/system/slo` | SLO summary (availability, latency, queue trend, connectivity, error budget) |
| GET | `/api/v1/system/slo/history` | Lightweight historical SLO snapshots |
| GET | `/api/v1/system/retention/policies` | List retention policies (tenant-aware, optional header) |
| POST | `/api/v1/system/retention/policies` | Create retention policy (admin only) |
| PUT | `/api/v1/system/retention/policies/{id}` | Update retention policy (admin only) |
| DELETE | `/api/v1/system/retention/policies/{id}` | Delete retention policy (admin only) |
| POST | `/api/v1/system/retention/dry-run` | Non-destructive retention preview |
| POST | `/api/v1/system/retention/execute` | Execute retention maintenance (admin only) |
| POST | `/api/v1/system/backup/start` | Start backup runbook operation stub (admin only) |
| GET | `/api/v1/system/backup/history` | Backup/restore operation history |
| POST | `/api/v1/system/backup/restore-test` | Trigger restore-test runbook stub (admin only) |
| POST | `/api/v1/system/reload` | Hot-reload rules (analyst/admin) |
| GET | `/api/v1/export/events?format=csv` | Export events (admin only) |
| GET | `/api/v1/events/{id}/pcap` | Download PCAP |

### Playbook Safety Notes

- Playbook execution is additive and non-blocking: qualifying event-driven runs are queued asynchronously.
- Destructive action handlers are safety-gated by environment flags:
  - `NIDS_PLAYBOOK_ALLOW_ADD_TO_BLOCKLIST=true` to permit automatic blocklist writes.
- Ticket creation action is currently an integration-safe stub and requires provider config in DB; no secrets are hardcoded.
- Every action execution is persisted in `playbook_executions` and audited through `audit_log`.

### Platform Hardening Safety Notes

- Retention execution is safe-by-default: deletion is disabled unless `apply_delete=true` **and** `confirm_delete=true`.
- Retention dry-run is always non-destructive and reports archive/delete candidates before execution.
- Backup and restore-test APIs are operational hooks/stubs in this environment; they record metadata only (no destructive DB restore or dump command by default).
- Platform hardening entities (`retention_policies`, `slo_snapshots`, `backup_operations`) support optional tenant context via `X-Tenant-ID` while preserving single-tenant behavior when absent.

---

## Detection Rules

Rules can be JSON files (`config/rules.json`) or live CRUD via the API.

### Rule Types

| Type | Description |
|------|-------------|
| `SIGNATURE` | Protocol, IP, port, flags, threshold/time window |
| `RATE_LIMIT` | Trigger if X packets/sec from same IP |
| `PAYLOAD_MATCH` | Regex match on packet payload |
| `GEO_BLOCK` | Block traffic from specific countries |
| `WHITELIST` | Always-pass rules for trusted IPs |

### Example Rule (JSON)

```json
{
  "id": 10,
  "name": "SSH Brute Force",
  "rule_type": "SIGNATURE",
  "enabled": true,
  "priority": "HIGH",
  "description": "Suspicious SSH brute force attempt",
  "criteria": {
    "protocol": "tcp",
    "dst_port": 22,
    "flags": "SYN",
    "threshold": 10,
    "time_window": 30
  }
}
```

---

## ML Model

Ensemble of 3 models — anomaly flagged if 2+ agree:

1. **IsolationForest** — Unsupervised isolation-based detection
2. **RandomForestClassifier** — Supervised classifier (CICIDS2017/NSL-KDD features)
3. **LocalOutlierFactor** — Density-based outlier detection

### Features (15 total)

Base (10): `packet_length`, `protocol`, `src_port`, `dst_port`, `tcp_flags`, `icmp_type`, `payload_length`, `is_fragmented`, `ttl`, `header_length`

Extended (5): `bytes_per_second`, `packets_per_second`, `connection_duration`, `unique_ports_accessed`, `reverse_dns_failed`

---

## Testing

```bash
pip install pytest pytest-asyncio httpx pytest-cov
pytest tests/ -v --cov=config --cov=api --cov-fail-under=70
```

---

## Project Structure

```
nids_project/
├── config/
│   ├── main.py                    # Orchestration entry point
│   ├── cli.py                     # CLI (start/stop/configure/events)
│   ├── settings.py                # Pydantic settings
│   ├── packet_capture.py         # Scapy packet capture
│   ├── signature_detection.py     # Original rule engine
│   ├── signature_detection_v2.py  # Extended rule engine
│   ├── anomaly_detection.py       # Original ML detection
│   ├── anomaly_detection_v2.py    # Ensemble ML detection
│   ├── database.py               # Original SQLite module
│   ├── database_v2.py            # SQLAlchemy (PostgreSQL/SQLite)
│   ├── notifications.py          # Original notifications
│   ├── notifications_v2.py      # Extended (PagerDuty, Teams, Syslog)
│   ├── logging_alerting.py       # Structured logging
│   ├── network_scanner.py        # ARP network scanner
│   ├── dashboard.py              # Flask web dashboard
│   ├── async_pipeline.py         # Async queue pipeline
│   ├── threat_intel.py           # Threat intelligence engine
│   ├── pcap_forensics.py         # PCAP capture & analysis
│   ├── rules.json                # Detection rules
│   ├── requirements.txt          # Python dependencies
│   └── blocklists/               # IP blocklist files
├── api/
│   └── main.py                  # FastAPI REST API
├── models/
│   ├── train_model.py            # Model training script
│   ├── anomaly_model.joblib      # Trained model
│   └── versions/                 # Model versioning directory
├── logs/
│   ├── nids.log                 # Structured log file
│   ├── nids.db                  # SQLite database
│   └── pcap/                    # PCAP forensics files
├── tests/
│   ├── test_signature_detection.py
│   ├── test_anomaly_detection.py
│   ├── test_api.py
│   ├── test_notifications.py
│   └── test_threat_intel.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── RULE_ENGINE.md
│   └── DEPLOYMENT.md
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## License

MIT
