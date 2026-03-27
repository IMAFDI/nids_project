# NIDS Architecture

## Component Overview

### Packet Capture (`config/packet_capture.py`)
- Uses Scapy's `sniff()` for packet capture
- Supports live (infinite) and batch modes
- BPF filter support for pre-filtering traffic
- Per-packet callbacks for real-time processing
- Handles `PermissionError` gracefully with clear instructions to run as sudo

### Async Pipeline (`config/async_pipeline.py`)
- `asyncio.Queue` based producer/consumer architecture
- Configurable queue depth (default: 10,000)
- Multiple concurrent worker coroutines (default: 4)
- Backpressure handling: drops packets when queue is full
- Metrics tracking: packets received/processed/dropped, queue depth, avg processing time
- Thread-safe metrics with `threading.Lock`

### Signature Detection (`config/signature_detection_v2.py`)
- **Rule types**: SIGNATURE, RATE_LIMIT, PAYLOAD_MATCH, GEO_BLOCK, WHITELIST
- **Stateful**: Tracks per-(rule_id, src_ip) counters with time-window expiry
- **Whitelist**: Supports both exact IPs and CIDR subnets
- **GeoIP**: Optional GeoLite2 country lookup for GEO_BLOCK rules
- Rules loaded from both JSON files and database (live CRUD)

### ML Anomaly Detection (`config/anomaly_detection_v2.py`)
- **Ensemble voting**: 2 of 3 models must agree to flag anomaly
  - IsolationForest (unsupervised)
  - RandomForestClassifier (supervised)
  - LocalOutlierFactor (density-based)
- **Flow tracking**: Computes per-flow features (bytes/sec, packets/sec, duration, unique ports)
- **15 features**: 10 base network features + 5 flow-based features
- **Model versioning**: `models/versions/v{timestamp}/` directories

### Threat Intelligence (`config/threat_intel.py`)
- **Sources**: AbuseIPDB API (free tier), local blocklist files
- **Caching**: Redis (preferred) with in-memory TTL fallback
- **Auto-escalation**: Boosts severity for IPs in threat feeds
- **Blocklist formats**: IP addresses and CIDR notation
- **Deduplication**: Per-(src_ip, rule_id) deduplication window

### Database (`config/database_v2.py`)
- **SQLAlchemy ORM** with PostgreSQL (preferred) and SQLite fallback
- **Tables**: intrusion_events, system_events, alert_rules, threat_intel, audit_log
- **Indexes**: timestamp, severity, src_ip, rule_id, event_type
- **Thread-safe sessions** via `contextmanager`
- **CRUD helpers** for all entities

### Notifications (`config/notifications_v2.py`)
- **Channels**: Email (SMTP), Slack (webhooks), PagerDuty (Events API v2), Teams (webhooks), Syslog (UDP/TCP RFC 5424)
- **Background worker**: `threading.Thread` processing async queue
- **Retry logic**: Max 3 retries with exponential backoff
- **Deduplication**: Per-(src_ip, rule_id) deduplication window
- **Structured payloads**: All channels receive consistent alert data

### REST API (`api/main.py`)
- **FastAPI** with full OpenAPI docs at `/docs`
- **JWT auth** (HS256, 24h expiry, configurable secret)
- **Rate limiting**: In-memory per-IP rate limiting (100 req/min)
- **Correlation IDs**: UUID per request in response headers
- **Endpoints**: Events, Rules, Blocklist, Stats, System metrics, Export, PCAP download

### Web Dashboard (`config/dashboard.py`)
- **Flask** with Server-Sent Events (SSE) for live updates
- **Pages**: Overview, Events, Devices (network scanner), Whitelist
- **Real-time charts**: Chart.js timeline and bar charts
- **Dark theme** for extended monitoring sessions

## Data Flow

```
Packet Capture
    │
    ▼
Async Pipeline Queue (max_depth=10000)
    │
    ▼
┌───────────────────────────────────────┐
│  Worker Coroutines (N=4)              │
│                                       │
│  1. Signature Detection               │
│     ├── Load rules from DB/json       │
│     ├── Check whitelist                │
│     └── Evaluate rules                 │
│                                       │
│  2. ML Anomaly Detection              │
│     ├── Update flow tracker            │
│     ├── Extract 15 features            │
│     └── Ensemble predict()             │
│                                       │
│  3. Threat Intel Check                │
│     ├── Cache lookup (Redis/memory)   │
│     ├── Blocklist check               │
│     └── AbuseIPDB API (if needed)      │
└───────────────────────────────────────┘
    │
    ├─▶ Log event (database)
    │
    ├─▶ Send notifications (async queue)
    │
    ├─▶ Push to SSE dashboard
    │
    └─▶ PCAP capture (if HIGH/CRITICAL)
```

## Deployment Modes

### Development
- SQLite database (file-based)
- Flask dashboard on port 5000
- CLI start command

### Production (Docker)
- PostgreSQL for persistence
- Redis for threat intel cache
- FastAPI on port 8000
- React frontend on port 3000
- Nginx reverse proxy (in docker-compose)

### Bare Metal
- PostgreSQL instance required
- Redis optional (falls back to in-memory cache)
- Non-root user in Dockerfile
- NET_ADMIN capability for packet capture
