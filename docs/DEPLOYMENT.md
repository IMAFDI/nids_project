# NIDS Deployment Guide

## Contents

1. [Docker Compose (Recommended)](#docker-compose)
2. [Bare Metal](#bare-metal)
3. [AWS EC2](#aws-ec2)
4. [Environment Variables](#environment-variables)
5. [Database Setup](#database-setup)
6. [Reverse Proxy](#reverse-proxy)

---

## Docker Compose

### Prerequisites

- Docker 20.10+
- Docker Compose v2+

### Steps

```bash
# Clone the repository
git clone https://github.com/IMAFDI/nids_project.git
cd nids_project

# Copy and configure environment
cp .env.example .env
# Edit .env with your credentials

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f nids
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| `postgres` | 5432 | PostgreSQL database |
| `redis` | 6379 | Redis cache |
| `nids` | 8000 | FastAPI REST API |
| `frontend` | 3000 | React dashboard |

### Stopping

```bash
docker-compose down        # Stop containers
docker-compose down -v     # Stop and remove volumes (WARNING: deletes data)
```

---

## Bare Metal

### Prerequisites

- Python 3.11+
- PostgreSQL 15+ (optional, SQLite default)
- Redis 7+ (optional)
- `libpcap-dev` (for Scapy packet capture)
- Root/sudo access (for packet capture)

### Steps

```bash
# 1. Clone
git clone https://github.com/IMAFDI/nids_project.git
cd nids_project

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r config/requirements.txt

# 4. Train the ML model
python models/train_model.py

# 5. Configure environment
cp .env.example .env
# Edit .env

# 6. Initialize database
python -c "from config.database_v2 import init_db; init_db()"

# 7. Run the NIDS
sudo python config/main.py --live --dashboard
```

### Running as a systemd service

```ini
# /etc/systemd/system/nids.service
[Unit]
Description=NIDS Service
After=network.target

[Service]
Type=simple
User=nids
WorkingDirectory=/opt/nids
ExecStart=/opt/nids/.venv/bin/python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable nids
sudo systemctl start nids
```

---

## AWS EC2

### 1. Launch Instance

- **AMI**: Amazon Linux 2023 or Ubuntu 22.04
- **Instance type**: t3.medium or larger
- **Security group**: Allow ports 22 (SSH), 8000 (API), 3000 (Dashboard)

### 2. Install Dependencies

```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv git libpcap-dev docker.io docker-compose
sudo usermod -aG docker ubuntu
# Log out and back in
```

### 3. Clone and Configure

```bash
git clone https://github.com/IMAFDI/nids_project.git
cd nids_project
cp .env.example .env
# Configure .env with your settings
```

### 4. Set Up PostgreSQL (RDS or EC2)

**Option A: RDS PostgreSQL**
```bash
# In .env:
NIDS_DB__URL=postgresql://nids:PASSWORD@your-rds-endpoint:5432/nids
```

**Option B: PostgreSQL on EC2**
```bash
sudo apt install -y postgresql postgresql-contrib
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER nids WITH PASSWORD 'changeme';"
sudo -u postgres psql -c "CREATE DATABASE nids OWNER nids;"
```

### 5. Capture Permissions

```bash
# Grant CAP_NET_RAW and CAP_NET_ADMIN for packet capture
sudo setcap 'cap_net_raw,cap_net_admin=eip' $(which python3)
# Or run with sudo in container (docker-compose already sets cap_add)
```

### 6. SSL/TLS

For production, put the API behind an Application Load Balancer with SSL termination, or add a reverse proxy with certbot (Let's Encrypt).

---

## Environment Variables

Full reference in `.env.example`. Key variables:

### Database
```bash
NIDS_DB__URL=postgresql://nids:PASSWORD@host:5432/nids   # or sqlite://path
NIDS_DB__POOL_SIZE=5
NIDS_DB__MAX_OVERFLOW=10
```

### API / JWT
```bash
NIDS_JWT__SECRET=your-super-secret-key-here
NIDS_JWT__EXPIRY_HOURS=24
NIDS_API__USER=admin
NIDS_API__PASSWORD=your-secure-password
```

### Notifications
```bash
# Email
NIDS_EMAIL__ENABLED=true
NIDS_EMAIL__HOST=smtp.gmail.com
NIDS_EMAIL__PORT=587
NIDS_EMAIL__USER=your@email.com
NIDS_EMAIL__PASSWORD=app-password

# Slack
NIDS_SLACK__ENABLED=true
NIDS_SLACK__WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ

# PagerDuty
NIDS_PAGERDUTY__ENABLED=true
NIDS_PAGERDUTY__ROUTING_KEY=your-routing-key

# Teams
NIDS_TEAMS__ENABLED=true
NIDS_TEAMS__WEBHOOK=https://your-tenant.webhook.office.com/...
```

### Threat Intelligence
```bash
NIDS_THREATINTEL__ABUSEIPDB_API_KEY=your-api-key
NIDS_THREATINTEL__ABUSEIPDB_CHECK_SEVERITY=50
```

---

## Database Setup

### PostgreSQL (Production)

```sql
-- Create database and user
CREATE USER nids WITH PASSWORD 'your-password';
CREATE DATABASE nids OWNER nids;
GRANT ALL PRIVILEGES ON DATABASE nids TO nids;

-- Connect and grant schema access
\c nids
GRANT ALL ON SCHEMA public TO nids;
```

### SQLite (Development)

SQLite requires no setup — database file is created automatically at `logs/nids.db`.

---

## Reverse Proxy

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name nids.example.com;

    ssl_certificate /etc/letsencrypt/live/nids.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nids.example.com/privkey.pem;

    # API
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:3000/;
        proxy_set_header Host $host;
    }
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName nids.example.com

    SSLEngine on
    SSLCertificateFile /path/to/fullchain.pem
    SSLCertificateKeyFile /path/to/privkey.pem

    ProxyPreserveHost On
    ProxyPass /api/ http://127.0.0.1:8000/api/
    ProxyPassReverse /api/ http://127.0.0.1:8000/api/
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
```
