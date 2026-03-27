# NIDS — Complete Setup and Testing Guide

## 🎯 Quick Start Options

You have **3 ways** to run the NIDS:

1. **Docker (Recommended)** — Full stack with one command
2. **Local Development** — Backend + Frontend separately
3. **Backend Only** — Test API without frontend

---

## Option 1: Docker Compose (Recommended) 🐳

### Prerequisites
- Docker Desktop installed
- Docker Compose v2+
- 4GB RAM available

### Steps

```bash
# 1. Navigate to project
cd /Users/imafdi/Desktop/Project/my-projects/nids_project

# 2. Checkout the feature branch
git checkout feature/industry-upgrade

# 3. Create .env file
cp .env.example .env

# 4. Edit .env (REQUIRED)
nano .env
# Set at minimum:
# NIDS_JWT__SECRET=your-super-secret-key-change-this-in-production
# NIDS_API__PASSWORD=your-admin-password

# 5. Start all services
docker-compose up -d

# 6. Check logs
docker-compose logs -f nids

# 7. Wait for services to be healthy (30-60 seconds)
docker-compose ps

# 8. Access the application
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
# Login: admin / (password from .env)
```

### Verify Services

```bash
# Check all services are running
docker-compose ps

# Expected output:
# postgres   running   5432/tcp
# redis      running   6379/tcp
# nids       running   8000/tcp
# frontend   running   80/tcp -> 3000/tcp

# Test API health
curl http://localhost:8000/api/v1/health

# Should return:
# {"status":"healthy","uptime_seconds":42,"version":"1.0.0"}
```

### Stop Services

```bash
docker-compose down
# Or keep data:
docker-compose down --volumes
```

---

## Option 2: Local Development (Without Docker) 💻

### Prerequisites
- Python 3.11+
- Node.js 18+
- Redis (optional, for threat intel caching)
- PostgreSQL (optional, defaults to SQLite)

### Step 1: Backend Setup

```bash
# 1. Navigate to project
cd /Users/imafdi/Desktop/Project/my-projects/nids_project

# 2. Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r config/requirements.txt

# 4. Create .env file
cp .env.example .env
nano .env

# Minimal config for local testing:
cat > .env << 'EOF'
NIDS_DB__URL=sqlite:///logs/nids.db
NIDS_JWT__SECRET=local-dev-secret-change-in-production
NIDS_API__USER=admin
NIDS_API__PASSWORD=admin
NIDS_CAPTURE__INTERFACE=lo0
NIDS_EMAIL__ENABLED=false
NIDS_SLACK__ENABLED=false
EOF

# 5. Initialize database (if PostgreSQL)
# python -c "from config.database_v2 import init_db; init_db()"

# 6. Start the API server
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Server should start at: http://localhost:8000
# API docs at: http://localhost:8000/docs
```

**Keep this terminal open!**

### Step 2: Frontend Setup (New Terminal)

```bash
# 1. Navigate to frontend directory
cd /Users/imafdi/Desktop/Project/my-projects/nids_project/frontend

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev

# Vite should start at: http://localhost:3000
```

**Open browser:** http://localhost:3000
**Login:** admin / admin

---

## Option 3: Backend Only (API Testing) 🔧

Perfect for testing without the UI:

```bash
# 1. Start backend (see Option 2, Step 1)
uvicorn api.main:app --reload --port 8000

# 2. Open API documentation
open http://localhost:8000/docs

# 3. Test with curl
# Get JWT token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Should return:
# {"access_token":"eyJ0eXAi...","token_type":"bearer"}

# Save the token
export TOKEN="eyJ0eXAi..."

# Test authenticated endpoint
curl http://localhost:8000/api/v1/stats \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🧪 Running Tests

### Run All Tests

```bash
cd /Users/imafdi/Desktop/Project/my-projects/nids_project

# Activate virtual environment
source .venv/bin/activate

# Install test dependencies (if not already)
pip install pytest pytest-asyncio pytest-cov httpx

# Run all tests with coverage
pytest tests/ \
  --cov=config \
  --cov=api \
  --cov-report=term-missing \
  --cov-report=html \
  -v

# View HTML coverage report
open htmlcov/index.html
```

### Run Specific Test Suites

```bash
# Test API endpoints only
pytest tests/test_api.py -v

# Test signature detection
pytest tests/test_signature_detection.py -v

# Test ML anomaly detection
pytest tests/test_anomaly_detection.py -v

# Test notifications
pytest tests/test_notifications.py -v

# Test threat intel
pytest tests/test_threat_intel.py -v
```

### Run Linting

```bash
# Install linting tools
pip install ruff bandit

# Run ruff (code style)
ruff check config/ api/ models/ --output-format=text

# Run bandit (security)
bandit -r config/ api/ models/ -f txt
```

---

## 🎮 Testing the Dashboard

### 1. Login Page
- Navigate to http://localhost:3000
- Enter: `admin` / `admin`
- Should redirect to dashboard

### 2. Dashboard Page
- Check stat cards update
- Verify severity pie chart renders
- Check system health bars
- Confirm top attackers table

### 3. Events Page
- Should show paginated events table
- Test severity filter dropdown
- Test source IP filter
- Click row expand icon to see details
- Test acknowledge button
- Test export CSV/JSON

### 4. Rules Page
- Should display rule cards
- Test enable/disable toggle
- Click edit button (shows alert if not implemented)
- Test delete button (shows confirmation)

### 5. Threat Map Page
- World map should render
- Countries with events should be colored
- Test severity filter buttons
- Check top attack sources list

### 6. ML Monitor Page
- Verify model version displayed
- Check feature importance chart
- Check anomaly distribution chart
- Review model performance table

### 7. Settings Page
- Toggle email notifications
- Enter Slack webhook
- Test save button
- Should show success message

---

## 🐛 Troubleshooting

### Backend Issues

**Problem:** `uvicorn: command not found`
```bash
# Solution: Activate virtual environment
source .venv/bin/activate
pip install uvicorn
```

**Problem:** `ModuleNotFoundError: No module named 'fastapi'`
```bash
# Solution: Install dependencies
pip install -r config/requirements.txt
```

**Problem:** `Database connection failed`
```bash
# Solution: Check .env file
# For SQLite (default):
NIDS_DB__URL=sqlite:///logs/nids.db

# Ensure logs/ directory exists
mkdir -p logs
```

**Problem:** `JWT secret not configured`
```bash
# Solution: Set in .env
echo "NIDS_JWT__SECRET=my-secret-key" >> .env
```

### Frontend Issues

**Problem:** `npm: command not found`
```bash
# Solution: Install Node.js
brew install node  # macOS
# Or download from https://nodejs.org
```

**Problem:** `Failed to fetch` errors in browser console
```bash
# Solution: Ensure backend is running on port 8000
# Check CORS is enabled in api/main.py (already configured)
```

**Problem:** `Cannot find module` errors
```bash
# Solution: Reinstall dependencies
cd frontend
rm -rf node_modules package-lock.json
npm install
```

**Problem:** `401 Unauthorized` on all API calls
```bash
# Solution: Check JWT token
# Clear localStorage and login again
# Open browser console:
localStorage.clear()
location.reload()
```

### Docker Issues

**Problem:** `Cannot connect to Docker daemon`
```bash
# Solution: Start Docker Desktop
open -a Docker
```

**Problem:** Port 8000 or 3000 already in use
```bash
# Solution: Stop conflicting services or change ports
# Edit docker-compose.yml:
ports:
  - "8001:8000"  # Backend on 8001
  - "3001:80"    # Frontend on 3001
```

**Problem:** Postgres health check failing
```bash
# Solution: Wait longer (takes 30-60 seconds on first start)
docker-compose logs postgres

# Or recreate volumes:
docker-compose down -v
docker-compose up -d
```

---

## 📊 Verify Everything Works

### Checklist

```bash
# ✅ Backend
curl http://localhost:8000/api/v1/health
# Expected: {"status":"healthy",...}

# ✅ Login works
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# Expected: {"access_token":"..."}

# ✅ Frontend loads
open http://localhost:3000
# Expected: Login page appears

# ✅ Can authenticate
# Login with admin/admin
# Expected: Redirects to dashboard

# ✅ Dashboard shows data
# Expected: Stat cards, charts visible

# ✅ Events page works
# Expected: Table with events (may be empty initially)

# ✅ Rules page works
# Expected: List of detection rules

# ✅ Tests pass
pytest tests/ -v
# Expected: All tests pass

# ✅ Docker works
docker-compose ps
# Expected: All services "Up" and "healthy"
```

---

## 🚀 Generate Test Data (Optional)

To populate the dashboard with sample data:

```python
# Create a test script: scripts/generate_test_data.py
import sys
sys.path.insert(0, '/Users/imafdi/Desktop/Project/my-projects/nids_project')

from config.database_v2 import log_intrusion_event, create_rule
from datetime import datetime, timedelta
import random

# Generate 100 sample events
severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
protocols = ['TCP', 'UDP', 'ICMP']
ips = [f'192.168.1.{i}' for i in range(1, 101)]

for i in range(100):
    log_intrusion_event(
        timestamp=datetime.now() - timedelta(hours=random.randint(0, 24)),
        severity=random.choice(severities),
        src_ip=random.choice(ips),
        dst_ip='10.0.0.1',
        src_port=random.randint(1024, 65535),
        dst_port=random.choice([80, 443, 22, 3389]),
        protocol=random.choice(protocols),
        rule_triggered=f'rule_{random.randint(1,5)}',
        ml_score=random.random(),
        description=f'Test event {i}'
    )

print("✅ Generated 100 test events")
```

Run it:
```bash
python scripts/generate_test_data.py
```

---

## 🎯 Next Steps After Testing

1. **Configure Real Network Interface**
   ```bash
   # Edit .env
   NIDS_CAPTURE__INTERFACE=eth0  # Your actual interface
   ```

2. **Set Up Notifications**
   - Add Slack webhook
   - Configure email SMTP
   - Add PagerDuty routing key

3. **Enable Threat Intelligence**
   ```bash
   # Get free API key from https://www.abuseipdb.com
   NIDS_THREATINTEL__ABUSEIPDB_API_KEY=your_key_here
   ```

4. **Download GeoIP Database**
   ```bash
   # Download GeoLite2-Country.mmdb
   # Place in: config/GeoLite2-Country.mmdb
   ```

5. **Set Strong JWT Secret**
   ```bash
   # Generate random secret
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   # Add to .env:
   NIDS_JWT__SECRET=<generated_secret>
   ```

6. **Deploy to Production**
   - See `docs/DEPLOYMENT.md` for full guide
   - Use PostgreSQL instead of SQLite
   - Enable HTTPS with nginx/Caddy
   - Set up log rotation

---

## 📞 Need Help?

**Common Commands:**

```bash
# View backend logs
docker-compose logs -f nids

# View frontend logs
docker-compose logs -f frontend

# Restart a service
docker-compose restart nids

# Rebuild after code changes
docker-compose up -d --build

# Check API documentation
open http://localhost:8000/docs

# Run tests in watch mode
pytest tests/ -v --lf

# Check Python environment
which python
python --version
pip list | grep fastapi
```

**API Endpoints to Test:**
- GET `/api/v1/health` — Health check
- POST `/api/v1/auth/login` — Get JWT token
- GET `/api/v1/events` — List events
- GET `/api/v1/rules` — List rules
- GET `/api/v1/stats` — Dashboard stats
- GET `/api/v1/system/metrics` — System metrics

**Default Credentials:**
- Username: `admin`
- Password: `admin` (or from NIDS_API__PASSWORD in .env)

---

**🎉 You're all set! Start detecting threats!**
