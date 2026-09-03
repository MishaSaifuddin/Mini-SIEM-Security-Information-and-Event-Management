# Mini SIEM - Security Information & Event Management Platform

A lightweight, web-based SIEM platform for log collection, security monitoring, detection, and alerting. Built with FastAPI (Python) backend and React frontend.

> **🌐 Live Demo:** [https://involved-featuring-illinois-broad.trycloudflare.com](https://involved-featuring-illinois-broad.trycloudflare.com)
> Login: `admin` / `admin123` — *Quick tunnel URL is temporary and changes on restart. See [Deployment](#deployment).*

## Features

### Log Collection
- REST API for event ingestion (single & batch)
- Lightweight Python agent for endpoint log collection (Windows Event Logs, syslog, web server logs, auth logs, JSON app logs)
- Log normalization across multiple source types
- Auto-registration of log sources

### Detection Engine
- Rule-based signature detection
- Sigma rule format support (import YAML rules)
- 11 pre-configured rules covering common attack techniques:
  - Brute Force Attacks (failed logins)
  - Impossible Travel (unusual login patterns)
  - Port Scanning
  - Privilege Escalation (new admin accounts)
  - Suspicious IP Communication (C2)
  - Malware Indicators (mimikatz, encoded commands, etc.)
  - Audit Log Tampering
  - Backdoor Installation
  - Web Attacks
  - Account Lockout
- Threshold-based rules with time windows
- MITRE ATT&CK technique mapping

### Alerting & Incident Response
- Real-time alert generation on rule matches
- Alert management workflow (Open → In Progress → Resolved / False Positive)
- Alert detail view with related events
- Severity classification (Critical/High/Medium/Low/Info)

### Dashboard
- SOC overview with real-time KPIs
- Event & alert activity timelines
- Severity distribution charts
- Top log sources and event types
- Recent alerts feed
- Event explorer with filtering & search

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React Frontend                        │
│        Dashboard | Events | Alerts | Rules | Sources    │
└──────────────────────────┬──────────────────────────────┘
                           │ REST API (JSON)
┌──────────────────────────▼──────────────────────────────┐
│              FastAPI Backend (Python)                    │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │  Ingestion  │  │ Normalizer   │  │ Detection Engine│  │
│  │  API        │  │ (Log format) │  │ (Rules/Sigma)  │   │
│  └────────────┘  └──────────────┘  └────────────────┘   │
│                        │                                 │
│              ┌─────────▼──────────┐                      │
│              │    Database        │                      │
│              │ (Events, Alerts,   │                      │
│              │  Rules, Sources)   │                      │
│              └────────────────────┘                      │
└──────────────────────────┬──────────────────────────────┘
                           │
        ┌──────────────────┼───────────────────┐
        │                  │                   │
┌───────▼──────┐  ┌────────▼────────┐  ┌──────▼──────┐
│  Agent       │  │  REST API       │  │ Log Simulator│
│ (endpoints)  │  │  ingestion      │  │ (demo data)  │
└──────────────┘  └─────────────────┘  └─────────────┘
```

## Quick Start

### 1. Backend (FastAPI)

```bash
cd backend

# Create & activate virtual environment
python3 -m venv venv
# Windows:
venv\Scripts\activate
# Unix/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --reload --port 8000
```

Backend runs at `http://localhost:8000` — API docs at `http://localhost:8000/docs`

### 2. Frontend (React)

```bash
cd frontend
npm install
npm start
```

Frontend runs at `http://localhost:3000`

### 3. Login

Default credentials: `admin` / `admin123`

## Ingesting Logs

### Single Event
```bash
curl -X POST http://localhost:8000/api/events/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "source_name": "web-server-01",
    "source_type": "web_server",
    "hostname": "web-server-01",
    "description": "GET /admin HTTP/1.1",
    "source_ip": "185.220.101.42",
    "response_code": "403",
    "severity": "info"
  }'
```

### Batch
```bash
curl -X POST http://localhost:8000/api/events/ingest/batch \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"events": [{ ... }, { ... }]}'
```

### Using the Log Simulator (for testing/demo)
```bash
cd backend
python app/data/simulate_logs.py
```

This generates realistic auth, Windows, firewall, web server, and malware logs and sends them to the SIEM.

### Using the Agent (production - installed on endpoints)

```bash
# On a Linux endpoint - tail auth logs
python agent/agent.py --tail /var/log/auth.log --source-type auth --siem-url http://<server>:8000

# On a Windows endpoint - collect Windows Event Logs
python agent/agent.py --collect-windows --siem-url http://<server>:8000

# Run a syslog receiver
python agent/agent.py --syslog-port 514 --siem-url http://<server>:8000

# Watch JSON application logs
python agent/agent.py --json-logs /var/log/app/app.log --siem-url http://<server>:8000
```

## Detection Rules

The platform comes with 11 pre-configured rules. You can also:

- Create custom rules via the UI (specify conditions as JSON)
- Import Sigma rules via the UI or API
- Test rules against recent events
- Enable/disable rules in real-time

### Rule Condition Format

Single field match:
```json
{ "event_type": "failed_login" }
```

Using operators:
```json
{
  "description": { "contains": "Failed password" },
  "source_ip": { "in": ["185.220.101.42", "45.155.205.5"] }
}
```

Or-logic:
```json
{
  "$or": [
    { "event_type": "failed_login" },
    { "process_name": { "contains": "mimikatz" } }
  ]
}
```

Available operators: `equals`, `contains`, `not_contains`, `startswith`, `endswith`, `regex`, `in`, `not_in`, `greater_than`, `less_than`, `is_null`, `not_null`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Login, get JWT token |
| POST | `/api/auth/register` | Register new user |
| POST | `/api/events/ingest` | Ingest single event |
| POST | `/api/events/ingest/batch` | Ingest batch of events |
| GET | `/api/events/` | Query events with filters |
| GET | `/api/events/stats` | Event statistics |
| GET | `/api/alerts/` | List alerts |
| GET | `/api/alerts/stats` | Alert statistics |
| PUT | `/api/alerts/{id}` | Update alert status |
| GET | `/api/rules/` | List detection rules |
| POST | `/api/rules/` | Create detection rule |
| POST | `/api/rules/sigma` | Import Sigma rule |
| POST | `/api/rules/test` | Test rule against recent events |
| GET | `/api/sources/` | List log sources |
| POST | `/api/sources/` | Register log source |
| GET | `/api/dashboard/summary` | Dashboard summary data |

## Configuration

Environment variables:
- `DB_ENGINE` - `sqlite` (default) or `mysql`
- `SECRET_KEY` - JWT signing key (change in production)
- `SIEM_URL` - for agent, backend URL

For MySQL:
```bash
export DB_ENGINE=mysql
export MYSQL_HOST=localhost
export MYSQL_USER=siem
export MYSQL_PASSWORD=secret
export MYSQL_DB=mini_siem
```

## CISA Alignment

This platform follows CISA guidance on centralized log collection and protection:
- **Centralized collection**: All logs from multiple sources feed into a single platform
- **Detection**: Rules map to MITRE ATT&CK techniques
- **Incident response**: Alert triage workflow with notes, assignment, and resolution tracking
- **Log integrity**: Audit log tampering detection
- **Observability**: SOC dashboard for continuous monitoring

## Deployment

The built React UI is served directly by the FastAPI backend on a single port, so the whole platform (UI + API) is reachable at one URL.

### Local
```bash
# Backend (serves UI + API), production mode
cd backend
venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open http://localhost:8000

### Publish publicly (free, no account) — Cloudflare Quick Tunnel
1. Ensure the backend is running on port 8000.
2. Download and run cloudflared (see `deploy/README.md`):
   ```bash
   cd deploy
   cloudflared tunnel --url http://127.0.0.1:8000
   ```
3. Cloudflare outputs a public `https://<random>.trycloudflare.com` URL.

**Note:** Quick tunnels are temporary (new URL per restart, no uptime guarantee). For a permanent URL, use a named tunnel pointed at a domain you own.

> ⚠️ **Security:** Change the default `admin` password before exposing publicly. Anyone with credentials has full access.
