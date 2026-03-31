# ResponseRay

A web-based Digital Forensics and Incident Response (DFIR) platform for investigating Windows endpoints. Upload forensic captures from the [ResponseRay Collector](collector/) or CyberTriage, automatically parse them via [ct-to-timesketch](https://github.com/NCLGISA/ct-to-timesketch), and explore the results through an interactive browser UI.

**Current version:** `2026.3.30.9`

## Architecture

```
┌──────────────┐    ┌─────────────┐    ┌────────────────────┐
│   React UI   │◄──►│    Nginx    │◄──►│   Go API + Worker  │
│  (Vite/TS)   │    │  (reverse   │    │   (chi router)     │
│  Tailwind    │    │   proxy)    │    │                    │
└──────────────┘    └─────────────┘    └──┬──────────────┬──┘
                                          │              │
                                 ┌────────▼────────┐  ┌──▼──────────┐
                                 │  PostgreSQL 16  │  │  Redis 7    │
                                 │  (JSONB events) │  │  (job queue │
                                 │                 │  │  + progress)│
                                 └─────────────────┘  └─────────────┘
```

| Component | Tech |
|-----------|------|
| Backend API | Go 1.22, chi router, pgx/v5 connection pool |
| Background Worker | Go — consumes jobs from Redis queue, runs ct-to-timesketch, ingests JSONL |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, TanStack Table/Query |
| Database | PostgreSQL 16 with JSONB event storage, trigram indexes |
| Job Queue | Redis 7 (Docker) — BRPOP-based job queue with real-time progress tracking |
| Reverse Proxy | Nginx (Docker) — serves static frontend, proxies `/api/` to Go |
| Auth | Password + API key (designed to sit behind Cloudflare Zero Trust) |
| Collector | C# .NET 8 — self-contained Windows executable, raw drive forensic capture |

## Features

- **Incident Management** — Create sites (incidents), upload multiple captures per site, and investigate each independently
- **Automatic Parsing** — Uploaded captures are queued in Redis and processed by ct-to-timesketch, then ingested into PostgreSQL
- **Processing Progress** — Real-time progress tracking: queue position, processing stage, event ingest progress bar, elapsed time
- **Chunked Uploads** — Files are split into 50 MB chunks client-side to work behind Cloudflare's 100 MB limit
- **Per-Capture Isolation** — Each upload's data is scoped independently
- **Dashboard** — Total events, notable/suspicious counts, findings breakdown, event type distribution
- **Windows Accounts** — User accounts with admin status, earliest/latest activity
- **Logons** — Grouped by username with expandable session details; toggle machine accounts
- **Processes & Execution** — Process creation (4688), prefetch execution, BAM, Amcache, UserAssist
- **Services** — Installed services from registry and live service state
- **Persistence** — Winlogon, WMI persistence, startup items, scheduled tasks
- **Network** — Active connections, shares, SMB sessions, DNS cache, DHCP
- **Web & Data** — Browser history, typed URLs, recent documents, LNK targets
- **SRUM** — Application usage, network connectivity, and network usage from SRUDB.dat
- **System Info** — OS configuration, installed software, network profiles
- **Windows Defender** — Defender detection and configuration events
- **PowerShell** — Script block logging and console history
- **File System** — Interactive directory tree with multi-drive support (C:, E:, etc.) and artifact download
- **Timeline** — Chronological event view with jump-to-date/time
- **Remote Access Detection** — Automatic identification of 30+ remote access tools
- **Findings** — Mark events as Bad, Suspicious, or Good; filter and review
- **Search** — Full-text search across all event data
- **API Key Management** — Create/revoke API keys for external programmatic access
- **Event Log Viewer** — Browse Windows Event Logs by channel with filtering

## Prerequisites

- Linux server (tested on Ubuntu 24.04)
- Go 1.22+
- Node.js 18+ / npm
- Docker & Docker Compose
- [ct-to-timesketch](https://github.com/NCLGISA/ct-to-timesketch) binary

## Project Structure

```
ResponseRay/
├── backend/
│   ├── cmd/
│   │   ├── api/main.go              # API server entry point
│   │   └── worker/main.go           # Background worker entry point
│   └── internal/
│       ├── auth/                     # Password + API key middleware
│       ├── db/                       # PostgreSQL connection + migrations
│       ├── handlers/                 # HTTP handlers (sites, uploads, events, filesystem, etc.)
│       ├── ingest/                   # JSONL → PostgreSQL ingestion
│       ├── rdb/                      # Redis client, job queue, progress tracking
│       └── models/                   # Shared data structures
├── frontend/
│   ├── src/
│   │   ├── pages/                    # React page components
│   │   ├── components/               # Layout, sidebar, shared UI
│   │   ├── hooks/                    # Custom hooks (useEvents, useTheme)
│   │   └── lib/                      # API client, utilities
│   └── package.json
├── collector/                        # Windows forensic collector (see collector/README.md)
│   ├── src/ResponseRayCollector/
│   │   ├── Program.cs                # CLI entry point
│   │   ├── Collectors/               # Individual artifact collectors
│   │   ├── Models/                   # Manifest and data models
│   │   └── Utils/                    # FileHelper, ConsoleOutput
│   └── publish/                      # Built executable
├── ct-to-timesketch/                 # Forensic artifact parser (Go)
│   ├── cmd/ct-to-timesketch/         # CLI entry point
│   └── internal/
│       ├── extractors/               # evtx, registry, mft, browser, prefetch, srum, etc.
│       ├── directory/                # Collector archive processing
│       ├── converter/                # Event conversion
│       └── postprocess/              # CloudRules threat detection
├── docker-compose.yml                # PostgreSQL, Redis, Nginx, API containers
├── nginx.conf                        # Reverse proxy config
├── .env.example                      # Environment variable template
└── README.md
```

## Deployment

### Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/NCLGISA/ResponseRay.git /opt/responseray
cd /opt/responseray
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and AUTH_PASSWORD
docker compose up -d
```

This starts PostgreSQL, Redis, Nginx, the API server, and builds the frontend automatically.

### Option 2: Hybrid (Native Go + Docker Services)

This runs PostgreSQL and Redis in Docker with the Go API/Worker as native binaries managed by systemd.

#### 1. Clone and configure

```bash
git clone https://github.com/NCLGISA/ResponseRay.git /opt/responseray
cd /opt/responseray
cp .env.example .env
# Edit .env — set passwords and paths
```

#### 2. Start PostgreSQL and Redis

```bash
docker compose up -d postgres redis
```

#### 3. Install ct-to-timesketch

```bash
cd /opt/responseray/ct-to-timesketch
go build -o /usr/local/bin/ct-to-timesketch ./cmd/ct-to-timesketch/
```

#### 4. Build the Go backend

```bash
cd /opt/responseray/backend
go build -o /opt/responseray/bin/responseray-api ./cmd/api
go build -o /opt/responseray/bin/responseray-worker ./cmd/worker
```

#### 5. Create systemd service

**`/etc/systemd/system/responseray.service`**:

```ini
[Unit]
Description=ResponseRay API + Worker
After=docker.service
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=/opt/responseray/.env
ExecStart=/bin/bash -c '/opt/responseray/bin/responseray-api & /opt/responseray/bin/responseray-worker & wait'
Restart=on-failure
WorkingDirectory=/opt/responseray

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now responseray
```

#### 6. Build and serve the frontend

```bash
cd /opt/responseray/frontend
npm install
npm run build
docker compose up -d nginx
```

### Update workflow

```bash
# On the server:
cd /opt/responseray && git pull origin master
cd backend && go build -o ../bin/responseray-api ./cmd/api && go build -o ../bin/responseray-worker ./cmd/worker
cd ../ct-to-timesketch && go build -o /usr/local/bin/ct-to-timesketch ./cmd/ct-to-timesketch/
cd ../frontend && npm run build
sudo systemctl restart responseray
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `responseray` | Database name |
| `POSTGRES_USER` | `responseray` | Database user |
| `POSTGRES_PASSWORD` | `changeme_in_production` | Database password |
| `REDIS_ADDR` | `127.0.0.1:6379` | Redis address for job queue and progress |
| `API_PORT` | `8080` | Go API listen port |
| `AUTH_PASSWORD` | `changeme_in_production` | Login password |
| `CT_BINARY_PATH` | `/usr/local/bin/ct-to-timesketch` | Path to ct-to-timesketch binary |
| `UPLOAD_DIR` | `/data/uploads` | Upload file storage |
| `ARTIFACTS_DIR` | `/data/artifacts` | Extracted artifacts storage |
| `REPORTS_DIR` | `/data/reports` | Parsed JSONL output storage |
| `TRUSTED_PROXIES` | — | Cloudflare IP ranges for `X-Forwarded-For` |

## API Reference

All endpoints are under `/api/`. Every request (except `/api/health`) must be authenticated.

### Authentication

**1. Password (Basic Auth)** — used by the web UI:

```bash
curl -u "analyst:your_password" https://your-server/api/sites/
```

**2. API Key** — recommended for integrations and automation:

```bash
curl -H "X-API-Key: rr_your_key_here" https://your-server/api/sites/
```

API keys are created in the web UI (Home > API Keys) or via the API.

### Python Example

```python
import requests

BASE = "https://your-server/api"
HEADERS = {"X-API-Key": "rr_your_key_here"}

# List all sites
sites = requests.get(f"{BASE}/sites/", headers=HEADERS).json()

# Get dashboard for a specific capture
stats = requests.get(f"{BASE}/sites/{site_id}/dashboard",
    headers=HEADERS, params={"upload_id": upload_id}).json()

# Search events
events = requests.get(f"{BASE}/sites/{site_id}/events", headers=HEADERS, params={
    "upload_id": upload_id,
    "search": "mimikatz",
    "event_types": "windows_process,process_execution",
    "limit": "50",
}).json()

# Mark an event as bad
requests.patch(f"{BASE}/sites/{site_id}/events/{event_id}/finding",
    headers={**HEADERS, "Content-Type": "application/json"},
    json={"finding": "bad", "finding_note": "Credential dumping tool"})

# Download a captured artifact
resp = requests.get(f"{BASE}/sites/{site_id}/filesystem/download/{upload_id}",
    headers=HEADERS, params={"path": "/c/windows/system32/", "name": "cmd.exe"})
with open("cmd.exe", "wb") as f:
    f.write(resp.content)
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check (no auth) |
| `GET` | `/api/sites/` | List all sites |
| `POST` | `/api/sites/` | Create a site |
| `GET` | `/api/sites/{id}/` | Get site details |
| `PUT` | `/api/sites/{id}/` | Update site |
| `DELETE` | `/api/sites/{id}/` | Delete site and all data |
| `GET` | `/api/sites/{id}/uploads` | List uploads for a site |
| `POST` | `/api/sites/{id}/uploads/init` | Initialize chunked upload |
| `PUT` | `/api/sites/{id}/uploads/{uid}/chunks/{idx}` | Upload a chunk |
| `POST` | `/api/sites/{id}/uploads/{uid}/complete` | Complete chunked upload |
| `DELETE` | `/api/sites/{id}/uploads/{uid}` | Delete upload and events |
| `GET` | `/api/sites/{id}/dashboard` | Dashboard statistics |
| `GET` | `/api/sites/{id}/events` | Query events (supports filtering, search, pagination) |
| `PATCH` | `/api/sites/{id}/events/{eid}/finding` | Update event finding |
| `POST` | `/api/sites/{id}/events/findings` | Bulk update findings |
| `GET` | `/api/sites/{id}/filesystem` | List filesystem directory |
| `GET` | `/api/sites/{id}/filesystem/download/{uid}` | Download captured file |
| `GET` | `/api/sites/{id}/logons/users` | Logon user summary |
| `GET` | `/api/sites/{id}/remote-access` | Remote access tool detection |
| `GET` | `/api/keys/` | List API keys |
| `POST` | `/api/keys/` | Create API key |
| `DELETE` | `/api/keys/{kid}` | Delete API key |

### Event Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `upload_id` | UUID | Filter to a specific upload |
| `event_types` | string | Comma-separated event types |
| `search` | string | Full-text search across message field |
| `finding` | string | Filter: `bad`, `suspicious`, `good`, `any`, `none` |
| `notable` | bool | Show only CyberTriage notable events |
| `date_from` | ISO datetime | Events on or after this timestamp |
| `date_to` | ISO datetime | Events on or before this timestamp |
| `channel` | string | Filter by EVTX channel |
| `sort` | string | Sort field: `datetime`, `event_type`, `message` |
| `dir` | string | Sort direction: `asc` or `desc` |
| `offset` | int | Pagination offset |
| `limit` | int | Results per page (max 1000) |
| `data.*` | string | Filter on JSONB data fields (e.g., `data.LogonType=10`) |

### Event Types

| Event Type | Source | Description |
|------------|--------|-------------|
| `file_timeline` | MFT | File system timeline ($SI timestamps) |
| `file_timeline_fn` | MFT | File system timeline ($FN timestamps) |
| `windows_logon` | EVTX | Logon events (4624, 4625) |
| `windows_authentication` | EVTX | Kerberos/NTLM auth (4776, 4768) |
| `windows_rdp` | EVTX | RDP session events |
| `windows_process` | EVTX | Process creation (4688) |
| `running_process` | Live | Running processes at capture time |
| `process_execution` | Prefetch | Prefetch-based execution evidence |
| `prefetch_execution` | Prefetch | Prefetch execution with run count |
| `registry_bam` | Registry | Background Activity Moderator |
| `registry_amcache` | Registry | Amcache execution history |
| `registry_userassist` | Registry | UserAssist program execution |
| `windows_service` | EVTX | Service install/modification |
| `windows_task` | EVTX | Scheduled task events |
| `active_connection` | Live | Network connections at capture time |
| `network_connection` | EVTX | Historical network connections |
| `network_share` | EVTX | SMB share access |
| `dns_cache_entry` | Live | DNS cache at capture time |
| `windows_dns` | EVTX | Historical DNS events |
| `windows_dhcp` | Live | DHCP data at capture time |
| `browser_history` | Browser DB | Browser history entries |
| `registry_typedurls` | Registry | Typed URLs from registry |
| `srum_app_usage` | SRUM | Application resource usage |
| `os_config` | Live | OS configuration at capture time |
| `registry_software` | Registry | Installed software |
| `registry_networklist` | Registry | Network profiles |
| `windows_defender` | EVTX | Defender events |
| `powershell` | EVTX | PowerShell script block logging |
| `usb_device` | EVTX | USB device connections |
| `wmi_persistence` | WMI | WMI persistence entries |
| `recyclebin` | Filesystem | Recycle bin entries |
| `lnk_target` | LNK files | Shortcut file targets |

## Versioning

CalVer format: `Year.Month.Day.Revision` (e.g., `2026.3.30.9`). The version is displayed on the login screen, home page, and dashboard.

## License

Internal use — Currituck County, NC.
