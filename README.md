# ResponseRay

A web-based Digital Forensics and Incident Response (DFIR) platform for investigating Windows endpoints. Upload CyberTriage forensic captures, automatically parse them via [ct-to-timesketch](https://github.com/NCLGISA/ct-to-timesketch), and explore the results through an interactive browser UI.

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

## Features

- **Incident Management** — Create sites (incidents), upload multiple CyberTriage captures per site, and investigate each capture independently
- **Automatic Parsing** — Uploaded `.json.gz` captures are queued in Redis and processed sequentially by ct-to-timesketch, then ingested into PostgreSQL
- **Processing Progress** — Real-time progress tracking on the Captures page: queue position, processing stage, event ingest progress bar, and elapsed time
- **Chunked Uploads** — Files are split into 50 MB chunks on the client side to work behind Cloudflare's 100 MB limit
- **Per-Capture Isolation** — Each upload's data is scoped independently; select a capture within a site to view its data
- **Dashboard** — High-level stats: total events, notable/suspicious counts, findings breakdown, event type distribution
- **Windows Accounts** — User accounts with admin status, earliest/latest activity, observed actions
- **Logons** — Grouped by username with expandable session details; toggle to show/hide machine accounts (`$`)
- **Network Shares** — SMB share access events
- **Web Artifacts** — Browser history and typed URLs
- **Data Accessed** — File access, recent documents, LNK targets
- **Triggered Tasks** — Scheduled task creation and execution
- **Processes** — Process execution and creation events
- **Active Connections & Listening Ports** — Network connection data
- **DNS Cache** — Cached DNS resolution entries
- **System Info** — Host details and OS configuration
- **Attached Devices** — USB and device connection history
- **File System** — Interactive, clickable directory tree with artifact download
- **Timeline** — Chronological event view with jump-to-date/time
- **Remote Access Detection** — Automatic identification of 30+ remote access tools (AnyDesk, TeamViewer, RDP, etc.)
- **Findings** — Mark events as Bad, Suspicious, or Good; filter and review
- **Search** — Full-text search across all event data
- **API Key Management** — Create/revoke API keys for external programmatic access
- **Sortable Columns** — Timestamp columns are click-sortable (ascending/descending)
- **Copy to Clipboard** — Click-to-copy on any field in the event detail panel
- **Collapsible Sidebar** — Collapse the navigation menu for more viewing space

## Prerequisites

- Linux server (tested on Ubuntu 24.04)
- Go 1.22+
- Node.js 18+ / npm
- Docker & Docker Compose
- [ct-to-timesketch](https://github.com/NCLGISA/ct-to-timesketch) binary installed at `/usr/local/bin/ct-to-timesketch`

## Project Structure

```
ResponseRay/
├── backend/
│   ├── cmd/
│   │   ├── api/main.go          # API server entry point
│   │   └── worker/main.go       # Background worker entry point
│   └── internal/
│       ├── auth/auth.go         # Password + API key middleware
│       ├── db/db.go             # PostgreSQL connection + migrations
│       ├── handlers/            # HTTP handlers (sites, uploads, events, etc.)
│       ├── ingest/ingest.go     # JSONL → PostgreSQL ingestion
│       ├── rdb/rdb.go           # Redis client, job queue, progress tracking
│       └── models/models.go     # Shared data structures
├── frontend/
│   ├── src/
│   │   ├── pages/               # React page components
│   │   ├── components/          # Layout, sidebar, shared UI
│   │   ├── hooks/               # useEvents custom hook
│   │   └── lib/                 # API client, utilities
│   └── package.json
├── docker-compose.yml           # PostgreSQL + Nginx containers
├── nginx.conf                   # Reverse proxy config
└── README.md
```

## Deployment (Dev Server)

This setup runs PostgreSQL and Nginx in Docker, with the Go API/Worker as native binaries managed by systemd.

### 1. Clone and configure

```bash
git clone https://github.com/MixinGasAndHaulinAss/ResponseRay.git /opt/responseray
cd /opt/responseray
```

Create a `.env` file:

```bash
POSTGRES_DB=responseray
POSTGRES_USER=responseray
POSTGRES_PASSWORD=your_secure_password
AUTH_PASSWORD=your_login_password
REDIS_ADDR=127.0.0.1:6379
UPLOAD_DIR=/data/uploads
ARTIFACTS_DIR=/data/artifacts
REPORTS_DIR=/data/reports
CT_BINARY_PATH=/usr/local/bin/ct-to-timesketch
API_PORT=8080
```

### 2. Start PostgreSQL, Redis, and Nginx

```bash
docker compose up -d postgres redis
```

Redis runs as a Docker container with AOF persistence enabled. Data is stored in the `redisdata` volume.

Update `nginx.conf` if your port differs, then:

```bash
docker compose up -d nginx
```

Nginx listens on port 80 (or 8888 if you remap). It proxies `/api/` to the Go API and serves the built frontend from `/usr/share/nginx/html`.

### 3. Build the Go backend

```bash
cd /opt/responseray/backend
go build -o /opt/responseray/bin/responseray-api ./cmd/api
go build -o /opt/responseray/bin/responseray-worker ./cmd/worker
```

### 4. Create systemd services

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

### 5. Build the frontend

```bash
cd /opt/responseray/frontend
npm install
npm run build
```

The built files land in `frontend/dist/`. Nginx serves them. Copy or mount as needed:

```bash
docker cp frontend/dist/. responseray-nginx-1:/usr/share/nginx/html/
docker restart responseray-nginx-1
```

### 6. Update workflow

```bash
# On your local machine:
git push origin master

# On the server:
cd /opt/responseray
git pull origin master
cd backend && go build -o ../bin/responseray-api ./cmd/api && go build -o ../bin/responseray-worker ./cmd/worker
cd ../frontend && npm run build
sudo systemctl restart responseray
docker restart responseray-nginx-1
```

---

## API Reference

All endpoints are under `/api/`. Every request (except `/api/health`) must be authenticated.

### Authentication

ResponseRay supports two authentication methods:

**1. Password (Basic Auth)** — used by the web UI and quick scripts:

```bash
curl -u "analyst:your_password" https://your-server/api/sites/
```

**2. API Key** — recommended for integrations, scripts, and automation:

```bash
curl -H "X-API-Key: rr_your_key_here" https://your-server/api/sites/
```

API keys are created in the web UI (Home > API Keys) or via the API. The key is shown once at creation and stored as a SHA-256 hash.

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
    headers=HEADERS, params={"path": "/Windows/System32/", "name": "cmd.exe"})
with open("cmd.exe", "wb") as f:
    f.write(resp.content)
```

---

### Health Check

```
GET /api/health
```

No authentication required. Returns `{"status":"ok"}`.

---

### API Keys

#### List API Keys

```
GET /api/keys/
```

Returns all API keys (key values are never returned, only the prefix).

**Response:**

```json
[
  {
    "id": "uuid",
    "name": "SOAR Integration",
    "prefix": "rr_a1b2c3d4",
    "created_at": "2026-03-24T12:00:00Z",
    "last_used": "2026-03-24T14:30:00Z",
    "is_active": true
  }
]
```

#### Create API Key

```
POST /api/keys/
Content-Type: application/json

{"name": "My Integration"}
```

**Response (201):**

```json
{
  "id": "uuid",
  "name": "My Integration",
  "prefix": "rr_a1b2c3d4",
  "key": "rr_a1b2c3d4e5f6...full_key_here",
  "created_at": "2026-03-24T12:00:00Z",
  "last_used": null,
  "is_active": true
}
```

The `key` field is only returned at creation. Store it securely.

#### Delete API Key

```
DELETE /api/keys/{key_id}
```

Returns `204 No Content`.

---

### Sites

#### List Sites

```
GET /api/sites/
```

**Response:**

```json
[
  {
    "id": "uuid",
    "name": "Workstation-042 Compromise",
    "description": "Suspected ransomware incident",
    "created_at": "2026-03-20T10:00:00Z",
    "updated_at": "2026-03-20T10:00:00Z",
    "upload_count": 2,
    "event_count": 450000
  }
]
```

#### Create Site

```
POST /api/sites/
Content-Type: application/json

{"name": "Incident Name", "description": "Optional description"}
```

**Response (201):** Site object.

#### Get Site

```
GET /api/sites/{site_id}/
```

**Response:** Site object (without counts).

#### Update Site

```
PUT /api/sites/{site_id}/
Content-Type: application/json

{"name": "Updated Name", "description": "Updated description"}
```

**Response:** `204 No Content`.

#### Delete Site

```
DELETE /api/sites/{site_id}/
```

Deletes the site, all uploads, all events, and removes all files from disk (uploads, artifacts, reports).

**Response:** `204 No Content`.

---

### Uploads

#### List Uploads

```
GET /api/sites/{site_id}/uploads
```

**Response:**

```json
[
  {
    "id": "uuid",
    "site_id": "uuid",
    "filename": "capture.json.gz",
    "host_name": "DESKTOP-ABC123",
    "status": "complete",
    "event_count": 225000,
    "error_msg": "",
    "created_at": "2026-03-20T10:05:00Z",
    "updated_at": "2026-03-20T10:12:00Z"
  }
]
```

Upload statuses: `pending`, `processing`, `complete`, `error`, `chunking`.

#### Initialize Chunked Upload

```
POST /api/sites/{site_id}/uploads/init
Content-Type: application/json

{
  "filename": "capture.json.gz",
  "total_size": 524288000,
  "chunk_size": 52428800,
  "total_parts": 10
}
```

**Response (201):**

```json
{"upload_id": "uuid", "total_parts": 10, "chunk_size": 52428800}
```

#### Upload Chunk

```
PUT /api/sites/{site_id}/uploads/{upload_id}/chunks/{chunk_index}
Content-Type: application/octet-stream

<binary chunk data>
```

**Response:**

```json
{"chunk_idx": 0, "size": 52428800}
```

#### Complete Chunked Upload

```
POST /api/sites/{site_id}/uploads/{upload_id}/complete
```

Reassembles chunks into the final file, sets status to `pending` for worker processing.

**Response:**

```json
{"upload_id": "uuid", "filename": "capture.json.gz", "total_size": 524288000, "status": "pending"}
```

#### Get Upload Status

```
GET /api/sites/{site_id}/uploads/{upload_id}
```

**Response:** Upload object.

#### Delete Upload

```
DELETE /api/sites/{site_id}/uploads/{upload_id}
```

Deletes the upload record, events, and all files from disk.

**Response:** `204 No Content`.

---

### Dashboard

```
GET /api/sites/{site_id}/dashboard
```

**Query parameters:**

| Parameter | Description |
|-----------|-------------|
| `upload_id` | Filter stats to a specific upload |

**Response:**

```json
{
  "total_events": 225000,
  "event_counts": {
    "windows_logon": 5200,
    "file_timeline": 180000,
    "windows_process": 3400
  },
  "notable_count": 42,
  "suspicious_count": 18,
  "finding_counts": {"bad": 3, "suspicious": 7, "good": 12},
  "uploads": [{"id": "uuid", "filename": "capture.json.gz", "...": "..."}]
}
```

---

### Events

#### Query Events

```
GET /api/sites/{site_id}/events
```

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `upload_id` | UUID | — | Filter to a specific upload |
| `event_types` | string | — | Comma-separated event types (e.g., `windows_logon,windows_process`) |
| `search` | string | — | Full-text search across message field |
| `finding` | string | — | Filter by finding: `bad`, `suspicious`, `good`, `any`, `none` |
| `notable` | bool | — | `true` to show only CyberTriage notable events |
| `suspicious` | bool | — | `true` to show only suspicious events |
| `date_from` | ISO datetime | — | Events on or after this timestamp |
| `date_to` | ISO datetime | — | Events on or before this timestamp |
| `channel` | string | — | Filter by EVTX channel (e.g., `Security`, `System`) |
| `sort` | string | `datetime` | Sort field: `datetime`, `event_type`, `message`, `id` |
| `dir` | string | `desc` | Sort direction: `asc` or `desc` |
| `offset` | int | 0 | Pagination offset |
| `limit` | int | 100 | Results per page (max 1000) |
| `data.*` | string | — | Filter on JSONB data fields (e.g., `data.LogonType=10`) |

**Response:**

```json
{
  "items": [
    {
      "id": 12345,
      "upload_id": "uuid",
      "site_id": "uuid",
      "datetime": "2026-03-15T08:30:00Z",
      "event_type": "windows_logon",
      "data_type": "windows:evtx:record",
      "message": "Successful logon: DESKTOP\\admin (Type 10)",
      "host_name": "DESKTOP-ABC123",
      "source_short": "Security",
      "timestamp_desc": "Event Recorded",
      "ct_significance": null,
      "is_suspicious": false,
      "finding": null,
      "finding_note": null,
      "data": {
        "event_identifier": "4624",
        "TargetUserName": "admin",
        "LogonType": "10",
        "IpAddress": "10.0.0.50",
        "channel": "Security"
      }
    }
  ],
  "total": 5200,
  "offset": 0,
  "limit": 100,
  "has_more": true
}
```

**Examples:**

```bash
# Get RDP logons in a date range
curl -H "X-API-Key: rr_..." \
  "https://server/api/sites/{id}/events?upload_id={uid}&event_types=windows_logon&data.LogonType=10&date_from=2026-03-01&date_to=2026-03-15"

# Search for PowerShell activity
curl -H "X-API-Key: rr_..." \
  "https://server/api/sites/{id}/events?upload_id={uid}&search=powershell&sort=datetime&dir=asc"

# Get all events marked as bad
curl -H "X-API-Key: rr_..." \
  "https://server/api/sites/{id}/events?upload_id={uid}&finding=bad"
```

#### Update Event Finding

```
PATCH /api/sites/{site_id}/events/{event_id}/finding
Content-Type: application/json

{"finding": "bad", "finding_note": "Known malware dropper"}
```

Valid findings: `bad`, `suspicious`, `good`, or `null` to clear.

**Response:** `204 No Content`.

#### Bulk Update Findings

```
POST /api/sites/{site_id}/events/findings
Content-Type: application/json

{
  "event_ids": [12345, 12346, 12347],
  "finding": "suspicious",
  "finding_note": "Unusual lateral movement pattern"
}
```

**Response:** `204 No Content`.

---

### File System

#### List Directory

```
GET /api/sites/{site_id}/filesystem
```

**Query parameters:**

| Parameter | Description |
|-----------|-------------|
| `path` | Directory path to list (default `/`). Must end with `/`. |
| `upload_id` | Filter to a specific upload |

**Response:**

```json
{
  "path": "/Windows/System32/",
  "entries": [
    {
      "name": "drivers",
      "is_dir": true,
      "file_count": 245
    },
    {
      "name": "cmd.exe",
      "is_dir": false,
      "size": 289792,
      "latest_time": "2026-03-15T08:00:00Z",
      "md5": "abc123...",
      "sha256": "def456...",
      "is_deleted": false,
      "has_timestomp": false,
      "significance": null,
      "is_suspicious": false,
      "has_artifact": true
    }
  ]
}
```

`has_artifact: true` means the captured file binary is available for download.

#### Download Captured File

```
GET /api/sites/{site_id}/filesystem/download/{upload_id}?path=/Windows/System32/&name=cmd.exe
```

Returns the raw binary file with `Content-Disposition: attachment`.

---

### Logon Users

```
GET /api/sites/{site_id}/logons/users
```

**Query parameters:**

| Parameter | Description |
|-----------|-------------|
| `upload_id` | Filter to a specific upload |

**Response:**

```json
[
  {
    "username": "admin",
    "total_events": 142,
    "success_count": 130,
    "fail_count": 12,
    "unique_ips": 3,
    "first_seen": "2026-03-10T06:00:00Z",
    "last_seen": "2026-03-15T22:00:00Z",
    "auth_packages": "NTLM, Kerberos",
    "logon_types": "2, 3, 10",
    "domain": "CONTOSO"
  }
]
```

---

### Remote Access Detection

```
GET /api/sites/{site_id}/remote-access
```

**Query parameters:**

| Parameter | Description |
|-----------|-------------|
| `upload_id` | Filter to a specific upload |

Scans events for 30+ known remote access tools (AnyDesk, TeamViewer, ConnectWise, BeyondTrust, Radmin, LogMeIn, Splashtop, RustDesk, etc.).

**Response:**

```json
[
  {
    "name": "AnyDesk",
    "category": "Remote Desktop",
    "event_count": 47,
    "event_types": ["windows_process", "windows_service"],
    "first_seen": "2026-03-12T14:00:00Z",
    "last_seen": "2026-03-15T09:30:00Z",
    "search_terms": ["anydesk"]
  }
]
```

---

### Event Types

Common `event_type` values found in parsed CyberTriage captures:

| Event Type | Description |
|------------|-------------|
| `windows_logon` | Windows logon events (4624, 4625, etc.) |
| `windows_authentication` | Kerberos/NTLM authentication (4776, 4768, etc.) |
| `windows_rdp` | RDP session events |
| `session_logon` | Interactive session logons |
| `windows_process` | Process creation/termination (4688, 4689) |
| `process_execution` | Prefetch-based process execution |
| `windows_service` | Service install/modification |
| `windows_task` | Scheduled task events |
| `file_timeline` | MFT file timeline entries |
| `file_timeline_fn` | MFT $FN attribute timeline |
| `file_access` | Recent file access |
| `browser_history` | Browser history entries |
| `registry_typedurls` | Typed URLs from registry |
| `registry_recentdocs` | Recent documents from registry |
| `lnk_target` | LNK file targets |
| `network_connection` | Active/listening connections |
| `network_share` | SMB share access |
| `windows_dns` | DNS cache entries |
| `windows_smb` | SMB session events |
| `account_created` | User account information |
| `os_config` | OS configuration settings |
| `srum_app_usage` | SRUM application usage |
| `srum_network_connectivity` | SRUM network data |
| `windows_defender` | Windows Defender events |
| `powershell` | PowerShell script block logging |
| `evtx_event` | Generic EVTX events |
| `usb_device` | USB device connections |
| `wmi_persistence` | WMI persistence entries |
| `recyclebin` | Recycle bin entries |

---

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

## Error Responses

All errors return JSON-compatible text with an appropriate HTTP status code:

| Status | Meaning |
|--------|---------|
| `400` | Bad request — invalid parameters or missing required fields |
| `401` | Unauthorized — invalid or missing authentication |
| `404` | Not found — resource does not exist |
| `500` | Internal server error |

## Versioning

CalVer format: `Year.Month.Day.Revision` (e.g., `2026.3.24.1`). The version is displayed on the login screen, home page, and dashboard.

## License

Internal use.
