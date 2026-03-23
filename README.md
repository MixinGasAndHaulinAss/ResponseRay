# ResponseRay

A web-based Digital Forensics and Incident Response (DFIR) platform for investigating Windows endpoints. Upload CyberTriage forensic captures, automatically parse them via [ct-to-timesketch](https://github.com/NCLGISA/ct-to-timesketch), and explore the results through an interactive browser UI.

## Architecture

```
┌──────────────┐    ┌─────────────┐    ┌────────────────┐
│   React UI   │◄──►│    Nginx    │◄──►│   Go API + Worker  │
│  (Vite/TS)   │    │  (reverse   │    │   (chi router)     │
│  Tailwind    │    │   proxy)    │    │                    │
└──────────────┘    └─────────────┘    └────────┬───────────┘
                                                │
                                       ┌────────▼───────────┐
                                       │   PostgreSQL 16    │
                                       │   (JSONB events)   │
                                       └────────────────────┘
```

| Component | Tech |
|-----------|------|
| Backend API | Go 1.22, chi router, pgx/v5 connection pool |
| Background Worker | Go — polls for pending uploads, runs ct-to-timesketch, ingests JSONL |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, TanStack Table/Query |
| Database | PostgreSQL 16 with JSONB event storage, trigram indexes |
| Reverse Proxy | Nginx (Docker) — serves static frontend, proxies `/api/` to Go |
| Auth | Password-based (designed to sit behind Cloudflare Zero Trust) |

## Features

- **Incident Management** — Create sites (incidents), upload multiple CyberTriage captures per site, and investigate each capture independently
- **Automatic Parsing** — Uploaded `.json.gz` captures are processed by ct-to-timesketch and ingested into PostgreSQL
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
- **File System** — Interactive, clickable directory tree navigation
- **Timeline** — Chronological event view with jump-to-date/time
- **Remote Access Detection** — Automatic identification of 30+ remote access tools (AnyDesk, TeamViewer, RDP, etc.)
- **Findings** — Mark events as Bad, Suspicious, or Good; filter and review
- **Search** — Full-text search across all event data
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
│       ├── auth/auth.go         # Password middleware
│       ├── db/db.go             # PostgreSQL connection + migrations
│       ├── handlers/            # HTTP handlers (sites, uploads, events, dashboard, etc.)
│       ├── ingest/ingest.go     # JSONL → PostgreSQL ingestion
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
UPLOAD_DIR=/data/uploads
ARTIFACTS_DIR=/data/artifacts
REPORTS_DIR=/data/reports
CT_BINARY_PATH=/usr/local/bin/ct-to-timesketch
API_PORT=8080
```

### 2. Start PostgreSQL and Nginx

```bash
docker compose up -d postgres
```

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

## API Endpoints

All endpoints are under `/api/` and require the `X-Auth-Password` header.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/sites` | List all sites |
| `POST` | `/api/sites` | Create a site |
| `GET` | `/api/sites/:id` | Get site details |
| `PUT` | `/api/sites/:id` | Update site |
| `DELETE` | `/api/sites/:id` | Delete site and all data |
| `GET` | `/api/sites/:id/dashboard?upload_id=` | Dashboard stats |
| `GET` | `/api/sites/:id/uploads` | List uploads |
| `POST` | `/api/sites/:id/uploads` | Upload a capture (small files) |
| `POST` | `/api/sites/:id/uploads/init` | Initialize chunked upload |
| `PUT` | `/api/sites/:id/uploads/:uid/chunks/:idx` | Upload a chunk |
| `POST` | `/api/sites/:id/uploads/:uid/complete` | Finalize chunked upload |
| `GET` | `/api/sites/:id/events?upload_id=&event_types=&page=&per_page=` | Query events |
| `PATCH` | `/api/sites/:id/events/:eid/finding` | Update event finding |
| `POST` | `/api/sites/:id/events/findings` | Bulk update findings |
| `GET` | `/api/sites/:id/filesystem?path=&upload_id=` | Browse file system |
| `GET` | `/api/sites/:id/logons/users?upload_id=` | Logon user summaries |
| `GET` | `/api/sites/:id/remote-access?upload_id=` | Detect remote access tools |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `responseray` | Database name |
| `POSTGRES_USER` | `responseray` | Database user |
| `POSTGRES_PASSWORD` | `changeme_in_production` | Database password |
| `API_PORT` | `8080` | Go API listen port |
| `AUTH_PASSWORD` | `changeme_in_production` | Login password |
| `CT_BINARY_PATH` | `/usr/local/bin/ct-to-timesketch` | Path to ct-to-timesketch binary |
| `UPLOAD_DIR` | `/data/uploads` | Upload file storage |
| `ARTIFACTS_DIR` | `/data/artifacts` | Extracted artifacts storage |
| `REPORTS_DIR` | `/data/reports` | Parsed JSONL output storage |

## Versioning

CalVer format: `Year.Month.Day.Revision` (e.g., `2026.3.23.3`). The version is displayed on the login screen, home page, and dashboard.

## License

Internal use.
