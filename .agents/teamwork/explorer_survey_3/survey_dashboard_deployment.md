# SecureScan: Frontend Dashboard, Container Deployment & Documentation Specification (R3, R4, R5)

**Document Version:** 1.0.0  
**Author:** Teamwork Explorer Survey Agent 3  
**Target:** Heyram Infrastructure Placement Assessment — SecureScan Security Platform  
**Scope:** Requirements R3 (React Dashboard), R4 (Docker Compose & Deployment Setup), R5 (Project Documentation)

---

## 1. Executive Summary

SecureScan is an enterprise-grade web security scanner platform that wraps the multi-engine SecureShip CLI within a Python FastAPI backend and delivers an interactive, dark-themed React dashboard. The entire platform is engineered to be deployable via Docker Compose under strict resource boundaries (3 GB RAM, 1.5 CPUs) with zero runtime binary downloads, air-gap readiness, and instant zero-configuration public sharing via Cloudflare Quick Tunnel.

This survey establishes the complete technical specification, component architecture, data contracts, container topologies, and documentation standards for requirements **R3**, **R4**, and **R5**, enabling seamless downstream implementation and rigorous verification.

---

## 2. Requirement R3: SecureScan React Dashboard Specification

### 2.1 Technology Stack & Architectural Principles

The dashboard provides a responsive, dark-themed user interface designed for high-density security telemetry:

| Layer | Technology | Version | Rationale |
| :--- | :--- | :--- | :--- |
| **Framework** | React | `^18.3.1` | Concurrent rendering, stable ecosystem, robust TypeScript integration. |
| **Language** | TypeScript | `^5.5.0` | Strict type safety across all finding models, scan summaries, and API payloads. |
| **Build Tool** | Vite | `^5.4.0` | Sub-second HMR, optimized production tree-shaking, minimal bundle footprint. |
| **Styling** | Tailwind CSS | `^3.4.0` | Utility-first CSS, dark-mode styling, zero CSS runtime overhead. |
| **Visualizations** | Recharts | `^2.12.0` | Declarative SVG charting library with responsive containers and tooltips. |
| **Icons** | Lucide React | `^0.400.0` | Modern, consistent iconography for severity, scanners, and actions. |
| **Code Highlighting**| PrismJS / Custom Tokenizer | `^1.29.0` | Syntax highlighting for 10+ languages with precise line gutter pinning. |

### 2.2 UI State Machine & User Experience Flows

The React application coordinates five primary application states via a top-level state machine:

```
               ┌──────────────┐
               │     IDLE     │ ◄─── (Reset / "New Scan")
               └──────┬───────┘
                      │ File dropped / selected (<= 50MB)
                      ▼
               ┌──────────────┐
               │  UPLOADING   │ (POST /api/scan multipart)
               └──────┬───────┘
                      │ HTTP 200: { job_id, poll_url }
                      ▼
               ┌──────────────┐
        ┌────► │   POLLING    │ ◄─── (Poll every 2.0s: GET /api/jobs/{id})
        │      └──────┬───────┘
(Status == 'running'  │
 or 'queued')         ├─── Status == 'failed' ───► [ ERROR_STATE ]
                      │
                      │ Status == 'done'
                      ▼
               ┌──────────────┐
               │ REPORT_READY │ (GET /api/reports/{id})
               └──────────────┘
                      │
                      ├──► [ Slide-in Code Viewer Drawer ] (on finding click)
                      └──► [ Direct Export Triggers ] (JSON, SARIF, HTML, PDF)
```

### 2.3 Drag-and-Drop Upload Zone

- **DOM Event Handling:** Implements `onDragEnter`, `onDragOver`, `onDragLeave`, and `onDrop` on a hero drop zone, with a hidden `<input type="file" accept=".zip" />` for standard file browsing.
- **Client-Side Guardrails:**
  - File extension must end in `.zip` or have MIME type `application/zip` / `application/x-zip-compressed`.
  - File size must not exceed `52,428,800` bytes (50 MB). If exceeded, the file is rejected immediately before network dispatch, displaying a warning banner: *"File exceeds maximum allowed upload size of 50 MB"*.
- **Visual Feedback:**
  - Active drag state highlights border in `emerald-500` with subtle pulse animation and background tint.
  - Displays selected file name, file size (formatted in MB), and an animated upload progress bar during HTTP transmission.

### 2.4 Real-Time Status Polling Engine

- **Interval:** 2,000 milliseconds (2.0s) polling loop triggered upon receiving `job_id` from `POST /api/scan`.
- **Query Endpoint:** `GET /api/jobs/{job_id}` returning `{ job_id, status, progress, message, created_at, updated_at }`.
- **Lifecycle States Handled:**
  1. `queued`: Displays spinning loader with badge *"In Queue (Position 1)"*.
  2. `running`: Displays progress steps:
     - *"Extracting and validating archive..."*
     - *"Executing security sub-engines (Gitleaks, Trivy, OSV-Scanner, Checkov, OpenGrep)..."*
     - *"Synthesizing unified CWE and OWASP Top 10 findings..."*
     - *"Extracting vulnerable snippet context..."*
     - Live elapsed timer (e.g. `Elapsed: 4.8s`).
  3. `done`: Automatically transitions application state to `REPORT_READY`, executes `GET /api/reports/{job_id}`, and renders the full dashboard.
  4. `failed`: Halts polling, displays an alert dialog showing the verbatim failure reason (e.g., *"Security Violation: Archive contains Zip-Slip path traversal"*, *"Archive exceeds compression ratio limit"*), and provides a *"Try Another Archive"* button.

### 2.5 Data Visualizations & Analytics (Recharts)

The summary view renders three dedicated Recharts visualizations:

1. **Severity Donut Chart (`PieChart`):**
   - Dimensions: Inner radius `60px`, outer radius `90px`, padding angle `4°`.
   - Palette:
     - `CRITICAL`: `#ef4444` (Crimson Red)
     - `HIGH`: `#f97316` (Vibrant Orange)
     - `MEDIUM`: `#eab308` (Amber Yellow)
     - `LOW`: `#3b82f6` (Ocean Blue)
     - `INFO`: `#64748b` (Slate Gray)
   - Centered label displaying the total number of findings.
   - Interactive hover tooltips displaying exact count and percentage of total findings.

2. **Scanner Breakdown Bar Chart (`BarChart`):**
   - Displays finding distribution across all 5 integrated engines:
     - `opengrep`: SAST (Source Code Analysis)
     - `gitleaks`: Secrets & Hardcoded Credentials
     - `trivy`: Dependency CVEs & Configuration
     - `osv-scanner`: Open Source Vulnerability Database SCA
     - `checkov`: Infrastructure-as-Code (IaC) Misconfigurations
   - Horizontal or vertical bars with hover count tooltips and duration metrics.

3. **OWASP Category Breakdown Chart (`BarChart`):**
   - Aggregates findings mapped to OWASP Top 10:2021:
     - `A01:2021 - Broken Access Control`
     - `A02:2021 - Cryptographic Failures`
     - `A03:2021 - Injection`
     - `A04:2021 - Insecure Design`
     - `A05:2021 - Security Misconfiguration`
     - `A06:2021 - Vulnerable and Outdated Components`
     - `A07:2021 - Identification and Authentication Failures`
     - `A08:2021 - Software and Data Integrity Failures`
     - `A09:2021 - Security Logging and Monitoring Failures`
     - `A10:2021 - Server-Side Request Forgery (SSRF)`
   - Clear visual representation of threat surface distribution.

### 2.6 Sortable & Filterable Findings Table

The findings table offers comprehensive exploration capabilities:

- **Multi-Facet Filter Controls:**
  - **Full-Text Search:** Real-time filter matching substring queries against `title`, `ruleId`, `description`, `filePath`, and `cweIds`.
  - **Severity Filter:** Toggle pills for `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
  - **Category Filter:** Dropdown for `ALL`, `SAST`, `SCA`, `SECRET`, `IAC`, `SUPPLY_CHAIN`.
  - **Scanner Filter:** Dropdown for `ALL`, `opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`.
  - **Reachability Filter:** Dropdown for `ALL`, `REACHABLE_CALL_PATH`, `REACHABLE_IMPORT`, `UNREACHABLE`, `UNKNOWN`.
- **Column Sorting:**
  - Clickable headers with directional arrows (`▲` / `▼`).
  - Severity rank sort (CRITICAL > HIGH > MEDIUM > LOW > INFO).
  - Alphabetical sort for Finding Title, Scanner, Category, and File Path.
  - Numeric sort for Line Number.
- **Row Presentation:**
  - Severity badge with high-contrast text.
  - Finding title, rule ID badge, and CWE tags.
  - Target file path with truncated leading directory and line number.
  - Action button: *"Inspect Code"*. Clicking anywhere on the row opens the slide-in code viewer.

### 2.7 Slide-In Code Viewer Drawer

- **Container:** Off-canvas drawer sliding from the right viewport edge (`fixed inset-y-0 right-0 w-full max-w-3xl bg-slate-900 border-l border-slate-700 shadow-2xl z-50 transform transition-transform duration-300 ease-in-out`).
- **Dismissal:** Accessible Close (`✕`) button, backdrop overlay click, and keyboard `Escape` event listener.
- **Header Section:**
  - Finding Title and Rule ID.
  - Severity, Scanner, and OWASP Top 10 badges.
  - Full file path with one-click *"Copy Path"* clipboard button.
  - Line coordinate badge: `Line ${finding.location.startLine}` (or `${startLine}-${endLine}`).
- **Syntax-Highlighted Snippet Viewer:**
  - Context Window: Displays the exact reported vulnerable line pinned in the center, flanked by ±5 lines of surrounding code context.
  - Line Numbers: Gutter with zero-padded or right-aligned line numbers matching the actual source file coordinates.
  - Pinning Effect: The vulnerable line is highlighted with a prominent background (`bg-red-500/20`), a solid left indicator border (`border-l-4 border-red-500`), and a danger badge in the gutter.
  - Syntax Highlighting: Automatic language detection from file extension (`.ts`, `.js`, `.py`, `.json`, `.yml`, `.go`, `.java`, `.tf`, etc.).
- **Remediation & Triage Section:**
  - Actionable fix guidance from the scanner or AI triage.
  - Recommended dependency version upgrade (for SCA CVEs).
  - Proposed unified diff snippet when available.
  - Collapsible raw scanner evidence block.

### 2.8 Multi-Format Export Downloads

The action bar provides four distinct export triggers that initiate instant browser downloads from backend streaming endpoints:

| Format | URL Endpoint | MIME Type | Browser Download Filename |
| :--- | :--- | :--- | :--- |
| **JSON** | `/api/reports/{id}/export?format=json` | `application/json` | `securescan-report-{id}.json` |
| **SARIF** | `/api/reports/{id}/export?format=sarif` | `application/sarif+json` | `securescan-report-{id}.sarif` |
| **HTML** | `/api/reports/{id}/export?format=html` | `text/html; charset=utf-8` | `securescan-report-{id}.html` |
| **PDF** | `/api/reports/{id}/export?format=pdf` | `application/pdf` | `securescan-report-{id}.pdf` |

Each button shows a spinner during download preparation and triggers native browser saving without page reloads.

### 2.9 Frontend Project Structure

```
frontend/
├── index.html
├── package.json
├── postcss.config.js
├── tailwind.config.js
├── tsconfig.json
├── tsconfig.node.json
├── vite.config.ts
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── index.css
│   ├── types/
│   │   ├── scan.ts          # Unified finding, report, and job models
│   │   └── api.ts           # API response envelopes
│   ├── services/
│   │   └── api.ts           # Axios / fetch client with polling & export helpers
│   └── components/
│       ├── Header.tsx        # App header & branding
│       ├── UploadZone.tsx    # Drag-and-drop 50MB file zone
│       ├── PollingStatus.tsx # 2s status polling & progress animation
│       ├── DashboardSummary.tsx # Top KPI cards
│       ├── Charts/
│       │   ├── SeverityDonut.tsx    # Recharts severity donut
│       │   ├── ScannerBarChart.tsx  # Recharts scanner breakdown
│       │   └── OwaspBreakdown.tsx   # Recharts OWASP Top 10 breakdown
│       ├── FindingsTable.tsx        # Filterable & sortable table
│       ├── CodeViewerDrawer.tsx     # Slide-in drawer with line pinning & ±5 context
│       └── ExportButtons.tsx        # 4 export triggers
```

---

## 3. Requirement R4: Docker Compose & Deployment Setup Specification

### 3.1 Container Stack Architecture

The deployment topology consists of two production services orchestrated by `docker-compose.yml`, with an optional Cloudflare Quick Tunnel profile:

```
                           [ Internet / Reviewer ]
                                      │
                                      ▼ (HTTPS TLS)
                           ┌─────────────────────┐
                           │ Cloudflare Quick    │ (profile: tunnel)
                           │ Tunnel (cloudflared)│
                           └──────────┬──────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Docker Compose Network: securescan-net                                  │
│                                                                        │
│  ┌─────────────────────────┐               ┌────────────────────────┐  │
│  │   frontend (Nginx)      │ ──/api/*────► │   backend (FastAPI)    │  │
│  │   Port 80 (Host: 3000)  │ (reverse      │   Port 8000 (Internal) │  │
│  │   Static React SPA      │  proxy)       │   Uvicorn ASGI         │  │
│  │   Healthcheck: /        │               │   Healthcheck: /health │  │
│  │   Limits: 0.5 CPU, 512M │               │   Limits: 1.5 CPU, 3G  │  │
│  └─────────────────────────┘               └───────────┬────────────┘  │
│                                                        │               │
│                                                        ▼               │
│                                            ┌────────────────────────┐  │
│                                            │ Pre-Baked Scanner Tools│  │
│                                            │ /opt/secureship/bin/   │  │
│                                            │  • opengrep (1.31.0)   │  │
│                                            │  • gitleaks (8.24.0)   │  │
│                                            │  • trivy (0.76.0)      │  │
│                                            │  • osv-scanner (1.9.2) │  │
│                                            │  • checkov (3.3.29)    │  │
│                                            │  • secureship CLI      │  │
│                                            └────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Pre-Baking Scanner Binaries (Zero Runtime Downloads)

In strict accordance with acceptance criteria and enterprise security policy, **no external binaries or databases may be downloaded at container runtime**. All scanner binaries are verified against cryptographic SHA-256 digests at Docker build time:

1. **OpenGrep (`1.31.0`):** Pre-compiled standalone binary verified against SHA-256 hash `dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147`.
2. **Gitleaks (`8.24.0`):** Pinned archive verified against upstream manifest `gitleaks_8.24.0_checksums.txt` (`cb49b7de5ee986510fe8666ca0273a6cc15eb82571f2f14832c9e8920751f3a4`).
3. **Trivy (`0.76.0`):** Pinned archive verified against upstream manifest `trivy_0.76.0_checksums.txt` (`e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7`).
4. **OSV-Scanner (`1.9.2`):** Standalone binary verified against `osv-scanner_SHA256SUMS` (`d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b`).
5. **Checkov (`3.3.29`):** Installed in an isolated Python virtualenv (`/opt/checkov-venv`) with wrapper script at `/opt/secureship/bin/checkov`.
6. **SecureShip CLI:** Built from monorepo source packages via `pnpm build`, installed to `/opt/secureship/cli`, and symlinked to `/usr/local/bin/secureship`.
7. **Permissions & Immutability:** All binaries placed in `/opt/secureship/bin/` with ownership `root:root` and mode `0555` (read-only executable), preventing tampering by scanned code.
8. **Container Diagnostics Verification:** The image build executes `secureship doctor` during the build sequence to validate that all 5 sub-engines are detected and operational.

### 3.3 Resource Limits & Isolation Guarantees

In accordance with requirement R4, hard resource quotas are enforced in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '1.5'
      memory: 3G
    reservations:
      cpus: '0.5'
      memory: 1G
```

- **PID 1 Signal Management:** `tini` is configured as the PID 1 supervisor (`ENTRYPOINT ["tini", "--", ...]`), guaranteeing immediate propagation of `SIGTERM` and `SIGINT` signals on `docker stop` or timeout.
- **Non-Root Execution:** Container drops privileges to non-root UID/GID `10001:10001` (`secureship`).
- **Ephemeral Storage:** Temporary extraction folders are created under `/tmp/securescan/` with mode `0700` and guaranteed deletion upon scan completion or failure.

### 3.4 Container Healthchecks & Liveness Probes

- **Backend Healthcheck:**
  - Probe: `python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"`
  - Interval: `10s`
  - Timeout: `5s`
  - Retries: `3`
  - Start Period: `10s`
- **Frontend Healthcheck:**
  - Probe: `wget -qO- http://127.0.0.1:80/ || exit 1`
  - Interval: `10s`
  - Timeout: `3s`
  - Retries: `3`
  - Start Period: `5s`

### 3.5 Cloudflare Quick Tunnel Configuration & Documentation

Cloudflare Quick Tunnel provides instant, zero-configuration public HTTPS tunneling without requiring a Cloudflare account, custom domain, or open firewall ports:

1. **Docker Compose Profile Configuration:**
   An optional `tunnel` service is integrated into `docker-compose.yml` under the `tunnel` profile:
   ```yaml
   tunnel:
     image: cloudflare/cloudflared:latest
     container_name: securescan-tunnel
     restart: unless-stopped
     command: tunnel --no-autoupdate --url http://frontend:80
     depends_on:
       frontend:
         condition: service_healthy
     profiles:
       - tunnel
   ```
2. **One-Command Execution:**
   - To launch stack with tunnel: `docker compose --profile tunnel up -d`
   - To retrieve public URL: `docker compose logs tunnel | grep -o 'https://.*\.trycloudflare\.com'`
3. **Host CLI Alternative:**
   - If running locally: `cloudflared tunnel --url http://localhost:3000`
4. **Security Notice:**
   - Quick tunnel URLs are publicly routable for the duration of the container process. Users should only share generated URLs with authorized assessment evaluators.

### 3.6 Docker Compose & Dockerfile Specifications

#### A. Backend Dockerfile (`Dockerfile.backend`)
```dockerfile
# Stage 1: Build SecureShip CLI
FROM node:22-bookworm-slim AS cli-builder
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@12.14.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.json tools.lock.json ./
COPY packages/ ./packages/
RUN pnpm install --frozen-lockfile && pnpm build
RUN pnpm --filter @secureship/cli deploy --prod /out/cli

# Stage 2: Provision Verified External Scanner Binaries
FROM node:22-bookworm-slim AS tools-provider
WORKDIR /workspace
COPY --from=cli-builder /out/cli /opt/secureship/cli
RUN ln -s /opt/secureship/cli/dist/index.js /usr/local/bin/secureship && \
    mkdir -p /out/bin && \
    secureship install-tools --dir /out/bin --target-platform linux-amd64 --force && \
    chmod 0555 /out/bin/*

# Stage 3: Python Checkov & Backend Dependencies
FROM python:3.11-slim-bookworm AS python-builder
WORKDIR /opt
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir \
      fastapi==0.115.0 \
      uvicorn[standard]==0.31.0 \
      python-multipart==0.0.12 \
      pydantic==2.9.2 \
      jinja2==3.1.4 \
      reportlab==4.2.5 \
      checkov==3.3.29

# Stage 4: Production Runner Image
FROM python:3.11-slim-bookworm AS runner
LABEL org.opencontainers.image.title="SecureScan Backend" \
      org.opencontainers.image.description="FastAPI Scanner Wrapper & Multi-Format Report Engine" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install Node.js 22 runtime for SecureShip CLI, git, tini, and ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    tini \
    ca-certificates && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Setup non-root secureship user
RUN groupadd -g 10001 secureship && \
    useradd -u 10001 -g secureship -m -s /bin/sh secureship

# Setup tool directories
RUN mkdir -p /opt/secureship/bin /opt/secureship/cli /app /tmp/securescan
COPY --from=cli-builder /out/cli /opt/secureship/cli
RUN ln -s /opt/secureship/cli/dist/index.js /usr/local/bin/secureship
COPY --from=tools-provider /out/bin/ /opt/secureship/bin/
COPY --from=python-builder /opt/venv /opt/venv
RUN ln -s /opt/venv/bin/checkov /opt/secureship/bin/checkov

# Set root ownership and immutable permissions
RUN chown -R root:root /opt/secureship/bin && chmod 0555 /opt/secureship/bin && chmod 0555 /opt/secureship/bin/*
RUN chown -R secureship:secureship /app /tmp/securescan /home/secureship

# Environment variables
ENV PATH="/opt/secureship/bin:/opt/venv/bin:/usr/local/bin:${PATH}" \
    SECURESHIP_CONTAINER="1" \
    PYTHONUNBUFFERED="1" \
    PORT="8000" \
    TMPDIR="/tmp/securescan"

COPY backend/ /app/backend/
WORKDIR /app

USER secureship
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### B. Frontend Dockerfile (`frontend/Dockerfile`)
```dockerfile
# Stage 1: Build React Dashboard
FROM node:22-alpine AS builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Nginx Web Server & Reverse Proxy
FROM nginx:alpine AS runner
LABEL org.opencontainers.image.title="SecureScan Frontend" \
      org.opencontainers.image.description="React Security Analytics Dashboard"
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

#### C. Frontend Nginx Configuration (`frontend/nginx.conf`)
```nginx
server {
    listen 80;
    server_name localhost;
    client_max_body_size 50M;

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 60s;
    }
}
```

#### D. Production Docker Compose (`docker-compose.yml`)
```yaml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    image: securescan-backend:latest
    container_name: securescan-backend
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - PORT=8000
      - HOST=0.0.0.0
      - SECURESHIP_CONTAINER=1
      - MAX_UPLOAD_SIZE_MB=50
      - SCAN_TIMEOUT_SECONDS=300
    tmpfs:
      - /tmp/securescan:rw,noexec,nosuid,size=512m
    deploy:
      resources:
        limits:
          cpus: '1.5'
          memory: 3G
        reservations:
          cpus: '0.5'
          memory: 1G
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s

  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
    image: securescan-frontend:latest
    container_name: securescan-frontend
    restart: unless-stopped
    ports:
      - "3000:80"
    depends_on:
      backend:
        condition: service_healthy
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:80/ || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s

  tunnel:
    image: cloudflare/cloudflared:latest
    container_name: securescan-tunnel
    restart: unless-stopped
    command: tunnel --no-autoupdate --url http://frontend:80
    depends_on:
      frontend:
        condition: service_healthy
    profiles:
      - tunnel

networks:
  default:
    name: securescan-network
```

---

## 4. Requirement R5: Project Documentation Suite Specification

Requirement R5 demands a comprehensive, fully populated documentation suite with **no placeholder stubs, TODOs, or empty sections**. Four authoritative documentation files are specified:

### 4.1 `docs/ARCHITECTURE.md` (and root `ARCHITECTURE.md`)
The system architecture manual must provide:
1. **Executive Overview:** Problem statement, placement assessment context, and architectural goals.
2. **Core Invariants & Guarantees:**
   - Invariant Ledger Guarantee: $\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$.
   - Failure Isolation Guarantee: Individual scanner timeouts never abort the overall scan.
   - Zero Runtime Downloads Guarantee: Complete air-gapped readiness.
3. **End-to-End System Diagrams:**
   - Mermaid Component Diagram detailing Frontend, Nginx, FastAPI, Queue, CLI, and File System.
   - Sequence Diagram illustrating the complete lifecycle: Upload -> Validation -> Extraction -> Queue -> Execution -> Normalization -> Context Slicing -> Report Storage -> Polling -> Display -> Multi-Format Export.
4. **Defensive Architecture Deep-Dive:**
   - Safe Extraction Engine: Algorithm details for zip-slip, zip-bomb, and symlink protection.
   - Subprocess Execution Hardening: Zero shell execution, argument arrays, POSIX signal trapping.
5. **Data Model & Finding Normalization:**
   - Canonical `NormalizedFinding` and `ScanReport` schema definitions.
   - CWE mapping and OWASP Top 10:2021 classification rules.

### 4.2 `docs/REFERENCES.md` (and root `REFERENCES.md`)
The authoritative reference compendium must contain formal security standards and peer-reviewed academic literature:
1. **Security Standards Compendium:**
   - **OWASP Top 10:2021:** Detailed descriptions of all 10 categories (A01:2021 to A10:2021) with CWE mapping tables.
   - **MITRE CWE:** Coverage of the 2023/2024 CWE Top 25 Most Dangerous Software Weaknesses.
   - **OASIS SARIF v2.1.0:** Specification breakdown for `sarif-spec-v2.1.0`, rules objects, results, physical locations, and artifact locations.
   - **NIST Guidelines:** NIST SP 800-53 Rev. 5, NIST SP 800-218 (SSDF), and NIST SP 800-115.
   - **SLSA Framework:** Level 1-3 requirements for build hermeticity and provenance.
2. **Academic Citations (10+ Formal Citations):**
   - Must include complete citation metadata (Authors, Year, Title, Journal/Conference, DOI/URL, and architectural relevance):
     1. *Zip Slip Vulnerability: Exploiting Archive Extraction* (Snyk Research, 2018).
     2. Reps, T., Horwitz, S., & Sagiv, M. (1995). *Precise Interprocedural Dataflow Analysis via Graph Reachability*. ACM SIGPLAN POPL.
     3. Landwehr, C. E., et al. (1994). *A Taxonomy of Computer Program Security Flaws*. ACM Computing Surveys.
     4. Chess, B., & McGraw, G. (2004). *Static Analysis for Security*. IEEE Security & Privacy.
     5. Livshits, V. B., & Lam, M. S. (2005). *Finding Security Vulnerabilities in Java Applications with Static Analysis*. USENIX Security.
     6. Ernst, M. D., et al. (2007). *The Daikon system for dynamic detection of likely invariants*. Science of Computer Programming.
     7. Cadar, C., et al. (2008). *KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs*. USENIX OSDI.
     8. Godefroid, P. (2007). *Random Testing for Higher Security: Dynamic Test Generation with DART, SAGE, and Pex*. ACM SIGPLAN.
     9. Wheeler, D. A. (2005). *Countering Trusting Trust through Diverse Double-Compiling*. ACM ACSAC.
     10. Cifuentes, C., & Fraboulet, A. (1997). *Interprocedural Data Flow Decompilation*. Theoretical Aspects of Software Engineering.

### 4.3 `docs/THIRD-PARTY.md` (and root `THIRD-PARTY.md`)
The third-party attribution and governance document must provide:
1. **Software Bill of Materials (SBOM):**
   - Complete tabular inventory of every external component, library, binary, and base image with name, version, role, license, upstream URL, and SHA-256 verification hash.
2. **Scanner Engines Attributions & Upstream Licenses:**
   - Full text or authoritative links for OpenGrep (LGPL-2.1), Gitleaks (MIT), Trivy (Apache-2.0), OSV-Scanner (Apache-2.0), and Checkov (Apache-2.0).
3. **Frontend & Backend Ecosystem Dependencies:**
   - React, Vite, Tailwind CSS, Recharts, Lucide, PrismJS (MIT).
   - FastAPI, Uvicorn, Pydantic, ReportLab, Jinja2 (MIT, BSD-3-Clause, Apache-2.0).
4. **License Compatibility Matrix & Legal Verification:**
   - Formal verification confirming zero license incompatibilities and compliance with LGPL-2.1 dynamic CLI process boundary isolation.

### 4.4 `README.md` (Project Root)
The primary entrypoint document must provide:
1. **Platform Introduction & Badges:** Overview of SecureScan for the Heyram Infrastructure placement assessment.
2. **Feature Highlights:** Drag-and-drop 50MB upload, safe extraction, job queue, multi-engine scanning, dark React UI, Recharts analytics, slide-in code viewer, and 4-format export.
3. **One-Command Quick Start:**
   - Docker Compose: `docker compose up --build`
   - Local access: `http://localhost:3000` (UI) and `http://localhost:8000/docs` (API).
4. **Cloudflare Quick Tunnel Instructions:**
   - Running with profile: `docker compose --profile tunnel up`
   - Accessing public HTTPS URL.
5. **Complete API Reference:** Detailed documentation for `/api/scan`, `/api/jobs/{id}`, `/api/reports/{id}`, `/api/reports/{id}/export`, and `/api/health`.
6. **Synthetic Verification Runbook:** Step-by-step instructions for running test archives (clean, vulnerable, zip-slip exploit, zip-bomb exploit) and verifying exports.
7. **Environment Variables & Configuration Matrix:** Comprehensive table of all configurable settings.

---

## 5. Implementation Roadmap & Downstream Action Plan

To ensure seamless execution across subsequent milestone phases:

1. **Phase 1: React Dashboard Implementation (Worker Milestone):**
   - Initialize `frontend/` with Vite React TypeScript template.
   - Configure Tailwind CSS dark theme and install dependencies (`recharts`, `lucide-react`, `prismjs`).
   - Implement `UploadZone.tsx` with 50MB client-side validation.
   - Implement `PollingStatus.tsx` with 2.0s interval querying `/api/jobs/{id}`.
   - Implement `DashboardSummary.tsx` and Recharts visualizations (`SeverityDonut`, `ScannerBarChart`, `OwaspBreakdown`).
   - Implement `FindingsTable.tsx` with sorting, filtering, and row click selection.
   - Implement `CodeViewerDrawer.tsx` with line pinning and ±5 line context viewer.
   - Implement `ExportButtons.tsx` triggering JSON, SARIF, HTML, and PDF downloads.
   - Verify clean build (`npm run build`).

2. **Phase 2: Docker Compose & Deployment Integration (Worker Milestone):**
   - Write `Dockerfile.backend` with multi-stage pre-baking of `secureship` CLI, `opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`, and FastAPI app.
   - Write `frontend/Dockerfile` and `frontend/nginx.conf` with reverse proxy to `backend:8000`.
   - Write `docker-compose.yml` with 3G RAM / 1.5 CPU limits, healthchecks, and `tunnel` profile.
   - Verify `docker compose up --build` boots both services and healthchecks turn healthy.

3. **Phase 3: Documentation Delivery (Worker Milestone):**
   - Write `ARCHITECTURE.md` (and `docs/ARCHITECTURE.md`).
   - Write `REFERENCES.md` (and `docs/REFERENCES.md`).
   - Write `THIRD-PARTY.md` (and `docs/THIRD-PARTY.md`).
   - Update `README.md` at project root.
   - Ensure zero placeholder stubs, TODOs, or missing sections.
