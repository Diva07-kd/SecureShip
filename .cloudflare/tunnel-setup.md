# Cloudflare Quick Tunnel Deployment Runbook (Option A)

This guide provides instructions for deploying **SecureScan** publicly using **Cloudflare Quick Tunnels (Option A)** for the Heyram Infrastructure placement assessment.

---

## 1. Overview of Option A (Quick Tunnel)

Cloudflare Quick Tunnels provide an ephemeral, authenticated HTTPS ingress point with zero setup:
- **No Cloudflare account required**
- **No DNS configuration or domain purchase needed**
- **Instant end-to-end TLS encryption** (`https://*.trycloudflare.com`)
- **Direct reverse proxying** to the frontend container (Port 3000/80) and API (Port 8000)

```
[ Public Web User ]
        │ HTTPS (Port 443)
        ▼
[ Cloudflare Global Edge Network ]
        │ Encrypted Quick Tunnel Connection
        ▼
[ cloudflared container / host CLI ]
        │ HTTP (Port 80)
        ▼
[ securescan-frontend (Nginx) ]
   ├── Static React Dashboard (Port 80)
   └── Reverse Proxy (/api/*) ──► [ securescan-backend (FastAPI :8000) ]
```

---

## 2. Launching via Docker Compose Profile

The provided `docker-compose.yml` includes an integrated `tunnel` service configured under the `tunnel` profile.

### Step 1: Start the Full Stack with Quick Tunnel
Run the following command in the repository root:
```bash
docker compose --profile tunnel up --build -d
```

### Step 2: Retrieve the Public URL
Fetch the generated `trycloudflare.com` URL directly from the tunnel container logs:
```bash
docker compose logs tunnel | grep -o 'https://[a-zA-Z0-9-]\+\.trycloudflare\.com'
```

*Example output:*
```
https://heyram-assessment-securescan.trycloudflare.com
```

### Step 3: Verify Public Endpoint
Open the generated URL in any web browser. You should immediately see the dark-themed SecureScan dashboard with all five pre-baked security engines marked ready.

---

## 3. Alternative: Launching via Local `cloudflared` Binary

If you prefer running `cloudflared` directly on your host machine without Docker:

### Step 1: Install `cloudflared`
- **macOS (Homebrew):** `brew install cloudflare/cloudflare/cloudflared`
- **Linux (Debian/Ubuntu):**
  ```bash
  curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  sudo dpkg -i cloudflared.deb
  ```
- **Windows (Winget / Chocolatey):**
  ```powershell
  winget install --id Cloudflare.cloudflared
  ```

### Step 2: Start the SecureScan Local Stack
```bash
docker compose up -d
# Or for local development:
# Backend: uvicorn app.main:app --port 8000
# Frontend: npm run dev -- --port 3000
```

### Step 3: Expose Local Port 3000
```bash
cloudflared tunnel --url http://localhost:3000
```

Look for the log output:
```
+--------------------------------------------------------------------------------------------+
|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
|  https://quick-sample-tunnel-name.trycloudflare.com                                        |
+--------------------------------------------------------------------------------------------+
```

---

## 4. End-to-End Verification Checklist

When accessing the public tunnel URL:
1. **Health Check:** `curl https://<tunnel-url>/api/health` returns `HTTP 200` with `status: healthy`.
2. **Dashboard UI:** React SPA renders dark theme (`#090d16`), stat cards, and 50MB drag-and-drop upload zone.
3. **Archive Scan:** Upload a test `.zip` file — status poller ticks every 2s, transitions through `extracting` -> `scanning` -> `enriching` -> `completed`.
4. **Reports & Exports:**
   - Severity donut chart and OWASP Top 10 breakdown populate correctly.
   - Click "Inspect" to open the slide-in Code Viewer Drawer pinning the vulnerable line.
   - Click "JSON", "SARIF 2.1.0", "Single-File HTML", and "Executive PDF" to verify all 4 download formats.

---

## 5. Security & Resource Ceilings in Tunnel Mode

| Component | Invariant / Limit | Defense Mechanism |
|-----------|-------------------|-------------------|
| Upload Size | 50 MB (52,428,800 bytes) | Client-side guard + Nginx `client_max_body_size` + FastAPI streaming check |
| Memory Ceiling | 3,072 MB (3 GB) | Docker cgroup hard memory limit prevents host exhaustion |
| CPU Ceiling | 1.5 Cores | Cgroup CPU quota prevents denial of service |
| Job Concurrency | 1 Concurrent Scan | `asyncio.Queue` single-worker ensures predictable resource usage |
| Scan Timeout | 300 Seconds | Hard subprocess timeout kills hung scanners |
