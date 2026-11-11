# SecureShip Fleet Server Operations & Security Guide

This guide documents the security architecture, credential management, reverse proxy integration, and production deployment practices for SecureShip Fleet (CISO Cockpit & Telemetry Hub).

---

## 1. Authentication Architecture & Security Invariants

SecureShip Fleet enforces authentication by default across all management and ingestion endpoints:

- **Token Secrecy (I1):** Raw tokens are never printed to stdout/stderr, logged to console, serialized in JSON, or inspected via `util.inspect()`. FleetServer retains only the SHA-256 cryptographic digest in an isolated WeakMap.
- **Secure by Default (I2):** Both entry points (`secureship fleet start` and standalone `secureship-fleet`) enforce authentication. If no token is provided, a cryptographically secure 256-bit token is auto-generated and stored in a permissions-restricted file (`0600`), and only its path is displayed.
- **Default-Deny Gate (I3):** Every route requires valid authentication except explicit public endpoints (`GET /` and `GET /dashboard`, which serve HTML only and zero telemetry data), OPTIONS preflight requests, and documented legacy ingest requests.
- **No Pre-Auth Oracles (I4):** Unauthenticated requests never reach schema validation (Zod) and receive identical 401 Unauthorized responses before parsing payload content.
- **Transit Protection (I6):** Client commands refuse to send bearer credentials over unencrypted HTTP to non-loopback remote endpoints unless explicitly overridden.

---

## 2. Generating & Managing Fleet Tokens

Tokens must contain 24 to 512 printable ASCII characters with no spaces (`/^[\x21-\x7E]{24,512}$/`).

### 2.1 Generating a Cryptographically Secure Token

Generate a 256-bit base64url token (43 characters) using Node.js:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

### 2.2 Writing a Token File Without Byte Order Marks (BOM)

#### PowerShell (Windows):

PowerShell 5's default `>` operator writes UTF-16 with a BOM. Use .NET's `UTF8Encoding($false)` to write clean UTF-8:

```powershell
$token = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).Replace("+","-").Replace("/","_").TrimEnd("=")
[System.IO.Directory]::CreateDirectory("$HOME\.secureship") | Out-Null
[System.IO.File]::WriteAllText("$HOME\.secureship\fleet-token", "$token`n", [System.Text.UTF8Encoding]::new($false))
```

#### POSIX Shell (Linux / macOS / Alpine):

```bash
mkdir -p ~/.secureship && chmod 0700 ~/.secureship
token=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
printf '%s\n' "$token" > ~/.secureship/fleet-token
chmod 0600 ~/.secureship/fleet-token
```

---

## 3. Container & Kubernetes Secret Deployments

FleetServer natively supports Docker secrets and Kubernetes Secret volume mounts, resolving symlinked paths and supporting read-only secret permissions (`0444` / `0400`).

### 3.1 Kubernetes Deployment Example

Mount a Secret containing `fleet-token` into `/run/secrets/fleet`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureship-fleet
  labels:
    app: secureship-fleet
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secureship-fleet
  template:
    metadata:
      labels:
        app: secureship-fleet
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: fleet
          image: secureship/fleet:latest
          env:
            - name: FLEET_PORT
              value: '4000'
            - name: FLEET_HOST
              value: '0.0.0.0'
            - name: FLEET_DATA
              value: '/data/fleet-db.json'
            - name: FLEET_TOKEN_FILE
              value: '/run/secrets/fleet/token'
            - name: FLEET_ALLOWED_HOSTS
              value: 'ciso.internal.corp,secureship-fleet.secureship.svc.cluster.local'
            - name: FLEET_ALLOWED_ORIGINS
              value: 'https://ciso.internal.corp'
          ports:
            - containerPort: 4000
          readinessProbe:
            httpGet:
              path: /
              port: 4000
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /
              port: 4000
            initialDelaySeconds: 10
            periodSeconds: 15
          volumeMounts:
            - name: fleet-secret
              mountPath: /run/secrets/fleet
              readOnly: true
            - name: fleet-data
              mountPath: /data
      volumes:
        - name: fleet-secret
          secret:
            secretName: secureship-fleet-token
            defaultMode: 0440
        - name: fleet-data
          persistentVolumeClaim:
            claimName: secureship-fleet-pvc
```

### 3.2 Docker Compose Example

```yaml
services:
  fleet:
    image: secureship/fleet:latest
    environment:
      FLEET_HOST: '0.0.0.0'
      FLEET_PORT: '4000'
      FLEET_TOKEN_FILE: '/run/secrets/fleet_token'
      FLEET_ALLOWED_HOSTS: 'ciso.internal.corp'
      FLEET_ALLOWED_ORIGINS: 'https://ciso.internal.corp'
    ports:
      - '4000:4000'
    secrets:
      - fleet_token
    volumes:
      - fleet_data:/data

secrets:
  fleet_token:
    file: ./fleet-token.txt

volumes:
  fleet_data:
```

---

## 4. Reverse Proxy & TLS Configuration

SecureShip Fleet speaks plain HTTP only and is designed to run behind a dedicated TLS termination reverse proxy (Nginx, Envoy, Traefik, AWS ALB, Cloudflare).

### 4.1 Host and Origin Whitelisting

When deploying behind a proxy or ingress:

1. Set `FLEET_HOST=0.0.0.0` to listen on container network interfaces.
2. Configure `FLEET_ALLOWED_HOSTS` with comma-separated hostnames/IPs that clients use to access the proxy (e.g. `ciso.internal.corp`).
3. Configure `FLEET_ALLOWED_ORIGINS` with the trusted browser origin (e.g. `https://ciso.internal.corp`). Wildcards (`*`) are prohibited.

### 4.2 Nginx Reverse Proxy Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name ciso.internal.corp;

    ssl_certificate     /etc/ssl/certs/ciso.internal.corp.crt;
    ssl_certificate_key /etc/ssl/private/ciso.internal.corp.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 12M;

    location / {
        proxy_pass http://127.0.0.1:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 5. Client CLI Configuration & Safety Policies

### 5.1 Cleartext Remote HTTP Prohibition

Client CLI subcommands (`secureship fleet status`, `secureship fleet export-cra`, and `FleetClient`) refuse to send tokens to remote non-loopback endpoints over cleartext `http://`.

To allow insecure HTTP in air-gapped test environments only, set:

```bash
export SECURESHIP_ALLOW_INSECURE_FLEET_HTTP=1
```

When enabled, the CLI emits a warning to stderr on every invocation and never prints credentials.

### 5.2 Flag Deprecation: `--token`

The `--token <token>` command-line flag is **DEPRECATED**. Tokens passed via command-line arguments are visible in process listings (`ps -ef`) and saved in shell histories.

Recommended alternatives:

1. `FLEET_TOKEN_FILE`: Point to a permissions-restricted file (mode 0600 or Docker secret).
2. `FLEET_TOKEN`: Provide token via ambient process environment.
3. `--token-file <path>`: Pass file path explicitly.

---

## 6. Legacy Ingest Body Token Deprecation

Historic SecureShip clients sent `fleetToken` inside the JSON payload of `POST /api/ingest`.

- Legacy body-authenticated requests are subject to an immediate 2 MiB payload cap (`legacyBodyTokenMaxBytes`).
- Authenticated requests sending `Authorization: Bearer <token>` or `x-fleet-token` support the full 10 MiB ingest payload limit (`maxBodyBytes`).
- Operators can disable the legacy body token path entirely by setting `FLEET_ALLOW_LEGACY_BODY_TOKEN=0` or `false`.

---

## 7. Breaking Changes & Upgrade Notes

1. **`HOST` Environment Variable Ignored:** The generic `HOST` variable is ignored by the Fleet server to prevent unintentional host exposure. Use `FLEET_HOST` instead.
2. **Port Precedence Updated:** Port resolution order is now: explicit CLI argument > `FLEET_PORT` > `PORT` > `4000`.
3. **Empty `authToken` Rejected:** Passing an empty string or whitespace-only token to `new FleetServer({ authToken: "" })` now throws an Error.
4. **Mandatory Authentication:** `secureship fleet start` and standalone `secureship-fleet` require authentication by default. When no token is configured by the operator, a random token is generated into a 0600 file (`~/.secureship/fleet-token`) and its path is printed.
5. **Default-Deny API Gating:** Non-public routes outside of `/api/` are no longer unauthenticated by default.
6. **Strict Policy Validation:** `POST /api/policy` validates all inputs and rejects unknown or invalid keys with HTTP 400.
7. **Restricted Database Modes:** Database files and backup files are created with mode `0600` on POSIX hosts (owner read/write only).

---

## 8. Persistence, Storage Architecture & Crash Consistency (Gate 13)

FleetStore provides crash-consistent persistence with disaster recovery against power outages, process kills, and disk faults:

- **Atomic Protocols:** Writes to temporary files (`${target}.tmp.<pid>.<time>.<rand>`) with `fsync` and read-back verification before atomic rename.
- **Resilient Disaster Recovery:** At startup, FleetStore validates primary and backup files. A corrupted primary is automatically quarantined and healed from `.bak`.
- **Evidence Preservation:** Corrupt files are never wiped; they are quarantined to `${target}.corrupt-<UTC yyyymmddThhmmssZ>-<4 hex>` (mode 0600).
- **Docker & Volume Deployments:** Operators should mount directory volumes (`-v /var/data:/data`) rather than single-file bind mounts. Single-file bind mounts fall back to non-atomic mode (`non-atomic-fallback`).
- **Single-Writer Constraint:** Each database file must be managed by exactly one writer process. Multi-instance setups should deploy a dedicated instance per volume or inspect `getPersistenceStatus()`.
