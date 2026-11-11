# SecureShip Container Operations & Hardening Runbook

This runbook documents production deployment, security hardening, and operational usage for the official SecureShip CLI container image (`secureship/cli`).

---

## 1. Overview & Architectural Guarantees

The SecureShip CLI container is a self-contained, multi-architecture (`linux/amd64` and `linux/arm64`) OCI-compliant image built on Debian slim (`node:22-bookworm-slim`).

### Core Guarantees:

- **Zero Runtime Downloads:** All 5 external scanner engines (`opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`) and 9 Tree-sitter WebAssembly language grammars are pre-compiled, verified against cryptographic SHA-256 pins in `tools.lock.json`, and pre-installed in `/opt/secureship/bin`.
- **Immutable System Tools:** Scanner binaries reside in `/opt/secureship/bin` with root ownership (`root:root`) and read-only/executable permissions (`0555`), preventing tampering or planted-binary attacks from scanned repositories.
- **Fixed Non-Root UID/GID 10001:** By default, the container drops privileges to user `secureship` (UID `10001`, GID `10001`). It fully supports arbitrary host UID mappings (`--user $(id -u):$(id -g)`).
- **PID 1 Signal Propagation:** The image uses `tini` as its entrypoint supervisor (`ENTRYPOINT ["tini", "--", "secureship"]`), ensuring immediate and clean SIGTERM/SIGINT propagation when stopping background containers (`docker stop`).
- **Air-Gap Compatible:** The image operates with full fidelity under `--network none`.

---

## 2. Production Run Commands

### 2.1 System Diagnostics & Environment Verification

```bash
docker run --rm secureship/cli:latest doctor
```

### 2.2 Standard Workspace Scan (Read-Only Mount)

Scan the current repository by mounting it read-only (`:ro`) into `/workspace`:

```bash
docker run --rm \
  -v "$(pwd):/workspace:ro" \
  secureship/cli:latest scan /workspace
```

### 2.3 Separate Output Mount (SARIF & JSON Reports)

When saving reports on disk while preserving a read-only source mount:

```bash
mkdir -p ./reports
docker run --rm \
  -v "$(pwd):/workspace:ro" \
  -v "$(pwd)/reports:/reports:rw" \
  secureship/cli:latest scan /workspace \
    --output /reports/report.json \
    --sarif /reports/report.sarif
```

### 2.4 Hardened Non-Root & Read-Only Root Filesystem Execution

Run with maximum container isolation:

- Read-only root filesystem (`--read-only`)
- Ephemeral `/tmp` mount (`--tmpfs /tmp`)
- Arbitrary host user/group (`--user $(id -u):$(id -g)`)
- Dropped Linux capabilities (`--cap-drop ALL`)
- No new privileges (`--security-opt no-new-privileges`)

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid \
  --tmpfs /home/secureship/.secureship:rw \
  -v "$(pwd):/workspace:ro" \
  secureship/cli:latest scan /workspace
```

### 2.5 Strict Air-Gapped Execution (`--network none`)

Execute scanning with all outbound container networking completely severed at the Linux network namespace level:

```bash
docker run --rm \
  --network none \
  -v "$(pwd):/workspace:ro" \
  secureship/cli:latest scan /workspace --offline
```

### 2.6 Git Incremental Diff Scan (`--diff` / `--staged`)

When scanning a git repository mounted from another host UID, SecureShip automatically detects the container environment (`SECURESHIP_CONTAINER=1`) and passes `-c safe.directory=/workspace` to Git for the target directory only, preventing `detected dubious ownership` failures:

```bash
docker run --rm \
  -v "$(pwd):/workspace:ro" \
  secureship/cli:latest scan /workspace --diff HEAD~1
```

### 2.7 Apple Silicon & ARM64 Support

The image is natively built for both `linux/amd64` and `linux/arm64`. On Apple Silicon (M1/M2/M3/M4) or AWS Graviton, Docker automatically pulls and executes the native `arm64` image with zero emulation overhead:

```bash
docker run --rm --platform linux/arm64 secureship/cli:latest doctor
```

### 2.8 Podman (Rootless Execution)

SecureShip executes cleanly under rootless Podman without requiring root privileges or group adjustments:

```bash
podman run --rm \
  --security-opt no-new-privileges \
  -v "$(pwd):/workspace:ro" \
  secureship/cli:latest scan /workspace
```

---

## 3. Volume Permissions & Storage Layout

| Directory Path                    | Container Owner | Default Permissions   | Purpose                                                                                |
| :-------------------------------- | :-------------- | :-------------------- | :------------------------------------------------------------------------------------- |
| `/opt/secureship/bin`             | `root:root`     | `0555` (Read/Execute) | Immutable scanner binaries (`opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`) |
| `/opt/secureship/cli`             | `root:root`     | `0555` (Read/Execute) | Standalone bundled CLI runtime and WASM grammars                                       |
| `/home/secureship/.secureship`    | `10001:10001`   | `0700` (Read/Write)   | Default user configuration, license tokens, and AI usage ledgers                       |
| `/home/secureship/.secureship/db` | `10001:10001`   | `0700` (Read/Write)   | Offline vulnerability database generations (`CURRENT` pointer)                         |
| `/licenses`                       | `root:root`     | `0444` (Read-Only)    | Upstream third-party licenses and notices                                              |

---

## 4. OCI Image Tags & Size Budget

- **`secureship/cli:latest`**: Latest production release built from `main`.
- **`secureship/cli:v1.0.0-beta.1`**: SemVer tagged immutable release.
- **`secureship/cli:sha-<commit>`**: Commit-pinned release digests.

**Image Size Budget:**
The self-contained image includes the Node 22 runtime, Python 3.11 minimal runtime for Checkov, Git, Tini, and all 5 pre-compiled security engines with 9 WASM grammars. Target compressed image size is under 550 MB, and uncompressed rootfs is under 1.2 GB.
