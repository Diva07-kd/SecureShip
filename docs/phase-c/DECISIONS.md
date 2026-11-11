# SecureShip Phase C — Architectural & Security Decisions (DECISIONS.md)

### Decision 1: Single Source of Truth (SSoT) for Tool Pins

- **Problem**: Versions, asset URLs, and SHA-256 hashes were scattered across `install-tools.ts`, `supported-versions.json`, Dockerfile snippets, and documentation. Furthermore, several hashes in `install-tools.ts` were fabricated or pointed to 404 releases (Defect D2).
- **Decision**: Create a single machine-readable, schema-validated file `packages/scanner-adapters/src/tools.lock.json` and a typed loader (`tools-lock.ts`) with a Zod schema. `install-tools`, Docker build scripts, `doctor`, and CI verification scripts read from this single source of truth.
- **Tools Included**:
  - `opengrep`: v1.31.0 (with libc dimension: musl vs manylinux/glibc for x64 and arm64, darwin-x64, darwin-arm64, win32-x64)
  - `gitleaks`: v8.24.0 (linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64)
  - `osv-scanner`: v1.9.2 (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, win32-amd64)
  - `trivy`: v0.76.0 (Linux-64bit, Linux-ARM64, macOS-64bit, macOS-ARM64, windows-64bit)
  - `checkov`: v3.3.29 (Python virtual environment in container; manual/virtualenv on host)

### Decision 2: Elimination of Trust Downgrade (Defect D1)

- **Problem**: In `InstallToolsCommand`, fetching a remote manifest allowed `effectiveSha256` to override the bundled pin. If upstream releases were re-tagged or compromised, SecureShip would trust the attacker's manifest.
- **Decision**: The bundled pin in `tools.lock.json` is strictly authoritative. If an upstream manifest is fetched, it serves as a cross-verification check only. Any discrepancy between the remote manifest and the bundled pin immediately aborts execution with a hard failure.

### Decision 3: Centralized Path Resolution & Planted-Binary Defense (Defect D10)

- **Problem**: Binary resolution was hardcoded to `~/.secureship/bin` and system `PATH`. Immutable system directories (`/opt/secureship/bin`) and `SECURESHIP_BIN_DIR` / `SECURESHIP_HOME` environment variables were ignored.
- **Decision**: Implement central path resolvers in `packages/scanner-adapters/src/paths.ts`:
  - `resolveSecureshipHome()`: reads `SECURESHIP_HOME` env var, falling back to `path.join(os.homedir(), '.secureship')`.
  - `resolveToolDirs(options)`: priority order:
    1. Explicit flag/option `dir`
    2. Environment variable `SECURESHIP_BIN_DIR`
    3. Immutable system tool directory `/opt/secureship/bin` (if exists)
    4. User tool directory `<home>/bin`
    5. System `PATH`
  - `resolveDbDir()`: reads `SECURESHIP_DB_DIR`, falling back to `<home>/db`.
  - All candidates and resolved executables are subject to `assertNotInsideTarget(candidate, targetDir)`.

### Decision 4: Safe In-Process Archive Extraction (Defect D9)

- **Problem**: `install-tools` shelled out to `tar`, `unzip`, or `powershell Expand-Archive`, making it fail in minimal environments (such as Alpine without `unzip`) and vulnerable to symlink traversal via weak string prefix checks.
- **Decision**: Implement safe, pure Node in-process archive extractors for `tar.gz` and `zip` without spawning child processes.
  - Reject absolute paths, `..` directory traversals, symlinks, hardlinks, and device files.
  - Enforce extraction size limits and entry count limits.
  - Extract only the exact target binary needed.

### Decision 5: Docker Container Hardening & Multi-Stage Architecture (Defect D5, D6, D7, D11)

- **Base OS**: `node:22-bookworm-slim` for builder, and `debian:bookworm-slim` for runner. Debian slim provides standard glibc support required by all 5 security engines across both amd64 and arm64 architectures.
- **User & Permissions**: Fixed non-root UID/GID `10001` (`secureship`).
- **Binary Directory**: `/opt/secureship/bin` owned by `root:root` with read-and-execute permissions `0555` (immutable).
- **Process Supervision**: `ENTRYPOINT ["tini", "--", "secureship"]` ensures clean signal propagation (SIGTERM/SIGINT) preventing hung containers during `docker stop`.
- **Git Container Safe Directory**: When `SECURESHIP_CONTAINER=1` or container markers are detected, Git commands on the scan target pass `-c safe.directory=<resolvedTarget>` to prevent dubious ownership errors on bind-mounted directories.
