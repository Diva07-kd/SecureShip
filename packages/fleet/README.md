# @secureship/fleet 🛡️

Centralized CISO Cockpit, Telemetry Hub, and Corporate Policy Engine for SecureShip.

---

## Persistence and Recovery

FleetStore implements a crash-consistent, atomic persistence protocol (Wave 1 Gate 13 / CWE-362, CWE-390 remediation) designed to ensure that uninterrupted or interrupted write operations never corrupt telemetry or cause data wipes on restart.

### 1. File Structure and File Roles

Under the configured database directory (default: `.secureship/fleet-db.json` or `FLEET_DATA`):

- **Primary Database File (`${target}`, e.g., `fleet-db.json`)**:
  Contains the active format v1 snapshot formatted as pretty-printed JSON with 2-space indentation. File permissions on POSIX systems are strictly restricted to `0600` (read/write by owner only; non-readable by group or others).
- **Backup File (`${target}.bak`)**:
  The last known-good database state. Rotated atomically only after a write to temp has succeeded, fsynced, and passed cryptographic read-back verification. Never overwritten from an unverified or corrupt primary.
- **Quarantine Files (`${target}.corrupt-<UTC yyyymmddThhmmssZ>-<4 hex>`)**:
  When corruption is encountered during load or external modification inspection, the invalid file is renamed or copied to an immutable quarantine file with mode `0600`. Up to `quarantineKeep` (default: 5) quarantine files are retained for security auditing and forensic recovery; older quarantines are pruned automatically.
- **Temporary Persistence Files (`${target}.tmp.<pid>.<timestamp>.<rand>`)**:
  Staging files created during atomic writes with mode `0600` and exclusive creation flag `wx`. Automatically pruned on startup if older than 10 minutes.
- **Backup Staging Files (`${target}.bak.tmp.<rand>`)**:
  Temporary staging files used during atomic backup rotation.

### 2. Atomic Write Protocol

Every state modification (`ingest`, `updatePolicy`, `clear`) executes the following synchronous 9-step atomic persistence pipeline:

1. **Path Resolution**: Resolves the real filesystem path via `realpathSync` so that symlinked primary files (e.g., `/data/fleet-db.json` pointing to a volume mount) update their target directly rather than breaking the symlink. Ensures parent directory exists with mode `0700`.
2. **Serialization & Integrity Hashing**: Serializes state to Format v1 `{ formatVersion: 1, repos, policy, updatedAt, integrity: { algorithm: 'sha256', digest } }` into a single in-memory buffer, and calculates the SHA-256 digest of the raw buffer.
3. **Exclusive Temp File Allocation**: Opens `${target}.tmp.<pid>.<time>.<rand>` in the **same filesystem directory** using mode `0600` and flag `'wx'` (O_CREAT | O_EXCL) to prevent symlink attacks and PID collisions. Flushes all bytes via a write loop and executes `fsyncSync`.
4. **Read-Back Verification**: Reads the temporary file back from disk and verifies its SHA-256 digest against the in-memory buffer. A mismatch aborts immediately with `PERSIST_VERIFY_FAILED` and removes the temp file, leaving the primary file untouched.
5. **Atomic Backup Rotation**: If the primary file exists, checks whether its size and mtime match `lastWritten`. If modified externally, validates its structure before rotating. If valid, rotates via `copyFileSync(primary -> bak.tmp)` + `fsync` + `rename(bak.tmp -> bak)`. If primary is corrupt, copies primary to a quarantine file and skips rotation (preserving the existing good backup).
6. **Atomic Rename**: Atomically renames `${target}.tmp.*` over the target database file. On Windows (`win32`), transient file locks held by antivirus scanners or search indexers are retried up to 6 times with exponential backoff (10, 20, 40, 80, 160, 320 ms).
7. **Single-File Bind Mount Fallback**: If rename fails with `EBUSY` or `EXDEV` (Docker single-file bind mounts), executes a verified in-place fallback write with immediate restore from backup on verification failure.
8. **Directory Fsync**: On POSIX filesystems, opens the parent directory in read mode and executes `fsync` to ensure the directory entry metadata is committed to non-volatile storage.
9. **POSIX Mode Enforcement**: Enforces mode `0600` on the target database file.

### 3. Load & Disaster Recovery Algorithm

At initialization, `FleetStore` resolves the database path and evaluates Candidate A (Primary) and Candidate B (`.bak`):

- **Primary Valid**: Loaded directly. Outcome: `source: 'primary'`.
- **Primary Corrupt, Backup Valid**: Automatically recovers from backup. Logs `FLEET_STORE_RECOVERED_FROM_BACKUP` (warning) and `FLEET_STORE_PRIMARY_CORRUPT`, quarantines Candidate A, loads Candidate B, and immediately heals the primary file by persisting the recovered state. Outcome: `source: 'backup'`, `recovered: true`.
- **Both Absent**: Fresh start. Outcome: `source: 'none'`, zero warnings.
- **Both Present and Corrupt (or One Corrupt and Backup Absent)**:
  - Default mode (`strictLoad: false`): Logs `FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION` (error), quarantines all corrupt files byte-identically, starts with an empty repository map and corporate default policy. **Nothing is written to disk at load time.**
  - Strict mode (`strictLoad: true`): Throws `FleetStoreCorruptionError` listing the offending file paths and failure codes before any file on disk is modified.

### 4. Single-Writer Requirement & External Modifications

FleetStore requires a single writer process per database file. Running multiple concurrent `FleetServer` or `secureship fleet start` processes pointing to the same storage path without distributed locking causes lost updates.

When an external process modifies the database file between persist operations, FleetStore detects the change via stat comparison (`size` and `mtimeMs`), logs warning `FLEET_STORE_EXTERNAL_MODIFICATION`, and safely rotates the externally written file into backup before overwriting.

### 5. Deployment Guidelines: Docker, Kubernetes & Volumes

#### Mount a Directory, Not a Single File

When deploying Fleet in containers, mount a directory volume rather than a single-file bind mount:

- **Recommended**:
  ```bash
  docker run -v /var/lib/secureship/data:/data secureship/fleet:latest
  ```
- **Discouraged (Single-File Bind Mount)**:
  ```bash
  docker run -v /var/lib/secureship/fleet-db.json:/data/fleet-db.json secureship/fleet:latest
  ```
  In Docker and Kubernetes, single-file bind mounts cannot be replaced atomically via `renameSync` because the Linux kernel returns `EBUSY`. While FleetStore gracefully falls back to non-atomic in-place writing with backup protection (`mode: 'non-atomic-fallback'`), directory mounts provide complete POSIX atomicity.

#### Alpine Non-Root & Read-Only Root Filesystems

In locked-down containers (`read-only` rootfs, non-root user `10001:10001`), ensure the parent data directory is mounted as a writable volume or tmpfs:

```yaml
securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
volumeMounts:
  - name: fleet-data
    mountPath: /data
```

#### Windows Antivirus Exclusion

On Windows hosts, enterprise endpoint protection or search indexers can hold open file handles with `FileShare.None`. While FleetStore retries with backoff, operators should exclude `.secureship/` data directories from real-time file scanners for optimal latency.

### 6. Permissions and Breaking Changes

- **Restricted File Mode (0600 / 0700)**: Database files are created with `0600` and newly created directories with `0700` on POSIX hosts. Any group or world readers will receive permission denied errors.
- **Format Version 1**: Database snapshots now include `"formatVersion": 1` and cryptographic `"integrity"`. Downgrading to older software versions or loading files with format versions greater than 1 throws `FleetStoreUnsupportedVersionError` fail-closed to prevent accidental state corruption.
- **Strict Policy Validation**: `updatePolicy` rejects unknown keys and validates known field types, throwing `FleetStoreValidationError` (HTTP 400 on `POST /api/policy`).

### 7. Observability & Health Introspection

Operators and health checkers can inspect the runtime persistence health using:

- `store.getPersistenceStatus()`:
  - `healthy: boolean`: Indicates whether disk persistence is operating normally (`true` when zero consecutive failures).
  - `mode: 'memory-only' | 'atomic' | 'non-atomic-fallback'`: Current storage engine mode.
  - `consecutiveFailures: number`: Count of sequential persist errors.
  - `lastSuccessAt?: string`: ISO-8601 timestamp of last successful persist.
  - `lastError?: { code: string; message: string; at: string }`: Sanitized error code and timestamp (zero customer payload content or secrets).
- `store.getLoadReport()`:
  - `source: 'none' | 'primary' | 'backup' | 'empty-after-corruption'`: Initial state origin.
  - `recovered: boolean`: Whether state was recovered from a backup file.
  - `quarantined: string[]`: Paths to quarantined evidence files.
  - `warnings: string[]`: Stable warning codes emitted during startup.
