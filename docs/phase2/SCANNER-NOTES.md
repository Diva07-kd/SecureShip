# SecureShip Phase 2: Scanner Integration & Verification Notes

## 1. Scanner Status & Verification Matrix

In accordance with Phase 2 specifications (R0, R1), all 5 scanner adapters have been verified live against real binaries installed on the host system PATH, with golden fixtures captured and normalized parser assertions in `packages/scanner-adapters/test/fixtures/real/` and `packages/scanner-adapters/test/live-contract.test.ts`.

| Scanner         |   Category   | Installed & Tested Version |      Live Verification Status      |
| :-------------- | :----------: | :------------------------: | :--------------------------------: |
| **Gitleaks**    |   `SECRET`   |          `8.30.1`          | **Verified Live (5/5 tests pass)** |
| **Opengrep**    |    `SAST`    |          `1.31.0`          | **Verified Live (5/5 tests pass)** |
| **Trivy**       | `SCA`, `IAC` |          `0.76.0`          | **Verified Live (5/5 tests pass)** |
| **OSV-Scanner** |    `SCA`     |          `2.7.0`           | **Verified Live (5/5 tests pass)** |
| **Checkov**     |    `IAC`     |          `3.3.29`          | **Verified Live (5/5 tests pass)** |

---

## 2. CLI Flag Verification Table (`flag | verified-live (version) or docs-only`)

Below is the exhaustive audit of all CLI arguments used by SecureShip adapters, categorized as **verified-live** (tested directly against the installed binary) or **docs-only** (documented fallback):

### 2.1 Gitleaks (`gitleaks.adapter.ts`)

| Flag / Subcommand       | Status                     | Notes / Version Details                                                         |
| :---------------------- | :------------------------- | :------------------------------------------------------------------------------ |
| `dir`                   | **verified-live (8.30.1)** | Used for filesystem scanning of directories without requiring a git repository. |
| `--report-format sarif` | **verified-live (8.30.1)** | Generates standard SARIF 2.1.0 output.                                          |
| `--report-path <file>`  | **verified-live (8.30.1)** | Directs SARIF output to the temporary isolation file.                           |
| `--redact`              | **verified-live (8.30.1)** | Obfuscates detected secrets in SARIF snippets (scanner-level redaction).        |
| `--no-banner`           | **verified-live (8.30.1)** | Suppresses ascii art banner for clean execution logging.                        |
| `--exit-code 0`         | **verified-live (8.30.1)** | Standardizes exit code on finding discovery; non-zero reserved for errors.      |
| `detect`                | **docs-only (>=8.0.0)**    | Historical subcommand alternative for git repo history scans.                   |

### 2.2 Opengrep / Semgrep (`opengrep.adapter.ts`)

| Flag / Subcommand             | Status                     | Notes / Version Details                                                   |
| :---------------------------- | :------------------------- | :------------------------------------------------------------------------ |
| `scan`                        | **verified-live (1.31.0)** | Primary invocation subcommand for both Opengrep and Semgrep CLI.          |
| `--config <path>`             | **verified-live (1.31.0)** | Supplies local rule pack path (`rules/secureship-sast/`).                 |
| `--sarif-output=<file>`       | **verified-live (1.31.0)** | Opengrep syntax for streaming SARIF report directly to target file.       |
| `--sarif` / `--output <file>` | **docs-only (>=1.70.0)**   | Fallback syntax when semgrep binary is used instead of opengrep.          |
| `--disable-version-check`     | **verified-live (1.31.0)** | Prevents external phone-home network requests.                            |
| `--no-git-ignore`             | **verified-live (1.31.0)** | Ensures all applicable source files within targetDir are scanned.         |
| `--metrics=off`               | **docs-only (Semgrep)**    | Supported in standard Semgrep; removed for Opengrep 1.31.0 compatibility. |

### 2.3 Trivy (`trivy.adapter.ts`)

| Flag / Subcommand           | Status                     | Notes / Version Details                                                                         |
| :-------------------------- | :------------------------- | :---------------------------------------------------------------------------------------------- |
| `fs`                        | **verified-live (0.76.0)** | Filesystem scanning mode.                                                                       |
| `--scanners vuln,misconfig` | **verified-live (0.76.0)** | Restricts scanning to vulnerability and misconfiguration checks (secrets deferred to Gitleaks). |
| `--format sarif`            | **verified-live (0.76.0)** | Formats output as SARIF 2.1.0.                                                                  |
| `--output <file>`           | **verified-live (0.76.0)** | Specifies destination SARIF output file path.                                                   |
| `--offline-scan`            | **verified-live (0.76.0)** | Disables remote dependency API lookups.                                                         |
| `--skip-db-update`          | **verified-live (0.76.0)** | Skips remote vulnerability DB download from ghcr.io (requires cached local DB).                 |
| `--skip-check-update`       | **verified-live (0.76.0)** | Skips rego policy checks updates.                                                               |
| `--cache-dir <dir>`         | **verified-live (0.76.0)** | Points Trivy to custom or ambient cache directory.                                              |

### 2.4 OSV-Scanner (`osv-scanner.adapter.ts`)

| Flag / Subcommand            | Status                    | Notes / Version Details                                                           |
| :--------------------------- | :------------------------ | :-------------------------------------------------------------------------------- |
| `scan source`                | **verified-live (2.7.0)** | OSV-Scanner v2 primary subcommand for filesystem scanning.                        |
| `-r <dir>`                   | **verified-live (2.7.0)** | Recursively scans all lockfiles and manifests in targetDir.                       |
| `--format sarif`             | **verified-live (2.7.0)** | Standard SARIF 2.1.0 output formatting.                                           |
| `--output-file <file>`       | **verified-live (2.7.0)** | Routes SARIF output to temporary path.                                            |
| `--offline`                  | **verified-live (2.7.0)** | Disables live network lookups against `api.osv.dev` and uses local DB if present. |
| `--lockfile` / `--recursive` | **docs-only (v1.x)**      | OSV-Scanner v1 syntax (v2 syntax `scan source -r` is actively tested).            |

### 2.5 Checkov (`checkov.adapter.ts`)

| Flag / Subcommand                             | Status                     | Notes / Version Details                                                        |
| :-------------------------------------------- | :------------------------- | :----------------------------------------------------------------------------- |
| `-d <dir>`                                    | **verified-live (3.3.29)** | Directory path to scan for IaC manifests.                                      |
| `--framework terraform,dockerfile,kubernetes` | **verified-live (3.3.29)** | Limits checks to supported IaC frameworks.                                     |
| `--output sarif`                              | **verified-live (3.3.29)** | Emits findings in SARIF 2.1.0 format.                                          |
| `--output-file-path <dir>`                    | **verified-live (3.3.29)** | Directory where Checkov writes `results_sarif.sarif`.                          |
| `--soft-fail`                                 | **verified-live (3.3.29)** | Prevents non-zero exit codes on policy violations (finding discovery exits 0). |
| `--quiet`                                     | **verified-live (3.3.29)** | Suppresses verbose progress output.                                            |
| `--compact`                                   | **verified-live (3.3.29)** | Minimizes log chatter during execution.                                        |
| `--skip-download`                             | **verified-live (3.3.29)** | Prevents downloading external Terraform modules in offline mode.               |
| `--no-guide`                                  | **deprecated / removed**   | Not supported in Checkov 3.3.29 (removed to prevent CLI parse errors).         |

---

## 3. Offline Mode Behavior & Local Database Handling

When `--offline` is specified on the CLI or configured in `secureship.config.json`:

1. **Trivy Database Pre-requisite:**

   - Trivy requires `%LOCALAPPDATA%\trivy\db\trivy.db` (or `~/.cache/trivy/db/trivy.db`).
   - If the local database cache is missing in offline mode, `TrivyAdapter` cleanly returns status `PARTIAL_FAILURE` with an actionable error message directing the user to populate the cache via `trivy image --download-db-only` or run online.
   - When the cache exists, Trivy runs in under 3 seconds in full offline mode using `--offline-scan --skip-db-update --skip-check-update`.

2. **OSV-Scanner Offline:**

   - Skips network queries against OSV API and exits cleanly with status `SUCCESS` (0 findings if no local database dump is configured).

3. **Checkov Offline:**

   - Runs with `--skip-download` to evaluate all local Terraform, Dockerfile, and Kubernetes policies without external module downloads.

4. **Opengrep Offline:**

   - Evaluates the bundled SecureShip SAST ruleset (`rules/secureship-sast/`) with `--disable-version-check` completely offline.

5. **Gitleaks Offline:**
   - Completely offline by design using local regex rule patterns.

---

## 4. Exit Code Mapping per Scanner

| Scanner         | Exit Code 0                             | Exit Code 1                            | Exit Code 2+                           |
| :-------------- | :-------------------------------------- | :------------------------------------- | :------------------------------------- |
| **Opengrep**    | Clean (no findings)                     | Findings discovered (`SUCCESS`)        | Syntax / Configuration error (`ERROR`) |
| **Gitleaks**    | Clean (no leaks)                        | Leaks discovered (`SUCCESS`)           | Execution error (`ERROR`)              |
| **Trivy**       | Clean / Findings discovered (`SUCCESS`) | DB update error in offline mode        | Fatal error (`ERROR`)                  |
| **OSV-Scanner** | Clean                                   | Vulnerabilities discovered (`SUCCESS`) | Execution error (`ERROR`)              |
| **Checkov**     | Clean / Findings (`--soft-fail`)        | Uncaught error                         | Configuration error (`ERROR`)          |

---

## 5. Golden Fixtures & Live Contract Tests

Real SARIF outputs from mini-scans on sample fixtures have been sanitized (fake secrets only) and committed to:

- `packages/scanner-adapters/test/fixtures/real/gitleaks.sarif`
- `packages/scanner-adapters/test/fixtures/real/opengrep.sarif`
- `packages/scanner-adapters/test/fixtures/real/trivy.sarif`
- `packages/scanner-adapters/test/fixtures/real/osv-scanner.sarif`
- `packages/scanner-adapters/test/fixtures/real/checkov.sarif`

The live test suite `packages/scanner-adapters/test/live-contract.test.ts` executes all 5 real binaries on disk, asserts status `SUCCESS`, and validates finding extraction.
