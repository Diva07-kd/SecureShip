# SecureShip 🛡️

SecureShip is an enterprise-grade, local-first security CLI and orchestration pipeline. It executes multi-engine security scanners (`opengrep`/`semgrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`) in isolated child processes, normalizes disparate findings into a unified SARIF 2.1.0 schema, tags non-production code (Gate 1), maintains an auditable mathematical suppression ledger, and supports boundary-safe incremental git diff scans.

---

## 🔒 Core Principles

- **P1. Invariant Ledger Guarantee**: Every raw scanner finding is accounted for in exactly one bucket:
  $$\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$$
  Diff scoping is applied first; findings outside the diff never enter the suppression ledger.
- **P2. Visible Results**: Scans are transparent. Missing binaries (`TOOL_MISSING`), timeouts, and crashes are recorded in the report and never silently swallowed.
- **P3. Failure Isolation**: One scanner crashing or timing out never aborts other scanners.
- **P4. Local-First & Zero Telemetry**: Zero outbound network requests by SecureShip. External scanner network access is disabled when `--offline` is set.
- **P5. Double Secret Redaction**: Secrets are sanitized with `SecretRedactor` both inside subprocesses and during SARIF normalization.
- **P6. Safe Subprocesses**: Zero shell execution (`shell: false`), private temp directories (`0700` permissions), and tree termination on SIGINT/timeout.

---

## 🚀 Quick Start

### Prerequisites

- Node.js `>= 18.0.0`
- `pnpm >= 9.0.0`
- `git >= 2.25.0`

### Installation & Build

```bash
# 1. Install dependencies
pnpm install

# 2. Build monorepo packages
pnpm build

# 3. Verify types, linting, and formatting
pnpm typecheck
pnpm lint
pnpm format:check

# 4. Run full test suite with coverage
pnpm test:coverage

# 5. Run synthetic benchmark replay
pnpm --filter "@secureship/benchmark" run benchmark:replay
```

---

## 💻 CLI Commands

### `secureship scan [target]`

Executes security scanners against the target workspace directory (defaults to `.`).

```bash
# Standard full scan with Gate 2 Reachability analysis (default: annotate)
secureship scan . --gate2 annotate

# Opt-in suppression of unimported high-confidence SCA dependencies
secureship scan . --gate2 suppress

# Incremental diff scan against main branch
secureship scan . --diff main

# Scan only git staged changes with line-level filtering
secureship scan . --staged --diff-lines

# Export pure parseable JSON report to stdout
secureship scan . --json

# Export SARIF 2.1.0 and JSON report files
secureship scan . --output report.json --sarif report.sarif

# Strict mode: fail with exit code 3 if any scanner is missing or errors
secureship scan . --strict

# Offline mode with fail threshold
secureship scan . --offline --fail-on CRITICAL --no-color
```

#### CLI Options

| Flag                      | Description                                                                                    |    Default    |
| :------------------------ | :--------------------------------------------------------------------------------------------- | :-----------: |
| `--scanners <list>`       | Comma-separated scanner list (`opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`).      | Auto-detected |
| `--gate2 <mode>`          | Gate 2 reachability engine mode: `off`, `annotate`, or `suppress`.                             |  `annotate`   |
| `--no-cache`              | Disable external AST extraction cache.                                                         |    `false`    |
| `--diff <ref>`            | Diff reference (e.g. `main`, `HEAD~1`) for incremental scanning.                               |     None      |
| `--staged`                | Scan only staged git changes.                                                                  |    `false`    |
| `--diff-lines`            | Restrict SAST/SCA/IAC findings to modified hunk line ranges.                                   |    `false`    |
| `--fail-on <sev>`         | Fail threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE`).                          |    `HIGH`     |
| `--json`                  | Output pure JSON report to stdout.                                                             |    `false`    |
| `--output <file>`         | Write `ScanReport` JSON to specified file.                                                     |     None      |
| `--sarif <file>`          | Export standardized SARIF 2.1.0 to specified file.                                             |     None      |
| `--include-suppressed`    | Include suppressed findings in report and SARIF export.                                        |    `false`    |
| `--include-nonproduction` | Bypass Gate 1 suppression and report test/doc findings.                                        |    `false`    |
| `--baseline <file>`       | Path to baseline file to suppress known existing findings.                                     |     None      |
| `--update-baseline`       | Update baseline file with current findings (full scan only).                                   |    `false`    |
| `--config <file>`         | Path to explicit `secureship.config.json` (recommended for CI).                                |   Root auto   |
| `--timeout <ms>`          | Global scanner execution timeout in milliseconds.                                              |    `60000`    |
| `--concurrency <num>`     | Max parallel scanner executions.                                                               |      `4`      |
| `--offline`               | Restrict scanners to offline operation and local caches.                                       |    `false`    |
| `--strict`                | Exit code 3 if any selected scanner is missing or fails.                                       |    `false`    |
| `--ai`                    | Enable Gate 3 AI triage.                                                                       |    `false`    |
| `--gate3 <mode>`          | Gate 3 mode: `annotate` (default) or `suppress` (EXPERIMENTAL).                                |  `annotate`   |
| `--ai-provider <name>`    | AI provider: `anthropic`, `openai`, or `fake`.                                                 |  `anthropic`  |
| `--ai-model <name>`       | Model name (required when AI is enabled).                                                      |     None      |
| `--ai-base-url <url>`     | Endpoint URL (supports local Ollama, LM Studio, vLLM).                                         | Provider def  |
| `--ai-dry-run`            | Assemble and test slices without network calls, consent, or API keys.                          |    `false`    |
| `--ai-estimate`           | Estimate token and finding counts without making network requests.                             |    `false`    |
| `--ai-trace [path]`       | Save redacted JSON prompt audit trace to explicit path or per-user traces dir (never in repo). |    `false`    |
| `--no-ai-cache`           | Bypass Gate 3 HMAC-authenticated triage cache.                                                 |    `false`    |
| `--no-function-level`     | Disable function-level (symbol-level) reachability refinement.                                 |    `false`    |
| `--no-color`              | Disable ANSI color formatting.                                                                 |    `false`    |
| `--verbose`               | Enable debug log output with detailed evidence chains.                                         |    `false`    |

> [!WARNING] > **CI/CD Security Trust Model:**
> When scanning untrusted external pull requests or open-source forks, **never** allow the scanner to read an unreviewed `secureship.config.json` from the repository root. A pull request could tamper with ignore rules or disable Gate 2. Always supply a trusted configuration file via `--config /path/to/trusted.config.json` in CI workflows. Repository configs can NEVER enable AI or alter endpoints (Amendment A1).

---

### `secureship ai <enable|disable|status>`

Manages per-user AI triage configuration and explicit network consent in `~/.secureship/config.json`.

```bash
# Interactively configure provider, model, and endpoint consent
secureship ai enable

# Non-interactive configuration (CI/scripted)
secureship ai enable --provider openai --model qwen2.5-coder:7b --base-url http://localhost:11434/v1 --yes

# View current AI configuration, consent bindings, and budget
secureship ai status

# Disable AI triage and revoke endpoint consent
secureship ai disable
```

---

### `secureship explain <report>`

Provides an advisory explanation and remediation guidance for a finding from an untrusted report file, jailing all paths inside `--root` (default `cwd`).

```bash
secureship explain report.json --finding sast-rule-1 --root .
```

---

### `secureship graph [target]`

Visualizes and inspects the whole-repository import dependency graph constructed by WebAssembly Tree-sitter.

```bash
# Inspect graph entrypoints, reachability statistics, and dynamic files
secureship graph .

# Emit raw graph statistics in JSON format
secureship graph . --json

# Export graph topology in GraphViz DOT format for visualization
secureship graph . --format dot > graph.dot
```

---

### `secureship doctor`

Verifies environment prerequisites, supported versions, external scanner paths, and validates SHA-256 integrity of all bundled WebAssembly grammar binaries.

```bash
secureship doctor
```

### `secureship detect [target]`

Analyzes project intelligence (languages, package managers, framework, CI environment).

```bash
secureship detect . --json
```

### `secureship status`

Displays local license status, Free BYOK tier, and capability matrix (including local Ollama / LM Studio / vLLM support).

```bash
secureship status
```

### `secureship reachability symbols [--json]`

Lists curated and verified vulnerable symbol entries loaded from the offline cryptographic dataset. Displays primary advisory ID, package, ecosystem, trigger type, entry points completeness, and cryptographic integrity status.

```bash
secureship reachability symbols
secureship reachability symbols --json
```

---

## 🔬 Phase B: Function-Level (Symbol-Level) Reachability for SCA

Phase B introduces **sound, positive-evidence-based symbol-level reachability refinement** for direct dependencies in npm and PyPI ecosystems.

### Key Capabilities & Guarantees:

- **Sound Pruning (Principle F1):** Findings are pruned to `UNREACHABLE` (`UNINVOKED_SYMBOL`) only when positive static evidence proves that no public entry point to the vulnerability is referenced or leaked.
- **Fail-Closed by Design (Principle F1 & Rule R4):** Any dynamic binding, argument pass, callback leak, spread, reflection (`getattr`), or parse ambiguity triggers immediate fail-closed classification (`NAMESPACE_ESCAPES`), keeping findings reported.
- **Direct Leaf Dependencies Only (Principle F5):** Function-level pruning applies only to direct dependencies with zero installed dependents in the workspace lockfile.
- **Terminal Tags & Human Feedback:**
  - `[CALL PATH PROVEN]`: Concrete AST call path from production entrypoint to vulnerable symbol.
  - `[SYMBOL REFERENCED]`: Vulnerable symbol referenced or called in production code.
  - `[SYMBOL NOT REFERENCED]`: Uninvoked symbol with verified entry points and satisfied preconditions.
  - `[IMPORTED]`: Package imported with namespace escapes or dynamic bindings.
- **Offline Cryptographic Integrity:** All vulnerability data is loaded offline and verified with SHA-256 manifests (`vulnerable-symbols.manifest.json`). Zero scan-time network calls.

---

## ⚙️ Configuration (`secureship.config.json`)

```json
{
  "$schema": "https://secureship.dev/schemas/v1/config.json",
  "failOn": "HIGH",
  "scanners": {
    "opengrep": true,
    "gitleaks": true,
    "trivy": true,
    "osv-scanner": true,
    "checkov": true
  },
  "timeouts": {
    "default": 60000,
    "trivy": 120000
  },
  "gate1": {
    "enabled": true,
    "keepProviderSecrets": true,
    "customTestDirs": ["custom_fixtures"]
  },
  "ignore": [
    {
      "ruleId": "secureship-js-eval",
      "pathGlob": "scripts/**",
      "reason": "Administrative automation script with validated local inputs",
      "expires": "2026-12-31"
    }
  ]
}
```

---

## 📦 Container Operations & Hardening

SecureShip provides a production-grade, hardened Docker container image with zero runtime downloads, immutable root-owned scanner binaries (`/opt/secureship/bin`), non-root execution (UID `10001`), and read-only filesystem support.

- Full documentation and runbook: [docs/docker.md](docs/docker.md)
- Third-party scanner engine notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

```bash
# Pull and run system diagnostics
docker run --rm secureship/cli:latest doctor

# Run an isolated scan over a read-only bind mount
docker run --rm -v "$(pwd):/workspace:ro" secureship/cli:latest scan /workspace
```

---

## 🛡️ Air-Gap & Offline Database Management

SecureShip supports complete disconnected operations in classified, SCIF, or air-gapped zones without network access:

- Full documentation and runbook: [docs/air-gap.md](docs/air-gap.md)

```bash
# 1. Snapshot and sign offline databases (on connected machine)
secureship bundle-offline --output bundle.tar.gz --sign-key private.pem

# 2. Verify and import bundle atomically (on air-gapped machine)
secureship import-offline bundle.tar.gz --trust-key public.pem

# 3. Run zero-network scans with cryptographic database validation
secureship scan --offline .
```

---

## 📊 Benchmark Harness

SecureShip includes a reproducible replay benchmark harness testing Precision, Recall, and Suppression-Recall against ground-truth security corpora:

```bash
pnpm --filter "@secureship/benchmark" run benchmark:replay
```

Threshold requirements:

- **Precision**: $\ge 85\%$
- **Recall**: $\ge 80\%$
- **F1 Score**: $\ge 80\%$
- **Suppression-Recall**: $\ge 90\%$

---

## 📄 License

Apache-2.0. Copyright (c) 2026 SecureShip Team.
