# SecureShip CLI & Monorepo Technical Specification Survey

- Generated: 2026-11-07T06:17:00Z
- Author: spec-miner (explorer_survey_1)
- Working Directory: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE`
- Target Document: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_survey_1\survey_secureship_cli.md`

---

## 1. Executive Summary & Monorepo Architecture

SecureShip is a Zero-False-Positive DevSecOps Intelligence Engine & Verification Platform built as a TypeScript monorepo using `pnpm` (version 12.14.0) with ES modules (`"type": "module"`). It orchestrates multiple security analysis sub-engines (SAST, Secrets, SCA, Threat Intel, IaC, and Supply Chain), correlates findings, and applies a multi-gate validation pipeline:
- **Gate 1**: Scope Filtering (test/mock/documentation suppression)
- **Gate 2**: Reachability Analysis (Tree-sitter WASM AST call graphs, import graphs, and curated vulnerable symbol datasets)
- **Gate 3**: AI Triage (zero-leakage redacted prompt generation with advisory false-positive suppression)
- **Gate 4**: Dynamic Verification & Remediation (sandboxed patch generation and verification)

### Monorepo Workspaces Layout
| Workspace Package | Directory | Role & Responsibilities |
|---|---|---|
| `@secureship/cli` | `packages/cli` | Main Commander-based CLI tool (`secureship`), bin entrypoint `./dist/index.js` |
| `@secureship/contracts` | `packages/contracts` | Shared Zod schemas, TypeScript types, finding models, ScanReport models, brand helpers |
| `@secureship/core-engine` | `packages/core-engine` | `ScanOrchestrator`, Gate 1 scope filtering, SARIF exporter, baseline/ignore engines, process runner |
| `@secureship/scanner-adapters` | `packages/scanner-adapters` | Binary resolvers, lockfile verification, tool installers, adapters for Opengrep, Gitleaks, Trivy, OSV-Scanner, Checkov |
| `@secureship/reachability` | `packages/reachability` | Gate 2 AST call path analysis, import graphs, bundled Tree-sitter WASM grammars |
| `@secureship/context-slicer` | `packages/context-slicer` | Code context slicer, secret redactor, AST scope finder, usage site finder |
| `@secureship/patch-engine` | `packages/patch-engine` | Patch generator and unified diff application |
| `@secureship/sandbox` | `packages/sandbox` | Container and native process sandboxing for remediation |
| `@secureship/ai` | `packages/ai` | Gate 3 AI triage, consent management, OpenAI/Anthropic/Fake client, HMAC cache |
| `@secureship/fleet` | `packages/fleet` | Central telemetry ingestion, CISO cockpit web server, CRA export |
| `@secureship/benchmark` | `packages/benchmark` | Replay and live benchmarks, corpus cases (`case1`–`case21`), metrics evaluation |
| `secureship-security` | `packages/vscode-extension` | VS Code extension wrapper |
| `@secureship/license-server` | `packages/license-server` | Offline and online cryptographic licensing server |

---

## 2. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Entrypoint | `secureship` CLI executable | Primary CLI executable bundled via tsup into `packages/cli/dist/index.js` with shebang `#!/usr/bin/env node` | CLI arguments | Stdout / Stderr streams, exit code | Process exits with standard exit codes | `packages/cli/package.json`, `Dockerfile.cli` |
| 2 | Command | `secureship doctor` | Diagnostic probe verifying Node (>=18), Git, storage paths, scanner binaries, SHA-256 lock pins, WASM grammars, AI config, container runtime, and license | None | Structured human diagnostic table | Outputs `✖` or `⚠` status icons; exit code 0 | `packages/cli/src/commands/doctor.ts` |
| 3 | Command | `secureship scan [path]` | Multi-scanner execution pipeline with Gate 1 scope filtering, Gate 2 reachability, and Gate 3 AI triage | `[path]` (default: `.`), options (`--scanners`, `--json`, `--sarif`, `--fail-on`, etc.) | JSON to stdout (`--json`) or human table; optional file writes via `--output` / `--sarif` | Exit code 0 (clean/below failOn), 1 (findings at/above failOn), 2 (invalid args/config), 3 (infrastructure failure) | `packages/cli/src/commands/scan.ts` |
| 4 | Command | `secureship detect [path]` | Stack and language detection, lockfile discovery, test/mock path classification for Gate 1 Scope Filtering | `[path]` (default: `.`), optional `--json` | Text summary or JSON profile (`ProjectProfile`) | Exits 0 on valid analysis | `packages/cli/src/commands/detect.ts` |
| 5 | Command | `secureship graph [path]` | Whole-repository import dependency graph construction and inspection | `[path]`, `--format <text\|json\|dot>`, `--no-cache` | DOT digraph or JSON graph statistics | Exits 0 on valid graph | `packages/cli/src/commands/graph.ts` |
| 6 | Command | `secureship install-tools` | Downloader & cryptographic verifier for external scanner engines against `tools.lock.json` | `--tools <list>`, `--dir <path>`, `--target-platform <arch>`, `--libc <type>`, `--force`, `--dry-run`, `--json` | Downloaded binaries verified by SHA-256 | Exits non-zero on checksum mismatch or download error | `packages/cli/src/commands/install-tools.ts`, `tools.lock.json` |
| 7 | Command | `secureship setup` | Auto-provisions and verifies all SecureShip sub-engines | `--force` | Status messages | Exits 0 on success, warning if incomplete | `packages/cli/src/index.ts` |
| 8 | Command | `secureship status` | Displays active license tier (`FREE_BYOK`, `PRO_TEAM`, `ENTERPRISE`), operational capabilities, and quotas | Optional `--json` | License report | Exits 0 | `packages/cli/src/commands/status.ts` |
| 9 | Command | `secureship license` | License tier management: `activate <key>`, `status`, `upgrade`, `remove` | Subcommands and flags (`--server`, `--offline-file`, `--force`, `--json`) | Status messages or JSON | Exits non-zero on activation failure | `packages/cli/src/commands/license.ts` |
| 10 | Command | `secureship init [dir]` | Initializes `secureship.config.json`, CI/CD GitHub action workflow, and baseline | `--fail-on`, `--scanners`, `--gate2`, `--generate-action`, `--create-baseline`, `--yes`, `--force` | Generates configuration files | Exits 0 on success | `packages/cli/src/commands/init.ts` |
| 11 | Command | `secureship ai` | Gate 3 AI triage configuration and consent management (`enable`, `disable`, `status`, `test`) | Subcommands and flags (`--provider`, `--model`, `--base-url`, `--gate3`, `--yes`) | Confirmation message / latency measurement | Exits 2 on invalid provider/url | `packages/cli/src/commands/ai.ts` |
| 12 | Command | `secureship explain [target]` | Advisory AI explanation for a specific finding in an untrusted ScanReport | `[target]` (ID/fingerprint/index), `--report <file>`, `--root <dir>`, `--json` | Finding explanation markdown / JSON | Exits 2 on missing finding or unconfigured AI | `packages/cli/src/commands/explain.ts` |
| 13 | Command | `secureship fix [target]` | Generates and verifies remediation patches for security findings (Gate 4) | `[target]`, `--report <file>`, `--require <status>`, `--verify <level>`, `--attempts <n>`, `--json` | Patch report and verification diff | Exits 0 on verified patch, non-zero otherwise | `packages/cli/src/commands/fix.ts` |
| 14 | Command | `secureship fix apply <id>` | Atomically applies a verified fix bundle to the working tree | `<id>`, `--allow-non-git`, `--allow-dirty`, `--root <dir>` | Working tree patch application | Exits non-zero on patch reject or dirty tree | `packages/cli/src/commands/fix.ts` |
| 15 | Command | `secureship verify <patch-file>` | Verifies a human-authored patch file against a security finding | `<patch-file>`, `--finding <id>`, `--report <file>`, `--verify <level>`, `--json` | Verification verdict report | Exits non-zero on verification failure | `packages/cli/src/commands/verify.ts` |
| 16 | Command | `secureship sandbox` | Manages Gate 4 execution sandboxes, container runtimes, and host trust (`status`, `doctor`, `enable`, `disable`, `use-native`, `trust-host`) | Subcommands | Status report | Exits 0 on success | `packages/cli/src/commands/sandbox.ts` |
| 17 | Command | `secureship sbom [dir]` | Generates EU Cyber Resilience Act & US EO 14028 compliant SBOM (CycloneDX / SPDX) | `[dir]`, `--format <cyclonedx\|spdx>`, `--output <file>`, `--with-vulns`, `--signed`, `--check-licenses` | SBOM JSON | Exits 0 on success | `packages/cli/src/commands/sbom.ts` |
| 18 | Command | `secureship fleet` | Manages self-hosted SecureShip Fleet cockpit, telemetry ingestion, and CRA export (`start`, `status`, `export-cra`) | Subcommands and flags (`--port`, `--host`, `--endpoint`, `--token-file`, `--output`) | Starts server or exports compliance JSON | Exits 0 on success | `packages/cli/src/commands/fleet.ts` |
| 19 | Command | `secureship bundle-offline` | Snapshots and exports vulnerability databases and scanner binaries into a signed offline bundle | `--output <file>`, `--platform <list>`, `--ecosystems <list>`, `--sign-key <pem>`, `--key-id <id>` | Deterministic `.tar.gz` bundle with manifest | Exits 0 on export | `packages/cli/src/commands/bundle-offline.ts` |
| 20 | Command | `secureship import-offline [bundle]` | Verifies and imports an air-gap database bundle into active generation | `[bundle]`, `--trust-key <pem...>`, `--allow-unsigned`, `--dry-run`, `--verify-only`, `--rollback` | Active database generation switch | Exits non-zero on signature invalid | `packages/cli/src/commands/import-offline.ts` |
| 21 | Scan Flag | `--scanners <list>` | Restricts scanner execution to specified list or aliases (`sast`/`opengrep`, `secrets`/`gitleaks`, `sca`/`trivy`, `intel`/`osv-scanner`, `iac`/`checkov`) | Comma-separated scanner names | Only runs matching scanner adapters | Unknown scanner raises error, exits 2 | `packages/cli/src/commands/scan.ts:280-298` |
| 22 | Scan Flag | `--json` | Emits raw machine-readable ScanReport JSON to stdout | Boolean flag | Pure JSON to stdout | Non-JSON text suppressed from stdout | `packages/cli/src/commands/scan.ts:377-380` |
| 23 | Scan Flag | `--output <file>` | Writes complete ScanReport JSON to destination file | File path string | File written on disk | Exits 2 if target directory is non-writable | `packages/cli/src/commands/scan.ts:352-360` |
| 24 | Scan Flag | `--sarif <file>` | Exports standardized SARIF 2.1.0 output to destination file | File path string | Compliant SARIF 2.1.0 document | Exits 2 if directory non-writable | `packages/cli/src/commands/scan.ts:363-375` |
| 25 | Scan Flag | `--fail-on <severity>` | Sets minimum severity threshold to return exit code 1 (CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE; default: `HIGH`) | Severity string | Determines exit code (0 vs 1) | Invalid severity defaults to HIGH rank | `packages/cli/src/commands/scan.ts:498-508` |
| 26 | Scan Flag | `--gate2 <mode>` | Controls Gate 2 AST and call-path reachability analysis (`annotate`, `suppress`, `off`) | Mode string | Annotates or suppresses unreachable SCA findings | Invalid mode exits 2 with JSON error | `packages/cli/src/commands/scan.ts:180-188` |
| 27 | Scan Flag | `--gate3 <mode>` | Controls Gate 3 AI triage analysis (`annotate`, `suppress`, `off`) | Mode string | Annotates or suppresses likely false-positives | Invalid mode exits 2 with JSON error | `packages/cli/src/commands/scan.ts:190-198` |
| 28 | Scan Flag | `--diff <ref>` | Performs differential scan relative to git reference | Git ref string (e.g. `origin/main`) | Scans only changed files | Git error bubbles up | `packages/cli/src/commands/scan.ts:309` |
| 29 | Scan Flag | `--staged` | Performs differential scan against staged git changes | Boolean flag | Scans only staged files | Git error bubbles up | `packages/cli/src/commands/scan.ts:310` |
| 30 | Scan Flag | `--diff-lines` | Strictly filters SAST and IaC findings to lines touched by git diff | Boolean flag | Scopes findings to modified line ranges | Exits 0/1 based on filtered findings | `packages/cli/src/commands/scan.ts:311` |
| 31 | Scan Flag | `--baseline <file>` | Loads known findings baseline to suppress recurring alerts | Baseline JSON file path | Suppresses known findings under `BASELINE_KNOWN` | Exits 0 if no new findings exceed threshold | `packages/cli/src/commands/scan.ts:314` |
| 32 | Scan Flag | `--update-baseline` | Writes current findings to baseline file | Boolean flag | Overwrites/creates baseline file | Mutually exclusive with diff/staged | `packages/cli/src/commands/scan.ts:315` |
| 33 | Scan Flag | `--timeout <ms>` | Scanner subprocess execution timeout in milliseconds | Milliseconds string/number | Terminates scanner if exceeded (`TIMEOUT` status) | If all fail, exit 3 | `packages/cli/src/commands/scan.ts:317` |
| 34 | Scan Flag | `--concurrency <n>` | Concurrency for parallel scanner process execution (default: 4) | Integer | Sets worker pool size | Out of range falls back to defaults | `packages/cli/src/commands/scan.ts:318` |
| 35 | Scan Flag | `--strict` | Fails scan with exit code 3 if any individual scanner fails or is missing | Boolean flag | Changes exit code to 3 on partial failure | Exits 3 on missing/failed scanner | `packages/cli/src/commands/scan.ts:426-447` |
| 36 | Scan Flag | `--offline` | Enforces zero network access and offline database lookups | Boolean flag | Prevents outbound sockets | Exits 3 on offline security violation | `packages/cli/src/commands/scan.ts:320, 530` |
| 37 | Scan Flag | `--check-licenses` | Evaluates dependency licenses against allow and deny compliance rules | Boolean flag | Violation report in summary | Exits 1 if license violations exist | `packages/cli/src/commands/scan.ts:455-495` |
| 38 | Safe Extraction | Safe Tar/Zip Extraction | In-process extraction strictly protecting against path traversal (`../`), symlinks, hardlinks, decompression bombs, and absolute paths | Buffer or archive file path | Safely extracted files on disk | Throws Error on security violation | `packages/scanner-adapters/src/safe-archive.ts` |

---

## 3. Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | `secureship scan` | Findings present below `--fail-on` threshold (e.g. MEDIUM finding with default `--fail-on HIGH`) | Scan completes successfully, emits full ScanReport JSON, exits with **code 0**. |
| 2 | `secureship scan` | Findings present at or above `--fail-on` threshold (e.g. MEDIUM finding with `--fail-on MEDIUM`) | Scan completes successfully, emits full ScanReport JSON to stdout, exits with **code 1**. |
| 3 | `secureship scan` | Clean scan with zero findings | Scan completes successfully, emits full ScanReport JSON with `findings: []`, exits with **code 0**. |
| 4 | `secureship scan` | Invalid argument (e.g. `--gate2 invalid_mode`) | Emits JSON error `{"error": "Invalid --gate2 mode \"invalid_mode\". Allowed modes: off, annotate, suppress"}` to stderr, exits with **code 2**. |
| 5 | `secureship scan` | Unknown scanner name passed to `--scanners unknown_engine` | Emits `Unknown scanner(s) specified: unknown_engine. Supported engines: sast, secrets, sca, intel, iac`, exits with **code 2**. |
| 6 | `secureship scan` | Strict mode enabled (`--strict`) and an engine fails or is missing | Detects non-SUCCESS scanner status, emits error message, exits with **code 3**. |
| 7 | `secureship scan` | All selected scanners fail to execute | Detects `no scanner completed`, prints warning, exits with **code 3**. |
| 8 | `secureship scan` | License violation detected with `--check-licenses` | Evaluates component licenses; finding violations causes scanner to exit with **code 1**. |
| 9 | `secureship scan` | Offline violation detected during `--offline` mode | Network operation trapped, throws `[Offline Security Violation]`, exits with **code 3**. |
| 10 | `secureship scan` | User sends interrupt signal (Ctrl+C / SIGINT) | SIGINT handler aborts child processes, outputs cancellation message, exits with **code 130**. |
| 11 | `secureship doctor` | Execution in host or container environment | Auto-detects container environment (`isContainerEnvironment()`), checks user identity, tests storage paths, verifies Node >= 18, probes Git, inspects all 5 sub-engines against `tools.lock.json`, and verifies Tree-sitter WASM grammars. Exits with **code 0**. |
| 12 | `SafeArchiveExtractor` | Archive containing path traversal sequence (e.g. `../../etc/passwd`) | In-process header scanner inspects entry names before decompression, rejects `..`, and throws `Security violation: Archive entry contains prohibited traversal sequences`. |
| 13 | `SafeArchiveExtractor` | Archive containing symlink or hardlink entry | Inspects TAR typeflag (`'1'` hardlink, `'2'` symlink) or ZIP external attributes, throws `Security violation: Symlink entry is prohibited in safe extraction`. |
| 14 | `SafeArchiveExtractor` | Decompression bomb (huge uncompressed size or compression ratio > 100x) | Enforces `maxOutputLength` and uncompressed bounds check, throws decompression limit error. |

---

## 4. Exit Code Semantics Specification

The SecureShip CLI employs strict, standardized exit codes across all commands. The wrapper backend service MUST accurately interpret these codes:

| Exit Code | Semantic Meaning | Scanner Execution State | Wrapper Action |
|:---:|:---|:---|:---|
| **0** | **Clean / Success** | The scan completed successfully. No findings were discovered at or above the `--fail-on` severity threshold. | Parse stdout/output JSON; store ScanReport; mark job as `done`. |
| **1** | **Findings Present / Policy Violation** | The scan completed successfully, but one or more security findings or license violations met or exceeded the failure threshold. Valid ScanReport JSON is generated. | Parse stdout/output JSON; store ScanReport; mark job as `done` (NOT failed). |
| **2** | **Usage / Configuration Error** | CLI parameters, configuration files, AI settings, or output paths were invalid (e.g. unknown flag, malformed json, unwriteable directory). | Mark job as `failed`; capture stderr for error diagnostics. |
| **3** | **Infrastructure / Engine Failure** | Critical scanner execution failure: either zero scanners completed, strict mode failed (`--strict`), or offline air-gap policy was violated. | Mark job as `failed`; capture scanner execution error details. |
| **130** | **Process Terminated (SIGINT)** | Execution was cancelled by user interrupt or hard timeout abort signal. | Mark job as `failed` (timeout/cancelled); clean up temporary scratch directory. |

> **Critical Rule for Backend Wrapper**: Exit code 0 and Exit code 1 are **BOTH SUCCESSFUL SCANS**. The backend must parse and return the ScanReport JSON regardless of whether the exit code is 0 or 1.

---

## 5. Output Schemas & Data Models

### 5.1 ScanReport JSON Model (Version 1.3)
When executed with `--json` or `--output <file>`, SecureShip emits a single top-level JSON object conforming to `ScanReportSchema`:

```typescript
export interface ScanReport {
  schemaVersion: '1.0' | '1.1' | '1.2' | '1.3';
  tool: {
    name: 'secureship';
    version: string;
  };
  target: string;                      // Normalized absolute scan target path
  mode: 'FULL' | 'DIFF';               // Scan mode
  diffBase?: string;                   // Git ref if diff scan
  startedAt: string;                   // ISO 8601 UTC timestamp
  durationMs: number;                  // Total scan execution duration
  scanners: ScannerExecutionSummary[]; // Per-engine execution metrics & status
  findings: NormalizedFinding[];       // Active (unsuppressed) security findings
  suppressed: SuppressedFinding[];     // Filtered / suppressed findings (Gate 1, 2, 3)
  summary: ScanSummary;                // Aggregated metrics by severity, category, reachability
  ai?: AiExecutionSummary;             // Gate 3 AI triage summary (if enabled)
  tier?: LicenseTier;                  // Active license tier (e.g. FREE_BYOK, PRO_TEAM)
  offline?: OfflineProvenance;         // Offline database signatures and age (if offline)
  warnings: string[];                  // Execution warnings
}
```

### 5.2 NormalizedFinding Schema
Each individual vulnerability is normalized into a consistent cross-scanner representation:

```typescript
export interface NormalizedFinding {
  id: string;                          // Unique finding ID (e.g. "finding-4dc03bcdfeb7706d")
  fingerprint: string;                 // SHA-256 fingerprint for deduplication & baselining
  ruleId: string;                      // Scanner or white-labeled rule identifier
  scannerName: ScannerName;            // 'opengrep' | 'gitleaks' | 'osv-scanner' | 'trivy' | 'checkov'
  category: FindingCategory;          // 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'SUPPLY_CHAIN'
  severity: Severity;                  // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  confidence: Confidence;              // 'HIGH' | 'MEDIUM' | 'LOW'
  reachability: Reachability;          // 'UNKNOWN' | 'REACHABLE_CALL_PATH' | 'REACHABLE_IMPORT' | 'UNREACHABLE'
  reachabilityDetail?: ReachabilityDetail;
  location: {
    filePath: string;                  // Workspace-relative POSIX path
    startLine: number;                 // 1-based start line number
    endLine: number;                   // 1-based end line number
    startColumn?: number;
    endColumn?: number;
    redactedSnippet?: string;          // Redacted snippet if available
  };
  upstreamValidationStatus: UpstreamValidationStatus;
  verificationStatus: VerificationStatus;
  scopeTag: ScopeTag;                  // 'PRODUCTION' | 'TEST_OR_MOCK' | 'DOCUMENTATION' | 'EXAMPLE'
  title: string;                       // Human-readable finding title
  description: string;                 // Detailed vulnerability description
  cweIds: string[];                    // CWE IDs (e.g. ["CWE-502", "CWE-89"])
  aliases?: string[];                  // CVE IDs or upstream rule IDs (e.g. ["CVE-2021-44906"])
  package?: {
    ecosystem: string;                 // 'npm', 'PyPI', 'Go', 'Maven', etc.
    name: string;
    version: string;
    fixedVersion?: string;
  };
  lockfilePath?: string;
  evidence: ScannerEvidence[];
  fixRecommendation?: FixRecommendation;
  aiTriage?: AiTriage;
  createdAt: string;                   // ISO timestamp
}
```

### 5.3 ScanSummary Schema
Aggregated statistics for high-level dashboard display:
```typescript
export interface ScanSummary {
  totalRaw: number;
  totalReported: number;
  totalSuppressed: number;
  totalOutOfScope: number;
  bySeverity: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO', number>;
  byCategory: Record<'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'SUPPLY_CHAIN', number>;
  byReachability?: Record<'REACHABLE_CALL_PATH' | 'REACHABLE_IMPORT' | 'UNREACHABLE' | 'UNKNOWN', number>;
  suppressedByReason: Record<string, number>;
  functionLevel?: {
    evaluated: number;
    noSymbolData: number;
    symbolReferenced: number;
    callPathProven: number;
    uninvoked: number;
    escapedOrUnknown: number;
    skippedTier: number;
    blockedByReason: Record<string, number>;
  };
}
```

---

## 6. Doctor Command Diagnostic Specifications

The `secureship doctor` command validates the execution environment before running scans:
1. **Node.js Environment**: Verifies `node --version` is >= 18.0.0.
2. **Platform & Process Identity**: Prints OS platform, architecture, container runtime detection (`isContainerEnvironment()`), and UID/GID.
3. **Storage Directories**: Tests writability of:
   - `SECURESHIP_HOME` (`~/.secureship`)
   - `Tool Candidate Dirs` (`/opt/secureship/bin` or `~/.secureship/bin`)
   - `Vulnerability DB Dir` (`~/.secureship/db`)
4. **Git**: Checks git presence and version (needed for diff scans).
5. **Core Sub-Engines**:
   - `opengrep` (SAST): Checks binary on PATH/overrides, runs `--version`, compares SHA-256 with `tools.lock.json`.
   - `gitleaks` (Secrets): Runs `gitleaks version`, compares SHA-256 with `tools.lock.json`.
   - `trivy` (SCA): Runs `trivy --version`, compares SHA-256 with `tools.lock.json`.
   - `osv-scanner` (Threat Intel): Runs `osv-scanner --version`, compares SHA-256 with `tools.lock.json`.
   - `checkov` (IaC): Checks Python venv or checkov CLI, runs `--version`.
6. **Reachability WASM Grammars**: Verifies SHA-256 integrity and file sizes of:
   - `tree-sitter.wasm`
   - `tree-sitter-javascript.wasm`
   - `tree-sitter-typescript.wasm`
   - `tree-sitter-tsx.wasm`
   - `tree-sitter-python.wasm`
   - `tree-sitter-go.wasm`
   - `tree-sitter-java.wasm`
   - `tree-sitter-rust.wasm`
   - `tree-sitter-c_sharp.wasm`
7. **Curated Symbol Datasets**: Verifies `secureship-curated-vulnerable-symbols-v1` SHA-256 checksum.
8. **AI Triage Configuration**: Checks provider, model, API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SECURESHIP_AI_API_KEY`), and Gitleaks secondary redaction.
9. **Sandbox Environment**: Inspects Docker/Podman availability for Gate 4 dynamic verification.
10. **License Tier & Capabilities**: Validates license file, active tier, and remaining AI quota.
11. **Offline Vulnerability DB**: Checks `CURRENT` pointer, generation ID, bundle ID, schema version, and cryptographic signature.

---

## 7. Safe Extraction & Archive Handling Specification

The backend service requires a safe zip extraction utility (`safe_extract()`) before executing scans. The existing implementation in `packages/scanner-adapters/src/safe-archive.ts` provides the reference behavior:

### Strict Extraction Invariants
1. **Zip-Slip (Path Traversal)**:
   - Must reject any entry whose name starts with `/`, `\`, contains `..` segments, or contains null bytes `\0`.
   - Must canonicalize destination paths and verify: `dest_file.resolve().is_relative_to(target_dir.resolve())`.
2. **Symlink and Hardlink Prevention**:
   - Must inspect entry attributes. In ZIP files, POSIX file permissions are stored in the upper 16 bits of `external_attr`. A symlink is flagged when `(attr >> 16) & 0o120000 == 0o120000` (hex: `0xA1ED` or mask `0o120000`).
   - Must reject symlinks and hardlinks with a `ValueError`.
3. **Decompression Bomb Defense**:
   - Check compression ratio: `uncompressed_size / compressed_size > 100` must be rejected with `ValueError`.
   - Enforce single file size limit: no file may exceed 10 MB (10,485,760 bytes).
   - Enforce total extracted size limit: total archive contents must not exceed 50 MB (52,428,800 bytes).
   - Enforce maximum entry count limit: maximum 10,000 files per archive.
4. **Temporary Directory Lifecycle**:
   - Extract into an isolated temporary directory (e.g. `tempfile.mkdtemp(prefix="securescan_")`).
   - Guarantee cleanup using `try ... finally` or asynchronous context managers, ensuring all files are unlinked on scan completion or failure.

---

## 8. Existing Test Assets & Fixtures

The repository contains extensive security test fixtures in `packages/benchmark/corpus/`:

| Corpus Case | Vulnerability Type | Primary Engine | Target Files |
|---|---|---|---|
| `case1-secrets-prod` | Hardcoded AWS Access Token (`aws-access-token`) | `gitleaks` | `src/aws-client.ts` |
| `case2-secrets-test-dummy` | Test dummy secret (Gate 1 suppressed) | `gitleaks` | `test/auth.test.ts` |
| `case3-sast-eval` | Code Injection / eval (`secureship-js-eval`) | `opengrep` | `src/calculator.js` |
| `case4-sca-lockfile` | Vulnerable npm package in package-lock.json | `trivy` / `osv-scanner` | `package-lock.json` |
| `case5-secrets-placeholder` | Template placeholder `<YOUR_KEY>` | `gitleaks` | `.env.example` |
| `case8-sast-child-process` | Command Injection (`child_process.exec`) | `opengrep` | `src/runner.js` |
| `case9-sast-sql-concat` | SQL Injection (`secureship-js-sql-concat`) | `opengrep` | `src/db.js` |
| `case10-sast-md5-checksum` | Insecure Cryptographic Hash MD5 | `opengrep` | `src/hash.py` |
| `case11-sast-python-pickle` | Unsafe Deserialization (`pickle.loads`, CWE-502) | `opengrep` | `app.py` |
| `case12-sca-axios` | Axios SSRF / Prototype Pollution CVE | `trivy` | `package-lock.json` |
| `case13-sca-minimist` | Minimist Prototype Pollution (CVE-2021-44906) | `trivy` | `package-lock.json` |
| `case15-sca-clean-package` | Clean, vulnerability-free package | All | `package.json` |
| `case16-iac-terraform-sg-open` | Open 0.0.0.0/0 Security Group | `checkov` | `main.tf` |
| `case17-iac-dockerfile-root` | Dockerfile missing USER directive | `checkov` | `Dockerfile` |
| `case18-iac-k8s-privileged` | Kubernetes privileged pod | `checkov` | `pod.yaml` |

These corpora serve as pre-verified source material for generating valid test archives for the FastAPI backend and frontend tests.

---

## 9. CWE to OWASP Top 10 (2021) Mapping Specification

To satisfy requirement R1 and acceptance criteria, the backend service must map finding rules and CWEs to the official OWASP Top 10 (2021) categories:

| OWASP Top 10 (2021) Category | Name | Common Mapped CWEs | Example SecureShip Rules |
|---|---|---|---|
| **A01:2021** | Broken Access Control | CWE-22 (Path Traversal), CWE-284, CWE-285, CWE-862, CWE-863 | `secureship-py-path-traversal`, directory traversal rules |
| **A02:2021** | Cryptographic Failures | CWE-259, CWE-321, CWE-327, CWE-328 (Broken Crypto), CWE-330, CWE-338 (Insecure PRNG), CWE-798 (Hardcoded Credentials) | `secureship-js-insecure-random`, `secureship-py-insecure-hash`, `secureship-js-hardcoded-jwt-secret`, `gitleaks` (all secret rules) |
| **A03:2021** | Injection | CWE-77, CWE-78 (Command Injection), CWE-79 (XSS), CWE-89 (SQLi), CWE-94, CWE-95 (Code Injection / Eval) | `secureship-js-eval`, `secureship-js-child-process-exec`, `secureship-py-subprocess-shell`, `secureship-js-sql-concat`, `secureship-py-sql-format` |
| **A04:2021** | Insecure Design | CWE-209, CWE-501, CWE-522, CWE-256 | Architecture & authentication design flaws |
| **A05:2021** | Security Misconfiguration | CWE-16, CWE-200, CWE-201, CWE-1004, IaC open ports, unprivileged root | `checkov` IaC findings (`CKV_AWS_*`, `CKV_DOCKER_*`, `CKV_K8S_*`) |
| **A06:2021** | Vulnerable and Outdated Components | CWE-1035, CWE-1104, CWE-937, SCA component CVEs | `trivy` (CVE-*), `osv-scanner` (GHSA-*, CVE-*) |
| **A07:2021** | Identification and Authentication Failures | CWE-287, CWE-384, CWE-613, CWE-798 | Session fixation, credential stuffing, weak auth |
| **A08:2021** | Software and Data Integrity Failures | CWE-494, CWE-502 (Deserialization of Untrusted Data), CWE-829 | `secureship-py-pickle-load`, `secureship-py-yaml-load`, supply chain tampering |
| **A09:2021** | Security Logging and Monitoring Failures | CWE-117, CWE-778 | Insufficient logging, log injection |
| **A10:2021** | Server-Side Request Forgery (SSRF) | CWE-918 | SSRF vulnerabilities |

---

## 10. CLI Execution & Wrapper Service Integration Recommendations

When the FastAPI backend wraps the SecureShip CLI inside the container or host:

1. **Subprocess Invocation**:
   ```python
   cmd = [
       "node",
       "/opt/secureship/cli/dist/index.js", # or "secureship" when in container PATH
       "scan",
       scan_dir,
       "--json",
       "--fail-on", "HIGH",
       "--timeout", "120000",
   ]
   ```
2. **Timeout & Execution Safety**:
   - Use `asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)` (argument list form; never `shell=True`).
   - Enforce hard execution timeout of 300 seconds (`asyncio.wait_for(proc.communicate(), timeout=300.0)`).
3. **Exit Code Evaluation**:
   - `returncode in (0, 1)`: Both indicate normal scan completion! Parse `stdout` as JSON.
   - `returncode not in (0, 1)`: Scan failed or had infrastructure errors. Parse `stderr` for diagnostics and set job status to `failed`.
4. **Context Snippet Extraction**:
   - If finding reports `location.filePath` and `location.startLine`, the backend context slicer reads the file from `scan_dir / filePath`, extracts lines `max(1, startLine - 5)` through `min(total_lines, endLine + 5)`, and attaches the snippet to the unified finding model.
5. **Multi-Format Exporter**:
   - JSON: Return unified report directly.
   - SARIF: Format findings into SARIF 2.1.0 schema conforming to `schemas/sarif-schema-2.1.0.json`.
   - HTML: Self-contained template with inline dark-mode CSS.
   - PDF: Generate binary PDF using ReportLab or Weasyprint.
