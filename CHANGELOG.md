# Changelog

All notable changes to the SecureShip repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] - 2026-11-03 - Wave 1: Crash-Consistent Persistence & Atomic Protocols (Gate 13 / F-FLT-004)

### Changed (Breaking Changes)

- **Policy Validation on Update (HTTP 400):** `store.updatePolicy` and `POST /api/policy` now validate policy update payloads structurally and type-check all values. Invalid payloads are rejected with HTTP 400 `{"error":"Invalid policy payload","details":[...field names]}` with existing policy preserved.
- **Unknown Policy Keys Dropped:** Unrecognized fields and prototype properties (`__proto__`, `constructor`, `prototype`) in policy payloads are stripped and never persisted to disk.
- **Strict POSIX File Modes (0600 / 0700):** Fleet database files (`fleet-db.json`), backup files (`.bak`), quarantine files (`.corrupt-*`), and temp files are created with mode `0600` (read/write owner only), and newly created directories with mode `0700`. External non-owner group or world read access is rejected.
- **Format Version 1 & Downgrade Refusal:** Databases are saved in Format Version 1 with cryptographic SHA-256 integrity digests. Loading a database with `formatVersion > 1` throws `FleetStoreUnsupportedVersionError` and halts modification, preventing accidental downgrades.

### Security Enhancements

- **Crash-Consistent Atomic Write Protocol:** Direct in-place `fs.writeFileSync` is replaced by an atomic temp-file-and-rename pipeline (`.tmp.<pid>.<time>.<rand>`) with `fsyncSync` and read-back verification against in-memory state.
- **Corrupt State Quarantining:** Corrupted primary or backup database files are quarantined to immutable timestamped forensic files (`.corrupt-<UTC yyyymmddThhmmssZ>-<rand>`) rather than overwritten or silently wiped.
- **Resilient Disaster Recovery:** At startup, `FleetStore` verifies both primary and backup files. If the primary file was truncated or corrupted during an abrupt system crash, it automatically recovers from the backup, emits audit warning `FLEET_STORE_RECOVERED_FROM_BACKUP`, and heals the primary database immediately.
- **Windows File Lock Backoff:** `atomicReplace` retries Windows file-rename operations against transient antivirus scanner and indexer locks with exponential backoff (10-320ms).
- **Container Single-File Bind Mount Fallback:** EBUSY/EXDEV errors on Docker single-file bind mounts gracefully trigger verified in-place fallback persistence with backup recovery.
- **Observability:** Added `store.getPersistenceStatus()` and `store.getLoadReport()` exposing storage health, consecutive failure counts, recovery source, and quarantined files without leaking secrets or telemetry.

---

## [0.6.0] - 2026-11-03 - Wave 1: Fleet Hardening & Credential Protection (Gate 11 / F-FLT-001)

### Changed (Breaking Changes)

- **Generic `HOST` Environment Variable Ignored:** The generic `HOST` variable is ignored by SecureShip Fleet server to prevent accidental network exposure. Operators must use `FLEET_HOST`.
- **Port Precedence Updated:** Server port resolution order is now: explicit CLI argument > `FLEET_PORT` > `PORT` > `4000`.
- **Empty `authToken` String Rejected:** Passing an empty string or whitespace-only token to `new FleetServer({ authToken: "" })` now throws an error.
- **Mandatory Authentication for Entry Points:** Both `secureship fleet start` and standalone `secureship-fleet` enforce authentication by default. When no token is provided, a 256-bit token is auto-generated into a restricted 0600 file (`~/.secureship/fleet-token`) and only its path is printed.
- **Default-Deny Endpoint Gating:** Every route requires authentication by default except explicit public endpoints (`GET /` and `GET /dashboard`, serving HTML only with zero telemetry data).
- **Flag Deprecation:** `--token <token>` is deprecated in favor of `FLEET_TOKEN_FILE` or `FLEET_TOKEN` to avoid process list exposure. Emits a stderr warning on use.

### Security Enhancements

- **Token Secrecy:** Removed raw token output from CLI stdout logs across all launch paths. `FleetServer` retains only SHA-256 token digests in an isolated WeakMap, preventing token extraction via JSON serialization or inspection.
- **Pre-Auth Attack Neutralization:** Unauthenticated callers cannot reach Zod schema validation or JSON error parsing, eliminating oracle and work amplification risks.
- **Payload Too Large (413) Honesty:** Replaced socket reset on payload cap overflow with clean HTTP 413 responses with `Connection: close` and body draining.
- **Client Transport Safety:** `FleetClient` and fleet CLI subcommands refuse to transmit tokens over cleartext HTTP to remote hosts unless `SECURESHIP_ALLOW_INSECURE_FLEET_HTTP=1` is set.
- **Multi-Source Credential Extraction:** Support for both `Authorization: Bearer <token>` and `x-fleet-token` headers for reverse proxy compatibility.
- **Docker & Kubernetes Secrets:** Native support for symlinked secret volume mounts (`0444`/`0440`) via `FLEET_TOKEN_FILE`.

---

## [0.5.0] - 2026-10-25 - Phase B: Function-Level Reachability for SCA

### Added

- **Function-Level (Symbol-Level) Reachability Pipeline (`@secureship/reachability`)**:
  - `VulnerableSymbolEntrySchema` and bundled dataset `vulnerable-symbols.json` containing 18 cross-verified advisories for npm and PyPI with source URLs and fix commits.
  - Cryptographic offline manifest `vulnerable-symbols.manifest.json` validating SHA-256 digest at load time.
  - Three-tier candidate extractor (`CandidateExtractor`): Tier 1 `STRUCTURED_ADVISORY`, Tier 2 `CURATED_DB`, Tier 3 hardened `HEURISTIC_TEXT` with stoplist and identifier boundaries.
  - Iterative bounded AST usage fact extraction (`JsSymbolUsageExtractor` and `PythonSymbolUsageExtractor`) covering 13 namespace escape forms, literal member/computed accesses, subpaths, callbacks, and dynamic loaders.
  - Hardened `CallGraphExtractor` using $O(N)$ iterative map traversal, and conservative `CallPathProver` proving entrypoint-to-symbol chains (max 10 hops, sorted tie-break).
  - Decision procedure implementing Rules R1–R6 and Preconditions P1–P10 in `ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport`.
  - Additive `ReferenceScanner` exclude mode skipping successfully parsed code files while retaining checks on framework templates (`.vue`, `.svelte`), configs, Dockerfiles, and scripts.
- **Contracts & Schema Version 1.3 (`@secureship/contracts`)**:
  - Additive evidence kinds: `SYMBOL_REFERENCED`, `SYMBOL_CALL_PATH`, `UNINVOKED_SYMBOL`, `NAMESPACE_ESCAPES`, `SYMBOL_DATA_UNAVAILABLE`.
  - Additive fields: `symbols`, `symbolSource`, `symbolUsageSites`, `symbolDataset`, `blockedBy`, `functionLevel` summary.
  - `UserConfig.reachability.functionLevel` (`'auto' | 'off'`). Repo config trust guard rejecting repo-resident reachability settings.
- **CLI Commands & Reporting (`@secureship/cli`)**:
  - New command: `secureship reachability symbols [--json]` for dataset inspection.
  - CLI flag: `--no-function-level` to disable function-level analysis.
  - Human terminal tags: `[CALL PATH PROVEN]`, `[SYMBOL REFERENCED]`, `[SYMBOL NOT REFERENCED]`, `[IMPORTED]`.
  - Rich `--verbose` output displaying resolved symbol, source tier, usage sites, and call-path chains.
  - Mandatory disclaimer on all outputs: _"Function-level analysis is static and best-effort; vulnerable-symbol data may be incomplete."_
  - SARIF 2.1.0 export carrying symbol evidence in `properties.secureship.reachability`.
- **Verification & Benchmark Suite (`@secureship/benchmark`)**:
  - 62 hand-labeled benchmark fixtures in `packages/benchmark/corpus/function-level/` with 0 false-unreachables (hard threshold 0).
  - Real-repo evaluation against 3 pinned repositories with real Trivy (0.76.0) and OSV-Scanner (2.7.0).
  - Independent AST audit script (`scripts/independent-audit.mjs`) verifying 0 false-unreachables across 46 audited findings and measuring 20.8% noise reduction.
  - Offline dataset integrity validation script: `pnpm verify:symbols`.

---

## [0.4.0] - 2026-10-19 - Phase 4: AI Triage (Gate 3)

### Added

- **Context Slicer Package (`@secureship/context-slicer`)**:
  - Syntactic AST scoping for JavaScript, TypeScript, and Terraform IaC extracting minimal enclosing functions, classes, and resource blocks.
  - Usage-site search discovering call sites and taint sources within token budgets.
  - Sensitive file denylist blocking `.env*`, `.git/*`, `certs/`, `*.pem`, `*.key`, `*.pfx`, `*.tfstate`, `id_rsa`, `.npmrc`, `.aws/`, and credential stores.
  - Symlink jailing using canonical realpaths (`fs.realpathSync`) preventing workspace breakout.
  - Two-pass automated secret redaction scanning raw files and sliced fragments for Stripe (`sk_live_`, `rk_live_`), Slack (`xox*`), Google (`AIza*`), npm (`npm_*`), credentialed URLs, variable assignments to secrets, and high-entropy literals (>= 32 chars, Shannon entropy >= 3.6).
  - Optional Gitleaks verification scan of assembled payloads before transmission.
  - Root-relative POSIX path normalization stripping absolute OS paths and usernames.
- **AI Triage Package (`@secureship/ai`)**:
  - `PromptBuilder` generating random 24-character hexadecimal nonces per request, neutralizing delimiter lookalikes in untrusted input, and generating distinct prompt variants for self-consistency evaluation.
  - `HttpClient` enforcing loopback restrictions (literal `localhost`, `127.0.0.0/8`, `[::1]`), HTTPS requirement for non-loopback, absolute redirect refusal (`redirect: 'error'`), max concurrency (default 2), and exponential backoff on HTTP 429.
  - `SkepticEngine` enforcing rigid Zod schema validation, multi-layer prompt injection detection, and strict verbatim citation verification against primary code slices.
  - `ConsentManager` cryptographically binding user consent to `scheme + host + port`.
  - `AiCache` HMAC-SHA256 external cache outside the target repository, re-verifying citations upon read.
  - `OutputSanitizer` stripping ANSI escapes, control characters, bidi overrides, zero-width characters, and dangerous link schemes from model output.
  - Anthropic Messages API (`/v1/messages`) and OpenAI-compatible Chat Completions (`/v1/chat/completions`) native adapters supporting local models (Ollama, LM Studio, vLLM).
  - Test-only fake provider (`@secureship/ai/testing`) for deterministic offline verification.
- **Gate 3 Pipeline & Policy Engine (`@secureship/core-engine`)**:
  - Separate `UserConfigSchema` loaded strictly from `~/.secureship/config.json`, CLI flags, and environment variables. Repo `ConfigSchema` strictly rejects `ai` and `gate3` keys with security warnings.
  - No `--api-key` CLI flag; keys sourced exclusively from environment variables or 0600 file, never logged or leaked.
  - Automatic skip of `SECRET` category findings and credential-class SAST findings (`CWE-798`, `CWE-259`, `CWE-321`, `secureship-js-hardcoded-jwt-secret`) under skip reason `CREDENTIAL_CLASS`.
  - Full suppression ledger accounting upholding Accounting Invariant P1 with suppression code `GATE3_LIKELY_FALSE_POSITIVE`.
  - Severity floor: `CRITICAL` and `HIGH` findings are never suppressed by default; only `SAST` findings qualify.
  - Failure isolation: provider or network failures leave findings reported with warnings and never alter scan exit codes.
  - Final deterministic sort: Severity desc -> Gate 2 reachability -> Gate 3 AI verdict -> Fingerprint.
- **CLI Commands & Verification (`@secureship/cli`)**:
  - `secureship ai enable`, `secureship ai disable`, and `secureship ai status` commands.
  - `secureship explain <report>` command jailing paths within `--root` (default cwd) and labeling output advisory.
  - `--ai`, `--gate3 <annotate|suppress>`, `--ai-dry-run`, `--ai-estimate`, `--ai-trace`, `--no-ai-cache` scan flags.
  - Prominent experimental warning banner displayed whenever `--gate3 suppress` is active.

---

## [0.3.0] - 2026-10-18 - Phase 3: Reachability Engine (Gate 2)

### Added

- **Reachability Engine Package (`@secureship/reachability`)**:
  - Bundled WebAssembly Tree-sitter parsers (`tree-sitter.wasm`, `tree-sitter-javascript.wasm`, `tree-sitter-typescript.wasm`, `tree-sitter-tsx.wasm`, `tree-sitter-python.wasm`) with hardcoded SHA-256 cryptographic integrity manifest.
  - Cross-platform, zero native C++ bindings or `node-gyp` requirements.
  - Fail-closed integrity verification (`verifyBundledWasm()`).
  - AST extraction cache stored outside the target repository (`~/.secureship/cache` or `%LOCALAPPDATA%/secureship/cache`), HMAC-SHA256 authenticated with a local machine key (`0600` permissions), immune to committed cache-poisoning attacks.
  - Fast iterative BFS import graph traversal from discovered production entrypoints.
  - Comprehensive JS/TS module resolver supporting `tsconfig.json` `baseUrl` & `paths`, `package.json` `#imports`, relative resolution, and monorepo workspace packages.
  - Python module resolver with static package map, PEP 503 normalization, and `.venv/` `.dist-info/top_level.txt` parser.
  - Lockfile dependency tree parser supporting `package-lock.json` (v2 & v3), `pnpm-lock.yaml` (v6 & v9), `poetry.lock`, and `Pipfile.lock` for transitive dependency parent tracing.
  - Reference scanner checking non-code files (package scripts, configs, Dockerfiles, YAML/TOML, and production string literals) before declaring any package unimported.
- **Gate 2 Orchestrator & Policy Engine**:
  - `annotate` mode (default): Attaches `ReachabilityDetail` evidence chains to findings and prioritizes reachable findings before unknown and unreachable findings.
  - `suppress` mode (opt-in): Selectively suppresses qualifying SCA vulnerabilities (leaf direct dependencies, verified unimported with `analysisConfidence: HIGH`, and severity below `neverSuppressSeverities`).
  - Suppression reason code `GATE2_UNREACHABLE` integrated into the Suppression Ledger while strictly upholding Accounting Invariant P1 ($\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$).
  - Mandatory disclaimer on all outputs: _"Import-level analysis only; not proof of exploitability or safety."_
  - Whole-repository graph construction in incremental `--diff` / `--staged` mode.
- **CLI Commands & Reporting**:
  - New command `secureship graph [target]` with options `--json` and `--format dot` for GraphViz visualization.
  - New scan options `--gate2 <off|annotate|suppress>` and `--no-cache`.
  - Human terminal tags: `[IMPORTED]`, `[NOT IMPORTED]`, `[UNKNOWN]`.
  - WASM grammar verification table in `secureship doctor`.
  - Updated `secureship status` displaying included import-level reachability in Free BYOK tier.
- **Verification & Benchmark Suite (`@secureship/benchmark`)**:
  - 31 Gate 2 corpus cases covering ESM/CJS imports, type-only imports, dynamic requires, config references, transitive chains, monorepos, and Python aliases.
  - Ground-truth fuzz test generating $\ge 300$ small JS & Python projects asserting $0$ false-unreachables and outputting confusion matrix.
  - Metamorphic mutation tests asserting that adding configs, string literals, npm scripts, syntax errors, or dynamic calls moves verdicts away from `UNREACHABLE-HIGH`.
  - Safety tests proving zero child processes spawned, zero network calls, and directory traversal escape rejection.
  - Real-repository evaluation report (`docs/phase3/EVALUATION.md`) evaluating `twbs/bootstrap`, `python-poetry/poetry`, and `full-stack-fastapi-postgresql` with a verified false-unreachable rate of **0.0%**.

---

## [0.2.0] - 2026-10-18 - Phase 2: Scan Pipeline

### Added

- **Multi-Engine Scanner Adapters (`@secureship/scanner-adapters`)**:
  - `OpengrepAdapter`: SAST scanner with fallback to Semgrep and bundled local rules.
  - `GitleaksAdapter`: Fast regex secret detection with double-redaction and `--no-git` scanning.
  - `TrivyAdapter`: Dependency vulnerability and misconfiguration scanning with `--offline` DB check.
  - `OsvScannerAdapter`: Advisory lockfile scanning across npm, pnpm, yarn, and pip.
  - `CheckovAdapter`: Infrastructure-as-Code (Terraform, Dockerfile, Kubernetes) scanning in soft-fail mode.
- **Process Isolation & Subprocess Runner**:
  - Isolated temporary execution directories (`mkdtemp` with `0700` POSIX permissions).
  - Target boundary guard against planted binary attacks in `BinaryResolver`.
  - Process tree termination (`taskkill` on Windows, process groups on POSIX) for timeouts and SIGINT (exit code 130).
- **Universal SARIF 2.1.0 Parser**:
  - Multi-run SARIF parser normalizing heterogeneous vendor outputs into `NormalizedFinding`.
  - Tolerant Zod schema parsing rule metadata, regions, and CVSS security severity scores.
  - Path traversal boundary protection and URL decoding.
  - Snippet truncation to 500 characters and secret sanitization with `SecretRedactor`.
- **Finding Correlation & SCA Alias Merging**:
  - Merging duplicate SCA findings matching `lockfile + ecosystem + package + version` with overlapping CVE/GHSA/OSV aliases.
- **Gate 1 Context-Aware Scope Tagging**:
  - Fast, bounded path classification (`PRODUCTION`, `TEST_OR_MOCK`, `EXAMPLE`, `DOCUMENTATION`).
  - Strict preservation of provider-specific credentials in tests unless matching known placeholder tokens.
  - `--include-nonproduction` flag to bypass Gate 1 suppression.
- **Auditable Mathematical Suppression Ledger**:
  - Invariant P1 accounting: $\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$.
  - Suppression reasons: `GATE1_TEST_OR_MOCK`, `GATE1_EXAMPLE`, `GATE1_DOCUMENTATION`, `USER_IGNORE_RULE`, `BASELINE_KNOWN`.
  - P1 Precedence: Diff scoping is applied first; out-of-diff findings never enter the ledger.
- **Boundary-Safe Git Scoping**:
  - Incremental scanning via `--diff <ref>`, `--staged`, and `--diff-lines`.
  - Validation rejecting refs with leading dashes (`-`) or shell metacharacters to eliminate option injection risks.
  - NUL-delimited parsing (`git diff -z`, `git status -z`).
- **Standardized SARIF 2.1.0 Exporter**:
  - Schema-valid export strictly satisfying the official OASIS SARIF 2.1.0 schema (validated with Ajv).
  - Suppression entries included when `--include-suppressed` is set.
- **CLI Scan Command (`secureship scan`)**:
  - Rich human-readable status table and grouped findings.
  - Pure parseable JSON output on stdout when `--json` is enabled.
  - Support for `--output <file>`, `--sarif <file>`, `--strict`, `--offline`, `--no-color`, and `--fail-on`.
- **Benchmark Evaluation Harness (`@secureship/benchmark`)**:
  - Replay engine measuring Precision, Recall, F1, and Suppression-Recall against recorded corpora.
  - Ground-truth synthetic scenarios across SAST, Secrets, and SCA.
- **Engineering Standards**:
  - Flat ESLint config (`eslint.config.js`) and Prettier (`.prettierrc.json`).
  - GitHub Actions CI workflow matrix (`.github/workflows/ci.yml`) across Ubuntu, Windows, and macOS on Node 18, 20, 22.

---

## [0.1.0] - 2026-10-18 - Phase 1: Foundation

### Added

- Core workspace packages: `@secureship/contracts`, `@secureship/core-engine`, `@secureship/cli`.
- `SafeProcessRunner` with environment sanitization and buffer caps.
- `ProjectDetector` heuristics for languages, package managers, and build tools.
- `SecretRedactor` patterns for AWS, GitHub, Slack, Stripe, and private keys.
- CLI commands: `secureship doctor`, `secureship detect`, `secureship status`.
- Initial 74 Phase 1 test suites.
