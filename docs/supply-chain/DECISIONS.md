# Architecture Decision Records: Supply-Chain Threat Engine

This document records the architectural decisions, trade-offs, and Invariant P1 alignment for the SecureShip Supply-Chain Threat Engine (Phase 1: WP0–WP3).

---

## ADR-001: Engine Placement and Monorepo Integration

- **Status**: Accepted
- **Context**: The Supply-Chain Threat Engine detects zero-day malware, install script traps, typosquats, Unicode/bidi attacks, and obfuscated payloads in third-party dependencies (npm/PyPI).
- **Decision**: Place the engine inside `packages/core-engine/src/supply-chain/` rather than creating a separate top-level package.
- **Rationale**:
  1. Deep integration with existing `ScanOrchestrator`, `SuppressionLedger`, and Gates 1–3 pipeline.
  2. Avoids package proliferation while allowing seamless reuse of contracts, logging, and reporting primitives.
  3. Consistent coverage enforcement under the monorepo's `packages/core-engine/**` coverage boundary.

---

## ADR-002: Finding Contract & Category Harmonization

- **Status**: Accepted
- **Context**: Supply-chain threats need to be normalized, reported, and audited alongside SAST, SCA, SECRET, and IAC findings.
- **Decision**:
  1. Add `'SUPPLY_CHAIN'` to `FindingCategorySchema` in `@secureship/contracts`.
  2. For Phase 1, represent supply chain findings as `NormalizedFinding` with `category: 'SUPPLY_CHAIN'`, `scannerName: 'generic'`, and rule IDs matching `SC-*`.
  3. Supply-chain specific metadata (capabilities, provider status, blocking flags) is attached within `evidence[0].metadata`.
  4. WP5 (Phase 2) will provide first-class typed extension schemas (`SupplyChainFindingSchema`).
- **Invariant P1 Impact**:
  - `SuppressionLedger.computeSummary()` initializes `byCategory` with `SUPPLY_CHAIN: 0`.
  - Adding this enum member maintains strict type checking and zero uncounted findings.

---

## ADR-003: Suppression Ledger & Invariant P1 Contract

- **Status**: Accepted
- **Context**: Invariant P1 enforces:
  $$\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$$
- **Decision**:
  1. Add `'SUPPLY_CHAIN_ALLOWLISTED'` to `SuppressionReasonCodeSchema`.
  2. All SC findings discovered during analysis increment `ledger.recordRaw(sc.findings.length)`.
  3. Findings are evaluated against Gate 1 (scope), user ignore rules, baseline ledger, and allowlists.
  4. Supply-chain findings filtered by policy allowlists are suppressed with reason code `'SUPPLY_CHAIN_ALLOWLISTED'`.
  5. Install-script and Unicode rules are marked `reachabilityGated: false` and are never erroneously suppressed by Gate 2.
  6. Invariant P1 is strictly verified by `ledger.verifyInvariant()` at report generation time.

---

## ADR-004: Reachability Enum Mapping in Phase 1

- **Status**: Accepted
- **Context**: The Supply-Chain Threat specification outlines reachability states:
  `REACHABLE | DEP_REACHABLE_ONLY | NOT_REACHABLE | NOT_APPLICABLE | UNKNOWN`.
  However, the base `ReachabilitySchema` in `@secureship/contracts` currently accepts:
  `REACHABLE_CALL_PATH | REACHABLE_IMPORT | UNREACHABLE | UNKNOWN`.
- **Decision**:
  - In Phase 1, SC findings set base `reachability: 'UNKNOWN'`.
  - Detailed SC reachability is tracked in `ScReachabilitySchema` inside `@secureship/contracts` and attached to `evidence[0].metadata.scReachability`.
  - In Phase 2 (WP4–WP5), unified reachability or dual-mode typing will be introduced without breaking downstream CLI or SARIF consumers.

---

## ADR-005: Zero External Runtime Dependencies

- **Status**: Accepted
- **Context**: Adding third-party dependencies increases attack surface and supply-chain risk for a security tool.
- **Decision**:
  - Use 0 new runtime npm dependencies.
  - Hashing uses `node:crypto` (`createHash('sha256')`).
  - Path normalization uses `node:path`.
  - File reading and directory traversal uses `node:fs` and `fast-glob` (already in `core-engine`).
  - Streaming and tar operations use `node:zlib` and `node:stream`.

---

## ADR-006: Metadata Providers & Graceful Degradation

- **Status**: Accepted
- **Context**: Registry metadata is needed for chrono-anomalies, download counts, and maintainer changes, but network access may be disabled or flaky.
- **Decision**:
  - `NullProvider` is the default provider: returns `UNAVAILABLE` for all calls, allowing pure detectors to run offline without errors.
  - Detectors handle `UNAVAILABLE` gracefully by flagging `metadataUnavailable: true` with lower confidence or info-level diagnostics.
  - `SnapshotProvider` serves deterministic, fixture-driven packument and download records for offline tests and air-gapped environments.
  - `RegistryProvider` is strictly opt-in via policy configuration and disabled by default.

---

## ADR-007: Popular Packages Seed & Typosquat Indexing

- **Status**: Accepted
- **Context**: Typosquat detection compares dependency names against popular packages. Calculating Levenshtein distances against tens of thousands of packages on each file is computationally prohibitive.
- **Decision**:
  - Seed `packages/core-engine/src/supply-chain/data/popular-npm.json` with ~200–300 verified top packages.
  - Implement `PopularListIndex` with length-bucketed pre-indexing: candidate names only compare against packages where $|len_{pkg} - len_{cand}| \le 2$.
  - Unrestricted Damerau-Levenshtein implementation with early-exit threshold guarantees $< 5\text{ms}$ execution time per package.

---

## ADR-008: AST Capability Detection via Existing Tree-Sitter WASM Singleton

- **Status**: Accepted
- **Context**: Evaluating dangerous package behaviors requires static AST analysis of JavaScript and TypeScript syntax without executing hostile code or introducing new heavy runtime dependencies.
- **Decision**:
  1. Reuse the existing WASM Tree-sitter singleton via `TreeSitterLoader.getParser(lang)` in `packages/reachability`.
  2. Implement strict resource isolation: always wrap Tree-sitter parse trees in `try ... finally { tree.delete(); }` to prevent WebAssembly heap exhaustion.
  3. Support AST queries for `process.env`, network modules/APIs (`http`, `https`, `fetch`, `net`), sensitive filesystem targets (`~/.ssh`, `~/.aws`, `.npmrc`, `/etc/passwd`), shell execution (`child_process`), dynamic `eval`/`Function`, dynamic `require`, and internal debugging bindings.
  4. Implement robust alias resolution for destructured imports, `const r = require; r('child_process')`, and computed member expressions (`cp['ex' + 'ec']`).
  5. Fallback to bounded token-level scanner only on parse failure, marking evidence `confidence: LOW`.

---

## ADR-009: Reachability Correlation & Non-Gated Exceptions

- **Status**: Accepted
- **Context**: Invariant P1 and developer ergonomics require distinguishing between reachable active capabilities and dormant dependency capabilities, while never suppressing install-time or syntax-level zero-day attacks.
- **Decision**:
  1. Map capability AST sites to enclosing function nodes and query `ReachabilityEngine`.
  2. Dangerous capability combinations (`SC-CAP-100+`) reachable from user-code entrypoints escalate to **P1 CRITICAL**.
  3. Capabilities present in dependencies but not reachable from entrypoints are marked `DEP_REACHABLE_ONLY`.
  4. When call-graph reachability is unavailable or fails, mark `UNKNOWN` without downgrading finding severity.
  5. **Non-Gated Exceptions**: Install-time scripts (`SC-INSTALL-*`), Trojan Source Unicode attacks (`SC-UNI-*`), registry manifest confusion (`SC-META-003`), and governance risks (`SC-GOV-*`) are classified `reachability: 'NOT_APPLICABLE'`. Gate 2 reachability analysis never downgrades, filters, or suppresses these findings.

---

## ADR-010: Gate 3 AI Threat Slicer Hostile Prompt Injection Defense

- **Status**: Accepted
- **Context**: Third-party package code sent to Gate 3 LLM triage is adversary-controlled input. Malicious packages may embed prompt injection attacks or Trojan Source characters.
- **Decision**:
  1. Wrap all dependency code in explicit delimited untrusted data blocks (`<<<UNTRUSTED_DEPENDENCY_DATA>>>`).
  2. Instruct the LLM that code content is inert untrusted payload data that cannot issue instructions.
  3. Strip and visually escape Bidi overrides (`U+202A`–`U+202E`, `U+2066`–`U+2069`) and zero-width code points (`U+200B`–`U+200D`, `U+FEFF`, `U+3164`) into visual strings (`\u202E`).
  4. Redact environment variables, tokens, and private keys prior to serialization.
  5. **Hard Guardrail**: The LLM triage verdict may add explanations or adjust confidence on heuristic rules (`SC-HALL-*`, `SC-GOV-*`), but is strictly forbidden from downgrading or suppressing deterministic CRITICAL, blocking, or P1 findings.
  6. Provide deterministic Attack Vector Explainer templates when AI triage is offline or unavailable.

---

## ADR-011: Gate 4 Pre-Install Security Gate & Universal `--ignore-scripts`

- **Status**: Accepted
- **Context**: Upgrading dependencies to fix CVEs (Gate 4) can inadvertently introduce zero-day supply-chain malware if the target version contains install-script traps, typosquats, or chrono anomalies.
- **Decision**:
  1. Implement `PreInstallGate` in `packages/core-engine/src/remediation/pre-install-gate.ts`, integrated into `ScaVerificationLadder` Stage 2 (POLICY).
  2. Before applying an upgrade, dry-run prospective lockfile changes in a temporary shadow directory.
  3. Block target versions that introduce install scripts, chrono/semver anomalies, manifest confusion, or blocking threats.
  4. Automatically evaluate candidate safe fallback versions in descending semver order.
  5. Enforce `--ignore-scripts` and scrub environment credentials (`AWS_*`, `NPM_TOKEN`, `SSH_AUTH_SOCK`) across all package manager operations in `SafeProcessRunner`.

---

## ADR-012: CLI Flags, Reporting Sanitization & Security Hardening

- **Status**: Accepted
- **Context**: Users require standalone supply chain audits, offline air-gapped execution, and safe terminal reporting without spoofing or ReDoS vulnerabilities.
- **Decision**:
  1. Add `--supply-chain-only` to run the threat engine exclusively without invoking external SAST/SCA scanners.
  2. Pass `--offline` through to force `NullProvider`, ensuring zero outbound network transmission.
  3. Implement `sanitizeTerminalOutput` in CLI reporting to strip ANSI/OSC escape sequences and visually escape Bidi controls.
  4. Implement `SafeTarExtractor` with path traversal guards, symlink/hardlink rejection, and tar-bomb size caps.
  5. Enforce ReDoS resilience with linear scanning and verify byte-identical deterministic JSON serialization.

---

## ADR-013: SPEC-GAP-1 — Short-Name Single-Edit Typosquats Handling

- **Status**: Accepted
- **Context**: For short popular package names of length 5 (e.g. `react`, `axios`, `chalk`), a single-edit transposition or substitution yields edit distance $D = 1$ and similarity score $1 - 1/5 = 0.80$, falling below the default threshold of $0.82$ and missing critical squats like `raect` and `axois`.
- **Decision**:
  1. Treat any candidate with edit distance $D = 1$ against a popular package of length $\ge 5$ as a typosquat candidate, regardless of whether $1 - D/\max(\text{len}) \ge 0.82$.
  2. For $D \le 2$ where similarity score $< 0.82$ but $D = 1$ on length $\ge 5$, assign default confidence `MEDIUM` and severity `MEDIUM` in the absence of provider download corroboration.
  3. When registry metadata corroborates low candidate downloads and high target downloads, escalate to `HIGH`.

---

## ADR-014: SPEC-GAP-2 — Charset-Aware Entropy Normalization for Hex Payloads

- **Status**: Accepted
- **Context**: A 16-symbol hexadecimal alphabet $[0-9a-fA-F]$ has theoretical maximum Shannon entropy $H = \log_2(16) = 4.0$. With a standard threshold of $H \ge 4.5$ designed for 64-symbol base64 ($H_{\max} = 6.0$), pure hex payloads could never trigger $H \ge 4.5$.
- **Decision**:
  1. Implement charset-aware threshold normalization in `detectHighEntropy`.
  2. For pure hexadecimal string literals ($[0-9a-fA-F]+$), normalize the entropy threshold:
     $$\text{effectiveThreshold} = \text{threshold} \times \frac{4.0}{6.0} = 4.5 \times \frac{2}{3} = 3.0$$
  3. High-entropy hex payloads with $H \ge 3.0$ and length $\ge 64$ are flagged as `SC-OBF-001`.

---

## ADR-015: SPEC-GAP-3 — Implicit node-gyp Install Semantics Alignment with npm

- **Status**: Accepted
- **Context**: According to official npm lifecycle documentation, implicit native compilation (`node-gyp rebuild`) triggers on `binding.gyp` only if neither `install` nor `preinstall` scripts are defined in `package.json`.
- **Decision**:
  1. Update `detectInstallScripts` to inspect both `scripts.install` and `scripts.preinstall`.
  2. If `scripts.preinstall` is defined, `SC-INSTALL-002` is NOT triggered when `binding.gyp` is present.
