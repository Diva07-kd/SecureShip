# Snyk CLI-Grade SCA Dependency Remediation Engine in SecureShip

## 1. Executive Summary

SecureShip's automated remediation subsystem has been enhanced with enterprise-grade Software Composition Analysis (SCA) dependency remediation capabilities inspired by the core algorithms of the **Snyk CLI** (Snyk Ltd., $7.4B valuation).

While traditional SAST remediation relies on Large Language Model (LLM) diff generation (Phase 5 Gate 4), **SCA dependency remediation in SecureShip is 100% deterministic, zero-cost, and requires zero LLM calls**. It resolves direct and transitive vulnerabilities across polyglot ecosystems (npm, pnpm, yarn, pip, poetry) using mathematical lockfile graph analysis, SemVer constraint resolution, and multi-strategy manifest pinning.

---

## 2. Architectural Comparison: Snyk CLI vs. SecureShip

| Architectural Dimension    | Snyk CLI (`snyk fix`)                                                    | SecureShip SCA Remediation Engine                                                                                                                                 |
| :------------------------- | :----------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Execution Model**        | Modifies developer's local working directory directly.                   | **Untouchable Working Tree**: All modifications execute inside an ephemeral `$TEMP` Shadow Copy.                                                                  |
| **External Dependencies**  | Heavy runtime footprint (`semver`, `@snyk/*`, external native binaries). | **Zero External Dependencies**: Pure stdlib TypeScript and internal Zod schemas.                                                                                  |
| **Verification Gate**      | Basic post-install check.                                                | **10-Stage Verification Ladder**: Isolated sandbox with baseline regression testing (`APPLY` ➔ `POLICY` ➔ `RESCAN` ➔ `INSTALL` ➔ `TYPECHECK` ➔ `BUILD` ➔ `TEST`). |
| **Security & Anti-Gaming** | Trusted environment assumed.                                             | **Anti-Gaming Policy Enforcement**: Signed HMAC-SHA256 reports, base-file SHA-256 validation, no major version bump without explicit flag.                        |
| **Network Isolation**      | Open network access during execution.                                    | **Scoped Network Sandbox**: Sandbox runs `--network none` by default; temporarily overrides to `--network=bridge` for the `INSTALL` stage only.                   |
| **Triage & Reachability**  | Proprietary cloud reachability.                                          | **Local AST Call-Graph Reachability**: 3-state reachability triage (`reachable`, `no-info`, `not-applicable`, `all`).                                             |

---

## 3. Core Algorithms Extracted & Implemented

### 3.1. Upward Lockfile Graph Traversal (`DepGraphBuilder`)

- **Location**: [`packages/patch-engine/src/sca/dep-graph-builder.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/src/sca/dep-graph-builder.ts)
- Reuses SecureShip's existing [`LockfileTreeParser`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/lockfile/lockfile-tree-parser.ts).
- Computes all ancestor chains (`root ➔ ... ➔ vulnerablePkg`) via upward traversal through the `dependentsMap`.
- Employs **path-scoped visited sets** rather than global visited sets: allows diamond dependencies (`A ➔ B ➔ vuln` and `A ➔ C ➔ vuln`) while reliably breaking circular dependency loops (`A ➔ B ➔ A ➔ vuln`).
- Provides `inducedSubgraph(vulnerablePackage)` returning only nodes along paths to the vulnerability, capped at 50 paths to guarantee bounded memory and execution time.

### 3.2. Pure SemVer Resolution Engine (`MinVersionResolver`)

- **Location**: [`packages/patch-engine/src/sca/min-version-resolver.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/src/sca/min-version-resolver.ts)
- Implemented with **zero external semver npm dependencies**.
- Parses standard semver patterns, range prefixes (`^`, `~`, `>=`, `<=`), and pre-release tags (`-alpha`, `-beta.1`).
- Resolves the minimum safe version satisfying `newVer > currentVer` while favoring non-breaking patch/minor upgrades.
- Provides `isMajorBump(currentVersion, targetVersion)` to enforce breaking change policy controls.

### 3.3. 3-Way Manifest Pinning (`TransitivePinner`)

- **Location**: [`packages/patch-engine/src/sca/transitive-pinner.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/src/sca/transitive-pinner.ts)
- Selects remediation strategy based on graph depth:
  ```
  isDirect → DIRECT_UPGRADE
  !isDirect && chain.length <= 2 → TRANSITIVE_PIN
  !isDirect && chain.length > 2  → OVERRIDES_INJECTION
  ```
- **Preservation Rules**:
  - `package.json`: Detects and preserves original indentation (2-space, 4-space, or tab). Mutates `dependencies`, `devDependencies`, `overrides` (npm/pnpm), or `resolutions` (yarn).
  - `requirements.txt`: Line-by-line streaming editor preserving existing comments, whitespace, and blank lines. Normalizes underscore vs. hyphen package names. Appends annotated pin comments:
    ```txt
    urllib3>=1.26.18  # not directly required, pinned by SecureShip to avoid CVE-XXXX
    ```
  - `pyproject.toml`: Minimal line-based editor targeting `[tool.poetry.dependencies]` and `[project.optional-dependencies]`.
- **Unified Diff Generation**: Generates standard unified diff strings and records SHA-256 base file hashes so that [`FixStore.applyFix`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/fix-store.ts) can validate file integrity before modifying disk.

### 3.4. Purpose-Specific SCA Policy Engine (`ScaPatchPolicyEngine`)

- **Location**: [`packages/patch-engine/src/sca/sca-policy-engine.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/src/sca/sca-policy-engine.ts)
- `PatchPolicyEngine` in Gate 4 intentionally marks manifest files (`package.json`, `pnpm-lock.yaml`) as `PROTECTED_PATTERNS` to stop AI code fixes from altering dependencies.
- `ScaPatchPolicyEngine` acts as an authenticated, purpose-specific gate for SCA upgrades, verifying:
  1. Target package name strictly matches finding package name.
  2. `targetVersion` is strictly greater than `currentVersion`.
  3. No breaking major version bump unless explicitly permitted (`allowMajorBump: true`).
  4. Selected strategy is valid and supported.

### 3.5. 10-Stage Isolated Verification Ladder (`ScaVerificationLadder`)

- **Location**: [`packages/core-engine/src/remediation/sca-verification-ladder.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/sca-verification-ladder.ts)
- Executes across 10 distinct verification stages:
  1. `APPLY`: Manifest edits applied strictly within `$TEMP` Shadow Copy.
  2. `POLICY`: Validated by `ScaPatchPolicyEngine`.
  3. `SYNTAX`: Non-applicable for manifest edits; marked as `SKIPPED` (FixReport schema consistency).
  4. `RESCAN`: Runs `OsvScannerAdapter` or `TrivyAdapter` on patched shadow copy to confirm CVE eradication.
  5. `NEW_FINDINGS`: Checks for newly introduced vulnerabilities.
  6. `IMPORTS`: Non-applicable for manifest edits; marked as `SKIPPED`.
  7. `INSTALL`: Executes package manager lock/dry-run (`npm install --package-lock-only`, `pnpm install --lockfile-only`, `pip install -r requirements.txt --dry-run`). **Temporary network override `--network=bridge` enabled for this stage only**.
  8. `TYPECHECK`: Executes `tsc --noEmit` if project contains `tsconfig.json`.
  9. `BUILD`: Executes `npm run build` if package.json has a build script.
  10. `TEST`: Baseline vs. Patched regression test run.
- Emits an **HMAC-SHA256 signed** `ScaFixReport` (v1.1) written to `.secureship/sca-fix-<fingerprint>.json`.

### 3.6. 3-State Reachability CLI Triage

- **Location**: [`packages/reachability/src/sca/sca-reachability-analyzer.ts`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/sca/sca-reachability-analyzer.ts) & [`packages/cli/src/commands/scan.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/scan.ts)
- Enables developer triage using the `--reachability-filter` option:
  - `reachable`: Findings where `reachability === 'REACHABLE_CALL_PATH' || reachability === 'REACHABLE_IMPORT'`.
  - `no-info`: Findings where `reachability === 'UNKNOWN'`.
  - `not-applicable`: Findings where evidence kind is `'NOT_APPLICABLE'`.
  - `all`: Unfiltered view.

---

## 4. Verification Evidence & Hardening Matrix

| Test Suite                | File                                                                                                                                     | Tests        | Outcome            |
| :------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------- | :----------- | :----------------- |
| **DepGraphBuilder**       | [`dep-graph-builder.test.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/test/sca/dep-graph-builder.test.ts)                    | 6            | ✅ PASS            |
| **MinVersionResolver**    | [`min-version-resolver.test.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/test/sca/min-version-resolver.test.ts)              | 15           | ✅ PASS            |
| **TransitivePinner**      | [`transitive-pinner.test.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/test/sca/transitive-pinner.test.ts)                    | 15           | ✅ PASS            |
| **ScaPolicyEngine**       | [`sca-policy-engine.test.ts`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/test/sca/sca-policy-engine.test.ts)                    | 5            | ✅ PASS            |
| **ReachabilityFilter**    | [`sca-reachability-filter.test.ts`](file:///c:/dev/SecureShip-IDE/packages/reachability/test/sca-reachability-filter.test.ts)            | 4            | ✅ PASS            |
| **ScaVerificationLadder** | [`sca-verification-ladder.test.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/test/remediation/sca-verification-ladder.test.ts) | 9            | ✅ PASS            |
| **CLI SCA Fix Dispatch**  | [`sca-remediation-cli.test.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/test/sca-remediation-cli.test.ts)                             | 3            | ✅ PASS            |
| **Full Repo Suite**       | `pnpm test` (104 files)                                                                                                                  | **806**      | **✅ 100% PASS**   |
| **Anti-Gaming Suite**     | `pnpm run verify:mutations`                                                                                                              | **28/28**    | **✅ 100% CAUGHT** |
| **TypeScript Typecheck**  | `pnpm typecheck` (11 packages)                                                                                                           | **0 errors** | **✅ CLEAN**       |

---

## 5. CLI Usage Examples

```bash
# 1. Scan with Snyk-style reachability filtering
secureship scan --reachability-filter=reachable

# 2. View SCA finding in scan report and note fingerprint
secureship scan --format json --output report.json

# 3. Deterministically remediate SCA finding through the 10-stage ladder
secureship fix <fingerprint>

# 4. Apply the verified SCA fix to developer working tree (validates HMAC and base-file SHA-256)
secureship fix apply .secureship/sca-fix-<fingerprint>.json
```
