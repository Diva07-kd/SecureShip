# SecureShip Phase 3: Reachability Engine — Scope, Trust Model & Limitations

This document outlines the security trust model, architectural boundaries, and explicit limitations of the SecureShip Phase 3 Reachability Engine (Gate 2).

---

## 1. Security Trust Model & CI Configuration Advice

> [!WARNING]
>
> ### Repository Configuration Trust Model (Amendment A16)
>
> When scanning untrusted external pull requests or open-source forks, **never** allow the scanner to read an unreviewed `secureship.config.json` from the target repository root.
>
> A malicious pull request could include a committed `secureship.config.json` designed to weaken security gates by:
>
> - Defining overly broad ignore rules or baseline suppressions.
> - Setting `gate2.mode = "off"` or overriding `neverSuppressSeverities`.
> - Configuring malicious entrypoint globs.
>
> **Recommended CI Practice:**
> In automated CI/CD pipelines evaluating untrusted PRs, supply a trusted configuration file from outside the PR branch using the `--config` flag:
>
> ```bash
> secureship scan --config /ci/trusted-secureship.config.json --gate2 annotate
> ```

---

## 2. Analytical Scope & Boundaries

### 2.1 Import-Level vs. Function-Level Reachability

- SecureShip Phase 3 provides **IMPORT-LEVEL** reachability analysis only.
- It proves whether a dependency or module is imported along an execution path originating from an entrypoint.
- It does **not** perform function-level call graph construction, inter-procedural dataflow analysis, or taint tracking.
- `REACHABLE_CALL_PATH` remains unused and documented as reserved for future Pro tier capabilities.
- **Mandatory User-Facing Disclaimer:**
  > _"Import-level analysis only; not proof of exploitability or safety."_

### 2.2 Non-Gated Finding Categories (Principle G8)

- **`SECRET` findings:** Always return `verdict: UNKNOWN, evidence.kind: NOT_APPLICABLE`. Secrets are dangerous whether the surrounding code is imported or dead.
- **`IAC` findings:** Always return `verdict: UNKNOWN, evidence.kind: NOT_APPLICABLE`. Infrastructure configurations (Terraform, Dockerfiles, Kubernetes) operate outside application module import graphs.

### 2.3 Python SCA Confidence Ceiling (Rule C1)

- **Rule C1:** In Phase 3, Python SCA findings are **NEVER** assigned `UNREACHABLE` with `HIGH` confidence.
- Even when all 7 positive evidence preconditions hold (declared directly in `pyproject.toml`, 0 dependents in `poetry.lock`/`Pipfile.lock`, 0 imports across production files, 0 references in configs/scripts), Python SCA findings are capped at **`MEDIUM`** confidence (`analysisConfidence: 'MEDIUM'`).
- If top-level module mapping or virtual environment metadata is unavailable, the finding degrades to `verdict: UNKNOWN, evidence.kind: UNMAPPED_PACKAGE, analysisConfidence: LOW`.
- Because default Gate 2 suppression policy strictly requires `HIGH` confidence, **no Python SCA finding is ever automatically suppressed under default policy in Phase 3**.

---

## 3. Supported & Unsupported Dependency Manifests

### 3.1 Fully Supported Lockfile Formats (Dependency Tree Enabled)

The Reachability Engine extracts full parent-child dependency trees, dev/optional flags, and transitive reachability paths from:

1. **`package-lock.json`**: Lockfile versions `2` and `3` (npm 7+).
2. **`pnpm-lock.yaml`**: Lockfile versions `6.0` (pnpm 8) and `9.0` (pnpm 9).
3. **`poetry.lock`**: Standard Poetry lockfiles with `[[package]]` tables.
4. **`Pipfile.lock`**: Standard Pipenv lockfiles with `default` and `develop` sections.
5. **Python Virtual Environments**: Local `.venv/` or `venv/` `.dist-info/top_level.txt` or `RECORD` metadata.

### 3.2 Unsupported Lockfile Formats (Fail-Closed to `UNKNOWN`)

Per Amendment **A9**, dependency manifests that lack full dependency graph trees degrade fail-closed:

- **`uv.lock`**: **Unsupported in Phase 3.** `uv.lock` is an unsupported flat/metadata lockfile format in Phase 3 without a dependency tree parser in `@secureship/reachability`. Repositories relying exclusively on `uv.lock` degrade fail-closed to `verdict: UNKNOWN, evidence.kind: NO_LOCKFILE_TREE, analysisConfidence: LOW`.
- **`yarn.lock`**: Yarn v1 flat format degrades to `verdict: UNKNOWN, evidence.kind: NO_LOCKFILE_TREE`.
- **`bun.lock` / `bun.lockb`**: Binary or flat text Bun lockfiles degrade to `verdict: UNKNOWN, evidence.kind: NO_LOCKFILE_TREE`.
- **Flat `requirements.txt`**: Without parent-child edge information, transitive dependencies cannot be safely proven unimported, degrading to `verdict: UNKNOWN, evidence.kind: NO_LOCKFILE_TREE`.
- **`package-lock.json` v1**: Legacy format lacking top-level `packages` map degrades to `verdict: UNKNOWN, evidence.kind: NO_LOCKFILE_TREE`.

---

## 4. Monorepo & Workspace Handling (Amendment A8)

SecureShip Phase 3 supports multi-package monorepos configured with npm workspaces, pnpm workspaces (`pnpm-workspace.yaml`), or Lerna:

- **Manifest Inspection:** Inspects all workspace package manifests (`package.json` across `packages/*` for npm v2/v3, `importers/*` for pnpm v6/v9).
- **Case (b) - Shared Declaration, Single Usage:** Package declared in both workspace A and workspace B, but imported only by B => evaluated as `REACHABLE_IMPORT` (`PACKAGE_IMPORTED`) with chain from B.
- **Case (c) - Shared Declaration, Unimported:** Package declared in both workspace A and workspace B, and imported by neither => evaluated as `UNREACHABLE` (`NOT_IMPORTED-HIGH`) when all positive evidence preconditions hold across the entire monorepo.
- **Case (d) - Transitive Workspace Dependency:** Workspace A depends on workspace B, and workspace B imports the package => evaluated as `REACHABLE` (`TRANSITIVE_VIA` or `PACKAGE_IMPORTED`).
- **Case (e) - Unsupported Monorepo Lockfiles:** Monorepos utilizing `yarn.lock` or `bun.lock` degrade fail-closed to `UNKNOWN (NO_LOCKFILE_TREE)`.

---

## 5. Reference Scanner Bounded Resource Guardrails (Fix C6)

To protect CI environments from denial-of-service, hangs, or resource exhaustion when searching for non-standard package references (e.g. plugins in strings, configs, CI workflows):

1. **Per-File Size Cap:** Maximum **1 MB** per file (`1,048,576` bytes). Files exceeding 1 MB are skipped, and `incompleteScan: true` is flagged (`reason: "file exceeds 1 MB limit"`).
2. **Total Byte Budget:** Maximum **50 MB** (`52,428,800` bytes) total cumulative content scanned across all inspected files. Exceeding this budget triggers `incompleteScan: true` (`reason: "total reference scan budget exceeded 50 MB"`).
3. **Wall-Clock Timeout:** Maximum **10 seconds** wall-clock execution time. If scanning exceeds 10s, scanning aborts immediately and flags `incompleteScan: true` (`reason: "reference scan timed out after 10000 ms"`).
4. **Deterministic Traversal:** Directory traversal and candidate file evaluation follow strict lexicographical sorting order.
5. **Fail-Closed Guardrail:** Whenever `incompleteScan: true` is flagged, candidate `NOT_IMPORTED` findings **immediately degrade fail-closed to `UNKNOWN (CONFIG_REFERENCE)`** with `analysisConfidence: LOW`. A budget cap hit will **never** allow a package to be falsely classified as `UNREACHABLE-HIGH`.

---

## 6. Grammar Version Staleness & Language Evolution

SecureShip bundles pinned, verified Tree-sitter WebAssembly grammars. When analyzing source files written with bleeding-edge or future language syntax:

- **Python 3.12+ Syntax:** Features such as PEP 695 `type` statements or complex nested quote f-strings that produce syntax error nodes (`rootNode.hasError === true`) are caught by the parser.
- **TypeScript 5.x Syntax:** Unrecognized newer constructs flag the file with `hasParseError: true`.
- **Fail-Closed Guarantee:**
  In all cases where a source file fails clean syntax parsing, project-level preconditions fail, and reachability verdicts **degrade fail-closed to `UNKNOWN (PARSE_FAILURE)`**.
  A syntax error will **never** cause a finding to be falsely classified as `UNREACHABLE` or suppressed.
