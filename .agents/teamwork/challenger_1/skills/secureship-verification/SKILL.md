---
name: secureship-verification
description: Step-by-step verification, testing, and operational runbook for the SecureShip security engine, covering WASM attestation, mutation testing, coverage floors, benchmark suites, and CLI validation.
---

# SecureShip Verification & QA Skill

Use this skill when verifying changes, validating pull requests, or running the full quality assurance pipeline across the SecureShip monorepo.

---

## 1. Quick Verification Pipeline

Run the standard monorepo validation sequence from the workspace root:

```powershell
# 1. Clean build across all packages
pnpm build

# 2. Strict typecheck across all workspaces
pnpm typecheck

# 3. Lint and code format checks
pnpm lint
pnpm format:check

# 4. Full test suite with coverage and per-file floors (385+ tests)
pnpm test:coverage
```

---

## 2. Dedicated Phase 3 Verification Gates

### A. WebAssembly Grammar Integrity

Validates that bundled Tree-sitter WASM files in `packages/reachability/wasm/` match hardcoded SHA-256 manifests and upstream package lockfiles:

```powershell
pnpm verify:wasm
```

### B. Mutation Sanity Suite (N1 – N17)

Executes all 17 metamorphic fault injections on an isolated temporary clone to prove that safety preconditions cannot be bypassed:

```powershell
pnpm verify:mutations
```

### C. Benchmark Suites (Replay & Live)

Evaluates precision, recall, F1, and suppression-recall against synthetic ground-truth corpora:

```powershell
# Fast offline replay against recorded corpora
pnpm benchmark:replay

# Live execution against installed scanner binaries
pnpm benchmark:live
```

---

## 3. CLI Functional Diagnostics

```powershell
# 1. System diagnostics (Node, Git, Scanner binaries, WASM grammars)
node packages/cli/dist/index.js doctor

# 2. Stack and project detector
node packages/cli/dist/index.js detect .

# 3. Status and license capabilities
node packages/cli/dist/index.js status

# 4. Import graph inspection (DOT or JSON)
node packages/cli/dist/index.js graph . --format dot
node packages/cli/dist/index.js graph . --json

# 5. Security scan with Gate 2 Reachability
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --gate2 annotate
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --gate2 suppress
```

---

## 4. Code Coverage Troubleshooting

If a new file or edit causes coverage to drop below thresholds:

1. Check `vitest.config.ts`:
   - Global: Lines $\ge 85\%$, Branches $\ge 75\%$.
   - Per-File Floor: Both Lines and Branches must meet $\ge 70\%$.
2. Every new source file in `packages/*/src/` must be added to `SOURCE_FILES_FLOOR` in `vitest.config.ts` once stabilized.
3. Test edge cases, error branches, and fail-closed fallbacks to ensure $\ge 70\%$ branch coverage.
