---
name: secureship-verification
description: Step-by-step verification, testing, and operational runbook for the SecureShip security engine, covering WASM attestation, mutation testing, coverage floors, benchmark suites, and CLI validation.
---

# SecureShip Verification & QA Skill

Use this skill when verifying changes, validating pull requests, or running the full quality assurance pipeline across the SecureShip monorepo.

## 1. Quick Verification Pipeline
pnpm build
pnpm typecheck
pnpm lint
pnpm format:check
pnpm test:coverage

## 2. Dedicated Phase 3 Verification Gates
pnpm verify:wasm
pnpm verify:mutations
pnpm benchmark:replay
pnpm benchmark:live

## 3. CLI Functional Diagnostics
node packages/cli/dist/index.js doctor
node packages/cli/dist/index.js detect .
node packages/cli/dist/index.js status
node packages/cli/dist/index.js graph . --format dot
node packages/cli/dist/index.js graph . --json
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --gate2 annotate
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --gate2 suppress
