# SecureShip Phase 1 — Verification Report

**Generated:** 2026-10-19
**Scope Rule:** Only Phase 1 components are judged. Parts I and J are INFO and do NOT affect PHASE 1 ACCEPTED / NOT ACCEPTED. Phase 2+ features are out of scope.

---

## 1. Environment

| Property         | Value                                                           |
| ---------------- | --------------------------------------------------------------- |
| OS               | Windows 11 (win32, x64)                                         |
| Node.js          | v24.19.0                                                        |
| pnpm             | 12.14.0                                                         |
| Monorepo         | pnpm workspace (packages/\*)                                    |
| Phase 1 Packages | @secureship/contracts, @secureship/core-engine, @secureship/cli |

---

## 2. Full Results Table

| ID  | Test                                         | Result | Evidence                                                                                                                                                             |
| --- | -------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | pnpm build exits 0                           | PASS   | exit code 0; all 8 packages built; cli/dist/index.js emitted (tsup, 54.94 KB)                                                                                        |
| A1b | pnpm typecheck exits 0                       | FAIL   | 16 TypeScript errors in packages/cli/src/commands/scan.ts — NormalizedFinding used but not imported at line 618; p possibly undefined at lines 504-581               |
| A1c | pnpm test exits 0                            | FAIL   | 1 test failed out of 558: explain command supports spec syntax in packages/cli/test/ai-cli.test.ts:288                                                               |
| A2  | tsconfig.base.json strict flags              | PASS   | strict:true, noUncheckedIndexedAccess:true, module:NodeNext, moduleResolution:NodeNext confirmed                                                                     |
| A3  | Dependency direction & cycles                | PASS   | contracts has no workspace imports; core-engine imports only contracts+context-slicer; cli imports both; no cycles                                                   |
| A4a | shell:true in production src                 | PASS   | Zero hits across all packages/_/src/\*\*/_.ts                                                                                                                        |
| A4b | exec/execSync usage                          | INFO   | execSync in safe-process-runner.ts:63 and binary-resolver.ts:50 for Windows registry query only (hardcoded input, no user data)                                      |
| A4c | eval( in production src                      | PASS   | Zero hits; only in comments in reachability extractors                                                                                                               |
| A4d | new Function in production src               | PASS   | Zero hits; only in comments                                                                                                                                          |
| A4e | :any / as any type escapes                   | INFO   | z.array(z.any()) at adapter.interface.ts:17; TypeScript override at line 28 is NormalizedFinding[]                                                                   |
| A4f | @ts-ignore directives                        | PASS   | Zero hits in any production source                                                                                                                                   |
| A4g | Hardcoded secrets/absolute paths             | PASS   | No real credentials; all test data uses clearly fake values                                                                                                          |
| A5  | .gitignore coverage                          | PASS   | node_modules/, dist/, coverage/, .turbo/, .secureship-shadow/, \*.log all present                                                                                    |
| A5b | pnpm-workspace.yaml covers packages/\*       | PASS   | packages: ['packages/*'] confirmed                                                                                                                                   |
| A6  | CLI dist shebang & bin entry                 | PASS   | dist/index.js line 1: #!/usr/bin/env node; package.json has "bin":{"secureship":"./dist/index.js"}                                                                   |
| A6b | CLI works from different cwd                 | PASS   | detect run from C:\Windows\Temp with absolute path returned valid JSON                                                                                               |
| B1  | All required schemas exported                | PASS   | All 17 required exports confirmed via contracts.verify.test.ts (11 tests PASS)                                                                                       |
| B2  | Enum rejection of invalid values             | PASS   | All enums reject lowercase, empty, null, undefined, numbers, unknown values                                                                                          |
| B3a | NormalizedFinding valid sample parses        | PASS   | 64-char fingerprint, required fields parse correctly                                                                                                                 |
| B3b | Required field removal fails                 | PASS   | Each of 12 required fields when removed causes parse failure                                                                                                         |
| B3c | startLine > endLine rejected                 | FAIL   | BUG-1: FindingLocationSchema uses .nonnegative() independently — no cross-field check; {startLine:10,endLine:5} -> success:true                                      |
| B3d | Fingerprint must be 64-char                  | PASS   | z.string().length(64) enforced; short hash rejected                                                                                                                  |
| B4  | filePath backslash/traversal                 | INFO   | src\\app\\a.ts and ../../etc/passwd both parse — normalization delegated to FindingCorrelator.toPosix(). By design, documented in B4 test                            |
| B5  | TierCapabilities all three tiers             | PASS   | FREE_BYOK: maxMonthlyAiFixes=15, allowCiCdGatekeeper=false, allowShadowWorktreeSandbox=false, allowSignedComplianceExport=false, allowCrossFileAstGraph=false        |
| B6  | Unknown extra keys stripped                  | PASS   | Zod strips extra keys by default; unexpectedExtraKey absent from output                                                                                              |
| C1  | Redacts all 7 secret categories              | PASS   | AWS->AKIA...[REDACTED], ghp*->ghp*...[REDACTED], github*pat*->redacted, Bearer JWT->Bearer [REDACTED_TOKEN], api_key->[REDACTED_SECRET], PEM->[REDACTED_PRIVATE_KEY] |
| C1x | Bare JWT (no Bearer prefix)                  | INFO   | No dedicated JWT regex; only caught via high-entropy heuristic (>=32 chars, entropy>=3.6)                                                                            |
| C2  | Secrets in sentences/JSON/multi              | PASS   | Surrounding text preserved; JSON fields preserved; two secrets on one line both redacted                                                                             |
| C2x | URL query string ?api_key=value              | FAIL   | BUG-2: https://api.example.com/data?api_key=supersecretvalue123456 NOT redacted — patterns require quoted values                                                     |
| C3  | Non-secrets preserved                        | PASS   | Prose, git SHA, UUID, version string, file path, code snippet all survive                                                                                            |
| C4  | Idempotency                                  | PASS   | redactText(redactText(x)) === redactText(x) confirmed                                                                                                                |
| C5a | redactObject deep redaction                  | PASS   | Nested objects/arrays redacted; number/bool/null primitives preserved; original not mutated                                                                          |
| C5b | Circular reference handling                  | FAIL   | BUG-3: redactObject on circular object throws Maximum call stack size exceeded                                                                                       |
| C6  | ReDoS on 1MB payloads                        | PASS   | All three 1MB inputs complete in <2000ms                                                                                                                             |
| C7  | Prefix exposure                              | PASS   | AKIA...[REDACTED]; ghp\_...[REDACTED] — only 4-char prefix shown                                                                                                     |
| D1  | Simple command + telemetry                   | PASS   | stdout/stderr/exitCode/durationMs all captured (D1 test PASS)                                                                                                        |
| D2  | Non-zero exit as data; missing binary        | PASS   | exitCode 17 returned as data; missing binary throws typed Error                                                                                                      |
| D3  | Argument injection as literal                | PASS   | ; echo PWNED / $(whoami) / && dir arrive as literal argv; shell:false confirmed                                                                                      |
| D4  | Timeout terminates within deadline           | PASS   | 60s sleep with 1500ms timeout -> timedOut:true, returns within 4s                                                                                                    |
| D5  | Process tree kill                            | PASS   | Windows: taskkill /PID /T /F via execFile (no shell). Grandchild PID dead after 500ms                                                                                |
| D6  | Buffer cap: stdout truncation                | PASS   | 50MB with 1MB cap -> truncated:true, stdout.length <=1.5MB                                                                                                           |
| D7  | Buffer cap: stderr truncation                | PASS   | 20x100KB stderr with 512KB cap -> truncated:true                                                                                                                     |
| D8  | Environment sanitization                     | PASS   | SECRET_TEST_TOKEN/AWS_SECRET_ACCESS_KEY/GITHUB_TOKEN stripped; PATH preserved; explicit env override works                                                           |
| D9  | Exit signal handling                         | PASS   | Windows: exitCode 137; POSIX: signal SIGKILL reported                                                                                                                |
| D10 | 20 parallel commands                         | PASS   | All 20 complete with correct unmixed output                                                                                                                          |
| D11 | UTF-8 decoding; nonexistent cwd              | PASS   | Unicode decoded correctly; nonexistent cwd throws typed Error                                                                                                        |
| D12 | Windows .cmd/.bat spawning                   | PASS   | .cmd explicitly forbidden by P7 policy; throws "forbidden" message                                                                                                   |
| E1  | Polyglot fixture detection                   | PASS   | TypeScript/Python/Go/Rust/Java; pnpm/pip/go/cargo/maven; all lockfiles/IaC; gitleaks/opengrep/osv-scanner/trivy/checkov                                              |
| E2  | Lockfile matrix in sub-folders               | PASS   | packages/client/package-lock.json and packages/server/poetry.lock found with POSIX paths                                                                             |
| E3  | Test directory classification + FP check     | PASS   | test/tests/**tests**/mocks/fixtures/spec classified; contest/latest/attestation/protests NOT classified                                                              |
| E4  | .gitignore respected                         | PASS   | build_output/ gitignored Python file not detected; node_modules/.git never traversed                                                                                 |
| E5  | Symlink escape prevention                    | PASS   | realpath + path.relative boundary check blocks symlink traversal; Dockerfile outside not detected                                                                    |
| E5x | Symlink loop                                 | INFO   | Windows handles via realpathSync try/catch; broken symlinks skipped; not fully stress-tested                                                                         |
| E6  | Edge inputs                                  | PASS   | Nonexistent path throws clear error; empty dir/unicode paths handled cleanly                                                                                         |
| E7  | Output validates ProjectProfileSchema; POSIX | PASS   | safeParse success:true; workspaceRoot and iacManifests have no backslashes on Windows                                                                                |
| E8  | Determinism across two runs                  | PASS   | run1 deep-equals run2; arrays stably ordered                                                                                                                         |
| E9  | 500-file performance                         | PASS   | 500-file fixture scanned in 1701ms (<5000ms threshold)                                                                                                               |
| E9x | 20,000-file performance (spec asks 20k)      | INFO   | Verification test uses 500 files only; 20k-file test not formally executed                                                                                           |
| E10 | Config-only project                          | PASS   | Only package.json + pnpm-lock.yaml: pnpm detected, languages=[]                                                                                                      |
| F1  | Fingerprint determinism and formula          | PASS   | SHA-256(posixFilePath:ruleId.toLowerCase():normalizedSink) verified by independent recompute; 64-char hex; 50-run determinism                                        |
| F2  | Path normalization in fingerprint            | PASS   | src/a/b.ts / src\\a\\b.ts / ./src/a/b.ts produce identical fingerprint                                                                                               |
| F3  | Multi-scanner dedup + evidence merge         | PASS   | opengrep+semgrep+trivy -> ONE finding with 3 evidence entries; severity=CRITICAL; confidence=HIGH                                                                    |
| F4  | Gate 1 scope filter                          | PASS   | tests/unit/login.test.ts -> LOW/UNREACHABLE/TEST_OR_MOCK; prod keeps HIGH; contest/ NOT downgraded                                                                   |
| F5  | Gate 1 for examples/docs/migrations          | INFO   | examples/ -> EXAMPLE, docs/ -> DOCUMENTATION via Gate1Scope.classifyPath(); migrations/ not classified; FindingCorrelator.isTestPath() only covers test dirs         |
| F6  | Secrets in findings masked                   | PASS   | AWS key in redactedSnippet -> AKIA...[REDACTED] in output                                                                                                            |
| F7  | Empty input / 1000 findings perf             | PASS   | correlate([])=[]; 1000 findings in <2000ms                                                                                                                           |
| F8  | All correlated findings validate schema      | PASS   | NormalizedFindingSchema.safeParse success:true on all output                                                                                                         |
| G1  | Logger redacts tokens in human+JSON mode     | PASS   | JSON mode: ghp\_...[REDACTED] in stdout; human mode: ANSI, no raw token                                                                                              |
| G2  | JSON lines parseable                         | PASS   | Each line is valid JSON with timestamp/level/message                                                                                                                 |
| G3  | Error/undefined logging no-throw             | PASS   | Error with stack, undefined metadata — no throws                                                                                                                     |
| H1  | --help / --version / unknown command         | PASS   | --help exit 0 + command list; --version -> 0.1.0-alpha; unknowncommandxyz -> exit 1                                                                                  |
| H2  | doctor: Node, git, scanner binaries          | PASS   | Node v24 shown as supported; git detected; 5 scanners shown as Optional/Missing; no crash                                                                            |
| H3  | detect: repo/polyglot/nonexistent/file       | PASS   | detect . returns profile; nonexistent -> exit 1 + clear message; --json is pure valid JSON                                                                           |
| H4  | status: FREE_BYOK, no network                | PASS   | FREE_BYOK, 15 fixes/month, v0.1.0, Local-first CLI; no network required                                                                                              |
| H5  | Different cwd; NO_COLOR=1                    | PASS   | detect from C:\Windows\Temp with absolute path -> correct JSON; NO_COLOR respected                                                                                   |
| H6  | CLI never prints env vars/secrets            | PASS   | doctor shows "Configured"/"Not set" only; no env var values printed                                                                                                  |
| I1  | Injection filenames adversarial              | INFO   | Shell-injection-named files treated as plain names; no execution triggered                                                                                           |
| I2  | Deep nesting 20 levels                       | INFO   | maxDepth:15 stops traversal cleanly; no stack overflow                                                                                                               |
| I3  | Large/malformed .gitignore                   | INFO   | 5000-line .gitignore processed in <3s                                                                                                                                |
| I4  | Binary/empty files                           | INFO   | No crash; TypeScript still detected                                                                                                                                  |
| J1  | Coverage thresholds                          | INFO   | Thresholds: Lines>=85%, Branches>=75% global; per-file>=70%/70%. Coverage unavailable (test failure aborted report)                                                  |
| J2  | Missing contract/CLI tests                   | INFO   | No tests for startLine>endLine, bare JWT, URL query secrets. CLI doctor/status have no unit tests                                                                    |

---

## 3. Summary Count & Verdict

| Category | Count |
| -------- | ----- |
| PASS     | 47    |
| FAIL     | 5     |
| INFO     | 9     |
| SKIPPED  | 0     |

### Mandatory Gates That Failed

| Gate            | Failure                                     |
| --------------- | ------------------------------------------- |
| A1 (typecheck)  | 16 TS errors in scan.ts                     |
| A1 (test suite) | 1 failing test in ai-cli.test.ts            |
| B3c             | startLine > endLine not rejected by schema  |
| C2x             | URL query string api_key=value not redacted |
| C5b             | Circular reference crashes redactObject     |

## PHASE 1 NOT ACCEPTED

Reason: 5 failures in Parts A-H. Mandatory gates A1, B3, C2, C5 all failed.
There must be zero FAILs in Parts B-H for acceptance.

---

## 4. Bug List (Ordered by Severity)

### HIGH — Security

**BUG-2: URL query string secrets not redacted**

- File: packages/context-slicer/src/redactor.ts:79-84
- Repro: SecretRedactor.redactText('https://api.example.com/data?api_key=supersecretvalue123456') returns input unchanged
- Root Cause: KEY_VALUE_SECRET pattern requires quotes around value; bare URL query params not matched
- Suggested Fix: Add URL*QUERY_SECRET pattern:
  regex: /([?&])(api[*-]?key|secret|token|password|access[_-]?token)=([^\s&"'#]{6,})/gi
  replacer: (\_m, sep, key) => `${sep}${key}=[REDACTED_SECRET]`

**BUG-3: Circular reference crashes redactObject**

- File: packages/context-slicer/src/redactor.ts:153-180
- Repro: const o = {}; o.self = o; SecretRedactor.redactObject(o) -> RangeError: Maximum call stack size exceeded
- Root Cause: No WeakSet cycle detection in recursive walk
- Suggested Fix: Add `_visited = new WeakSet()` parameter; check/add before recursing objects

### HIGH — Build/Type Safety

**BUG-4: TypeScript typecheck fails in scan.ts (16 errors)**

- File: packages/cli/src/commands/scan.ts:618, 504-581
- Repro: pnpm typecheck -> 16 errors
- Error 1 (line 618): Cannot find name 'NormalizedFinding' — type used in resolveReachabilityLabel() but not imported
- Error 2+ (lines 504-581): 'p' is possibly undefined — report.ai.dryRunPayloads[i] needs null guard
- Suggested Fix: Add `import { type NormalizedFinding } from '@secureship/contracts'` to scan.ts; add `if (!p) continue;` after array access

**BUG-5: Test fixture regression in ai-cli.test.ts**

- File: packages/cli/test/ai-cli.test.ts:288
- Repro: pnpm test -> FAIL: expected stderr to contain 'AI model is not configured' but got 'Invalid or malformed report file'
- Root Cause: Test fixture report object is missing required ScanReportSchema fields (startedAt, finding.fingerprint, finding.scannerName, etc.)
- Suggested Fix: Update the fixture around ai-cli.test.ts:260-285 with a complete, schema-valid report object

### MEDIUM — Data Integrity

**BUG-1: FindingLocationSchema allows startLine > endLine**

- File: packages/contracts/src/finding.schema.ts:50-57
- Repro: FindingLocationSchema.safeParse({filePath:'a.ts', startLine:10, endLine:5}).success === true
- Root Cause: Lines validated independently; no cross-field .refine()
- Suggested Fix:
  Add .refine(d => d.startLine <= d.endLine, { message: 'startLine must be <= endLine', path: ['startLine'] })

---

## 5. Spec Gaps

| Gap                                          | Description                                                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| FindingLocationSchema cross-field validation | Plan: startLine > endLine rejected — only negative rejected; startLine>endLine silently accepted (BUG-1)           |
| URL query-string secret redaction            | api_key=value in URLs without quotes not matched by any pattern (BUG-2)                                            |
| Bare JWT pattern                             | No dedicated JWT regex; only Bearer-wrapped JWTs + high-entropy heuristic                                          |
| Circular reference safety in redactObject    | Spec C5: circular references must not hang or crash — crashes with stack overflow (BUG-3)                          |
| FindingCorrelator EXAMPLE/DOCUMENTATION tags | isTestPath() only covers test dirs; EXAMPLE/DOCUMENTATION handled by Gate1Scope only, not correlator inline filter |
| 20,000-file performance                      | E9 spec asks 20k files; verification uses 500 only                                                                 |
| ScanExecutionResultSchema.findings z.any()   | Zod schema uses z.any() while TypeScript override is NormalizedFinding[] — not in sync at Zod level                |

---

## 6. Commands to Re-Run Verification

```powershell
# Environment check
node --version; pnpm --version

# A1 gates
pnpm build
pnpm typecheck
pnpm test
pnpm test:coverage

# Phase 1 specific verification suites
npx vitest run packages/contracts/test/verification/
npx vitest run packages/core-engine/test/verification/

# CLI sanity
node packages/cli/dist/index.js --help
node packages/cli/dist/index.js --version
node packages/cli/dist/index.js unknowncmd; echo "Exit: $LASTEXITCODE"
node packages/cli/dist/index.js status
node packages/cli/dist/index.js detect . --json

# BUG regression checks
node -e "import('./packages/context-slicer/dist/index.js').then(m => { const r = m.SecretRedactor.redactText('https://api.example.com/data?api_key=s3cr3tvalue123456'); console.log('BUG-2:', r.includes('s3cr3tvalue123456') ? 'STILL PRESENT' : 'FIXED'); })"
node -e "import('./packages/context-slicer/dist/index.js').then(m => { const o = {}; o.self = o; try { m.SecretRedactor.redactObject(o); console.log('BUG-3: FIXED'); } catch(e){ console.log('BUG-3: STILL PRESENT', e.message); } })"
node -e "import('./packages/contracts/dist/finding.schema.js').then(m => { const r = m.FindingLocationSchema.safeParse({filePath:'a.ts',startLine:10,endLine:5}); console.log('BUG-1:', r.success ? 'STILL PRESENT' : 'FIXED'); })"
```

---

## 7. Developer Notes

1. All 47 verification test check-points PASS — the verification scaffolding is solid.
2. The 5 failures are real bugs, not test infrastructure problems.
3. BUG-3 (circular reference) is the most dangerous: any downstream code passing a circular object through the logger/redactor will crash.
4. BUG-2 (URL query string) is the most likely to be triggered in real scans — CI logs commonly contain URLs with embedded API keys.
5. BUG-4 (typecheck) is surprising because tsup build exits 0 — tsup has weaker type checking than tsc --noEmit.
6. Once all 5 bugs are fixed, re-run: pnpm typecheck && pnpm test && pnpm test:coverage

---

_Report: docs/PHASE1_VERIFICATION_REPORT.md_
_Reviewer: Antigravity QA Agent — Production Grade Audit_
