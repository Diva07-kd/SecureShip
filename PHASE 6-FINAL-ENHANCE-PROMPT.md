# PHASE 6 — VSCODE EXTENSION: DEVELOPMENT & TESTING PROMPT

### SecureShip IDE Integration Layer — Full Production Implementation

> **Scope**: Only Phase 6. Do NOT touch Phase 1–5 code, tests, or configuration.
> **Codebase Context**: Grounded in SecureShip v0.4.0+ monorepo — all schemas, types, and CLI commands from live packages.

---

## ARCHITECTURE CONTEXT (Read Before Coding)

### What Already Exists in the Monorepo (Use These — Don't Reinvent):

| Package                             | Key Exports Used by Extension                                                                                                                  |
| :---------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------- |
| `@secureship/contracts`             | `NormalizedFinding`, `ScanReport`, `Severity`, `FindingCategory`, `TierCapabilities`, `TIER_CAPABILITY_DEFAULTS`, `ScannerName`, `LicenseTier` |
| `packages/cli`                      | `secureship scan`, `secureship doctor`, `secureship status`, `secureship fix`, `secureship explain` — invoked as child process by extension    |
| `packages/cli/src/commands/scan.ts` | `ScanCommandOptions` interface (understanding CLI flags)                                                                                       |
| `packages/core-engine`              | `ScanReport` output JSON format (read back after CLI invocation)                                                                               |
| `packages/scanner-adapters`         | Binary resolver path `~/.secureship/bin` (extension must add to PATH for child spawns)                                                         |

### CLI Invocation Pattern (Extension MUST follow this):

Extension NEVER imports from @secureship/\* directly into extension source.
Extension ALWAYS calls secureship CLI as an external child process.

### ScanReport JSON structure (from packages/contracts/src/scan-report.schema.ts):

- schemaVersion: '1.0' | '1.1' | '1.2'
- findings: NormalizedFinding[] (active non-suppressed findings)
- suppressed: SuppressedFinding[]
- summary: { totalReported, bySeverity, byCategory, ... }
- tier: LicenseTier
- scanners: ScannerExecutionSummary[]

### NormalizedFinding structure (data model driving all UI):

- id: string (UUID)
- fingerprint: string (64-char SHA-256)
- ruleId: string
- severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
- category: 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'SUPPLY_CHAIN'
- scannerName: 'opengrep' | 'gitleaks' | 'trivy' | 'osv-scanner' | 'checkov' | 'generic'
- location: { filePath: string, startLine: number, endLine: number }
- title: string, description: string
- reachability: 'REACHABLE' | 'UNREACHABLE' | 'UNKNOWN' | 'NOT_APPLICABLE'
- aiTriage?: { verdict, confidence, rationale, citations }
- fixRecommendation?: { explanation, proposedDiff, suggestedPackageUpgrade }
- package?: { name, version, fixedVersion }

---

## PHASE 6 OBJECTIVES

1. Create fully-functional VSCode extension (packages/vscode-extension/) surfacing SecureShip findings inline in VSCode WITHOUT modifying any existing package.
2. Implement 6 core capabilities: CLI auto-detection, background scan on save/open, inline diagnostic squiggles, hover risk cards on import statements, quick-fix code actions, sidebar tree panel.
3. Real-time status bar showing finding count and license tier.
4. Zero-telemetry — extension sends NO data anywhere. All computation via local CLI invocation.
5. Graceful degradation when CLI is not installed.

---

## 1. EXACT FILES TO CREATE

```
packages/vscode-extension/
├── package.json              <- VS Code Extension manifest (contributes, activationEvents, engines)
├── tsconfig.json             <- TypeScript config targeting vscode types, CJS module
├── tsup.config.ts            <- Build: extension.ts -> dist/extension.js (CJS for VS Code)
├── .vscodeignore             <- Exclude src/, *.ts, .map from VSIX
├── CHANGELOG.md              <- Required for Marketplace
├── README.md                 <- Marketplace README
├── media/
│   ├── secureship-icon-128.png
│   └── webview.css
└── src/
    ├── extension.ts          <- Entry: activate() + deactivate()
    ├── cli/
    │   ├── cli-locator.ts    <- Finds binary: setting > ~/.secureship/bin > PATH
    │   └── cli-runner.ts     <- Spawns secureship scan, returns ExtScanReport
    ├── providers/
    │   ├── diagnostic-provider.ts  <- NormalizedFinding[] -> vscode.Diagnostic[]
    │   ├── hover-provider.ts       <- Hover cards on import lines
    │   └── code-action-provider.ts <- "Fix/Explain with SecureShip" actions
    ├── scanner/
    │   ├── workspace-scanner.ts    <- Orchestrates scans, caches report, notifies providers
    │   └── scan-debouncer.ts       <- 1500ms debounce with AbortSignal cancellation
    ├── panel/
    │   └── findings-panel.ts       <- Sidebar tree view (grouped by severity)
    ├── status/
    │   └── status-bar.ts           <- "SecureShip: 3 HIGH | FREE" status bar
    └── types/
        └── extension-types.ts      <- Internal types mirroring @secureship/contracts
```

---

## 2. DEVELOPMENT PROMPT — SOURCE FILES OVERVIEW

### 2.1 packages/vscode-extension/package.json (Extension Manifest)

- `engines.vscode: "^1.85.0"` — minimum VSCode version
- `main: "./dist/extension.js"` — CJS bundle entry
- activationEvents: workspaceContains:\*_/package.json, _.ts, _.js, _.py + onCommand:\*
- contributes.commands: scanWorkspace, openFindings, installCli, showStatus
- contributes.views.explorer: secureship.findingsView (sidebar tree)
- contributes.configuration: cliPath, autoScanOnSave, scanDebounceMs, failOnSeverity, gate2Mode, supplyChainOnly
- devDependencies: @types/vscode ^1.85.0, @vscode/vsce ^2.24.0, tsup ^8.3.6, vitest ^2.1.8

### 2.2 packages/vscode-extension/tsconfig.json

- target: ES2020, module: commonjs (CJS required by extension host)
- strict: true, noEmit: true
- moduleResolution: bundler

### 2.3 packages/vscode-extension/src/types/extension-types.ts

IMPORTANT: Mirrors @secureship/contracts shapes but defined LOCALLY.
Do NOT import from @secureship/\* — avoids bundling WASM into .vsix.

Types to define:

- ExtSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
- ExtCategory: 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'SUPPLY_CHAIN'
- ExtReachability: 'REACHABLE' | 'UNREACHABLE' | 'UNKNOWN' | 'NOT_APPLICABLE'
- ExtLicenseTier: 'FREE_BYOK' | 'PRO_TEAM' | 'ENTERPRISE'
- ExtFindingLocation: { filePath, startLine (1-indexed), endLine (1-indexed), startColumn?, endColumn? }
- ExtNormalizedFinding: mirrors NormalizedFinding from finding.schema.ts
- ExtScanReport: mirrors ScanReport from scan-report.schema.ts
- ExtCliStatus: { tier, status, email?, seats?, daysRemaining?, capabilities, monthlyAiUsage }
- ScanState: { status: idle|scanning|complete|error, lastReport?, lastScanAt?, errorMessage? }

### 2.4 packages/vscode-extension/src/cli/cli-locator.ts

EXPORTS: findSecureShipCli(): Promise<string | null>, promptCliInstall(): void

findSecureShipCli() resolution order:

1. VSCode setting `secureship.cliPath` (if set and file exists)
2. ~/.secureship/bin/secureship[.exe] (Phase 1 install-tools default)
3. which/where secureship on system PATH

promptCliInstall(): shows vscode.window.showWarningMessage with "Install via npm" and "Open Install Docs" buttons

### 2.5 packages/vscode-extension/src/cli/cli-runner.ts

EXPORTS: runScan(), runStatusCheck()

buildChildEnv(): prepends ~/.secureship/bin to PATH so opengrep/gitleaks/trivy are visible

runScan(cliPath, workspaceRoot, signal, options):

- Spawns: secureship scan <workspaceRoot> --output <tmpFile> --json --no-color --gate2 <mode>
- Optional flags: --supply-chain-only, --offline
- AbortSignal: sends SIGTERM to child process, resolves null
- Reads JSON output file -> ExtScanReport
- Exit 0|1 with no output file = empty scan (no findings) = return empty report
- Exit 2+ with no output file = error = return null
- Always cleans up temp file

runStatusCheck(cliPath, workspaceRoot):

- Spawns: secureship status --json
- Returns parsed ExtCliStatus or null

### 2.6 packages/vscode-extension/src/scanner/scan-debouncer.ts

CLASS: ScanDebouncer(delayMs: number)

- schedule(cb): Aborts in-flight scan, clears pending timer, starts new timer
- cancelAll(): Aborts running scan + clears timer
- Uses AbortController per execution

### 2.7 packages/vscode-extension/src/scanner/workspace-scanner.ts

CLASS: WorkspaceScanner(cliPath, workspaceRoot)

- constructor reads scanDebounceMs from VSCode config
- onStateChange(listener): register state observer
- scanNow(): bypass debounce, run immediately
- scheduleDebounced(): checks autoScanOnSave setting first
- executeScan(signal): sets state=scanning, calls runScan, sets state=complete|error
- State broadcasts to all listeners on every change

### 2.8 packages/vscode-extension/src/providers/diagnostic-provider.ts

CLASS: SecureShipDiagnosticProvider implements vscode.Disposable

SEVERITY_MAP: CRITICAL->Error, HIGH->Error, MEDIUM->Warning, LOW->Information, INFO->Hint

publish(findings, workspaceRoot, minSeverity):

- Clears collection
- Filters by minSeverity using rank map
- LINE NUMBER: CLI 1-indexed -> VSCode 0-indexed (subtract 1)
- Groups by absolute file path
- Sets code with clickable rule link: https://secureship.dev/rules/<ruleId>
- source: "SecureShip (<scannerName>)"

### 2.9 packages/vscode-extension/src/providers/hover-provider.ts

CLASS: SecureShipHoverProvider implements vscode.HoverProvider

- updateFindings(findings): cache latest findings
- provideHover(document, position):
  - Extract package name from line via regex
  - Pattern: from 'pkg' | import('pkg') | require('pkg')
  - Normalize: @scope/pkg (2 segments), pkg (1 segment), ignore relative paths
  - Filter findings: category=SUPPLY_CHAIN AND package.name matches
  - Build MarkdownString with severity emoji, risk level, top 4 findings, safe version if available
  - Footer: links to openFindings + scanWorkspace commands

### 2.10 packages/vscode-extension/src/providers/code-action-provider.ts

CLASS: SecureShipCodeActionProvider implements vscode.CodeActionProvider

- provideCodeActions(doc, range, context):
  - Filter context.diagnostics where source starts with 'SecureShip'
  - For each: Action 1 (Explain, QuickFix), Action 2 (Fix if fixRecommendation exists), Action 3 (View, Empty)
  - Commands: secureship.explainFinding, secureship.fixFinding, secureship.openFindings

### 2.11 packages/vscode-extension/src/status/status-bar.ts

CLASS: SecureShipStatusBar implements vscode.Disposable

- StatusBarAlignment.Left, priority 100
- command: secureship.openFindings
- updateFromScanState(state):
  - idle: "$(shield) SecureShip"
  - scanning: "$(sync~spin) SecureShip: Scanning..."
  - complete with CRITICAL: "$(error) SecureShip: N CRITICAL, M HIGH | TIER" + errorBackground
  - complete with HIGH only: "$(warning) SecureShip: N HIGH | TIER" + warningBackground
  - complete no crits: "$(shield) SecureShip: N finding(s) | TIER"
  - complete 0 findings: "$(pass) SecureShip: No findings | TIER"
  - error: "$(error) SecureShip: Scan failed" + errorBackground
- tierLabel: FREE_BYOK->'FREE', PRO_TEAM->'PRO', ENTERPRISE->'ENT'

### 2.12 packages/vscode-extension/src/panel/findings-panel.ts

CLASSES: FindingsTreeItem, FindingsPanelProvider

FindingsTreeItem extends vscode.TreeItem:

- If finding: tooltip=ruleId+desc, description=scannerName+filePath:line, command=vscode.open with Range, icon=error|warning
- If group header: icon=shield

FindingsPanelProvider implements vscode.TreeDataProvider<FindingsTreeItem>:

- updateReport(report|null): regroups findings by severity, fires event
- getChildren(undefined): returns severity group headers in CRITICAL->HIGH->MEDIUM->LOW->INFO order
- getChildren(groupHeader): returns FindingsTreeItem per finding in that severity group
- Null report: returns "No scan results" placeholder
- Zero findings: returns "No findings" placeholder

### 2.13 packages/vscode-extension/src/extension.ts (Entry Point)

activate(context):

1. Find CLI - if missing: promptCliInstall, register installCli command, show status bar, RETURN
2. Create: diagnosticProv, hoverProv, codeActionProv, statusBar, findingsPanel, scanner
3. Register tree view: secureship.findingsView
4. Register hover provider for ts, js, tsx, json
5. Register code action provider for ts, js, python
6. Register commands: scanWorkspace, openFindings, installCli, showStatus, explainFinding, fixFinding
7. scanner.onStateChange -> update ALL providers (diagnostics, hover, codeAction, panel, statusBar, tier)
8. onDidSaveTextDocument -> scanner.scheduleDebounced() (skip node_modules/.git/dist/.secureship)
9. runStatusCheck background -> statusBar.setTier()
10. scanner.scanNow() initial scan
11. Welcome notification with "Scan Now" action
12. Push ALL disposables to context.subscriptions

deactivate():

- scanner?.cancelAll()
- diagnosticProv?.clear()

---

## 3. TESTING PROMPT — PHASE 6 UNIT TESTS

### Testing Architecture & Constraints

- Extension host NOT available in Vitest. All vscode.\* APIs must be mocked via vi.mock('vscode', ...).
- Business logic tested in isolation without VS Code runtime.
- Test files: packages/vscode-extension/test/\*.test.ts
- Run with: vitest run test/
- Anti-Fake-Test Law compliance: tests must fail if implementation is removed/broken.
  - NO tests that just check a value was returned without semantic verification
  - NO mocked return values that make tests pass regardless of logic

### 3.1 Test File: packages/vscode-extension/test/scan-debouncer.test.ts

WHAT TO TEST: ScanDebouncer timing, coalescing, cancellation, AbortSignal behavior

Tests (use vi.useFakeTimers() / vi.useRealTimers() in beforeEach/afterEach):

1. "calls callback exactly once after debounce delay"

   - schedule callback, advance timers by delay+50ms, run all timers async
   - assert callCount === 1

2. "coalesces 5 rapid triggers into exactly 1 callback execution"

   - loop: schedule + advance 50ms x5 (total 250ms, delay is 300ms)
   - advance 400ms more, run all
   - assert callCount === 1

3. "does NOT call callback after cancelAll() before timer fires"

   - schedule, cancelAll(), advance 500ms
   - assert callCount === 0

4. "AbortSignal is NOT aborted during normal execution"

   - schedule, advance past delay, run
   - capture signal.aborted inside callback -> assert false

5. "AbortSignal IS aborted when second scan triggers before first completes"

   - first callback blocks on a Promise; capture signal ref
   - advance past delay -> first fires
   - schedule second; advance past delay -> second fires
   - unblock first scan
   - assert first's signal.aborted === true

6. "independent ScanDebouncer instances don't interfere with each other"
   - Two ScanDebouncer instances, schedule on both
   - Advance timers
   - Both should fire independently: 2 total calls

### 3.2 Test File: packages/vscode-extension/test/diagnostic-provider.test.ts

WHAT TO TEST: Severity filtering, line number conversion, file grouping

Mock vscode module stub (define for all tests):

```typescript
vi.mock('vscode', () => ({
  languages: {
    createDiagnosticCollection: vi.fn(() => ({ clear: vi.fn(), set: vi.fn(), dispose: vi.fn() })),
  },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Range: class {
    constructor(
      public sl: number,
      public sc: number,
      public el: number,
      public ec: number
    ) {}
  },
  Diagnostic: class {
    public source?: string;
    public code?: unknown;
    constructor(
      public range: unknown,
      public message: string,
      public severity: number
    ) {}
  },
  Uri: { file: (p: string) => ({ fsPath: p }), parse: (s: string) => ({ href: s }) },
}));
```

Tests:

1. "CRITICAL severity maps to DiagnosticSeverity.Error (0)"

   - Verify CRITICAL finding creates Diagnostic with severity 0

2. "MEDIUM severity maps to DiagnosticSeverity.Warning (1)"

   - Verify MEDIUM finding creates Diagnostic with severity 1

3. "1-indexed startLine=10 converts to 0-indexed VSCode Range startLine=9"

   - finding.location.startLine=10, finding.location.endLine=12
   - assert Range constructed with (9, 0, 11, MAX_SAFE_INTEGER)

4. "findings below minSeverity threshold are excluded"

   - publish with minSeverity='HIGH', findings=[LOW, INFO, MEDIUM]
   - assert collection.set never called

5. "multiple findings in same file are batched in single collection.set call"

   - 3 findings all in 'src/index.ts'
   - assert collection.set called once for that URI with 3 diagnostics

6. "findings in different files each get their own collection.set call"

   - findings in 'src/a.ts' and 'src/b.ts'
   - assert collection.set called twice

7. "clear() calls collection.clear()"

   - provider.clear() -> assert collection.clear called

8. "diagnostic.source format is 'SecureShip (<scannerName>)'"
   - finding.scannerName='opengrep'
   - assert diag.source === 'SecureShip (opengrep)'

### 3.3 Test File: packages/vscode-extension/test/hover-provider.test.ts

WHAT TO TEST: Package name extraction regex, hover content correctness

No vscode mock needed for pure logic tests; mock only for provider tests.

Tests:

1. "extracts simple package from: import X from 'lodash'"

   - assert extracted name === 'lodash'

2. "extracts scoped package from: import { A } from '@secureship/contracts'"

   - assert extracted name === '@secureship/contracts'

3. "strips sub-path from: import fn from 'lodash/merge'"

   - assert extracted name === 'lodash'

4. "extracts from require(): const x = require('express')"

   - assert extracted name === 'express'

5. "returns null for lines with no import"

   - input: "const x = foo.bar()" -> null

6. "ignores relative imports (starting with '.')"

   - input: "import { a } from './utils'" -> normalizePackageName returns null

7. "SUPPLY_CHAIN findings matching package name trigger hover"

   - findings=[{category:'SUPPLY_CHAIN', package:{name:'lodash'}, severity:'CRITICAL'}]
   - assert provideHover for line "import x from 'lodash'" returns non-null

8. "SAST findings do NOT appear in hover (only SUPPLY_CHAIN)"

   - findings=[{category:'SAST', package:{name:'lodash'}}]
   - assert provideHover returns null

9. "highest severity correctly selected from multiple findings on same package"

   - findings: LOW, CRITICAL, HIGH all for 'evil-pkg'
   - hover markdown should show CRITICAL as risk level

10. "fixedVersion shown when package has fixedVersion"
    - finding.package.fixedVersion='1.2.3'
    - assert hover markdown contains '1.2.3'

### 3.4 Test File: packages/vscode-extension/test/findings-panel.test.ts

WHAT TO TEST: Tree grouping, severity sort order, child items, edge cases

Mock vscode:

```typescript
vi.mock('vscode', () => ({
  TreeItem: class {
    constructor(
      public label: string,
      public cs: number
    ) {}
  },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  ThemeIcon: class {
    constructor(public id: string) {}
  },
  EventEmitter: class {
    event = () => {};
    fire = vi.fn();
    dispose = vi.fn();
  },
  Uri: { file: (p: string) => ({ fsPath: p }) },
  Range: class {
    constructor(
      public sl: number,
      public sc: number,
      public el: number,
      public ec: number
    ) {}
  },
}));
```

Helper: makeReport(findings: Partial<ExtNormalizedFinding>[]): ExtScanReport

Tests:

1. "severity groups appear in CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO order"

   - report with one finding each severity
   - getChildren() root labels[0]='CRITICAL...', [1]='HIGH...', etc.

2. "severity groups show correct count in label"

   - 3 HIGH findings -> group label contains '3'

3. "empty severity groups are omitted from root"

   - only HIGH findings -> only HIGH group shown, no CRITICAL/MEDIUM/LOW/INFO

4. "getChildren(groupHeader) returns correct finding children"

   - 2 CRITICAL findings, expand CRITICAL group
   - assert 2 children with correct ruleId labels

5. "finding child label is truncated to 60 chars for long titles"

   - title.length=100 -> label contains at most 60+ruleId chars

6. "null report shows 'No scan results' placeholder"

   - updateReport(null) -> getChildren() returns 1 item with 'No scan results'

7. "zero-findings report shows 'No findings' placeholder"

   - report with empty findings array -> getChildren() returns 'No findings'

8. "second updateReport call resets previous grouping"
   - first: 3 CRITICAL; second: 2 HIGH
   - after second: only HIGH group visible, count=2

### 3.5 Test File: packages/vscode-extension/test/cli-runner.test.ts

WHAT TO TEST: runScan output parsing, AbortSignal handling, PATH injection

Mock node:child_process spawn at test boundary.

Tests:

1. "runScan parses valid JSON output file and returns ExtScanReport"

   - mock spawn writes valid JSON to --output arg file, exits 0
   - assert result.schemaVersion === '1.2', result.findings is array

2. "runScan returns null when AbortSignal fires before close event"

   - mock spawn never fires close event
   - ac.abort() -> await result -> assert null

3. "runScan returns empty report for exit code 0 with no output file"

   - mock spawn exits 0, no file written
   - assert result is non-null, result.findings.length === 0

4. "runScan returns null for exit code 2 with no output file"

   - mock spawn exits 2, no file written
   - assert result === null

5. "buildChildEnv prepends ~/.secureship/bin to PATH"

   - Spy on spawn, capture env argument
   - assert env.PATH starts with expected bin path

6. "runStatusCheck returns parsed ExtCliStatus on success"
   - mock spawn outputs valid status JSON to stdout
   - assert result.tier is valid tier string

### 3.6 Test File: packages/vscode-extension/test/cli-locator.test.ts

WHAT TO TEST: Resolution priority chain

Mock: vscode.workspace.getConfiguration, node:fs.existsSync, node:child_process.execSync

Tests:

1. "returns user setting path when file exists"

   - config returns '/custom/secureship', existsSync('/custom/secureship')=true
   - assert result === '/custom/secureship'

2. "skips invalid user setting and falls to user bin path"

   - config returns '/bad/path', existsSync('/bad/path')=false
   - existsSync(~/.secureship/bin/secureship)=true
   - assert result === userBinPath

3. "falls to PATH when user bin not found"

   - existsSync(userBinPath)=false
   - execSync('which secureship')=='/usr/local/bin/secureship', existsSync('/usr/local/bin/secureship')=true
   - assert result === '/usr/local/bin/secureship'

4. "returns null when all three sources fail"
   - config empty, user bin missing, execSync throws
   - assert result === null

---

## 4. VERIFICATION COMMANDS

```bash
# Step 1: Create package directory and install dependencies
cd packages/vscode-extension
npm install
cd ../..

# Step 2: TypeScript type-check (strict, zero errors)
cd packages/vscode-extension
npx tsc --noEmit
# Expected: 0 errors, 0 warnings

# Step 3: Build extension bundle (CJS for VS Code extension host)
npm run build
# Expected: dist/extension.js created as CommonJS module

# Step 4: Run unit tests
cd ../..
pnpm test packages/vscode-extension/test/
# Expected: All suites pass, no skipped tests

# Step 5: Anti-Fake-Test Law audit
npx tsx scripts/verify-test-integrity.ts packages/vscode-extension/test/
# Expected: "TEST INTEGRITY AUDIT PASSED"

# Step 6: Package as .vsix for installation testing
cd packages/vscode-extension
npm run package
# Expected: secureship-security-1.0.0-beta.1.vsix created

# Step 7: Install .vsix locally for manual E2E verification
code --install-extension secureship-security-1.0.0-beta.1.vsix
```

---

## 5. MANUAL E2E ACCEPTANCE CHECKLIST

After installing the .vsix in VS Code, verify all of these:

- [ ] Status bar shows "$(shield) SecureShip" at bottom-left on activation
- [ ] Opening a workspace with package.json triggers immediate background scan
- [ ] Status bar shows spinner during scan: "$(sync~spin) SecureShip: Scanning..."
- [ ] After scan completes: status bar shows finding counts by severity + tier label
- [ ] CRITICAL/HIGH findings show as red squiggly underlines in source files
- [ ] MEDIUM findings show as yellow underlines, LOW/INFO as subtle hints
- [ ] Hovering over `import 'lodash'` with supply chain findings shows risk hover card
- [ ] Hover card shows: package name, severity emoji, finding titles, safe version (if available)
- [ ] Right-click on red squiggle -> shows "SecureShip: Explain (ruleId)" in code actions
- [ ] "Explain" action opens integrated terminal and runs: secureship explain <fingerprint>
- [ ] For findings with fixRecommendation: "Fix" action also appears in code actions
- [ ] Explorer sidebar shows "SecureShip Findings" tree panel
- [ ] Panel shows findings grouped: CRITICAL > HIGH > MEDIUM > LOW > INFO
- [ ] Each group shows correct count in parentheses
- [ ] Clicking a finding navigates to correct file and line
- [ ] Saving any .ts or .js file triggers debounced rescan (1500ms delay)
- [ ] Saving files in node_modules/ or .git/ does NOT trigger rescan
- [ ] Running Command Palette "SecureShip: Scan Workspace" triggers immediate scan
- [ ] Running Command Palette "SecureShip: Show License Status" shows tier info notification
- [ ] On workspace without SecureShip CLI: shows warning with "Install via npm" button
- [ ] Extension deactivation cleanly disposes all resources (no error in console)

---

## 6. CRITICAL IMPLEMENTATION NOTES

> IMPORTANT: The extension MUST NOT import @secureship/contracts, @secureship/core-engine,
> or any other monorepo workspace package into its own source. VSIX must be self-contained.
> All type definitions from contracts are duplicated locally in src/types/extension-types.ts.

> WARNING: The extension MUST add ~/.secureship/bin to PATH when spawning child processes.
> Without this, opengrep, gitleaks, and trivy installed via Phase 1 install-tools will
> not be found by the CLI during scans triggered from the extension.
> See cli-runner.ts buildChildEnv() function.

> NOTE: VSCode extension uses CJS target. Build with tsup --format cjs.
> The --external vscode flag is critical: vscode is provided by host at runtime.

> NOTE: Line numbers from SecureShip CLI are 1-indexed (per NormalizedFinding schema).
> VSCode Range expects 0-indexed lines. Always subtract 1 when creating Range objects.
> startLine: f.location.startLine - 1 (with Math.max(0, ...) guard for line 1 findings)

> TIP: For VSIX size control, run: vsce ls
> Verify src/, _.ts, _.map excluded. Target VSIX size under 5MB.
> Extension icon (media/secureship-icon-128.png) must be exactly 128x128 PNG.
