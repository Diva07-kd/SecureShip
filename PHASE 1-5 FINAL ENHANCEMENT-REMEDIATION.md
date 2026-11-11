# PHASE 1-5 FINAL ENHANCEMENT — AUDIT & REMEDIATION PROMPTS

## SecureShip Production Readiness Audit

> **Audit Basis**: Full code review of implemented Phase 1–5 against the development strategy document.
> **Rule**: Code was reviewed — NOT trusted. Every gap is backed by actual file references.
> **Output**: One self-contained remediation prompt per phase. Execute each one independently.

---

## AUDIT METHODOLOGY

Files reviewed per phase:

- Phase 1: .github/workflows/{release,ci,docker}.yml, packages/cli/src/commands/install-tools.ts
- Phase 2: packages/cli/src/commands/{init,scan}.ts (runWatch, --new-only sections)
- Phase 3: packages/reachability/src/capabilities/{ast-capability-analyzer,python-capability-extractor}.ts
- Phase 4: packages/cli/src/commands/sbom.ts, packages/cli/src/index.ts
- Phase 5: packages/cli/src/commands/license.ts, packages/core-engine/src/license/{license-keys,ai-usage-ledger}.ts, packages/license-server/src/worker.ts, packages/core-engine/src/orchestrator/scan-orchestrator.ts

---

## PHASE 1 AUDIT RESULTS

### What Was Built (Verified):

- packages/cli/src/commands/install-tools.ts (20715 bytes) — SHA256 verification, Zip-Slip defense, PATH advice, 5 tools
- .github/workflows/release.yml (3872 bytes) — 4-platform binary matrix, npm publish with provenance
- .github/workflows/docker.yml (841 bytes) — Docker Hub push
- .github/workflows/ci.yml (1289 bytes) — 3-OS x 3-Node matrix, WASM verify, coverage

### Gaps Found:

**GAP-1.1 (CRITICAL): Hardcoded SHA256 values in KNOWN_TOOLS will fail on real downloads**
File: packages/cli/src/commands/install-tools.ts lines 44, 49, 54, 59 (opengrep), 73, 78... etc.
Problem: The SHA256 hashes are static strings that were manually specified. They will only match
if the exact same binary was used during development. After any upstream release update or if the
hashes were generated from a different build, verification will fail silently or crash.
The strategy specifies dynamic SHA256SUMS fetching from GitHub Releases API.
Currently: hardcoded sha256: '98d752c0c7a31548...' etc.

**GAP-1.2 (HIGH): CI pnpm version mismatch between ci.yml and release.yml**
File: .github/workflows/ci.yml line 33 uses pnpm version: 9
File: .github/workflows/release.yml line 45 uses pnpm version: 12.14.0
Problem: Different pnpm versions resolve lockfiles differently. CI passes with v9 but release
uses v12. This can cause silent dependency mismatches between test environment and release builds.

**GAP-1.3 (HIGH): CI missing mutation testing verification step**
File: .github/workflows/ci.yml
Problem: The strategy document (Part 0, section 0.2) requires pnpm verify:mutations (28/28 mutations
must be caught) as a gate before any release. The CI workflow has no mutation test step.
Only has: typecheck, lint, format:check, build, verify:wasm, test:coverage, benchmark:replay.
Missing: pnpm verify:mutations

**GAP-1.4 (MEDIUM): Homebrew formula and winget manifest not implemented**
The strategy (Stage 1, section 1.4) explicitly requires a Homebrew tap formula at
Formula/secureship.rb in a separate homebrew-tap repository. This was not created.
Also missing: winget manifest for Windows package manager distribution.

**GAP-1.5 (MEDIUM): release.yml npm publish does not gate on test pass**
File: .github/workflows/release.yml
The publish-npm job only depends on build-binaries (needs: build-binaries) but has no dependency
on tests passing. A broken build that produces binaries can publish to npm without tests running.
Missing: dependency on a test-pass job.

**GAP-1.6 (LOW): No docs/ci/ template directory as specified in strategy**
Strategy stage 2.2 specifies: New file: docs/ci/secureship-github-actions.yml as a documentation
template for users. This file does not exist in the repository.

---

## PHASE 1 REMEDIATION PROMPT

**Context**: You are remediating Phase 1 (Distribution Foundation) of the SecureShip monorepo.
This is a production-grade security CLI tool. Do NOT change any Phase 2-5 code.

**Repository structure**:

- Root: c:/dev/SecureShip-IDE/
- CI: .github/workflows/
- Install tools: packages/cli/src/commands/install-tools.ts

### TASK 1: Fix SHA256 Verification Strategy in install-tools.ts

**Problem**: KNOWN_TOOLS has hardcoded SHA256 values that will drift from actual release binaries.

**Fix**: Add a SHA256SUMS manifest URL to each tool definition and fetch it dynamically at install time.

In packages/cli/src/commands/install-tools.ts:

1. Add sha256ManifestUrl field to ToolDefinition interface:

```typescript
export interface ToolDefinition {
  name: ToolName;
  description: string;
  version: string;
  binaryName: string;
  sha256ManifestUrl?: string; // Optional: URL to download SHA256SUMS file for verification
  platforms: Partial<Record<`${SupportedPlatform}-${SupportedArch}`, PlatformAsset>>;
}
```

2. Add SHA256SUMS URLs to each tool in KNOWN_TOOLS:

```typescript
opengrep: {
  ...
  sha256ManifestUrl: 'https://github.com/opengrep/opengrep/releases/download/v1.31.0/SHA256SUMS',
  ...
}
gitleaks: {
  ...
  sha256ManifestUrl: 'https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/checksums.txt',
  ...
}
trivy: {
  ...
  sha256ManifestUrl: 'https://github.com/aquasecurity/trivy/releases/download/v0.58.2/trivy_0.58.2_checksums.txt',
  ...
}
```

3. Add fetchRemoteSha256() method to InstallToolsCommand class:

```typescript
public static async fetchRemoteSha256(
  manifestUrl: string,
  targetBinaryName: string
): Promise<string | null> {
  try {
    const res = await fetch(manifestUrl, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return null;
    const text = await res.text();
    // Parse "hash  filename" format (SHA256SUMS standard)
    for (const line of text.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        const hash = parts[0]!;
        const filename = parts[parts.length - 1]!.replace(/^\.\//, '').split('/').pop()!;
        if (filename === targetBinaryName || filename === path.basename(targetBinaryName)) {
          if (/^[a-f0-9]{64}$/i.test(hash)) return hash.toLowerCase();
        }
      }
    }
    return null;
  } catch {
    return null; // Manifest fetch failure is non-fatal: fall back to bundled hash
  }
}
```

4. In downloadAndInstallAsset() method, before calling the static sha256 verify:

```typescript
// Attempt to fetch fresh SHA256 from upstream manifest
if (toolDef?.sha256ManifestUrl) {
  const remoteHash = await InstallToolsCommand.fetchRemoteSha256(
    toolDef.sha256ManifestUrl,
    path.basename(asset.url)
  );
  if (remoteHash) {
    effectiveSha256 = remoteHash; // Use fresh upstream hash
  } else {
    // Warn but continue with bundled hash
    if (!options.json) {
      console.warn(pc.yellow('  ⚠ Could not fetch upstream SHA256 manifest. Using bundled hash.'));
    }
  }
}
```

### TASK 2: Fix CI pnpm Version Consistency

**File**: .github/workflows/ci.yml line 33
**Change**: Update pnpm version from 9 to 12.14.0 to match release.yml:

```yaml
- name: Setup pnpm
  uses: pnpm/action-setup@v4
  with:
    version: 12.14.0
```

### TASK 3: Add Mutation Testing to CI Pipeline

**File**: .github/workflows/ci.yml
**Change**: Add mutation verification step after test:coverage:

```yaml
- name: Run mutation tests (anti-fake-test law gate)
  run: pnpm verify:mutations
```

Place this AFTER the "Run tests with coverage" step and BEFORE the benchmark step.

### TASK 4: Fix release.yml — Add Test Dependency and Self-Dogfood Gate

**File**: .github/workflows/release.yml

Add a new pre-release test job that both binary build and npm-publish jobs depend on:

```yaml
run-tests:
  name: Run Full Test Suite (Release Gate)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: 22
    - uses: pnpm/action-setup@v4
      with:
        version: 12.14.0
    - run: pnpm install --frozen-lockfile && pnpm build
    - run: pnpm typecheck
    - run: pnpm test:coverage
    - run: pnpm verify:mutations
    - run: pnpm verify:wasm
```

Then update build-binaries and publish-npm to depend on this:

```yaml
  build-binaries:
    needs: run-tests
    ...
  publish-npm:
    needs: [run-tests, build-binaries]
    ...
```

### TASK 5: Create docs/ci/ template directory

**New file**: docs/ci/secureship-github-actions.yml
Create this file with the complete GitHub Actions YAML template as documented in the strategy
(Stage 2.2). Include both PR diff scan and full push scan variants with SARIF upload.
This is a DOCUMENTATION FILE for users — it is not executed by the repo itself.

### TASK 6: Add Homebrew formula stub

**New file**: docs/distribution/homebrew-formula.rb
Create a Homebrew formula template stub (not a live formula since it needs a separate repo):

```ruby
class Secureship < Formula
  desc "Zero-telemetry local-first security CLI for supply chain, SAST, secrets, and SCA"
  homepage "https://secureship.dev"
  version "1.0.0-beta.1"

  on_macos do
    on_arm do
      url "https://github.com/secureship/secureship/releases/download/v#{version}/secureship-darwin-arm64"
      sha256 "REPLACE_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/secureship/secureship/releases/download/v#{version}/secureship-darwin-x64"
      sha256 "REPLACE_AFTER_RELEASE"
    end
  end

  def install
    binary = Hardware::CPU.arm? ? "secureship-darwin-arm64" : "secureship-darwin-x64"
    bin.install binary => "secureship"
  end

  test do
    assert_match "SecureShip", shell_output("#{bin}/secureship --version")
  end
end
```

### TESTING REQUIREMENTS FOR PHASE 1 REMEDIATIONS:

Test file: packages/cli/test/install-tools/sha256-manifest.test.ts

Write tests that verify:

1. fetchRemoteSha256() correctly parses standard SHA256SUMS format (hash filename)
2. fetchRemoteSha256() handles checksums.txt format with paths (hash ./path/binary)
3. fetchRemoteSha256() returns null gracefully on network failure (AbortSignal.timeout fires)
4. fetchRemoteSha256() returns null when binary name not found in manifest
5. fetchRemoteSha256() rejects malformed hashes (not 64 hex chars)

All tests must be semantic: mock fetch at network boundary, assert real parsing logic runs.
Anti-Fake-Test Law: if fetchRemoteSha256 is deleted, all 5 tests must fail.

---

## PHASE 2 AUDIT RESULTS

### What Was Built (Verified):

- packages/cli/src/commands/init.ts (8368 bytes) — interactive wizard, config write, GitHub Actions scaffold, baseline init
- packages/cli/src/commands/scan.ts — --watch flag dispatches to runWatch(), --new-only filters baseline findings
- init.ts generates .github/workflows/secureship.yml with incremental PR scan + SARIF upload

### Gaps Found:

**GAP-2.1 (CRITICAL): runWatch() uses node:fs.watch instead of chokidar**
File: packages/cli/src/commands/scan.ts, line 761 and 790
Current code: const { watch } = await import('node:fs');
Strategy says (Stage 2.3): "const { watch } = await import('chokidar');"
Problem: node:fs.watch has well-documented bugs:

- On Windows: does NOT support recursive watching reliably (reports incorrect filenames)
- On Linux: requires inotify which has kernel descriptor limits in CI environments
- Does NOT support glob patterns, ignored paths with patterns, or reliable cross-platform events
- The current code manually filters with string.includes() which is fragile
- chokidar handles all of this correctly and is already a transitive dep in the ecosystem

**GAP-2.2 (HIGH): init.ts uses readline instead of @inquirer/prompts**
File: packages/cli/src/commands/init.ts, line 3
Current: import readline from 'node:readline/promises';
Strategy says (Stage 2.1): "Uses @inquirer/prompts (already in ecosystem, zero telemetry)"
Problem: readline does not provide the rich interactive experience (list selectors, checkboxes,
confirmation prompts) that the strategy designs for. Users get raw text input instead of
arrow-key navigation through choices, which is the industry standard for CLI onboarding.

**GAP-2.3 (HIGH): runWatch() does full re-scan on every change instead of incremental**
File: packages/cli/src/commands/scan.ts, line 807
Current: await ScanCommand.run(targetPath, { ...options, watch: false });
Strategy says (Stage 2.3):
if package.json changed → runSupplyChainScan()
if .ts/.js changed → runIncrementalReachability()
Problem: Every keystroke save triggers a full 5-scanner orchestration pipeline. For large projects
this is 30-90 seconds per change, making watch mode practically unusable. The strategy explicitly
designs file-type-aware incremental scanning.

**GAP-2.4 (MEDIUM): Generated GitHub Actions template missing --baseline flag on PR scan**
File: packages/cli/src/commands/init.ts, line 207-210 (scaffoldGithubActionWorkflow)
Current PR scan step:
secureship scan . --diff ... --sarif ... --new-only --fail-on HIGH
Strategy says (Stage 2.2) the PR scan should include: --baseline .secureship/baseline.json
This prevents noise from known findings when doing incremental diff scans.

**GAP-2.5 (LOW): No separate docs/ci/secureship-github-actions.yml documentation template**
Strategy Stage 2.2 specifies this as a separate file in docs/ci/ for user reference.
Currently the template exists only embedded in init.ts code string — not as a standalone docs file.

---

## PHASE 2 REMEDIATION PROMPT

**Context**: You are remediating Phase 2 (Developer Experience) of the SecureShip CLI.
Scope: packages/cli/src/commands/{scan,init}.ts only. Do NOT touch Phase 1, 3, 4, or 5 code.

### TASK 1: Replace node:fs.watch with chokidar in runWatch()

**File**: packages/cli/src/commands/scan.ts

First, verify chokidar is already a dependency:

```bash
grep -r "chokidar" packages/cli/package.json
```

If not present, add it: `pnpm --filter @secureship/cli add chokidar`

Then replace the entire runWatch() method implementation.

BEFORE (current implementation):

```typescript
public static async runWatch(targetPath: string, options: ScanCommandOptions): Promise<number> {
  const { watch } = await import('node:fs');
  ...
  const watcher = watch(
    targetPath,
    { recursive: true, signal: abortController.signal },
    (eventType, filename) => {
      if (!filename) return;
      const normalized = filename.replace(/\\/g, '/');
      if (ignoredSubstrings.some((ign) => normalized.includes(ign))) return;
      ...
```

AFTER (chokidar implementation):

```typescript
public static async runWatch(targetPath: string, options: ScanCommandOptions): Promise<number> {
  const chokidar = await import('chokidar');
  const noColor = Boolean(options.noColor) || options.color === false;
  const c = noColor ? pc.createColors(false) : pc;
  const resolvedPath = path.resolve(targetPath);

  console.log(c.bold(c.cyan('\n👁  SecureShip Watch Mode Active')));
  console.log(c.gray(`Monitoring: ${resolvedPath}. Press Ctrl+C to stop.\n`));

  // Initial full scan on start
  await ScanCommand.run(targetPath, { ...options, watch: false });

  let debounceTimer: NodeJS.Timeout | null = null;

  const watcher = chokidar.watch(resolvedPath, {
    ignored: [
      '**/node_modules/**',
      '**/.git/**',
      '**/dist/**',
      '**/.secureship/**',
      '**/coverage/**',
      '**/*.tmp',
    ],
    persistent: true,
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 50 },
  });

  const abortController = new AbortController();
  let resolvePromise!: (code: number) => void;
  const watchPromise = new Promise<number>((res) => { resolvePromise = res; });

  const sigintHandler = () => {
    console.log(pc.yellow('\nWatch mode terminated by user.'));
    void watcher.close().then(() => resolvePromise(0));
  };
  process.once('SIGINT', sigintHandler);

  const onFileChanged = (changedPath: string) => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      const rel = path.relative(resolvedPath, changedPath).replace(/\\/g, '/');
      console.log(c.bold(c.cyan(`\n[SecureShip Watch] Changed: ${rel} — re-scanning...\n`)));

      // Incremental strategy: package.json → supply chain only; source files → full scan
      const isPackageJson = rel.endsWith('package.json');
      const scanOptions: ScanCommandOptions = {
        ...options,
        watch: false,
        supplyChainOnly: isPackageJson ? true : options.supplyChainOnly,
      };
      await ScanCommand.run(targetPath, scanOptions);
    }, 300);
  };

  watcher.on('change', onFileChanged);
  watcher.on('add', onFileChanged);
  watcher.on('unlink', onFileChanged);
  watcher.on('error', (err: unknown) => {
    console.error(c.red(`[SecureShip Watch] Watcher error: ${String(err)}`));
  });

  return watchPromise;
}
```

### TASK 2: Add @inquirer/prompts to init.ts interactive wizard

**File**: packages/cli/src/commands/init.ts

First add dependency:

```bash
pnpm --filter @secureship/cli add @inquirer/prompts
```

Replace the readline-based interactive section with @inquirer/prompts:

```typescript
import { select, checkbox, confirm, input } from '@inquirer/prompts';
```

Replace the readline.createInterface block with proper inquirer prompts:

```typescript
if (!parsedOptions.yes && process.stdin.isTTY) {
  console.log(pc.bold(pc.cyan('\n⚙  SecureShip Interactive Project Setup Wizard\n')));

  failOn = (await select({
    message: 'Fail CI/CD pipeline on severity at or above:',
    choices: [
      { value: 'CRITICAL', name: 'CRITICAL — Only block on critical issues' },
      { value: 'HIGH', name: 'HIGH — Block on critical + high (recommended)' },
      { value: 'MEDIUM', name: 'MEDIUM — Block on critical + high + medium' },
      { value: 'NONE', name: 'NONE — Never fail CI' },
    ],
    default: 'HIGH',
  })) as FailOnSeverity;

  const scannerChoices = await checkbox({
    message: 'Enable security scanners:',
    choices: [
      { value: 'opengrep', name: 'opengrep — SAST static analysis', checked: true },
      { value: 'gitleaks', name: 'gitleaks — Secrets detection', checked: true },
      { value: 'trivy', name: 'trivy — SCA + IaC scanning', checked: true },
      { value: 'osv-scanner', name: 'osv-scanner — OSV vulnerability database', checked: true },
      { value: 'checkov', name: 'checkov — Infrastructure-as-Code', checked: false },
    ],
  });
  enabledScanners = scannerChoices;

  gate2Mode = (await select({
    message: 'Reachability verification mode (Gate 2):',
    choices: [
      { value: 'annotate', name: 'annotate — Tag findings with reachability info (default)' },
      { value: 'suppress', name: 'suppress — Suppress unreachable SCA findings (PRO tier)' },
      { value: 'off', name: 'off — Disable reachability analysis' },
    ],
    default: 'annotate',
  })) as 'annotate' | 'suppress' | 'off';

  generateAction = await confirm({
    message: 'Generate GitHub Actions CI workflow (.github/workflows/secureship.yml)?',
    default: true,
  });

  createBaseline = await confirm({
    message: 'Scan now and create initial baseline (.secureship/baseline.json)?',
    default: false,
  });
}
```

### TASK 3: Fix generated GitHub Actions template — add --baseline flag

**File**: packages/cli/src/commands/init.ts — scaffoldGithubActionWorkflow() method

Update the PR scan step in the generated YAML to include baseline suppression:

```typescript
// In the content template string, change the PR scan step from:
      - name: Incremental Diff Scan (Pull Request)
        if: github.event_name == 'pull_request'
        run: |
          secureship scan . \\
            --diff \${{ github.event.pull_request.base.sha }} \\
            --sarif secureship.sarif \\
            --new-only \\
            --fail-on HIGH

// TO:
      - name: Incremental Diff Scan (Pull Request)
        if: github.event_name == 'pull_request'
        run: |
          secureship scan . \\
            --diff \${{ github.event.pull_request.base.sha }} \\
            --sarif secureship.sarif \\
            --new-only \\
            --baseline .secureship/baseline.json \\
            --fail-on HIGH
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning (Pull Request)
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secureship.sarif
          category: secureship
```

### TASK 4: Create standalone docs/ci/ template

**New file**: docs/ci/secureship-github-actions.yml
Create a complete, standalone GitHub Actions template matching strategy Stage 2.2.
This file is DOCUMENTATION for users who integrate manually (not using `secureship init`).
Include both PR diff scan + full scan + SARIF upload + baseline update on main push.

### TESTING REQUIREMENTS FOR PHASE 2 REMEDIATIONS:

**Test file**: packages/cli/test/scanner/watch-mode.test.ts

Tests for TASK 1 (chokidar integration):

1. "runWatch() calls initial full scan before starting watcher" — mock chokidar.watch, assert ScanCommand.run called once on entry
2. "runWatch() triggers rescan with supplyChainOnly:true when package.json changes" — emit 'change' for 'package.json', assert scan called with supplyChainOnly:true
3. "runWatch() triggers full rescan when .ts file changes" — emit 'change' for 'src/index.ts', assert supplyChainOnly is NOT forced to true
4. "runWatch() debounces rapid file events to single scan" — emit 5 rapid changes, advance timer, assert scan called exactly once
5. "runWatch() resolves on SIGINT without dangling timers" — emit SIGINT, assert watcher.close() called and promise resolves 0

**Test file**: packages/cli/test/commands/init-inquirer.test.ts

Tests for TASK 2 (@inquirer/prompts):

1. "init --yes skips interactive prompts entirely and uses defaults" — assert no prompt functions called
2. "init writes correct failOn from select() response" — mock select to return 'CRITICAL', assert config.failOn === 'CRITICAL'
3. "init writes correct scanners from checkbox() response" — mock checkbox returning ['opengrep', 'trivy'], assert config.scanners
4. "Generated secureship.yml contains --baseline flag in PR scan step" — assert scaffolded content includes '--baseline .secureship/baseline.json'

---

## PHASE 3 AUDIT RESULTS

### What Was Built (Verified):

- python-capability-extractor.ts (19182 bytes) - full Tree-sitter Python AST extractor
- ast-capability-analyzer.ts correctly dispatches to Python at line 133 (lang === 'python')
- tree-sitter-loader.ts detectLanguage returns 'python' for .py and .pyw extensions
- tree-sitter-python.wasm (0.45MB) EXISTS in wasm/ directory
- 3 Python test files exist: python-capability-analyzer, python-extractor, python-resolver

### Gaps Found:

**GAP-3.1 (HIGH): No combination alert tests for Python (SC-CAP-100 to SC-CAP-106)**
Capability matrix combination alerts (shell+network=SC-CAP-100, env+network=SC-CAP-101, etc.)
have zero Python-sourced test coverage. All combination tests are JS/TS only.
If CapabilityMatrix.evaluate() skips Python capabilities, no test catches it.

**GAP-3.2 (HIGH): No .pyw extension coverage in any test file**
detectLanguage correctly handles .pyw but zero tests run .pyw through the full pipeline.
Windows Python scripts (.pyw) are a real supply chain attack vector.

**GAP-3.3 (MEDIUM): Python enclosingFunction not tested for class method attribution**
No test covers: capability site inside a class method should attribute enclosingFunction='methodName'
not 'ClassName'. This matters for triage precision in the UI.

**GAP-3.4 (MEDIUM): Python fallback token scan path not tested**
If tree-sitter hasError=true for malformed .py, extractPythonCapabilities falls back to
fallbackTokenScan. This error recovery path has no test and could silently miss threats.

**GAP-3.5 (LOW): Python dynamic eval obfuscation patterns not detected**
JS has constant folding for cp['ex'+'ec']. Python equivalent exec(base64.b64decode(...)) style
patterns common in PyPI supply chain attacks have no detection pattern.

---

## PHASE 3 REMEDIATION PROMPT

Scope: packages/reachability/test/ only. Do NOT modify src/ files.
Implementation is complete. These are TEST COVERAGE gaps.

### TASK 1: Add SC-CAP combination alert tests for Python

New file: packages/reachability/test/python-combination-alerts.test.ts

Write tests verifying Python packages triggering multiple capabilities generate correct SC-CAP-NNN:

1. SC-CAP-100 fires for Python code with subprocess.run + requests.get (shell+network)
2. SC-CAP-100 does NOT fire for shell-only Python code
3. SC-CAP-101 fires for Python code with os.environ + requests.post (env+network)
4. SC-CAP-102 fires for Python code with eval() + urllib.request.urlopen (eval+network)
5. SC-CAP-106 fires for Python code with subprocess + requests + os.environ (triple combo, CRITICAL)

Each test must: assert SPECIFIC ruleId present/absent. Not just "alerts.length > 0".
Anti-Fake-Test: if CapabilityMatrix.evaluate() returns [], all tests fail.

### TASK 2: Add .pyw extension pipeline test

Add to: packages/reachability/test/python-capability-analyzer.test.ts

Test: 'correctly analyzes .pyw Windows Python scripts (not fallback token scan)'
Code: Python with socket.connect + os.system, filename 'backdoor.pyw'
Assert: hasShell=true, hasNetwork=true, shellSite exists, no error thrown

### TASK 3: Add nested class method enclosingFunction test

Add to: packages/reachability/test/python-extractor.test.ts

Test: 'resolves enclosingFunction correctly for method inside class body'
Code: class Exfiltrator with def steal(self): subprocess.run(...)
Assert: shellSite.enclosingFunction === 'steal' (NOT 'Exfiltrator', NOT null)

### TASK 4: Add malformed Python fallback test

Add to: packages/reachability/test/python-capability-analyzer.test.ts

Test: 'gracefully handles syntax-error Python via fallback token scan'
Code: Python with deliberate syntax error (unclosed paren, invalid tokens)
Assert: result is defined, result.sites is Array (no throw), hasShell=true (fallback detects os.system)

### TASK 5: Add Python dynamic eval obfuscation detection

Add to: packages/reachability/src/capabilities/python-capability-extractor.ts

Add detection for exec(base64.b64decode(...)) patterns in the eval capability set:

- Pattern: call to exec() where argument is a b64decode() call
- Pattern: import codecs; exec(codecs.decode(...))
- Add corresponding test in python-extractor.test.ts asserting hasEval=true

Verification:
pnpm --filter "@secureship/reachability" test
pnpm --filter "@secureship/reachability" test --reporter verbose python-combination

---

## PHASE 4 AUDIT RESULTS

### What Was Built (Verified):

- packages/cli/src/commands/sbom.ts (9408 bytes) - CycloneDX 1.5 + SPDX 2.3, license compliance, tier gate for --signed
- packages/cli/src/index.ts line 484 - sbom command registered with all documented flags
- resolveScanReport() fallback at line 243-293: runs live supply-chain scan if no report file found
- --check-licenses, --allow, --deny flags implemented with Zod validation
- Windows cmd.exe comma desugaring handled in index.ts (lines 524-547)

### Gaps Found:

**GAP-4.1 (HIGH): --with-vulns cross-reference maps findings by file path, not by package name**
File: packages/cli/src/commands/sbom.ts line 650 (original strategy)
The resolveScanReport fallback runs supply chain analysis. But generateCycloneDXSbom()
correlates findings to components via:
f.location.filePath.includes(pkg.name)
Problem: This string-includes match is fragile.

- A finding for 'lodash' at 'node_modules/lodash/array.js' will match 'lodash'
- But a finding for 'lo' at 'node_modules/lodash' would also match 'lo'
- Scoped packages like '@babel/core' would never match because filePath contains '/' not '@babel/core'
  The correct approach is to match findings where finding.package.name === pkg.name (exact match).

**GAP-4.2 (HIGH): No SBOM command integration test**
Zero test files exist for the sbom command. The command is 9408 bytes of logic with no test coverage.
The license compliance evaluation, CycloneDX generation, SPDX generation, and tier gate all run
with zero test assertions. If discoverPackages() returns an empty array, the SBOM silently emits
a valid but empty BOM.

**GAP-4.3 (MEDIUM): CLI version is hardcoded as string literal '1.0.0-beta.1'**
File: packages/cli/src/commands/sbom.ts lines 82, 89
cliVersion: '1.0.0-beta.1' (hardcoded, appears twice)
This will drift from the actual package version when bumped. Should read from package.json.

**GAP-4.4 (MEDIUM): SBOM --signed flag shows tier gate error but provides no upgrade path**
When --signed is used on FREE tier, the error message says:
"run 'secureship license upgrade' to unlock signed compliance exports"
But there is no documentation in the error output of what PRO costs or how to get it.
Strategy says the upgrade should open a pricing page or show pricing inline.

**GAP-4.5 (LOW): resolveScanReport() fallback ScanReport has durationMs: 0**
The fallback ScanReport constructed at line 260-290 sets durationMs: 0 and scanners[0].durationMs: 0.
When this synthetic report is embedded in the SBOM, it creates misleading audit trail data
showing a "0ms" scan. Should use actual elapsed time or omit the field.

---

## PHASE 4 REMEDIATION PROMPT

Scope: packages/cli/src/commands/sbom.ts and packages/cli/test/sbom/

### TASK 1: Fix package vulnerability correlation to use exact package name match

File: The generateCycloneDXSbom() function in packages/core-engine/src/sbom/cyclonedx-generator.ts
(or wherever the correlation logic lives based on your review of core-engine exports)

Change the finding-to-component matching from file path string-includes to exact package name:
BEFORE:
vulnerabilities: scanReport?.findings
.filter(f => f.location.filePath.includes(pkg.name))

AFTER:
vulnerabilities: scanReport?.findings
.filter(f =>
// Exact package name match from the finding's package metadata
f.package?.name === pkg.name ||
// Fallback: scoped package path match (handles @scope/name in node_modules)
f.location.filePath.includes('/node_modules/' + pkg.name + '/') ||
f.location.filePath.includes('/node_modules/' + pkg.name.replace('@', '').replace('/', '/') + '/')
)

### TASK 2: Create SBOM command integration test file

New file: packages/cli/test/sbom/sbom-command.test.ts

Tests to write (use vitest, mock fs and core-engine imports at boundaries):

1. "sbom generates valid CycloneDX 1.5 JSON structure for discovered packages"

   - Mock discoverPackages to return 3 packages
   - Call SbomCommand.run('.', { format: 'cyclonedx', json: true })
   - Capture stdout, parse as JSON
   - Assert: bomFormat==='CycloneDX', specVersion==='1.5', components.length===3
   - Assert: each component has purl field starting with 'pkg:npm/'

2. "sbom generates valid SPDX 2.3 JSON structure"

   - Same setup but format: 'spdx'
   - Assert: spdxVersion==='SPDX-2.3', packages array exists

3. "sbom --signed rejects on FREE tier with exit code 1"

   - Mock resolveTierCapabilities to return FREE_BYOK with allowSignedComplianceExport=false
   - Assert: SbomCommand.run('.', { signed: true }) resolves to 1
   - Assert: stderr or console.error includes 'PRO_TEAM or ENTERPRISE'

4. "sbom --check-licenses with deny=GPL-3.0 returns exit code 1 when violation found"

   - Mock discoverPackages to return package with license 'GPL-3.0-or-later'
   - Mock evaluateLicenseCompliance to return violation
   - Assert: exit code 1

5. "sbom gracefully returns 1 when target directory does not exist"
   - Call with non-existent dir
   - Assert: exit code 1, error message contains dir path

Anti-Fake-Test Law: all assertions must be semantic (check actual field values, not just truthy).

### TASK 3: Replace hardcoded CLI version with package.json read

File: packages/cli/src/commands/sbom.ts

Add at top of file:
`	ypescript
import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const CLI_VERSION: string = (_require('../../package.json') as { version: string }).version;
`

Then replace both instances of '1.0.0-beta.1' with CLI_VERSION.

### TASK 4: Enhance --signed tier error with pricing info

In packages/cli/src/commands/sbom.ts, in the signed tier gate block:
After the error message, add:
`	ypescript
console.error(pc.dim('  Pricing: https://secureship.dev/pricing'));
console.error(pc.dim('  Run: secureship license upgrade  to open the pricing portal.'));
`

### TASK 5: Fix resolveScanReport() fallback to track actual duration

In packages/cli/src/commands/sbom.ts, resolveScanReport() fallback:
` ypescript
const fallbackStart = Date.now();
const scResult = await analyzeSupplyChain({ rootDir, policy });
const elapsed = Date.now() - fallbackStart;

// Use actual elapsed time
return {
...
durationMs: elapsed,
scanners: [{
name: 'generic',
version: '1.0.0',
status: 'SUCCESS',
durationMs: elapsed,
rawFindingCount: scResult.findings.length,
}],
...
};
`

Verification:
pnpm --filter "@secureship/cli" test test/sbom/
pnpm typecheck

---

## PHASE 5 AUDIT RESULTS

### What Was Built (Verified):

- packages/cli/src/commands/license.ts (6743 bytes) - activate (online+offline), status, upgrade, remove
- packages/core-engine/src/license/license-keys.ts - RS256 JWT sign/verify, embedded public key
- packages/core-engine/src/license/ai-usage-ledger.ts - monthly AI usage tracking with atomic writes
- packages/license-server/src/worker.ts - Cloudflare Worker: /v1/activate, /v1/validate, /v1/webhook/stripe
- packages/cli/src/index.ts lines 65-102 - all 4 license subcommands registered (activate, status, upgrade, remove)
- scan-orchestrator.ts line 186 - resolveTierCapabilities() called at every scan start (CONFIRMED)
- LicenseActivationRequestSchema: machineFingerprint is OPTIONAL (not a bug - confirmed)

### Gaps Found:

**GAP-5.1 (CRITICAL): Background JWT refresh not implemented on the CLI side**
The strategy (Stage 5, section 5.2) explicitly states:
"if (isNearExpiry(payload.exp)) { refreshLicenseInBackground(licenseJwtPath, payload.sub); }"
The orchestrator's resolveTierCapabilities() reads the JWT and enforces tier, but has NO
background refresh logic. A user with a 30-day JWT will simply fail after day 30 with no warning.
The license.ts activate command re-downloads manually, but there is no auto-refresh daemon.
Without this, paying customers will have their license silently expire during a scan.

**GAP-5.2 (HIGH): SECURESHIP_PUBLIC_KEY_PEM has a suspicious line break mid-PEM**
File: packages/core-engine/src/license/license-keys.ts lines 13-21
The embedded PEM key has an unusual line break inside the base64 content at line 15:
MIIBCgKCAQEA0Rr8rLGJ06eluX2FxjRf
Rz9U/iS9XZAXPUn7J7ClgQGkMw3l+piXSzWFV1lJzlmZGe2mU6kj5k8doAqCMCa8
The first line before the newline within the base64 content is suspiciously short (36 chars vs
standard 64-char PEM lines). This may indicate the key was truncated during copy-paste or
was generated with non-standard tooling. A malformed public key will cause verifyLicenseJwt()
to fail for ALL licenses, making the entire monetization layer non-functional.

ACTION REQUIRED: Generate a fresh RSA-2048 keypair using generateLicenseKeyPair() and replace
the embedded public key. Document and securely store the matching private key for the license server.

**GAP-5.3 (HIGH): AI usage quota enforcement not wired between ai-usage-ledger and orchestrator**
File: packages/core-engine/src/orchestrator/scan-orchestrator.ts
The strategy says Gate 3 AI triage should be disabled when monthlyAiFixes >= maxMonthlyAiFixes.
The ai-usage-ledger.ts exists and tracks usage correctly.
But: scan-orchestrator.ts does NOT call getMonthlyAiUsage() before enabling Gate 3 AI.
A FREE_BYOK user can run unlimited AI triage scans without the 15-fix cap being enforced.

**GAP-5.4 (MEDIUM): license activate does not send machineFingerprint**
File: packages/cli/src/commands/license.ts line 60-64
Current POST body: { activationCode: code }
Schema supports: { activationCode, email?, machineFingerprint? }
This is NOT a breaking bug (machineFingerprint is optional) but it means:

1. The license server cannot track per-machine activation for seat enforcement
2. ENTERPRISE multi-seat contracts cannot be audited
3. A single activation code can be shared across unlimited machines

**GAP-5.5 (MEDIUM): No license expiry warning at scan start**
When a license is within 7 days of expiry, the strategy says to warn the user.
Currently: no warning shown. Users discover expiry only when the scan fails to load tier caps
and silently degrades to FREE_BYOK without explanation.

**GAP-5.6 (LOW): license.ts status() delegates to StatusCommand.run() — double layer**
File: packages/cli/src/commands/license.ts line 125-128
LicenseCommand.status() just calls StatusCommand.run(). This is fine functionally but creates
a confusing chain. The license status subcommand and the top-level status command are identical.
This is a code duplication smell — not a functional bug.

---

## PHASE 5 REMEDIATION PROMPT

Scope: packages/core-engine/src/license/ and packages/cli/src/commands/license.ts
Do NOT touch Phase 1-4 code. Do NOT modify the license-server (that is a separate deployment).

### TASK 1 (CRITICAL): Implement background JWT refresh in resolveTierCapabilities()

File: packages/core-engine/src/license/license-resolver.ts (or wherever resolveTierCapabilities is defined)

Add these two helper functions and wire them into the existing license resolution flow:

` ypescript
const REFRESH_THRESHOLD_DAYS = 7;

function isNearExpiry(expTimestampSeconds: number, now: Date = new Date()): boolean {
const msRemaining = expTimestampSeconds _ 1000 - now.getTime();
return msRemaining > 0 && msRemaining < REFRESH_THRESHOLD_DAYS _ 24 _ 60 _ 60 \* 1000;
}

async function refreshLicenseInBackground(
licensePath: string,
sub: string,
serverUrl: string = 'https://license.secureship.dev'
): Promise<void> {
// Fire-and-forget: errors are non-fatal (user still has valid JWT)
try {
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 5000);
const res = await fetch(${serverUrl}/v1/validate, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ sub }),
signal: controller.signal,
});
clearTimeout(timeout);
if (res.ok) {
const data = await res.json() as { jwt?: string };
if (data.jwt) {
writeLicenseFile(data.jwt, licensePath);
}
}
} catch {
// Background refresh failure is silent — existing JWT remains valid
}
}
`

Then in the resolveTierCapabilities() logic after verifying the JWT is valid:
`	ypescript
if (payload && new Date(payload.exp * 1000) > new Date()) {
  // Background refresh if within 7 days of expiry
  if (isNearExpiry(payload.exp)) {
    void refreshLicenseInBackground(licenseJwtPath, payload.sub, options.licenseServerUrl);
  }
  return buildTierState(payload);
}
`

### TASK 2 (CRITICAL): Regenerate and replace the embedded RSA public key

Step 1: Generate a fresh keypair using the existing utility:
`	ypescript
import { generateLicenseKeyPair } from '@secureship/core-engine';
const { publicKeyPem, privateKeyPem } = generateLicenseKeyPair();
console.log('PUBLIC KEY (embed in CLI):\n', publicKeyPem);
console.log('PRIVATE KEY (store in license server secrets):\n', privateKeyPem);
`

Step 2: Replace SECURESHIP_PUBLIC_KEY_PEM in license-keys.ts with the freshly generated
2048-bit RSA public key in proper PEM format (64-char base64 lines, standard PKCS#8 SPKI encoding).

Step 3: The matching private key MUST be stored as a secret in the license server deployment
(Cloudflare Worker environment secret: SECURESHIP_LICENSE_PRIVATE_KEY).

Step 4: Add a verification test:
`	ypescript
// packages/core-engine/test/license/key-integrity.test.ts
it('embedded public key is a valid RSA-2048 SPKI PEM', () => {
  const { createPublicKey } = crypto;
  expect(() => createPublicKey(SECURESHIP_PUBLIC_KEY_PEM)).not.toThrow();
  const key = createPublicKey(SECURESHIP_PUBLIC_KEY_PEM);
  expect(key.asymmetricKeyType).toBe('rsa');
  const details = key.asymmetricKeyDetails;
  expect(details?.modulusLength).toBe(2048);
});
`

### TASK 3 (HIGH): Wire AI usage quota enforcement into scan orchestrator

File: packages/core-engine/src/orchestrator/scan-orchestrator.ts

After resolving tierCaps (line ~190), before Gate 3 AI is activated, add quota check:
`	ypescript
// Phase 5: AI Usage Quota Enforcement (FREE_BYOK: 15 fixes/month)
if (options.ai && tierCaps.maxMonthlyAiFixes !== null) {
  const usage = getMonthlyAiUsage(); // from ai-usage-ledger
  if (usage.fixesUsed >= tierCaps.maxMonthlyAiFixes) {
    logger.warn(
      Monthly AI fix quota reached (/ for ). +
       Gate 3 AI disabled. Upgrade to PRO_TEAM for 100 fixes/month. +
       Run 'secureship license upgrade' to unlock more.
    );
    options.ai = false;
  }
}
`

Import getMonthlyAiUsage from '../license/ai-usage-ledger.js'.

Write test in packages/core-engine/test/license/ai-quota.test.ts:

1. "AI triage disabled when fixesUsed >= maxMonthlyAiFixes for FREE_BYOK"
   - Mock getMonthlyAiUsage to return { fixesUsed: 15, ... }
   - Mock tier = FREE_BYOK (maxMonthlyAiFixes: 15)
   - Assert: AI option is false after orchestrator processes the quota check
2. "AI triage NOT disabled for PRO_TEAM (maxMonthlyAiFixes: 100)"
   - Mock fixesUsed=50, tier=PRO_TEAM
   - Assert: AI option remains enabled
3. "AI triage NOT disabled for ENTERPRISE (maxMonthlyAiFixes: null = unlimited)"
   - Mock fixesUsed=9999, tier=ENTERPRISE (null limit)
   - Assert: AI option remains enabled

### TASK 4 (MEDIUM): Add machineFingerprint to license activate request

File: packages/cli/src/commands/license.ts

Generate a machine fingerprint using available system info:
` ypescript
import { createHash } from 'node:crypto';
import { hostname } from 'node:os';

function getMachineFingerprint(): string {
// Deterministic but non-sensitive: combination of hostname + platform + arch
// Does NOT collect: IP, username, disk serial, MAC address (zero PII)
const raw = [hostname(), process.platform, process.arch].join('|');
return createHash('sha256').update(raw).digest('hex').slice(0, 16);
}
`

Add to the POST body in the online activation path:
`	ypescript
body: JSON.stringify({
  activationCode: code,
  machineFingerprint: getMachineFingerprint(),
}),
`

### TASK 5 (MEDIUM): Add license expiry warning at scan start

File: packages/core-engine/src/license/license-resolver.ts

In resolveTierCapabilities(), after verifying the JWT is valid:
`	ypescript
const daysRemaining = Math.ceil((payload.exp * 1000 - Date.now()) / (24 * 60 * 60 * 1000));
if (daysRemaining <= 7 && daysRemaining > 0) {
  // Use process.stderr to not pollute JSON output
  process.stderr.write(
    [SecureShip] WARNING: Your  license expires in  day(s).  +
    Run 'secureship license activate <new-key>' to renew.\n
  );
}
`

### TESTING REQUIREMENTS FOR PHASE 5:

Test file 1: packages/core-engine/test/license/key-integrity.test.ts

- 1 test: embedded public key is valid RSA-2048 SPKI (see TASK 2)

Test file 2: packages/core-engine/test/license/ai-quota.test.ts

- 3 tests: quota enforcement for FREE, PRO, ENTERPRISE tiers (see TASK 3)

Test file 3: packages/core-engine/test/license/background-refresh.test.ts

- Test: isNearExpiry() returns true when exp is 3 days from now
- Test: isNearExpiry() returns false when exp is 30 days from now
- Test: isNearExpiry() returns false when JWT is already expired
- Test: refreshLicenseInBackground() silently ignores network failures (no throw)
- Test: refreshLicenseInBackground() writes new JWT when server returns valid jwt field

Test file 4: packages/cli/test/license/machine-fingerprint.test.ts

- Test: getMachineFingerprint() returns 16-char hex string
- Test: getMachineFingerprint() is deterministic (same result on repeat calls)
- Test: getMachineFingerprint() does NOT include home directory path (no PII)

---

## SUMMARY: ALL PHASES REMEDIATION PRIORITY MATRIX

| Phase | Gap ID  | Severity | Description                                            | Effort  |
| :---- | :------ | :------- | :----------------------------------------------------- | :------ |
| 1     | GAP-1.1 | CRITICAL | Hardcoded SHA256 values in install-tools               | 1 day   |
| 5     | GAP-5.2 | CRITICAL | Malformed embedded RSA public key                      | 2 hours |
| 5     | GAP-5.3 | HIGH     | AI quota enforcement not wired                         | 4 hours |
| 5     | GAP-5.1 | HIGH     | No background JWT refresh                              | 4 hours |
| 1     | GAP-1.2 | HIGH     | CI pnpm version mismatch                               | 30 min  |
| 1     | GAP-1.3 | HIGH     | CI missing mutation test step                          | 30 min  |
| 2     | GAP-2.1 | CRITICAL | Watch mode uses node:fs.watch not chokidar             | 1 day   |
| 2     | GAP-2.2 | HIGH     | init.ts uses readline not @inquirer/prompts            | 4 hours |
| 2     | GAP-2.3 | HIGH     | Watch does full scan not incremental                   | 2 hours |
| 3     | GAP-3.1 | HIGH     | No Python combination alert tests                      | 4 hours |
| 3     | GAP-3.2 | HIGH     | No .pyw extension test                                 | 1 hour  |
| 4     | GAP-4.1 | HIGH     | SBOM vulnerability correlation uses fragile path match | 4 hours |
| 4     | GAP-4.2 | HIGH     | Zero SBOM command tests                                | 4 hours |
| 5     | GAP-5.4 | MEDIUM   | license activate missing machineFingerprint            | 2 hours |
| 5     | GAP-5.5 | MEDIUM   | No license expiry warning at scan start                | 2 hours |
| 1     | GAP-1.4 | MEDIUM   | No Homebrew/winget distribution artifacts              | 2 days  |
| 4     | GAP-4.3 | MEDIUM   | CLI version hardcoded in sbom.ts                       | 30 min  |
| 2     | GAP-2.4 | MEDIUM   | Generated GHA template missing --baseline              | 30 min  |
| 3     | GAP-3.3 | MEDIUM   | Python class method enclosingFunction test             | 1 hour  |
| 3     | GAP-3.4 | MEDIUM   | Python fallback path not tested                        | 1 hour  |
| 4     | GAP-4.4 | MEDIUM   | --signed error missing pricing context                 | 30 min  |

**Total estimated effort**: ~4-5 working days to resolve all gaps.
**CRITICAL items must be fixed before any public release.**
