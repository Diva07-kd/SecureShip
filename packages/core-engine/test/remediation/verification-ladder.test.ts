import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  UserConfigSchema,
  type IScannerAdapter,
  type NormalizedFinding,
  type PatchProposal,
  type UserConfig,
} from '@secureship/contracts';
import { FakeSandboxBackend } from '@secureship/sandbox';
import { VerificationLadder } from '../../src/remediation/verification-ladder.js';

describe('VerificationLadder', () => {
  let tempRepo: string;

  beforeEach(() => {
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-ladder-test-'));
    fs.mkdirSync(path.join(tempRepo, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tempRepo, 'src', 'vuln.ts'),
      'export function handle(input: string) {\n  const query = "SELECT * FROM users WHERE id = " + input;\n  return query;\n}\n'
    );
  });

  afterEach(() => {
    fs.rmSync(tempRepo, { recursive: true, force: true });
  });

  const baseFinding: NormalizedFinding = {
    id: 'f1',
    fingerprint: 'e'.repeat(64),
    ruleId: 'rules.sqli',
    scannerName: 'semgrep',
    category: 'SAST',
    severity: 'HIGH',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    title: 'SQL Injection',
    description: 'Dynamic concatenation',
    cweIds: ['CWE-89'],
    location: {
      filePath: 'src/vuln.ts',
      startLine: 2,
      endLine: 2,
    },
    evidence: [{ scannerName: 'semgrep', scannerRuleId: 'rules.sqli', message: 'SQL injection' }],
    createdAt: new Date().toISOString(),
  };

  const cleanProposal: PatchProposal = {
    findingFingerprint: 'e'.repeat(64),
    summary: 'Use parameterized query',
    diff: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,1 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  const query = "SELECT * FROM users WHERE id = $1";',
    rationale: 'Parameter binding fixes SQLi',
    assumptions: [],
    risks: [],
    model: 'fake-model',
    promptVersion: 'fix-1.0',
    attempt: 1,
  };

  const userConfig: UserConfig = UserConfigSchema.parse({
    enabled: true,
    fix: {
      maxFiles: 1,
      maxChangedLines: 60,
      maxDiffBytes: 20000,
      maxAttempts: 2,
      minNewFindingSeverity: 'MEDIUM',
      allowRemovalOnly: false,
    },
    sandbox: {
      backend: 'none',
      runtime: 'auto',
      images: {},
      limits: {
        memory: '2g',
        cpus: 2,
        pids: 512,
        tmpfsMb: 512,
        stageTimeoutSec: { install: 600, typecheck: 300, build: 600, test: 900 },
        totalTimeoutSec: 1800,
        outputCapBytes: 5242880,
      },
      install: { enabled: false, ignoreScripts: true },
      trustedHostRepos: [],
    },
  });

  it('runs static ladder cleanly and reports VERIFIED_STATIC when dynamic stages skipped', async () => {
    const fakeScanner: IScannerAdapter = {
      name: 'semgrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (dir: string) => {
        const content = fs.readFileSync(path.join(dir, 'src', 'vuln.ts'), 'utf8');
        const hasVuln = content.includes('WHERE id = " + input');
        return {
          scannerName: 'semgrep',
          status: 'SUCCESS',
          findings: hasVuln ? [baseFinding] : [],
          durationMs: 10,
          exitCode: 0,
          timedOut: false,
        };
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      adapters: [fakeScanner],
      skipDynamic: true,
    });

    expect(res.allowed).toBe(true);
    expect(res.report.status).toBe('VERIFIED_STATIC');
    expect(res.report.stages).toHaveLength(10);
    expect(res.report.stages.find((s) => s.id === 'APPLY')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'POLICY')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'SYNTAX')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'RESCAN')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'NEW_FINDINGS')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'IMPORTS')?.outcome).toBe('PASS');

    // Dynamic stages are SKIPPED
    expect(res.report.stages.find((s) => s.id === 'INSTALL')?.outcome).toBe('SKIPPED');
    expect(res.report.stages.find((s) => s.id === 'INSTALL')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );
    expect(res.report.stages.find((s) => s.id === 'TYPECHECK')?.outcome).toBe('SKIPPED');
    expect(res.report.stages.find((s) => s.id === 'TYPECHECK')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );
    expect(res.report.stages.find((s) => s.id === 'BUILD')?.outcome).toBe('SKIPPED');
    expect(res.report.stages.find((s) => s.id === 'BUILD')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );
    expect(res.report.stages.find((s) => s.id === 'TEST')?.outcome).toBe('SKIPPED');
    expect(res.report.stages.find((s) => s.id === 'TEST')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );

    // Working tree is strictly untouched
    const origContent = fs.readFileSync(path.join(tempRepo, 'src', 'vuln.ts'), 'utf8');
    expect(origContent).toContain('WHERE id = " + input');

    // Verify HMAC signature
    expect(VerificationLadder.verifySignature(res.report)).toBe(true);
  });

  it('fails ladder on policy violation (suppression marker)', async () => {
    const maliciousProposal: PatchProposal = {
      ...cleanProposal,
      diff: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,2 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  // nosemgrep\n+  const query = "SELECT * FROM users WHERE id = " + input;',
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: maliciousProposal,
      userConfig,
      skipDynamic: true,
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('FAILED');
    const policyStage = res.report.stages.find((s) => s.id === 'POLICY');
    expect(policyStage?.outcome).toBe('FAIL');
    expect(policyStage?.detail).toContain('SUPPRESSION_MARKER');
  });

  it('returns INCONCLUSIVE when originating scanner is missing (Mutation 9)', async () => {
    // Provide empty adapters list so originating scanner is missing
    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      adapters: [],
      skipDynamic: true,
    });

    const rescanStage = res.report.stages.find((s) => s.id === 'RESCAN');
    expect(rescanStage?.outcome).toBe('INCONCLUSIVE');
    expect(rescanStage?.detail).toContain('not available');
    expect(res.report.status).toBe('INCONCLUSIVE');
    expect(res.allowed).toBe(false);
    expect(res.failureReason).toBe('Requirement VERIFIED_STATIC not met: achieved INCONCLUSIVE');
  });

  it('fails ladder on syntax error in patched file', async () => {
    const syntaxErrProposal: PatchProposal = {
      ...cleanProposal,
      diff: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,1 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  const query = ;;; {{{ invalid syntax;',
    };

    const fakeScanner: IScannerAdapter = {
      name: 'semgrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async () => ({
        scannerName: 'semgrep',
        status: 'SUCCESS',
        findings: [],
        durationMs: 1,
        exitCode: 0,
        timedOut: false,
      }),
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: syntaxErrProposal,
      userConfig,
      adapters: [fakeScanner],
      skipDynamic: true,
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('FAILED');
    const syntaxStage = res.report.stages.find((s) => s.id === 'SYNTAX');
    expect(syntaxStage?.outcome).toBe('FAIL');
  });

  it('fails ladder when net-new finding is introduced on patched shadow copy (Mutation 10)', async () => {
    const fakeScanner: IScannerAdapter = {
      name: 'semgrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (dir: string) => {
        const content = fs.readFileSync(path.join(dir, 'src', 'vuln.ts'), 'utf8');
        // Baseline has original finding; patched introduces a new finding
        if (content.includes('WHERE id = " + input')) {
          return {
            scannerName: 'semgrep',
            status: 'SUCCESS',
            findings: [baseFinding],
            durationMs: 5,
            exitCode: 0,
            timedOut: false,
          };
        } else {
          // Patched has net-new finding
          const newFinding: NormalizedFinding = {
            ...baseFinding,
            id: 'f2',
            fingerprint: '9'.repeat(64),
            ruleId: 'rules.new_vuln',
            severity: 'HIGH',
            title: 'Net New Vulnerability',
          };
          return {
            scannerName: 'semgrep',
            status: 'SUCCESS',
            findings: [newFinding],
            durationMs: 5,
            exitCode: 0,
            timedOut: false,
          };
        }
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      adapters: [fakeScanner],
      skipDynamic: true,
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('FAILED');
    const newFindingsStage = res.report.stages.find((s) => s.id === 'NEW_FINDINGS');
    expect(newFindingsStage?.outcome).toBe('FAIL');
    expect(newFindingsStage?.detail).toContain('Net-new finding introduced');
  });

  it('runs dynamic stages with FakeSandboxBackend and reports VERIFIED_RUNTIME on pass', async () => {
    const fakeScanner: IScannerAdapter = {
      name: 'semgrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (dir: string) => {
        const content = fs.readFileSync(path.join(dir, 'src', 'vuln.ts'), 'utf8');
        const hasVuln = content.includes('WHERE id = " + input');
        return {
          scannerName: 'semgrep',
          status: 'SUCCESS',
          findings: hasVuln ? [baseFinding] : [],
          durationMs: 10,
          exitCode: 0,
          timedOut: false,
        };
      },
    };

    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });
    const patchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });

    const dynamicConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
        commands: {
          test: ['npm', 'test'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: dynamicConfig,
      adapters: [fakeScanner],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.allowed).toBe(true);
    expect(res.report.status).toBe('VERIFIED_RUNTIME');
    const testStage = res.report.stages.find((s) => s.id === 'TEST');
    expect(testStage?.outcome).toBe('PASS');
  });

  it('skips all stages and reports UNVERIFIED when verifyLevel is none', async () => {
    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      verifyLevel: 'none',
      requirement: 'UNVERIFIED',
    });

    expect(res.allowed).toBe(true);
    expect(res.report.status).toBe('UNVERIFIED');
    expect(res.report.stages.every((s) => s.outcome === 'SKIPPED')).toBe(true);
  });

  const createDefaultFakeScanner = (): IScannerAdapter => ({
    name: 'semgrep',
    category: 'SAST',
    version: async () => '1.0.0',
    isAvailable: async () => true,
    supportsProject: () => true,
    scan: async (dir: string) => {
      const vulnPath = path.join(dir, 'src', 'vuln.ts');
      const content = fs.existsSync(vulnPath) ? fs.readFileSync(vulnPath, 'utf8') : '';
      const hasVuln = content.includes('WHERE id = " + input');
      return {
        scannerName: 'semgrep',
        status: 'SUCCESS',
        findings: hasVuln ? [baseFinding] : [],
        durationMs: 10,
        exitCode: 0,
        timedOut: false,
      };
    },
  });

  it('fails at POLICY stage when diff contains policy violation', async () => {
    const violatingProposal: PatchProposal = {
      ...cleanProposal,
      diff: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,2 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  // nosemgrep\n+  const query = "SELECT * FROM users WHERE id = " + input;',
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: violatingProposal,
      userConfig,
      skipDynamic: true,
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('FAILED');
    const policyStage = res.report.stages.find((s) => s.id === 'POLICY');
    expect(policyStage?.outcome).toBe('FAIL');
    expect(policyStage?.detail).toContain('SUPPRESSION_MARKER');
  });

  it('fails at SYNTAX stage when diff introduces AST syntax error', async () => {
    const syntaxErrorProposal: PatchProposal = {
      ...cleanProposal,
      diff: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,1 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  const query = ;',
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: syntaxErrorProposal,
      userConfig,
      skipDynamic: true,
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('FAILED');
    const syntaxStage = res.report.stages.find((s) => s.id === 'SYNTAX');
    expect(syntaxStage?.outcome).toBe('FAIL');
  });

  it('reports INCONCLUSIVE when dynamic stage baseline fails', async () => {
    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 1, stderr: 'Baseline test broke' },
    });
    const patchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });

    const dynamicConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
        commands: {
          test: ['npm', 'test'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: dynamicConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.report.status).toBe('INCONCLUSIVE');
    const testStage = res.report.stages.find((s) => s.id === 'TEST');
    expect(testStage?.outcome).toBe('INCONCLUSIVE');
  });

  it('reports FAILED when dynamic stage fails on patched code', async () => {
    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });
    const patchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 1, stderr: 'Patched regression broke tests' },
    });

    const dynamicConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
        commands: {
          test: ['npm', 'test'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: dynamicConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.report.status).toBe('FAILED');
    const testStage = res.report.stages.find((s) => s.id === 'TEST');
    expect(testStage?.outcome).toBe('FAIL');
  });

  it('resolves correct backend based on user config', () => {
    const hostBackend = VerificationLadder.resolveBackend(
      { ...userConfig, sandbox: { ...userConfig.sandbox, backend: 'host' } },
      tempRepo,
      tempRepo
    );
    expect(hostBackend.name).toBe('host');

    expect(() =>
      VerificationLadder.resolveBackend(
        { ...userConfig, sandbox: { ...userConfig.sandbox, backend: 'none' } },
        tempRepo,
        tempRepo
      )
    ).toThrow("Sandbox backend 'none' does not support command execution");

    const containerBackend = VerificationLadder.resolveBackend(
      { ...userConfig, sandbox: { ...userConfig.sandbox, backend: 'container' } },
      tempRepo,
      tempRepo
    );
    expect(containerBackend.name).toBe('container');

    const nativeIsolatedBackend = VerificationLadder.resolveBackend(
      { ...userConfig, sandbox: { ...userConfig.sandbox, backend: 'native-isolated' } },
      tempRepo,
      tempRepo
    );
    expect(nativeIsolatedBackend.name).toBe('native-isolated');
  });

  it('rejects tampered reports in verifySignature', async () => {
    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      adapters: [createDefaultFakeScanner()],
      skipDynamic: true,
    });

    expect(VerificationLadder.verifySignature(res.report)).toBe(true);

    // Tampered status
    const tamperedReport = { ...res.report, status: 'VERIFIED_RUNTIME' as const };
    expect(VerificationLadder.verifySignature(tamperedReport)).toBe(false);

    // Invalid signature length
    const invalidSigReport = { ...res.report, signature: 'short' };
    expect(VerificationLadder.verifySignature(invalidSigReport)).toBe(false);
  });

  it('executes install, typecheck, and build dynamic stages cleanly', async () => {
    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });
    const patchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });

    const fullDynamicConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
        install: { enabled: true, ignoreScripts: true },
        commands: {
          typecheck: ['npm', 'run', 'typecheck'],
          build: ['npm', 'run', 'build'],
          test: ['npm', 'test'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: fullDynamicConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.report.status).toBe('VERIFIED_RUNTIME');
    expect(res.report.stages.find((s) => s.id === 'INSTALL')?.outcome).toBe('SKIPPED');
    expect(res.report.stages.find((s) => s.id === 'INSTALL')?.detail).toBe(
      'Dependency install is not executed by the code-fix verification ladder'
    );
    expect(res.report.stages.find((s) => s.id === 'TYPECHECK')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'BUILD')?.outcome).toBe('PASS');
    expect(res.report.stages.find((s) => s.id === 'TEST')?.outcome).toBe('PASS');
  });

  it('fails ladder when typecheck dynamic stage fails', async () => {
    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });
    const patchedBackend = new FakeSandboxBackend();
    patchedBackend.scriptResponse('TYPECHECK', { exitCode: 1, stderr: 'Type error' });

    const tcConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
        commands: {
          typecheck: ['npm', 'run', 'typecheck'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: tcConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.report.status).toBe('FAILED');
    expect(res.report.stages.find((s) => s.id === 'TYPECHECK')?.outcome).toBe('FAIL');
  });

  it('fails ladder when build dynamic stage fails', async () => {
    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });
    const patchedBackend = new FakeSandboxBackend();
    patchedBackend.scriptResponse('BUILD', { exitCode: 1, stderr: 'Build syntax error' });

    const buildConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
        commands: {
          build: ['npm', 'run', 'build'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: buildConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.report.status).toBe('FAILED');
    expect(res.report.stages.find((s) => s.id === 'BUILD')?.outcome).toBe('FAIL');
  });

  it('ignores injected backends and records 0 runs when sandbox.backend is none', async () => {
    const unpatchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });
    const patchedBackend = new FakeSandboxBackend({
      defaultResponse: { exitCode: 0, stdout: 'PASS' },
    });

    const noneWithCommandsConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'none',
        commands: {
          typecheck: ['npm', 'run', 'typecheck'],
          build: ['npm', 'run', 'build'],
          test: ['npm', 'test'],
        },
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: noneWithCommandsConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_STATIC',
      skipDynamic: false,
    });

    expect(unpatchedBackend.recordedRuns).toHaveLength(0);
    expect(patchedBackend.recordedRuns).toHaveLength(0);
    expect(res.report.status).toBe('VERIFIED_STATIC');
    expect(res.allowed).toBe(true);

    for (const stageId of ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'] as const) {
      const stage = res.report.stages.find((s) => s.id === stageId);
      expect(stage?.outcome).toBe('SKIPPED');
      expect(stage?.detail).toBe("Dynamic verification disabled: sandbox backend is 'none'");
    }
  });

  it('returns allowed: false and failureReason when requirement VERIFIED_RUNTIME not met due to backend none', async () => {
    const unpatchedBackend = new FakeSandboxBackend();
    const patchedBackend = new FakeSandboxBackend();

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      adapters: [createDefaultFakeScanner()],
      unpatchedBackend,
      patchedBackend,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('VERIFIED_STATIC');
    expect(res.failureReason).toBe(
      "Requirement VERIFIED_RUNTIME not met: dynamic verification disabled (sandbox backend 'none')"
    );
  });

  it('returns allowed: false and failureReason when requirement VERIFIED_RUNTIME not met due to skipDynamic', async () => {
    const containerConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: containerConfig,
      adapters: [createDefaultFakeScanner()],
      skipDynamic: true,
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('VERIFIED_STATIC');
    expect(res.failureReason).toBe(
      'Requirement VERIFIED_RUNTIME not met: dynamic verification skipped by caller'
    );
    for (const stageId of ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'] as const) {
      const stage = res.report.stages.find((s) => s.id === stageId);
      expect(stage?.outcome).toBe('SKIPPED');
      expect(stage?.detail).toBe('Dynamic verification skipped by caller (skipDynamic)');
    }
  });

  it('returns allowed: false and failureReason achieved INCONCLUSIVE when inconclusive even if backend is none', async () => {
    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig,
      adapters: [],
      requirement: 'VERIFIED_RUNTIME',
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('INCONCLUSIVE');
    expect(res.failureReason).toBe('Requirement VERIFIED_RUNTIME not met: achieved INCONCLUSIVE');
  });

  it('returns allowed: false and failureReason achieved VERIFIED_STATIC when dynamic enabled but no commands detected', async () => {
    const containerConfig: UserConfig = {
      ...userConfig,
      sandbox: {
        ...userConfig.sandbox,
        backend: 'container',
      },
    };

    const res = await VerificationLadder.execute({
      rootDir: tempRepo,
      finding: baseFinding,
      proposal: cleanProposal,
      userConfig: containerConfig,
      adapters: [createDefaultFakeScanner()],
      requirement: 'VERIFIED_RUNTIME',
      skipDynamic: false,
    });

    expect(res.allowed).toBe(false);
    expect(res.report.status).toBe('VERIFIED_STATIC');
    expect(res.failureReason).toBe(
      'Requirement VERIFIED_RUNTIME not met: achieved VERIFIED_STATIC'
    );
  });

  it('computeOverallStatus caps at VERIFIED_STATIC when dynamicDisabled is true, preserving FAIL/INCONCLUSIVE precedence', () => {
    // Dynamic stage PASS is capped at VERIFIED_STATIC when dynamicDisabled is true
    expect(
      VerificationLadder.computeOverallStatus(
        [
          { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
          { id: 'TEST', outcome: 'PASS', durationMs: 0, detail: '' },
        ],
        { dynamicDisabled: true }
      )
    ).toBe('VERIFIED_STATIC');

    // FAIL takes precedence over cap
    expect(
      VerificationLadder.computeOverallStatus(
        [
          { id: 'APPLY', outcome: 'FAIL', durationMs: 0, detail: '' },
          { id: 'TEST', outcome: 'PASS', durationMs: 0, detail: '' },
        ],
        { dynamicDisabled: true }
      )
    ).toBe('FAILED');

    // INCONCLUSIVE takes precedence over cap
    expect(
      VerificationLadder.computeOverallStatus(
        [
          { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
          { id: 'RESCAN', outcome: 'INCONCLUSIVE', durationMs: 0, detail: '' },
          { id: 'TEST', outcome: 'PASS', durationMs: 0, detail: '' },
        ],
        { dynamicDisabled: true }
      )
    ).toBe('INCONCLUSIVE');

    // Without dynamicDisabled, dynamic PASS gives VERIFIED_RUNTIME
    expect(
      VerificationLadder.computeOverallStatus([
        { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
        { id: 'TEST', outcome: 'PASS', durationMs: 0, detail: '' },
      ])
    ).toBe('VERIFIED_RUNTIME');
  });
});
