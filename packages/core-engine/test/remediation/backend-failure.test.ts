import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  UserConfigSchema,
  type IScannerAdapter,
  type NormalizedFinding,
  type PatchProposal,
  type ScaPatchProposal,
  type UserConfig,
} from '@secureship/contracts';
import type { ISandboxBackend, SandboxRunOptions, SandboxRunResult } from '@secureship/sandbox';
import { VerificationLadder } from '../../src/remediation/verification-ladder.js';
import { ScaVerificationLadder } from '../../src/remediation/sca-verification-ladder.js';

class ThrowingBackend implements ISandboxBackend {
  public readonly name = 'container' as const;
  constructor(private readonly errorMessage: string) {}
  async run(
    _command: string,
    _args: string[],
    _options?: SandboxRunOptions
  ): Promise<SandboxRunResult> {
    throw new Error(this.errorMessage);
  }
  async cleanup(): Promise<void> {}
  async isAvailable(): Promise<boolean> {
    return true;
  }
  getMetadata() {
    return { backend: 'container' as const };
  }
}

class NonZeroExitBackend implements ISandboxBackend {
  public readonly name = 'container' as const;
  constructor(private readonly exitCode: number = 1) {}
  async run(
    command: string,
    args: string[],
    _options?: SandboxRunOptions
  ): Promise<SandboxRunResult> {
    return {
      exitCode: this.exitCode,
      timedOut: false,
      durationMs: 10,
      stdout: '',
      stderr: `Process exited with code ${this.exitCode}`,
      outputTail: `Process exited with code ${this.exitCode}`,
      outputSha256: '0'.repeat(64),
      command,
      argv: args,
    };
  }
  async cleanup(): Promise<void> {}
  async isAvailable(): Promise<boolean> {
    return true;
  }
  getMetadata() {
    return { backend: 'container' as const };
  }
}

class AsyncRejectingBackend implements ISandboxBackend {
  public readonly name = 'container' as const;
  constructor(private readonly errorMessage: string) {}
  async run(
    _command: string,
    _args: string[],
    _options?: SandboxRunOptions
  ): Promise<SandboxRunResult> {
    await new Promise((resolve) => setTimeout(resolve, 5));
    return Promise.reject(new Error(this.errorMessage));
  }
  async cleanup(): Promise<void> {}
  async isAvailable(): Promise<boolean> {
    return true;
  }
  getMetadata() {
    return { backend: 'container' as const };
  }
}

function countShadowDirs(): number {
  try {
    const tmp = os.tmpdir();
    const entries = fs.readdirSync(tmp);
    return entries.filter((e) => e.startsWith('secureship-shadow-')).length;
  } catch {
    return 0;
  }
}

describe('LAYER G: Backend Failure Containment', () => {
  let tempRepo: string;
  let scaRepo: string;

  beforeEach(() => {
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-backend-err-test-'));
    fs.mkdirSync(path.join(tempRepo, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tempRepo, 'src', 'vuln.ts'),
      'export function handle(input: string) {\n  const query = "SELECT * FROM users WHERE id = " + input;\n  return query;\n}\n'
    );

    scaRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sca-backend-err-'));
    fs.writeFileSync(
      path.join(scaRepo, 'package.json'),
      JSON.stringify(
        {
          name: 'test-sca-app',
          version: '1.0.0',
          dependencies: { lodash: '4.17.20' },
        },
        null,
        2
      ) + '\n'
    );
  });

  afterEach(() => {
    if (tempRepo && fs.existsSync(tempRepo)) {
      fs.rmSync(tempRepo, { recursive: true, force: true });
    }
    if (scaRepo && fs.existsSync(scaRepo)) {
      fs.rmSync(scaRepo, { recursive: true, force: true });
    }
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  const baseFinding: NormalizedFinding = {
    id: 'f1',
    fingerprint: '1'.repeat(64),
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
    location: { filePath: 'src/vuln.ts', startLine: 2, endLine: 2 },
    evidence: [
      {
        scannerName: 'semgrep',
        scannerRuleId: 'rules.sqli',
        message: 'SQL injection',
      },
    ],
    createdAt: new Date().toISOString(),
  };

  const cleanProposal: PatchProposal = {
    findingFingerprint: '1'.repeat(64),
    summary: 'Use parameterized query',
    diff: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,1 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  const query = "SELECT * FROM users WHERE id = $1";',
    rationale: 'Parameter binding fixes SQLi',
    assumptions: [],
    risks: [],
    model: 'fake-model',
    promptVersion: 'fix-1.0',
    attempt: 1,
  };

  const scaFinding: NormalizedFinding = {
    id: 'f-sca',
    fingerprint: '2'.repeat(64),
    category: 'SCA',
    severity: 'HIGH',
    confidence: 'HIGH',
    ruleId: 'CVE-2020-8203',
    title: 'Prototype pollution in lodash',
    description: 'Prototype pollution in lodash',
    scannerName: 'osv-scanner',
    location: { filePath: 'package.json', startLine: 5, endLine: 5 },
    reachability: 'UNKNOWN',
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    cweIds: [],
    package: {
      ecosystem: 'npm',
      name: 'lodash',
      version: '4.17.20',
      fixedVersion: '4.17.21',
    },
    evidence: [
      {
        scannerName: 'osv-scanner',
        scannerRuleId: 'CVE-2020-8203',
        message: 'Prototype pollution',
      },
    ],
    createdAt: new Date().toISOString(),
  };

  const scaProposal: ScaPatchProposal = {
    findingFingerprint: '2'.repeat(64),
    packageManager: 'npm',
    targetPackage: 'lodash',
    currentVersion: '4.17.20',
    targetVersion: '4.17.21',
    isTransitive: false,
    strategy: 'DIRECT_UPGRADE',
    manifestPath: 'package.json',
    attempt: 1,
    generatedAt: new Date().toISOString(),
  };

  const dynamicConfig: UserConfig = UserConfigSchema.parse({
    sandbox: {
      backend: 'container',
      commands: {
        typecheck: ['npm', 'run', 'typecheck'],
        build: ['npm', 'run', 'build'],
        test: ['npm', 'test'],
      },
    },
  });

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
        durationMs: 1,
        exitCode: 0,
        timedOut: false,
      };
    },
  };

  const scaAdapter: IScannerAdapter = {
    name: 'osv-scanner',
    category: 'SCA',
    version: async () => '1.0.0',
    isAvailable: async () => true,
    supportsProject: () => true,
    scan: async () => ({
      scannerName: 'osv-scanner',
      status: 'SUCCESS',
      findings: [],
      durationMs: 1,
      exitCode: 0,
      timedOut: false,
    }),
  };

  const hostileErrorMessage =
    'Sandbox launch fault at /var/secrets/isolated/node_modules/daemon/worker.ts:89:12\n' +
    '    at launchProcess (/var/secrets/isolated/worker.ts:45:10)\n' +
    '    at async runJob (C:\\SecureShip\\Private\\runner.ts:22:5)';

  describe('ScaVerificationLadder Containment', () => {
    it('G1, G2, G3: contains (a) throwing backend with paths and stack trace', async () => {
      const throwingBackend = new ThrowingBackend(hostileErrorMessage);
      const shadowsBefore = countShadowDirs();

      const res = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: dynamicConfig,
        adapters: [scaAdapter],
        patchedBackend: throwingBackend,
        unpatchedBackend: throwingBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      const shadowsAfter = countShadowDirs();
      // G1: execute resolves cleanly, shadow dirs cleaned
      expect(shadowsAfter - shadowsBefore).toBe(0);

      // G2: status is never VERIFIED_RUNTIME, no dynamic stage PASS
      expect(res.report.status).toBe('INCONCLUSIVE');
      expect(res.allowed).toBe(false);
      const passDynamicStages = res.report.stages.filter(
        (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
      );
      expect(passDynamicStages).toEqual([]);

      // G3: Stage details contain no stack frames, no absolute paths, capped at 200 chars
      const installStage = res.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('INCONCLUSIVE');
      const detail = installStage?.detail ?? '';
      expect(detail.includes('\n')).toBe(false);
      expect(detail.includes('/var/secrets/isolated')).toBe(false);
      expect(detail.includes('C:\\SecureShip\\Private')).toBe(false);
      expect(detail.includes('<path>')).toBe(true);

      const prefix = 'Sandbox backend error during INSTALL: ';
      expect(detail.startsWith(prefix)).toBe(true);
      const payload = detail.slice(prefix.length);
      expect(payload.length).toBeLessThanOrEqual(200);

      // Short-circuiting: remaining dynamic stages are SKIPPED with exact reason
      for (const skippedId of ['TYPECHECK', 'BUILD', 'TEST'] as const) {
        const stage = res.report.stages.find((s) => s.id === skippedId);
        expect(stage?.outcome).toBe('SKIPPED');
        expect(stage?.detail).toBe('Skipped: sandbox backend unavailable (see INSTALL)');
      }
    });

    it('G1, G2: contains (b) non-zero exit code backend', async () => {
      const failBackend = new NonZeroExitBackend(127);
      const shadowsBefore = countShadowDirs();

      const res = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: dynamicConfig,
        adapters: [scaAdapter],
        patchedBackend: failBackend,
        unpatchedBackend: failBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      const shadowsAfter = countShadowDirs();
      expect(shadowsAfter - shadowsBefore).toBe(0);

      expect(res.report.status).toBe('FAILED');
      expect(res.allowed).toBe(false);
      expect(res.failureReason).toBe('Package manager install failed in sandbox');
      expect(res.report.stages.map((s) => s.id)).toEqual([
        'APPLY',
        'POLICY',
        'SYNTAX',
        'RESCAN',
        'NEW_FINDINGS',
        'IMPORTS',
        'INSTALL',
      ]);
      const installStage = res.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('FAIL');
      expect(installStage?.exitCode).toBe(127);
    });

    it('G1, G2, G3: contains (c) async rejecting backend', async () => {
      const rejectingBackend = new AsyncRejectingBackend(hostileErrorMessage);
      const shadowsBefore = countShadowDirs();

      const res = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: dynamicConfig,
        adapters: [scaAdapter],
        patchedBackend: rejectingBackend,
        unpatchedBackend: rejectingBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      const shadowsAfter = countShadowDirs();
      expect(shadowsAfter - shadowsBefore).toBe(0);

      expect(res.report.status).toBe('INCONCLUSIVE');
      expect(res.allowed).toBe(false);

      const installStage = res.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('INCONCLUSIVE');
      const detail = installStage?.detail ?? '';
      expect(detail.includes('\n')).toBe(false);
      expect(detail.includes('/var/secrets/isolated')).toBe(false);
      expect(detail.includes('<path>')).toBe(true);

      for (const skippedId of ['TYPECHECK', 'BUILD', 'TEST'] as const) {
        const stage = res.report.stages.find((s) => s.id === skippedId);
        expect(stage?.outcome).toBe('SKIPPED');
        expect(stage?.detail).toBe('Skipped: sandbox backend unavailable (see INSTALL)');
      }
    });
  });

  describe('VerificationLadder (Code Ladder) Containment', () => {
    it('G1, G2: contains (a) throwing backend without unhandled rejection or leaks', async () => {
      const throwingBackend = new ThrowingBackend(hostileErrorMessage);
      const shadowsBefore = countShadowDirs();

      const res = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: dynamicConfig,
        adapters: [fakeScanner],
        unpatchedBackend: throwingBackend,
        patchedBackend: throwingBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      const shadowsAfter = countShadowDirs();
      expect(shadowsAfter - shadowsBefore).toBe(0);

      expect(res.report.status).toBe('INCONCLUSIVE');
      expect(res.allowed).toBe(false);
      expect(res.failureReason).toBe('Requirement VERIFIED_RUNTIME not met: achieved INCONCLUSIVE');
      const dynamicPassStages = res.report.stages.filter(
        (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
      );
      expect(dynamicPassStages).toEqual([]);

      // Dynamic stages are inconclusive due to uncontained launch failure in baseline
      const dynamicExecuted = res.report.stages.filter((s) =>
        ['TYPECHECK', 'BUILD', 'TEST'].includes(s.id)
      );
      for (const stage of dynamicExecuted) {
        expect(stage.outcome).toBe('INCONCLUSIVE');
      }
    });

    it('G1, G2: contains (b) non-zero exit code backend', async () => {
      const failBackend = new NonZeroExitBackend(1);
      const shadowsBefore = countShadowDirs();

      const res = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: dynamicConfig,
        adapters: [fakeScanner],
        unpatchedBackend: failBackend,
        patchedBackend: failBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      const shadowsAfter = countShadowDirs();
      expect(shadowsAfter - shadowsBefore).toBe(0);

      expect(res.report.status).toBe('INCONCLUSIVE');
      expect(res.allowed).toBe(false);
      expect(res.failureReason).toBe('Requirement VERIFIED_RUNTIME not met: achieved INCONCLUSIVE');
      const dynamicPassStages = res.report.stages.filter(
        (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
      );
      expect(dynamicPassStages).toEqual([]);
      const tcStage = res.report.stages.find((s) => s.id === 'TYPECHECK');
      expect(tcStage?.outcome).toBe('INCONCLUSIVE');
    });

    it('G1, G2: contains (c) async rejecting backend', async () => {
      const rejectingBackend = new AsyncRejectingBackend(hostileErrorMessage);
      const shadowsBefore = countShadowDirs();

      const res = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: dynamicConfig,
        adapters: [fakeScanner],
        unpatchedBackend: rejectingBackend,
        patchedBackend: rejectingBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      const shadowsAfter = countShadowDirs();
      expect(shadowsAfter - shadowsBefore).toBe(0);

      expect(res.report.status).toBe('INCONCLUSIVE');
      expect(res.allowed).toBe(false);
      expect(res.failureReason).toBe('Requirement VERIFIED_RUNTIME not met: achieved INCONCLUSIVE');
      const dynamicPassStages = res.report.stages.filter(
        (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
      );
      expect(dynamicPassStages).toEqual([]);
      const tcStage = res.report.stages.find((s) => s.id === 'TYPECHECK');
      expect(tcStage?.outcome).toBe('INCONCLUSIVE');
    });
  });
});
