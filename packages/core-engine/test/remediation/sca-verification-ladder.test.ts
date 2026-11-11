import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  type NormalizedFinding,
  type ScaPatchProposal,
  type UserConfig,
  type IScannerAdapter,
  UserConfigSchema,
} from '@secureship/contracts';
import { FakeSandboxBackend } from '@secureship/sandbox';
import { ScaVerificationLadder } from '../../src/remediation/sca-verification-ladder.js';

describe('ScaVerificationLadder Unit Tests', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sca-ladder-'));
    // Initialize mock git repo
    fs.mkdirSync(path.join(tempDir, '.git'), { recursive: true });
    // Write sample package.json
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify(
        {
          name: 'test-app',
          version: '1.0.0',
          dependencies: {
            lodash: '4.17.20',
          },
        },
        null,
        2
      ) + '\n',
      'utf8'
    );
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  const baseFinding: NormalizedFinding = {
    id: 'f-1',
    fingerprint: 'a'.repeat(64),
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
        message: 'Prototype pollution in lodash',
      },
    ],
    createdAt: new Date().toISOString(),
  };

  const baseProposal: ScaPatchProposal = {
    findingFingerprint: 'a'.repeat(64),
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

  const userConfig: UserConfig = UserConfigSchema.parse({
    sandbox: {
      backend: 'none',
    },
  });

  it('executes full 10-stage SCA verification ladder with valid HMAC signature and baseFiles', async () => {
    const result = await ScaVerificationLadder.execute({
      rootDir: tempDir,
      finding: baseFinding,
      proposal: baseProposal,
      userConfig,
      requirement: 'VERIFIED_STATIC',
      skipDynamic: true,
    });

    expect(result.allowed).toBe(true);
    expect(result.report.schemaVersion).toBe('1.1');
    expect(result.report.status).toBe('VERIFIED_STATIC');
    expect(result.report.stages).toHaveLength(10);

    const stageIds = result.report.stages.map((s) => s.id);
    expect(stageIds).toEqual([
      'APPLY',
      'POLICY',
      'SYNTAX',
      'RESCAN',
      'NEW_FINDINGS',
      'IMPORTS',
      'INSTALL',
      'TYPECHECK',
      'BUILD',
      'TEST',
    ]);

    const syntaxStage = result.report.stages.find((s) => s.id === 'SYNTAX');
    expect(syntaxStage?.outcome).toBe('SKIPPED');
    const importsStage = result.report.stages.find((s) => s.id === 'IMPORTS');
    expect(importsStage?.outcome).toBe('SKIPPED');

    // Dynamic stages are SKIPPED when backend is none
    expect(result.report.stages.find((s) => s.id === 'INSTALL')?.outcome).toBe('SKIPPED');
    expect(result.report.stages.find((s) => s.id === 'INSTALL')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );
    expect(result.report.stages.find((s) => s.id === 'TYPECHECK')?.outcome).toBe('SKIPPED');
    expect(result.report.stages.find((s) => s.id === 'TYPECHECK')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );
    expect(result.report.stages.find((s) => s.id === 'BUILD')?.outcome).toBe('SKIPPED');
    expect(result.report.stages.find((s) => s.id === 'BUILD')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );
    expect(result.report.stages.find((s) => s.id === 'TEST')?.outcome).toBe('SKIPPED');
    expect(result.report.stages.find((s) => s.id === 'TEST')?.detail).toBe(
      "Dynamic verification disabled: sandbox backend is 'none'"
    );

    // Signature verification
    expect(ScaVerificationLadder.verifySignature(result.report)).toBe(true);

    // BaseFiles recorded
    expect(result.report.baseFiles).toBeDefined();
    expect(result.report.baseFiles?.length).toBeGreaterThan(0);
    expect(result.report.baseFiles?.[0]?.path).toBe('package.json');
    expect(result.report.baseFiles?.[0]?.sha256).toHaveLength(64);

    // Written to .secureship/sca-fix-<fingerprint>.json
    const reportOnDisk = path.join(
      tempDir,
      '.secureship',
      `sca-fix-${baseFinding.fingerprint}.json`
    );
    expect(fs.existsSync(reportOnDisk)).toBe(true);
  });

  it('fails early at POLICY stage if target version is breaking major bump without permission', async () => {
    const breakingProposal: ScaPatchProposal = {
      ...baseProposal,
      targetVersion: '5.0.0',
    };

    const result = await ScaVerificationLadder.execute({
      rootDir: tempDir,
      finding: baseFinding,
      proposal: breakingProposal,
      userConfig,
      requirement: 'VERIFIED_STATIC',
      skipDynamic: true,
    });

    expect(result.allowed).toBe(false);
    expect(result.report.status).toBe('FAILED');
    const policyStage = result.report.stages.find((s) => s.id === 'POLICY');
    expect(policyStage?.outcome).toBe('FAIL');
  });

  it('executes INSTALL stage with network=true in sandbox backend', async () => {
    const fakeBackend = new FakeSandboxBackend();

    const result = await ScaVerificationLadder.execute({
      rootDir: tempDir,
      finding: baseFinding,
      proposal: baseProposal,
      userConfig: UserConfigSchema.parse({
        sandbox: { backend: 'container' },
      }),
      sandboxBackend: fakeBackend,
      unpatchedBackend: fakeBackend,
      patchedBackend: fakeBackend,
      requirement: 'VERIFIED_STATIC',
      skipDynamic: false,
    });

    expect(fakeBackend.recordedRuns.length).toBeGreaterThan(0);
    expect(fakeBackend.recordedRuns[0]?.options.network).toBe(true);
    const installStage = result.report.stages.find((s) => s.id === 'INSTALL');
    expect(installStage?.outcome).toBe('PASS');
  });

  it('fails verification if INSTALL stage returns non-zero exit code', async () => {
    const failingBackend = new FakeSandboxBackend({
      defaultResponse: {
        exitCode: 1,
        stderr: 'ERESOLVE unable to resolve dependency tree',
      },
    });

    const result = await ScaVerificationLadder.execute({
      rootDir: tempDir,
      finding: baseFinding,
      proposal: baseProposal,
      userConfig: UserConfigSchema.parse({
        sandbox: { backend: 'container' },
      }),
      sandboxBackend: failingBackend,
      unpatchedBackend: failingBackend,
      patchedBackend: failingBackend,
      requirement: 'VERIFIED_STATIC',
      skipDynamic: false,
    });

    expect(result.allowed).toBe(false);
    expect(result.report.status).toBe('FAILED');
    const installStage = result.report.stages.find((s) => s.id === 'INSTALL');
    expect(installStage?.outcome).toBe('FAIL');
    expect(installStage?.exitCode).toBe(1);
  });

  describe('Helper methods and status computations', () => {
    it('getInstallCommand: returns correct package manager commands', () => {
      expect(ScaVerificationLadder.getInstallCommand('pnpm').command).toBe('pnpm');
      expect(ScaVerificationLadder.getInstallCommand('yarn').command).toBe('yarn');
      expect(ScaVerificationLadder.getInstallCommand('pip').command).toBe('pip');
      expect(ScaVerificationLadder.getInstallCommand('poetry').command).toBe('poetry');
      expect(ScaVerificationLadder.getInstallCommand('npm').command).toBe('npm');
    });

    it('computeOverallStatus: computes FAILED, INCONCLUSIVE, VERIFIED_RUNTIME, and VERIFIED_STATIC', () => {
      expect(
        ScaVerificationLadder.computeOverallStatus([
          { id: 'APPLY', outcome: 'FAIL', durationMs: 0, detail: '' },
        ])
      ).toBe('FAILED');

      expect(
        ScaVerificationLadder.computeOverallStatus([
          { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
          { id: 'RESCAN', outcome: 'INCONCLUSIVE', durationMs: 0, detail: '' },
        ])
      ).toBe('INCONCLUSIVE');

      expect(
        ScaVerificationLadder.computeOverallStatus([
          { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
          { id: 'INSTALL', outcome: 'PASS', durationMs: 0, detail: '' },
        ])
      ).toBe('VERIFIED_RUNTIME');

      expect(
        ScaVerificationLadder.computeOverallStatus([
          { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
          { id: 'POLICY', outcome: 'PASS', durationMs: 0, detail: '' },
        ])
      ).toBe('VERIFIED_STATIC');
    });

    it('resolveBackend: resolves container, host, and none backends', () => {
      const containerBackend = ScaVerificationLadder.resolveBackend(
        UserConfigSchema.parse({ sandbox: { backend: 'container' } }),
        tempDir,
        tempDir
      );
      expect(containerBackend.name).toBe('container');

      const hostBackend = ScaVerificationLadder.resolveBackend(
        UserConfigSchema.parse({ sandbox: { backend: 'host' } }),
        tempDir,
        tempDir
      );
      expect(hostBackend.name).toBe('host');

      expect(() =>
        ScaVerificationLadder.resolveBackend(
          UserConfigSchema.parse({ sandbox: { backend: 'none' } }),
          tempDir,
          tempDir
        )
      ).toThrow("Sandbox backend 'none' does not support command execution");

      const nativeBackend = ScaVerificationLadder.resolveBackend(
        UserConfigSchema.parse({ sandbox: { backend: 'native-isolated' } }),
        tempDir,
        tempDir
      );
      expect(nativeBackend.name).toBe('native-isolated');
    });

    it('verifySignature: rejects tampered reports', async () => {
      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig,
        skipDynamic: true,
      });

      expect(ScaVerificationLadder.verifySignature(result.report)).toBe(true);

      const tampered = {
        ...result.report,
        signature: 'deadbeef'.repeat(8),
      };
      expect(ScaVerificationLadder.verifySignature(tampered)).toBe(false);
    });

    it('handles RESCAN stage when scanner detects vulnerability is still present', async () => {
      const mockAdapter: IScannerAdapter = {
        name: 'osv-scanner',
        category: 'SCA',
        version: async () => '1.0.0',
        isAvailable: async () => true,
        supportsProject: () => true,
        scan: async () => ({
          scannerName: 'osv-scanner',
          status: 'SUCCESS',
          findings: [baseFinding],
          durationMs: 10,
          exitCode: 0,
          timedOut: false,
        }),
      };

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig,
        adapters: [mockAdapter],
        skipDynamic: true,
      });

      expect(result.allowed).toBe(false);
      expect(result.report.status).toBe('FAILED');
      const rescanStage = result.report.stages.find((s) => s.id === 'RESCAN');
      expect(rescanStage?.outcome).toBe('FAIL');
    });

    it('computeOverallStatus: caps at VERIFIED_STATIC when dynamicDisabled is true, preserving FAIL/INCONCLUSIVE precedence', () => {
      expect(
        ScaVerificationLadder.computeOverallStatus(
          [
            { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
            { id: 'INSTALL', outcome: 'PASS', durationMs: 0, detail: '' },
          ],
          { dynamicDisabled: true }
        )
      ).toBe('VERIFIED_STATIC');

      expect(
        ScaVerificationLadder.computeOverallStatus(
          [
            { id: 'APPLY', outcome: 'FAIL', durationMs: 0, detail: '' },
            { id: 'INSTALL', outcome: 'PASS', durationMs: 0, detail: '' },
          ],
          { dynamicDisabled: true }
        )
      ).toBe('FAILED');

      expect(
        ScaVerificationLadder.computeOverallStatus(
          [
            { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
            { id: 'RESCAN', outcome: 'INCONCLUSIVE', durationMs: 0, detail: '' },
            { id: 'INSTALL', outcome: 'PASS', durationMs: 0, detail: '' },
          ],
          { dynamicDisabled: true }
        )
      ).toBe('INCONCLUSIVE');
    });

    it('ignores injected backends and records 0 runs when sandbox.backend is none', async () => {
      const fakeBackend = new FakeSandboxBackend();

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig: UserConfigSchema.parse({
          sandbox: {
            backend: 'none',
            commands: {
              typecheck: ['npm', 'run', 'typecheck'],
              build: ['npm', 'run', 'build'],
              test: ['npm', 'test'],
            },
          },
        }),
        sandboxBackend: fakeBackend,
        unpatchedBackend: fakeBackend,
        patchedBackend: fakeBackend,
        requirement: 'VERIFIED_STATIC',
        skipDynamic: false,
      });

      expect(fakeBackend.recordedRuns).toHaveLength(0);
      expect(result.allowed).toBe(true);
      expect(result.report.status).toBe('VERIFIED_STATIC');

      for (const stageId of ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'] as const) {
        const stage = result.report.stages.find((s) => s.id === stageId);
        expect(stage?.outcome).toBe('SKIPPED');
        expect(stage?.detail).toBe("Dynamic verification disabled: sandbox backend is 'none'");
      }
    });

    it('returns allowed: false and failureReason when requirement VERIFIED_RUNTIME not met due to backend none', async () => {
      const fakeBackend = new FakeSandboxBackend();

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig: UserConfigSchema.parse({
          sandbox: { backend: 'none' },
        }),
        sandboxBackend: fakeBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(result.allowed).toBe(false);
      expect(result.report.status).toBe('VERIFIED_STATIC');
      expect(result.failureReason).toBe(
        "Requirement VERIFIED_RUNTIME not met: dynamic verification disabled (sandbox backend 'none')"
      );
    });

    it('returns allowed: false and failureReason when requirement VERIFIED_RUNTIME not met due to skipDynamic', async () => {
      const fakeBackend = new FakeSandboxBackend();

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig: UserConfigSchema.parse({
          sandbox: { backend: 'container' },
        }),
        sandboxBackend: fakeBackend,
        skipDynamic: true,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(result.allowed).toBe(false);
      expect(result.report.status).toBe('VERIFIED_STATIC');
      expect(result.failureReason).toBe(
        'Requirement VERIFIED_RUNTIME not met: dynamic verification skipped by caller'
      );
      for (const stageId of ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'] as const) {
        const stage = result.report.stages.find((s) => s.id === stageId);
        expect(stage?.outcome).toBe('SKIPPED');
        expect(stage?.detail).toBe('Dynamic verification skipped by caller (skipDynamic)');
      }
    });

    it('contains backend errors during dynamic stages as INCONCLUSIVE and skips remaining dynamic stages', async () => {
      const errorBackend = {
        name: 'container' as const,
        run: async () => {
          throw new Error('Sandbox container runtime terminated unexpectedly');
        },
        cleanup: async () => {},
        isAvailable: async () => true,
        getMetadata: () => ({ backend: 'container' as const }),
      };

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig: UserConfigSchema.parse({
          sandbox: {
            backend: 'container',
            commands: {
              typecheck: ['npm', 'run', 'typecheck'],
              build: ['npm', 'run', 'build'],
              test: ['npm', 'test'],
            },
          },
        }),
        sandboxBackend: errorBackend,
        requirement: 'VERIFIED_STATIC',
      });

      expect(result.allowed).toBe(false);
      expect(result.report.status).toBe('INCONCLUSIVE');

      const installStage = result.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('INCONCLUSIVE');
      expect(installStage?.detail).toBe(
        'Sandbox backend error during INSTALL: Sandbox container runtime terminated unexpectedly'
      );

      for (const stageId of ['TYPECHECK', 'BUILD', 'TEST'] as const) {
        const stage = result.report.stages.find((s) => s.id === stageId);
        expect(stage?.outcome).toBe('SKIPPED');
        expect(stage?.detail).toBe('Skipped: sandbox backend unavailable (see INSTALL)');
      }
    });

    it('sanitizes Unix absolute paths from backend error messages during dynamic containment', async () => {
      const errorBackend = {
        name: 'container' as const,
        run: async () => {
          throw new Error('Docker daemon error: connect ENOENT /var/run/docker.sock failed');
        },
        cleanup: async () => {},
        isAvailable: async () => true,
        getMetadata: () => ({ backend: 'container' as const }),
      };

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig: UserConfigSchema.parse({
          sandbox: { backend: 'container' },
        }),
        sandboxBackend: errorBackend,
        requirement: 'VERIFIED_STATIC',
      });

      expect(result.allowed).toBe(false);
      expect(result.report.status).toBe('INCONCLUSIVE');

      const installStage = result.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('INCONCLUSIVE');
      expect(installStage?.detail).toBe(
        'Sandbox backend error during INSTALL: Docker daemon error: connect ENOENT <path> failed'
      );
      expect(installStage?.detail).not.toContain('/var/run/docker.sock');
    });

    it('returns allowed: false and failureReason achieved FAILED when stage fails even if backend is none', async () => {
      const mockFailingAdapter: IScannerAdapter = {
        name: 'osv-scanner',
        category: 'SCA',
        version: async () => '1.0.0',
        isAvailable: async () => true,
        supportsProject: () => true,
        scan: async () => ({
          scannerName: 'osv-scanner',
          status: 'SUCCESS',
          findings: [baseFinding],
          durationMs: 10,
          exitCode: 0,
          timedOut: false,
        }),
      };

      const result = await ScaVerificationLadder.execute({
        rootDir: tempDir,
        finding: baseFinding,
        proposal: baseProposal,
        userConfig: UserConfigSchema.parse({
          sandbox: { backend: 'none' },
        }),
        adapters: [mockFailingAdapter],
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(result.allowed).toBe(false);
      expect(result.report.status).toBe('FAILED');
      expect(result.failureReason).toContain('still detected after version update');
    });
  });
});
