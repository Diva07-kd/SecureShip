import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import child_process from 'node:child_process';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  UserConfigSchema,
  type IScannerAdapter,
  type NormalizedFinding,
  type PatchProposal,
  type ScaPatchProposal,
  type StageId,
  type UserConfig,
  type VerificationStatus,
} from '@secureship/contracts';
import { FakeSandboxBackend } from '@secureship/sandbox';
import { VerificationLadder } from '../../src/remediation/verification-ladder.js';
import { ScaVerificationLadder } from '../../src/remediation/sca-verification-ladder.js';

interface DisabledMatrixParam {
  disabledBy: 'none_with_false' | 'container_with_true' | 'both';
  commandsConfigured: boolean;
  injectedBackends: boolean;
  requirement: 'VERIFIED_STATIC' | 'VERIFIED_RUNTIME';
  installEnabled: boolean;
}

function generateDisabledMatrix(): DisabledMatrixParam[] {
  const disabledByOptions: DisabledMatrixParam['disabledBy'][] = [
    'none_with_false',
    'container_with_true',
    'both',
  ];
  const commandsOptions = [false, true];
  const injectedOptions = [false, true];
  const requirementOptions: DisabledMatrixParam['requirement'][] = [
    'VERIFIED_STATIC',
    'VERIFIED_RUNTIME',
  ];
  const installOptions = [false, true];

  const combinations: DisabledMatrixParam[] = [];
  for (const d of disabledByOptions) {
    for (const c of commandsOptions) {
      for (const i of injectedOptions) {
        for (const r of requirementOptions) {
          for (const inst of installOptions) {
            combinations.push({
              disabledBy: d,
              commandsConfigured: c,
              injectedBackends: i,
              requirement: r,
              installEnabled: inst,
            });
          }
        }
      }
    }
  }
  return combinations;
}

describe('LAYER C, D, E, H, I: Sandbox Honesty, Property Controls, & Integrity', () => {
  let tempRepo: string;
  let scaRepo: string;

  beforeEach(() => {
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-honesty-code-'));
    fs.mkdirSync(path.join(tempRepo, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tempRepo, 'src', 'vuln.ts'),
      'export function handle(input: string) {\n  const query = "SELECT * FROM users WHERE id = " + input;\n  return query;\n}\n',
      'utf8'
    );

    scaRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-honesty-sca-'));
    fs.writeFileSync(
      path.join(scaRepo, 'package.json'),
      JSON.stringify(
        {
          name: 'honesty-sca-app',
          version: '1.0.0',
          dependencies: { lodash: '4.17.20' },
        },
        null,
        2
      ) + '\n',
      'utf8'
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
    fingerprint: '3'.repeat(64),
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
    evidence: [{ scannerName: 'semgrep', scannerRuleId: 'rules.sqli', message: 'SQL injection' }],
    createdAt: new Date().toISOString(),
  };

  const cleanProposal: PatchProposal = {
    findingFingerprint: '3'.repeat(64),
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
    id: 'f-sca-honesty',
    fingerprint: '4'.repeat(64),
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
    findingFingerprint: '4'.repeat(64),
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

  const expectedStageIds: StageId[] = [
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
  ];

  describe('LAYER C: Disabled Matrix (Decisive Verification)', () => {
    it('C (Code Ladder): evaluates all 48 combinations asserting C1 to C6 invariants', async () => {
      const matrix = generateDisabledMatrix();
      expect(matrix).toHaveLength(48);

      for (const item of matrix) {
        const backend = item.disabledBy === 'container_with_true' ? 'container' : 'none';
        const skipDynamic = item.disabledBy === 'none_with_false' ? false : true;

        const config: UserConfig = UserConfigSchema.parse({
          sandbox: {
            backend,
            install: { enabled: item.installEnabled },
            commands: item.commandsConfigured
              ? {
                  typecheck: ['npm', 'run', 'typecheck'],
                  build: ['npm', 'run', 'build'],
                  test: ['npm', 'test'],
                }
              : {},
          },
        });

        const unpatchedBackend = item.injectedBackends
          ? new FakeSandboxBackend({ defaultResponse: { exitCode: 0, stdout: 'PASS' } })
          : undefined;
        const patchedBackend = item.injectedBackends
          ? new FakeSandboxBackend({ defaultResponse: { exitCode: 0, stdout: 'PASS' } })
          : undefined;

        const resolveSpy = vi.spyOn(VerificationLadder, 'resolveBackend');

        const beforeByteContent = fs.readFileSync(path.join(tempRepo, 'src', 'vuln.ts'), 'utf8');

        // C6: The ladder resolves (does not reject) in every combination
        const res = await VerificationLadder.execute({
          rootDir: tempRepo,
          finding: baseFinding,
          proposal: cleanProposal,
          userConfig: config,
          adapters: [fakeScanner],
          unpatchedBackend,
          patchedBackend,
          requirement: item.requirement,
          skipDynamic,
        });

        // C1: report.status equals exactly 'VERIFIED_STATIC'
        expect(res.report.status).toBe('VERIFIED_STATIC');

        // C2: Stages equal 10 ids in exact order. Dynamic stages are SKIPPED with D7 detail
        const stageIds = res.report.stages.map((s) => s.id);
        expect(stageIds).toEqual(expectedStageIds);

        const isBackendNone = backend === 'none';
        const expectedDetail = isBackendNone
          ? "Dynamic verification disabled: sandbox backend is 'none'"
          : 'Dynamic verification skipped by caller (skipDynamic)';

        for (const stageId of ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'] as const) {
          const stage = res.report.stages.find((s) => s.id === stageId);
          expect(stage?.outcome).toBe('SKIPPED');
          expect(stage?.detail).toBe(expectedDetail);
        }

        // Static stages keep baseline outcomes
        for (const staticId of [
          'APPLY',
          'POLICY',
          'SYNTAX',
          'RESCAN',
          'NEW_FINDINGS',
          'IMPORTS',
        ] as const) {
          const stage = res.report.stages.find((s) => s.id === staticId);
          expect(stage?.outcome).toBe('PASS');
        }

        // C3: Zero backend access
        expect(resolveSpy).toHaveBeenCalledTimes(0);
        if (item.injectedBackends && unpatchedBackend && patchedBackend) {
          const totalRuns =
            unpatchedBackend.recordedRuns.length + patchedBackend.recordedRuns.length;
          expect(totalRuns).toBe(0);
        }

        // C4: allowed equals (requirement === 'VERIFIED_STATIC')
        const expectedAllowed = item.requirement === 'VERIFIED_STATIC';
        expect(res.allowed).toBe(expectedAllowed);

        if (!expectedAllowed) {
          const expectedFailureReason = isBackendNone
            ? "Requirement VERIFIED_RUNTIME not met: dynamic verification disabled (sandbox backend 'none')"
            : 'Requirement VERIFIED_RUNTIME not met: dynamic verification skipped by caller';
          expect(res.failureReason).toBe(expectedFailureReason);
        } else {
          expect(res.failureReason).toBeUndefined();
        }

        // C5: Report signature verifies and repository files are byte-identical
        expect(VerificationLadder.verifySignature(res.report)).toBe(true);
        const afterByteContent = fs.readFileSync(path.join(tempRepo, 'src', 'vuln.ts'), 'utf8');
        expect(afterByteContent).toBe(beforeByteContent);

        resolveSpy.mockRestore();
      }
    });

    it('C (SCA Ladder): evaluates all 48 combinations asserting C1 to C6 invariants', async () => {
      const matrix = generateDisabledMatrix();
      expect(matrix).toHaveLength(48);

      for (const item of matrix) {
        const backend = item.disabledBy === 'container_with_true' ? 'container' : 'none';
        const skipDynamic = item.disabledBy === 'none_with_false' ? false : true;

        const config: UserConfig = UserConfigSchema.parse({
          sandbox: {
            backend,
            install: { enabled: item.installEnabled },
            commands: item.commandsConfigured
              ? {
                  typecheck: ['npm', 'run', 'typecheck'],
                  build: ['npm', 'run', 'build'],
                  test: ['npm', 'test'],
                }
              : {},
          },
        });

        const unpatchedBackend = item.injectedBackends
          ? new FakeSandboxBackend({ defaultResponse: { exitCode: 0, stdout: 'PASS' } })
          : undefined;
        const patchedBackend = item.injectedBackends
          ? new FakeSandboxBackend({ defaultResponse: { exitCode: 0, stdout: 'PASS' } })
          : undefined;

        const resolveSpy = vi.spyOn(ScaVerificationLadder, 'resolveBackend');

        const beforeByteContent = fs.readFileSync(path.join(scaRepo, 'package.json'), 'utf8');

        // C6: The ladder resolves in every combination
        const res = await ScaVerificationLadder.execute({
          rootDir: scaRepo,
          finding: scaFinding,
          proposal: scaProposal,
          userConfig: config,
          adapters: [scaAdapter],
          unpatchedBackend,
          patchedBackend,
          requirement: item.requirement,
          skipDynamic,
        });

        // C1: report.status equals exactly 'VERIFIED_STATIC'
        expect(res.report.status).toBe('VERIFIED_STATIC');

        // C2: 10 stages in exact order, dynamic SKIPPED with D7 detail
        const stageIds = res.report.stages.map((s) => s.id);
        expect(stageIds).toEqual(expectedStageIds);

        const isBackendNone = backend === 'none';
        const expectedDetail = isBackendNone
          ? "Dynamic verification disabled: sandbox backend is 'none'"
          : 'Dynamic verification skipped by caller (skipDynamic)';

        for (const stageId of ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'] as const) {
          const stage = res.report.stages.find((s) => s.id === stageId);
          expect(stage?.outcome).toBe('SKIPPED');
          expect(stage?.detail).toBe(expectedDetail);
        }

        // C3: Zero backend access
        expect(resolveSpy).toHaveBeenCalledTimes(0);
        if (item.injectedBackends && unpatchedBackend && patchedBackend) {
          const totalRuns =
            unpatchedBackend.recordedRuns.length + patchedBackend.recordedRuns.length;
          expect(totalRuns).toBe(0);
        }

        // C4: allowed equals (requirement === 'VERIFIED_STATIC')
        const expectedAllowed = item.requirement === 'VERIFIED_STATIC';
        expect(res.allowed).toBe(expectedAllowed);

        if (!expectedAllowed) {
          const expectedFailureReason = isBackendNone
            ? "Requirement VERIFIED_RUNTIME not met: dynamic verification disabled (sandbox backend 'none')"
            : 'Requirement VERIFIED_RUNTIME not met: dynamic verification skipped by caller';
          expect(res.failureReason).toBe(expectedFailureReason);
        } else {
          expect(res.failureReason).toBeUndefined();
        }

        // C5: Report signature verifies and repository files are byte-identical
        expect(ScaVerificationLadder.verifySignature(res.report)).toBe(true);
        const afterByteContent = fs.readFileSync(path.join(scaRepo, 'package.json'), 'utf8');
        expect(afterByteContent).toBe(beforeByteContent);

        resolveSpy.mockRestore();
      }
    });
  });

  describe('LAYER D: Positive Controls (Runtime Reachable Honestly)', () => {
    it('D1 (Code Ladder): reaches VERIFIED_RUNTIME with partial command skips (D4)', async () => {
      const unpatchedBackend = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });
      const patchedBackend = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });

      const config: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          commands: {
            test: ['npm', 'test'],
          },
        },
      });

      const res = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: config,
        adapters: [fakeScanner],
        unpatchedBackend,
        patchedBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(res.report.status).toBe('VERIFIED_RUNTIME');
      expect(res.allowed).toBe(true);

      const installStage = res.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('SKIPPED');
      expect(installStage?.detail).toBe(
        'Dependency install is not executed by the code-fix verification ladder'
      );

      const tcStage = res.report.stages.find((s) => s.id === 'TYPECHECK');
      expect(tcStage?.outcome).toBe('SKIPPED');
      expect(tcStage?.detail).toBe('No typecheck command detected or configured');

      const buildStage = res.report.stages.find((s) => s.id === 'BUILD');
      expect(buildStage?.outcome).toBe('SKIPPED');
      expect(buildStage?.detail).toBe('No build command detected or configured');

      const testStage = res.report.stages.find((s) => s.id === 'TEST');
      expect(testStage?.outcome).toBe('PASS');

      // Patched backend recordedRuns contains exactly the configured test command
      expect(patchedBackend.recordedRuns.length).toBe(1);
      expect(patchedBackend.recordedRuns[0]?.command).toBe('npm');
      expect(patchedBackend.recordedRuns[0]?.argv).toEqual(['test']);
    });

    it('D2 (SCA Ladder): executes INSTALL stage with network: true and reports VERIFIED_RUNTIME', async () => {
      const unpatchedBackend = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });
      const patchedBackend = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });

      const config: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          install: { enabled: true },
        },
      });

      const res = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: config,
        adapters: [scaAdapter],
        unpatchedBackend,
        patchedBackend,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(res.report.status).toBe('VERIFIED_RUNTIME');
      expect(res.allowed).toBe(true);

      const installStage = res.report.stages.find((s) => s.id === 'INSTALL');
      expect(installStage?.outcome).toBe('PASS');
      expect(installStage?.detail).toBe('Lockfile synchronized cleanly in sandbox');

      expect(patchedBackend.recordedRuns.length).toBe(1);
      const run = patchedBackend.recordedRuns[0];
      expect(run?.command).toBe('npm');
      expect(run?.argv).toEqual(['install', '--package-lock-only', '--ignore-scripts']);
      expect(run?.options?.network).toBe(true);
    });

    it('D3: baseline-fail gives INCONCLUSIVE and patched-fail gives FAILED across both ladders', async () => {
      // Code Ladder: baseline-fail
      const baselineFailUnpatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 1, stderr: 'baseline test failed' },
      });
      const baselineFailPatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });

      const config: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          commands: { test: ['npm', 'test'] },
        },
      });

      const resInconclusive = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: config,
        adapters: [fakeScanner],
        unpatchedBackend: baselineFailUnpatched,
        patchedBackend: baselineFailPatched,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(resInconclusive.report.status).toBe('INCONCLUSIVE');
      expect(resInconclusive.allowed).toBe(false);
      expect(resInconclusive.failureReason).toBe(
        'Requirement VERIFIED_RUNTIME not met: achieved INCONCLUSIVE'
      );

      // Code Ladder: patched-fail
      const patchedFailUnpatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });
      const patchedFailPatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 1, stderr: 'regression failure' },
      });

      const resFailed = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: config,
        adapters: [fakeScanner],
        unpatchedBackend: patchedFailUnpatched,
        patchedBackend: patchedFailPatched,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(resFailed.report.status).toBe('FAILED');
      expect(resFailed.allowed).toBe(false);
      const testStage = resFailed.report.stages.find((s) => s.id === 'TEST');
      expect(testStage?.outcome).toBe('FAIL');
      expect(resFailed.failureReason).toBe(testStage?.detail);

      // SCA Ladder: baseline-fail
      const scaBaselineFailUnpatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 1, stderr: 'baseline typecheck failed' },
      });
      const scaBaselineFailPatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });

      const scaConfig: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          commands: { typecheck: ['npm', 'run', 'typecheck'] },
        },
      });

      const scaResInconclusive = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: scaConfig,
        adapters: [scaAdapter],
        unpatchedBackend: scaBaselineFailUnpatched,
        patchedBackend: scaBaselineFailPatched,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(scaResInconclusive.report.status).toBe('INCONCLUSIVE');
      expect(scaResInconclusive.allowed).toBe(false);

      // SCA Ladder: patched-fail
      const scaPatchedFailUnpatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 0, stdout: 'PASS' },
      });
      const scaPatchedFailPatched = new FakeSandboxBackend({
        defaultResponse: { exitCode: 1, stderr: 'regression typecheck failure' },
      });

      const scaResFailed = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: scaConfig,
        adapters: [scaAdapter],
        unpatchedBackend: scaPatchedFailUnpatched,
        patchedBackend: scaPatchedFailPatched,
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(scaResFailed.report.status).toBe('FAILED');
      expect(scaResFailed.allowed).toBe(false);
    });
  });

  describe('LAYER E: No Dynamic PASS Without Execution (Property Test)', () => {
    it('E1, E2, E3: verifies invariants over 40 seeded, deterministic configurations', async () => {
      let seed = 1337;
      function nextRandom(): number {
        seed = (seed * 1664525 + 1013904223) >>> 0;
        return seed / 4294967296;
      }

      const backends = ['none', 'container', 'host', 'native-isolated'] as const;

      for (let i = 0; i < 40; i++) {
        const backendChoice = backends[Math.floor(nextRandom() * backends.length)]!;
        const skipDynamicChoice = nextRandom() > 0.5;
        const installEnabledChoice = nextRandom() > 0.5;
        const hasTestCommand = nextRandom() > 0.3;
        const hasBuildCommand = nextRandom() > 0.5;
        const hasTypecheckCommand = nextRandom() > 0.5;
        const backendExitCode = nextRandom() > 0.2 ? 0 : 1;

        const config: UserConfig = UserConfigSchema.parse({
          sandbox: {
            backend: backendChoice,
            install: { enabled: installEnabledChoice },
            commands: {
              ...(hasTestCommand ? { test: ['npm', 'test'] } : {}),
              ...(hasBuildCommand ? { build: ['npm', 'run', 'build'] } : {}),
              ...(hasTypecheckCommand ? { typecheck: ['npm', 'run', 'typecheck'] } : {}),
            },
          },
        });

        const unpatchedBackend = new FakeSandboxBackend({
          defaultResponse: { exitCode: backendExitCode, stdout: 'OUT' },
        });
        const patchedBackend = new FakeSandboxBackend({
          defaultResponse: { exitCode: backendExitCode, stdout: 'OUT' },
        });

        // Run Code Ladder
        const codeRes = await VerificationLadder.execute({
          rootDir: tempRepo,
          finding: baseFinding,
          proposal: cleanProposal,
          userConfig: config,
          adapters: [fakeScanner],
          unpatchedBackend,
          patchedBackend,
          requirement: 'VERIFIED_RUNTIME',
          skipDynamic: skipDynamicChoice,
        });

        // E1: Every dynamic stage with outcome PASS has a matching recorded run (same command)
        for (const stage of codeRes.report.stages) {
          if (['TYPECHECK', 'BUILD', 'TEST'].includes(stage.id) && stage.outcome === 'PASS') {
            const hasRecordedRun = patchedBackend.recordedRuns.some((r) => {
              if (stage.id === 'TEST') return r.command === 'npm' && r.argv.includes('test');
              if (stage.id === 'BUILD') return r.command === 'npm' && r.argv.includes('build');
              if (stage.id === 'TYPECHECK')
                return r.command === 'npm' && r.argv.includes('typecheck');
              return false;
            });
            expect(hasRecordedRun).toBe(true);
          }
        }

        // E2: Code ladder INSTALL is NEVER 'PASS' in any configuration
        const codeInstallStage = codeRes.report.stages.find((s) => s.id === 'INSTALL');
        expect(codeInstallStage?.outcome).not.toBe('PASS');
        expect(codeInstallStage?.outcome).toBe('SKIPPED');
        const expectedCodeInstallDetail =
          backendChoice === 'none'
            ? "Dynamic verification disabled: sandbox backend is 'none'"
            : skipDynamicChoice
              ? 'Dynamic verification skipped by caller (skipDynamic)'
              : 'Dependency install is not executed by the code-fix verification ladder';
        expect(codeInstallStage?.detail).toBe(expectedCodeInstallDetail);

        // E3: status === 'VERIFIED_RUNTIME' implies at least one executed PASS
        if (codeRes.report.status === 'VERIFIED_RUNTIME') {
          const passDynamicStages = codeRes.report.stages.filter(
            (s) => ['TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
          );
          expect(passDynamicStages.length).toBeGreaterThan(0);
          expect(patchedBackend.recordedRuns.length).toBeGreaterThan(0);
        }

        // Run SCA Ladder
        const scaUnpatched = new FakeSandboxBackend({
          defaultResponse: { exitCode: backendExitCode, stdout: 'OUT' },
        });
        const scaPatched = new FakeSandboxBackend({
          defaultResponse: { exitCode: backendExitCode, stdout: 'OUT' },
        });

        const scaRes = await ScaVerificationLadder.execute({
          rootDir: scaRepo,
          finding: scaFinding,
          proposal: scaProposal,
          userConfig: config,
          adapters: [scaAdapter],
          unpatchedBackend: scaUnpatched,
          patchedBackend: scaPatched,
          requirement: 'VERIFIED_RUNTIME',
          skipDynamic: skipDynamicChoice,
        });

        for (const stage of scaRes.report.stages) {
          if (
            ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(stage.id) &&
            stage.outcome === 'PASS'
          ) {
            const hasRecordedRun = scaPatched.recordedRuns.some((r) => {
              if (stage.id === 'INSTALL')
                return (
                  r.command === 'npm' && r.argv.includes('install') && r.options?.network === true
                );
              if (stage.id === 'TEST') return r.command === 'npm' && r.argv.includes('test');
              if (stage.id === 'BUILD') return r.command === 'npm' && r.argv.includes('build');
              if (stage.id === 'TYPECHECK')
                return r.command === 'npm' && r.argv.includes('typecheck');
              return false;
            });
            expect(hasRecordedRun).toBe(true);
          }
        }

        if (scaRes.report.status === 'VERIFIED_RUNTIME') {
          const passDynamicStages = scaRes.report.stages.filter(
            (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
          );
          expect(passDynamicStages.length).toBeGreaterThan(0);
          expect(scaPatched.recordedRuns.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('LAYER H: Real "No Docker" Proof & Controls', () => {
    it('H1: executes safely when PATH hides container binaries and reports non-RUNTIME', async () => {
      if (process.platform === 'win32') {
        console.log('Layer H skipped: Windows PATH semantics do not prevent binary resolution');
        expect(process.platform).toBe('win32');
        return;
      }

      vi.stubEnv('PATH', '');

      const config: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          commands: { test: ['node', '-v'] },
        },
      });

      // Code Ladder without injected backends
      const codeRes = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: config,
        adapters: [fakeScanner],
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(codeRes.report.status).not.toBe('VERIFIED_RUNTIME');
      const codeDynamicPass = codeRes.report.stages.filter(
        (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
      );
      expect(codeDynamicPass).toEqual([]);

      // SCA Ladder without injected backends
      const scaRes = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: config,
        adapters: [scaAdapter],
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(scaRes.report.status).not.toBe('VERIFIED_RUNTIME');
      const scaDynamicPass = scaRes.report.stages.filter(
        (s) => ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'].includes(s.id) && s.outcome === 'PASS'
      );
      expect(scaDynamicPass).toEqual([]);
    });

    it('H2: live container check control', async () => {
      let hasDocker = false;
      try {
        const check = child_process.spawnSync('docker', ['info'], { timeout: 3000 });
        hasDocker = check.status === 0;
      } catch {
        hasDocker = false;
      }

      if (!hasDocker) {
        console.log('Layer H2 skipped: no container runtime');
        expect(hasDocker).toBe(false);
        return;
      }

      // Live control: container runtime is available
      const passConfig: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          commands: { test: ['node', '-e', 'process.exit(0)'] },
        },
      });

      const passRes = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: passConfig,
        adapters: [fakeScanner],
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(passRes.report.status).toBe('VERIFIED_RUNTIME');
      expect(passRes.allowed).toBe(true);
      const testStagePass = passRes.report.stages.find((s) => s.id === 'TEST');
      expect(testStagePass?.outcome).toBe('PASS');

      const failConfig: UserConfig = UserConfigSchema.parse({
        sandbox: {
          backend: 'container',
          commands: { test: ['node', '-e', 'process.exit(1)'] },
        },
      });

      const failRes = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: failConfig,
        adapters: [fakeScanner],
        requirement: 'VERIFIED_RUNTIME',
      });

      expect(failRes.report.status).toBe('FAILED');
      expect(failRes.allowed).toBe(false);
      const testStageFail = failRes.report.stages.find((s) => s.id === 'TEST');
      expect(testStageFail?.outcome).toBe('FAIL');
    });
  });

  describe('LAYER I: Regression & Tamper Invariants', () => {
    it('I2: detects status tampering and bad signature on FixReport across both ladders', async () => {
      // Code Ladder
      const config: UserConfig = UserConfigSchema.parse({
        sandbox: { backend: 'none' },
      });

      const res = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: config,
        adapters: [fakeScanner],
        skipDynamic: true,
      });

      expect(VerificationLadder.verifySignature(res.report)).toBe(true);

      // Status tampering
      const statusTampered = {
        ...res.report,
        status: 'VERIFIED_RUNTIME' as VerificationStatus,
      };
      expect(VerificationLadder.verifySignature(statusTampered)).toBe(false);

      // Bad signature tampering
      const sigTampered = {
        ...res.report,
        signature: 'f'.repeat(64),
      };
      expect(VerificationLadder.verifySignature(sigTampered)).toBe(false);

      // SCA Ladder
      const scaConfig: UserConfig = UserConfigSchema.parse({
        sandbox: { backend: 'none' },
      });

      const scaRes = await ScaVerificationLadder.execute({
        rootDir: scaRepo,
        finding: scaFinding,
        proposal: scaProposal,
        userConfig: scaConfig,
        adapters: [scaAdapter],
        skipDynamic: true,
      });

      expect(ScaVerificationLadder.verifySignature(scaRes.report)).toBe(true);

      const scaStatusTampered = {
        ...scaRes.report,
        status: 'VERIFIED_RUNTIME' as VerificationStatus,
      };
      expect(ScaVerificationLadder.verifySignature(scaStatusTampered)).toBe(false);

      const scaSigTampered = {
        ...scaRes.report,
        signature: 'f'.repeat(64),
      };
      expect(ScaVerificationLadder.verifySignature(scaSigTampered)).toBe(false);
    });

    it('I3: verifyLevel "none" returns UNVERIFIED with 10 SKIPPED stages and no shadow backend', async () => {
      const config: UserConfig = UserConfigSchema.parse({
        sandbox: { backend: 'container' },
      });

      const resolveSpy = vi.spyOn(VerificationLadder, 'resolveBackend');

      const res = await VerificationLadder.execute({
        rootDir: tempRepo,
        finding: baseFinding,
        proposal: cleanProposal,
        userConfig: config,
        adapters: [fakeScanner],
        verifyLevel: 'none',
        requirement: 'UNVERIFIED',
      });

      expect(res.report.status).toBe('UNVERIFIED');
      expect(res.allowed).toBe(true);
      expect(res.report.stages).toHaveLength(10);
      for (const stage of res.report.stages) {
        expect(stage.outcome).toBe('SKIPPED');
        expect(stage.detail).toBe('Verification skipped by --verify none');
      }
      expect(resolveSpy).toHaveBeenCalledTimes(0);

      resolveSpy.mockRestore();
    });
  });
});
