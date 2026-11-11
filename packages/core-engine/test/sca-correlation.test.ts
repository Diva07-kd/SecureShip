import { describe, it, expect } from 'vitest';
import { FindingCorrelator } from '../src/normalizer/finding-correlator.js';
import type { NormalizedFinding } from '@secureship/contracts';

describe('SCA Advisory Correlation & Alias Merging Suite', () => {
  it('merges overlapping SCA findings across scanners when package, version, and aliases intersect', () => {
    // Finding 1 from Trivy
    const trivyFinding: NormalizedFinding = {
      id: 'f-trivy-1',
      fingerprint: '1'.repeat(64),
      ruleId: 'CVE-2021-23337',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'package-lock.json',
        startLine: 12,
        endLine: 12,
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Command injection in lodash',
      description: 'Lodash vulnerable to command injection via template',
      cweIds: ['CWE-78'],
      aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
      package: {
        ecosystem: 'npm',
        name: 'lodash',
        version: '4.17.15',
        fixedVersion: '4.17.21',
      },
      lockfilePath: 'package-lock.json',
      evidence: [
        {
          scannerName: 'trivy',
          scannerRuleId: 'CVE-2021-23337',
          message: 'Trivy detected CVE-2021-23337 in lodash@4.17.15',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    // Finding 2 from OSV-Scanner (reports with GHSA ruleId)
    const osvFinding: NormalizedFinding = {
      id: 'f-osv-1',
      fingerprint: '2'.repeat(64),
      ruleId: 'GHSA-35jh-r3h4-6jhm',
      scannerName: 'osv-scanner',
      category: 'SCA',
      severity: 'CRITICAL', // Higher severity!
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'package-lock.json',
        startLine: 12,
        endLine: 12,
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Command injection in lodash',
      description: 'Command injection in lodash template',
      cweIds: ['CWE-78', 'CWE-94'],
      aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
      package: {
        ecosystem: 'npm',
        name: 'lodash',
        version: '4.17.15',
        fixedVersion: '4.17.21',
      },
      lockfilePath: 'package-lock.json',
      evidence: [
        {
          scannerName: 'osv-scanner',
          scannerRuleId: 'GHSA-35jh-r3h4-6jhm',
          message: 'OSV detected GHSA-35jh-r3h4-6jhm in lodash@4.17.15',
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const correlated = FindingCorrelator.correlate([trivyFinding, osvFinding]);

    // Both findings merged into 1!
    expect(correlated).toHaveLength(1);

    const merged = correlated[0]!;
    // Upgraded severity to CRITICAL
    expect(merged.severity).toBe('CRITICAL');
    // Evidence from both scanners merged
    expect(merged.evidence).toHaveLength(2);
    expect(merged.evidence.some((e) => e.scannerName === 'trivy')).toBe(true);
    expect(merged.evidence.some((e) => e.scannerName === 'osv-scanner')).toBe(true);
    // Combined CWEs
    expect(merged.cweIds).toContain('CWE-78');
    expect(merged.cweIds).toContain('CWE-94');
  });

  it('keeps findings distinct when package versions or advisories do not match', () => {
    const f1: NormalizedFinding = {
      id: 'f-1',
      fingerprint: '3'.repeat(64),
      ruleId: 'CVE-2021-0001',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath: 'package-lock.json', startLine: 10, endLine: 10 },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Vuln 1',
      description: 'Vuln 1',
      cweIds: [],
      package: { ecosystem: 'npm', name: 'axios', version: '0.21.0' },
      lockfilePath: 'package-lock.json',
      evidence: [{ scannerName: 'trivy', scannerRuleId: 'CVE-2021-0001', message: 'M1' }],
      createdAt: new Date().toISOString(),
    };

    const f2: NormalizedFinding = {
      id: 'f-2',
      fingerprint: '4'.repeat(64),
      ruleId: 'CVE-2022-9999',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath: 'package-lock.json', startLine: 10, endLine: 10 },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Vuln 2',
      description: 'Vuln 2',
      cweIds: [],
      package: { ecosystem: 'npm', name: 'axios', version: '0.21.0' },
      lockfilePath: 'package-lock.json',
      evidence: [{ scannerName: 'trivy', scannerRuleId: 'CVE-2022-9999', message: 'M2' }],
      createdAt: new Date().toISOString(),
    };

    const correlated = FindingCorrelator.correlate([f1, f2]);
    // Different CVEs without alias overlap remain separate findings
    expect(correlated).toHaveLength(2);
  });
});
