import { describe, it, expect } from 'vitest';
import type { NormalizedFinding } from '@secureship/contracts';
import { ScaReachabilityAnalyzer } from '../src/sca/sca-reachability-analyzer.js';

describe('ScaReachabilityAnalyzer.filterByReachability', () => {
  const sampleFindings = [
    {
      id: 'f-1',
      fingerprint: 'fp-1',
      category: 'SCA',
      severity: 'HIGH',
      ruleId: 'CVE-2023-1111',
      message: 'Vulnerable call path',
      scannerName: 'trivy',
      location: { filePath: 'package.json', startLine: 10, endLine: 10 },
      reachability: 'REACHABLE_CALL_PATH',
      reachabilityDetail: {
        verdict: 'REACHABLE_CALL_PATH',
        analysisConfidence: 'HIGH',
        evidence: { kind: 'IMPORT_CHAIN' },
        limitations: [],
      },
    },
    {
      id: 'f-2',
      fingerprint: 'fp-2',
      category: 'SCA',
      severity: 'MEDIUM',
      ruleId: 'CVE-2023-2222',
      message: 'Vulnerable import',
      scannerName: 'osv-scanner',
      location: { filePath: 'package.json', startLine: 15, endLine: 15 },
      reachability: 'REACHABLE_IMPORT',
      reachabilityDetail: {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'HIGH',
        evidence: { kind: 'PACKAGE_IMPORTED' },
        limitations: [],
      },
    },
    {
      id: 'f-3',
      fingerprint: 'fp-3',
      category: 'SCA',
      severity: 'LOW',
      ruleId: 'CVE-2023-3333',
      message: 'Unknown reachability',
      scannerName: 'trivy',
      location: { filePath: 'package.json', startLine: 20, endLine: 20 },
      reachability: 'UNKNOWN',
      reachabilityDetail: {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: { kind: 'PARSE_FAILURE' },
        limitations: [],
      },
    },
    {
      id: 'f-4',
      fingerprint: 'fp-4',
      category: 'SCA',
      severity: 'INFO',
      ruleId: 'CVE-2023-4444',
      message: 'Not applicable reachability',
      scannerName: 'trivy',
      location: { filePath: 'package.json', startLine: 25, endLine: 25 },
      reachability: 'UNREACHABLE',
      reachabilityDetail: {
        verdict: 'UNREACHABLE',
        analysisConfidence: 'HIGH',
        evidence: { kind: 'NOT_APPLICABLE' },
        limitations: [],
      },
    },
  ] as unknown as NormalizedFinding[];

  it('keeps only REACHABLE_CALL_PATH and REACHABLE_IMPORT when filter is "reachable"', () => {
    const result = ScaReachabilityAnalyzer.filterByReachability(sampleFindings, 'reachable');
    expect(result).toHaveLength(2);
    expect(result.map((f) => f.id)).toEqual(['f-1', 'f-2']);
  });

  it('keeps only UNKNOWN when filter is "no-info"', () => {
    const result = ScaReachabilityAnalyzer.filterByReachability(sampleFindings, 'no-info');
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('f-3');
  });

  it('keeps only NOT_APPLICABLE evidence when filter is "not-applicable"', () => {
    const result = ScaReachabilityAnalyzer.filterByReachability(sampleFindings, 'not-applicable');
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('f-4');
  });

  it('returns all findings unchanged when filter is "all" or undefined', () => {
    const resultAll = ScaReachabilityAnalyzer.filterByReachability(sampleFindings, 'all');
    expect(resultAll).toHaveLength(4);

    // @ts-expect-error testing default fallback
    const resultUndefined = ScaReachabilityAnalyzer.filterByReachability(sampleFindings, undefined);
    expect(resultUndefined).toHaveLength(4);
  });
});
