import { describe, it, expect } from 'vitest';
import { extractCleanSemver } from '../src/semver-extractor.js';

describe('extractCleanSemver with real scanner --version outputs', () => {
  it('extracts semver from real osv-scanner output', () => {
    const raw = `osv-scanner version: 2.7.0
osv-scalibr version: 0.5.3
commit: bfe2f84abd2f09fe0b83ba7f6dad40d296762f40
built at: 2026-10-12T00:39:39Z`;
    expect(extractCleanSemver(raw)).toBe('2.7.0');
  });

  it('extracts semver from real trivy output', () => {
    const raw = `Version: 0.76.0
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-10-19 00:45:30.553047111 +0000 UTC`;
    expect(extractCleanSemver(raw)).toBe('0.76.0');
  });

  it('extracts semver from real gitleaks output', () => {
    const raw = '8.30.1\n';
    expect(extractCleanSemver(raw)).toBe('8.30.1');
  });

  it('extracts semver from real opengrep output', () => {
    const raw = '1.31.0\n';
    expect(extractCleanSemver(raw)).toBe('1.31.0');
  });

  it('extracts semver from real checkov output', () => {
    const raw = '3.3.29\n';
    expect(extractCleanSemver(raw)).toBe('3.3.29');
  });

  it('extracts semver from semgrep prefixed output', () => {
    const raw = 'semgrep 1.70.0 (commit abc123)\n';
    expect(extractCleanSemver(raw)).toBe('1.70.0');
  });

  it('handles v-prefixed and pre-release semvers', () => {
    expect(extractCleanSemver('v1.2.3-rc1')).toBe('1.2.3-rc1');
    expect(extractCleanSemver('v2.0.0+build.184')).toBe('2.0.0+build.184');
  });

  it('falls back safely for unknown/empty input', () => {
    expect(extractCleanSemver('')).toBe('Unknown');
    expect(extractCleanSemver(null as unknown as string)).toBe('Unknown');
    expect(extractCleanSemver('No version info')).toBe('No version info');
  });
});
