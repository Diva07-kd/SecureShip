import { describe, it, expect } from 'vitest';
import type { ScaPatchProposal } from '@secureship/contracts';
import { ScaPatchPolicyEngine } from '../../src/sca/sca-policy-engine.js';

describe('ScaPatchPolicyEngine Unit Tests', () => {
  const baseProposal: ScaPatchProposal = {
    findingFingerprint: 'fp-100',
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

  it('allows safe patch/minor increment with valid manifest', () => {
    const res = ScaPatchPolicyEngine.validate(baseProposal);
    expect(res.allowed).toBe(true);
    expect(res.violations).toHaveLength(0);
  });

  it('rejects non-incrementing target version (target <= current)', () => {
    const res = ScaPatchPolicyEngine.validate({
      ...baseProposal,
      targetVersion: '4.17.20',
    });
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'NON_INCREMENTING_VERSION')).toBe(true);
  });

  it('rejects breaking major version bump when allowMajorBump is false', () => {
    const res = ScaPatchPolicyEngine.validate({
      ...baseProposal,
      targetVersion: '5.0.0',
    });
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'BREAKING_MAJOR_BUMP')).toBe(true);
  });

  it('permits breaking major version bump when allowMajorBump is explicitly true', () => {
    const res = ScaPatchPolicyEngine.validate(
      {
        ...baseProposal,
        targetVersion: '5.0.0',
      },
      { allowMajorBump: true }
    );
    expect(res.allowed).toBe(true);
  });

  it('rejects invalid manifest target paths', () => {
    const res = ScaPatchPolicyEngine.validate({
      ...baseProposal,
      manifestPath: 'src/index.ts',
    });
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'INVALID_MANIFEST_TARGET')).toBe(true);
  });
});
