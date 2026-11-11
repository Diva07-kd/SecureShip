import { describe, it, expect } from 'vitest';
import { getMachineFingerprint } from '../../src/commands/license.js';

describe('Machine Fingerprint Generator (Task 4)', () => {
  it('getMachineFingerprint() returns 16-char hex string', () => {
    const fp = getMachineFingerprint();
    expect(fp).toMatch(/^[a-f0-9]{16}$/);
    expect(fp.length).toBe(16);
  });

  it('getMachineFingerprint() is deterministic (same result on repeat calls)', () => {
    const fp1 = getMachineFingerprint();
    const fp2 = getMachineFingerprint();
    expect(fp1).toBe(fp2);
  });

  it('getMachineFingerprint() does NOT include home directory path (no PII)', () => {
    const originalHome = process.env.HOME;
    const originalUserProfile = process.env.USERPROFILE;
    try {
      const fpBefore = getMachineFingerprint();
      process.env.HOME = '/totally/different/custom/path';
      process.env.USERPROFILE = 'C:\\Totally\\Different\\Custom\\Path';
      const fpAfter = getMachineFingerprint();
      // Fingerprint must be strictly unaffected by user directory or username paths
      expect(fpAfter).toBe(fpBefore);
    } finally {
      process.env.HOME = originalHome;
      process.env.USERPROFILE = originalUserProfile;
    }
  });
});
