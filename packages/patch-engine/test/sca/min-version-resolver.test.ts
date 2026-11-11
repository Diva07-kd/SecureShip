import { describe, it, expect } from 'vitest';
import { MinVersionResolver } from '../../src/sca/min-version-resolver.js';

describe('MinVersionResolver Unit Tests', () => {
  describe('parseVersion', () => {
    it('parses standard semver strings', () => {
      const v = MinVersionResolver.parseVersion('1.2.3');
      expect(v).toEqual({
        major: 1,
        minor: 2,
        patch: 3,
        preRelease: '',
        range: '',
        isValid: true,
      });
    });

    it('extracts range prefixes (^, ~, >=)', () => {
      expect(MinVersionResolver.parseVersion('^1.2.3')).toMatchObject({
        major: 1,
        minor: 2,
        patch: 3,
        range: '^',
      });

      expect(MinVersionResolver.parseVersion('~2.4.0')).toMatchObject({
        major: 2,
        minor: 4,
        patch: 0,
        range: '~',
      });

      expect(MinVersionResolver.parseVersion('>=3.0.1')).toMatchObject({
        major: 3,
        minor: 0,
        patch: 1,
        range: '>=',
      });
    });

    it('handles pre-release tags and leading v', () => {
      const v = MinVersionResolver.parseVersion('v1.2.3-beta.1');
      expect(v).toEqual({
        major: 1,
        minor: 2,
        patch: 3,
        preRelease: 'beta.1',
        range: '',
        isValid: true,
      });
    });

    it('does not throw on invalid strings and returns graceful fallback', () => {
      const invalid = MinVersionResolver.parseVersion('invalid');
      expect(invalid.isValid).toBe(false);
      expect(invalid.major).toBe(0);

      // Empty or non-string inputs
      // @ts-expect-error testing invalid input
      expect(MinVersionResolver.parseVersion(null).isValid).toBe(false);
      // @ts-expect-error testing invalid input
      expect(MinVersionResolver.parseVersion(undefined).isValid).toBe(false);
    });
  });

  describe('compare', () => {
    it('compares majors, minors, patches', () => {
      const v1 = MinVersionResolver.parseVersion('2.0.0');
      const v2 = MinVersionResolver.parseVersion('1.9.9');
      expect(MinVersionResolver.compare(v1, v2)).toBe(1);
      expect(MinVersionResolver.compare(v2, v1)).toBe(-1);

      const v3 = MinVersionResolver.parseVersion('1.2.4');
      const v4 = MinVersionResolver.parseVersion('1.2.3');
      expect(MinVersionResolver.compare(v3, v4)).toBe(1);

      const v5 = MinVersionResolver.parseVersion('1.2.3');
      expect(MinVersionResolver.compare(v4, v5)).toBe(0);
    });

    it('ranks release higher than prerelease', () => {
      const release = MinVersionResolver.parseVersion('1.0.0');
      const rc = MinVersionResolver.parseVersion('1.0.0-rc.1');
      expect(MinVersionResolver.compare(release, rc)).toBe(1);
      expect(MinVersionResolver.compare(rc, release)).toBe(-1);
    });
  });

  describe('isMajorBump', () => {
    it('correctly identifies major breaking bumps in 1.x+', () => {
      expect(MinVersionResolver.isMajorBump('1.9.9', '2.0.0')).toBe(true);
      expect(MinVersionResolver.isMajorBump('1.9.9', '1.10.0')).toBe(false);
      expect(MinVersionResolver.isMajorBump('2.1.0', '2.1.1')).toBe(false);
    });

    it('treats 0.x minor increments as breaking according to SemVer spec', () => {
      expect(MinVersionResolver.isMajorBump('0.1.2', '0.2.0')).toBe(true);
      expect(MinVersionResolver.isMajorBump('0.1.2', '0.1.5')).toBe(false);
    });

    it('returns false when either version is invalid', () => {
      expect(MinVersionResolver.isMajorBump('invalid', '1.0.0')).toBe(false);
      expect(MinVersionResolver.isMajorBump('1.0.0', 'invalid')).toBe(false);
    });
  });

  describe('resolve', () => {
    it('resolves safe patch bump', () => {
      expect(MinVersionResolver.resolve('1.2.3', '1.2.5')).toBe('1.2.5');
    });

    it('allows major bump if no alternative fixedVersion exists', () => {
      expect(MinVersionResolver.resolve('1.2.3', '2.0.0')).toBe('2.0.0');
    });

    it('strips pre-release tags cleanly', () => {
      expect(MinVersionResolver.resolve('1.2.3-beta', '1.2.4')).toBe('1.2.4');
    });

    it('preserves range prefix from currentVersion (^, ~)', () => {
      expect(MinVersionResolver.resolve('^1.2.3', '1.2.5')).toBe('^1.2.5');
      expect(MinVersionResolver.resolve('~1.2.0', '1.2.4')).toBe('~1.2.4');
    });

    it('returns currentVersion if fixedVersion is missing or empty', () => {
      expect(MinVersionResolver.resolve('1.2.3', undefined)).toBe('1.2.3');
      expect(MinVersionResolver.resolve('1.2.3', '')).toBe('1.2.3');
    });

    it('returns fixedVersion as-is if non-standard semver', () => {
      expect(MinVersionResolver.resolve('1.0', 'nonstandard-git-hash')).toBe(
        'nonstandard-git-hash'
      );
    });
  });
});
