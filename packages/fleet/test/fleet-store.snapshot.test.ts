import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {
  parseSnapshotBytes,
  serializeSnapshot,
  FleetStoreUnsupportedVersionError,
} from '../src/storage/fleet-snapshot.js';
import { FleetStore } from '../src/storage/fleet-store.js';
import { makeRepoSummary, legacyFile, v1File, withBom } from './fixtures/store-fixtures.js';

describe('LAYER A: Snapshot Validation, Digest and Versioning (Gate 13 / F-FLT-004)', () => {
  let tempDir: string;
  let primaryDb: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-snapshot-test-'));
    primaryDb = path.join(tempDir, 'fleet-db.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // A1. Valid inputs: legacy file, v1 with digest, BOM (both), CRLF line endings, zero repos, 1,000 repos
  describe('A1: Valid inputs', () => {
    it('loads a legacy file without formatVersion or integrity', () => {
      const summary = makeRepoSummary('repo-legacy');

      const legacyContent = legacyFile({
        repos: [summary],
        policy: {
          policyVersion: '1.0',
          failOnSeverity: 'HIGH',
          blockUnreachableSca: false,
          deniedLicenses: ['GPL-3.0'],
          requireHmacAudit: true,
          updatedAt: '2026-11-04T00:00:00.000Z',
        },
      });

      const res = parseSnapshotBytes(Buffer.from(legacyContent, 'utf8'));
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.isLegacy).toBe(true);
        expect(res.snapshot.repos.length).toBe(1);
        expect(res.snapshot.repos[0]!.repoName).toBe('repo-legacy');
        expect(res.snapshot.policy.failOnSeverity).toBe('HIGH');
      }
    });

    it('loads a v1 file with an independently verified cryptographic digest', () => {
      const summary = makeRepoSummary('repo-v1');

      const policy = {
        policyVersion: '1.0',
        failOnSeverity: 'HIGH' as const,
        blockUnreachableSca: false,
        deniedLicenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
        requireHmacAudit: true,
        updatedAt: '2026-11-04T00:00:00.000Z',
      };

      const v1Content = v1File({
        repos: [summary],
        policy,
      });

      const res = parseSnapshotBytes(Buffer.from(v1Content, 'utf8'));
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.isLegacy).toBe(false);
        expect(res.snapshot.formatVersion).toBe(1);
        expect(res.snapshot.repos.length).toBe(1);
        expect(res.snapshot.integrity?.algorithm).toBe('sha256');

        const expectedDigest = crypto
          .createHash('sha256')
          .update(
            JSON.stringify({
              formatVersion: 1,
              repos: [summary],
              policy,
            }),
            'utf8'
          )
          .digest('hex');
        expect(res.snapshot.integrity?.digest).toBe(expectedDigest);
      }
    });

    it('loads a file with leading UTF-8 BOM bytes (0xEF, 0xBB, 0xBF)', () => {
      const v1Content = v1File({ repos: [] });
      const bomBuf = withBom(Buffer.from(v1Content, 'utf8'));

      const res = parseSnapshotBytes(bomBuf);
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.snapshot.repos.length).toBe(0);
      }
    });

    it('loads a file with leading UTF-16/Unicode FEFF character in string', () => {
      const v1Content = '\uFEFF' + v1File({ repos: [] });
      const res = parseSnapshotBytes(Buffer.from(v1Content, 'utf8'));
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.snapshot.repos.length).toBe(0);
      }
    });

    it('loads a file with CRLF line endings', () => {
      const v1Content = v1File({ repos: [] }).replace(/\n/g, '\r\n');
      const res = parseSnapshotBytes(Buffer.from(v1Content, 'utf8'));
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.snapshot.repos.length).toBe(0);
      }
    });

    it('loads snapshot with exactly 0 repos', () => {
      const v1Content = v1File({ repos: [] });
      const res = parseSnapshotBytes(Buffer.from(v1Content, 'utf8'));
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.snapshot.repos).toEqual([]);
      }
    });

    it('loads snapshot with 1,000 repos without loss', () => {
      const repos = Array.from({ length: 1000 }, (_, i) => ({
        repoName: `enterprise-repo-${i}`,
        branch: 'main',
        commitSha: 'c0ffee',
        latestScanAt: '2026-11-04T00:00:00.000Z',
        riskGrade: 'A' as const,
        riskScore: 92,
        activeCriticals: 0,
        activeHighs: 0,
        reachableCount: 0,
        suppressedCount: 0,
        reachabilitySuppressionPct: 0,
        componentCount: 1,
        compliant: true,
        vulnerabilities: [],
        sbomComponents: [],
      }));

      const v1Content = v1File({ repos });
      const res = parseSnapshotBytes(Buffer.from(v1Content, 'utf8'));
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.snapshot.repos.length).toBe(1000);
        expect(res.snapshot.repos[999]!.repoName).toBe('enterprise-repo-999');
      }
    });
  });

  // A2. Invalid inputs and exact reason codes
  describe('A2: Invalid inputs and reason codes', () => {
    it('returns JSON_SYNTAX_ERROR for empty string and whitespace', () => {
      const emptyRes = parseSnapshotBytes(Buffer.from('', 'utf8'));
      expect(emptyRes).toEqual({
        ok: false,
        code: 'JSON_SYNTAX_ERROR',
        detail: expect.stringContaining('Unexpected end of JSON input'),
      });

      const wsRes = parseSnapshotBytes(Buffer.from('   \t\r\n  ', 'utf8'));
      expect(wsRes.ok).toBe(false);
      if (!wsRes.ok) {
        expect(wsRes.code).toBe('JSON_SYNTAX_ERROR');
      }
    });

    it('returns JSON_SYNTAX_ERROR for truncated inputs (byte 0, 1, mid, len-1)', () => {
      const valid = v1File({ repos: [] });
      const buf = Buffer.from(valid, 'utf8');

      const at0 = parseSnapshotBytes(buf.subarray(0, 0));
      expect(at0.ok).toBe(false);
      if (!at0.ok) expect(at0.code).toBe('JSON_SYNTAX_ERROR');

      const at1 = parseSnapshotBytes(buf.subarray(0, 1));
      expect(at1.ok).toBe(false);
      if (!at1.ok) expect(at1.code).toBe('JSON_SYNTAX_ERROR');

      const mid = parseSnapshotBytes(buf.subarray(0, Math.floor(buf.length / 2)));
      expect(mid.ok).toBe(false);
      if (!mid.ok) expect(mid.code).toBe('JSON_SYNTAX_ERROR');

      const last = parseSnapshotBytes(buf.subarray(0, buf.length - 1));
      expect(last.ok).toBe(false);
      if (!last.ok) expect(last.code).toBe('JSON_SYNTAX_ERROR');
    });

    it('returns INVALID_ROOT for primitive JSON roots (null, [], string, number, boolean)', () => {
      const prims = ['null', '[]', '"hello"', '123', 'true', 'false'];
      for (const p of prims) {
        const res = parseSnapshotBytes(Buffer.from(p, 'utf8'));
        expect(res).toEqual({
          ok: false,
          code: 'INVALID_ROOT',
          detail: 'Root must be a plain object',
        });
      }
    });

    it('returns INVALID_REPOS for {} root without repos and non-array repos', () => {
      const noRepos = parseSnapshotBytes(Buffer.from('{}', 'utf8'));
      expect(noRepos).toEqual({
        ok: false,
        code: 'INVALID_REPOS',
        detail: 'repos must be an array',
      });

      const nonArray = parseSnapshotBytes(Buffer.from('{"repos": "not-an-array"}', 'utf8'));
      expect(nonArray).toEqual({
        ok: false,
        code: 'INVALID_REPOS',
        detail: 'repos must be an array',
      });
    });

    it('returns INVALID_REPO_ENTRY when repo entry is null, array, or number', () => {
      for (const invalidEntry of ['null', '[1, 2]', '42']) {
        const json = `{"repos": [${invalidEntry}]}`;
        const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
        expect(res).toEqual({
          ok: false,
          code: 'INVALID_REPO_ENTRY',
          detail: 'repos[0] must be a plain object',
        });
      }
    });

    it('returns INVALID_REPO_NAME when repoName is missing, empty, number, or whitespace-only', () => {
      const badNames = ['""', '"   "', '123'];
      for (const nameVal of badNames) {
        const json = `{"repos": [{"repoName": ${nameVal}}]}`;
        const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
        expect(res).toEqual({
          ok: false,
          code: 'INVALID_REPO_NAME',
          detail: 'repos[0].repoName must be a non-empty string',
        });
      }
    });

    it('returns DUPLICATE_REPO_NAME when duplicate repo names appear', () => {
      const validRepo = {
        repoName: 'dup-repo',
        branch: 'main',
        commitSha: 'abc',
        latestScanAt: '2026-11-04T00:00:00.000Z',
        riskGrade: 'A' as const,
        riskScore: 100,
        activeCriticals: 0,
        activeHighs: 0,
        reachableCount: 0,
        suppressedCount: 0,
        reachabilitySuppressionPct: 0,
        componentCount: 0,
        compliant: true,
        vulnerabilities: [],
        sbomComponents: [],
      };
      const v1Content = v1File({ repos: [validRepo, validRepo] });
      const res = parseSnapshotBytes(Buffer.from(v1Content, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'DUPLICATE_REPO_NAME',
        detail: 'Duplicate repoName "dup-repo" at index 1',
      });
    });

    it('returns INVALID_REPO_METRIC when riskScore is string or non-finite', () => {
      const validRepo = {
        repoName: 'repo-bad-metric',
        branch: 'main',
        commitSha: 'abc',
        latestScanAt: '2026-11-04T00:00:00.000Z',
        riskGrade: 'A',
        riskScore: 'not-a-number',
        activeCriticals: 0,
        activeHighs: 0,
        reachableCount: 0,
        suppressedCount: 0,
        reachabilitySuppressionPct: 0,
        componentCount: 0,
        compliant: true,
        vulnerabilities: [],
        sbomComponents: [],
      };
      const json = JSON.stringify({ repos: [validRepo] });
      const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'INVALID_REPO_METRIC',
        detail: 'repos[0].riskScore must be a finite number',
      });
    });

    it('returns INVALID_REPO_COMPONENTS when sbomComponents is not an array', () => {
      const validRepo = {
        repoName: 'repo-bad-sbom',
        branch: 'main',
        commitSha: 'abc',
        latestScanAt: '2026-11-04T00:00:00.000Z',
        riskGrade: 'A',
        riskScore: 100,
        activeCriticals: 0,
        activeHighs: 0,
        reachableCount: 0,
        suppressedCount: 0,
        reachabilitySuppressionPct: 0,
        componentCount: 0,
        compliant: true,
        vulnerabilities: [],
        sbomComponents: 'not-an-array',
      };
      const json = JSON.stringify({ repos: [validRepo] });
      const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'INVALID_REPO_COMPONENTS',
        detail: 'repos[0].sbomComponents must be an array',
      });
    });

    it('returns INVALID_POLICY when policy is not a plain object', () => {
      const json = '{"repos": [], "policy": "not-an-object"}';
      const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'INVALID_POLICY',
        detail: 'policy must be a plain object',
      });
    });

    it('returns INVALID_POLICY_FIELD for policy field type errors', () => {
      const testCases = [
        { policy: { failOnSeverity: 'garbage' }, field: 'failOnSeverity' },
        { policy: { failOnSeverity: 5 }, field: 'failOnSeverity' },
        { policy: { requireHmacAudit: 'no' }, field: 'requireHmacAudit' },
        { policy: { blockUnreachableSca: 'true' }, field: 'blockUnreachableSca' },
        { policy: { deniedLicenses: 'GPL' }, field: 'deniedLicenses' },
        { policy: { deniedLicenses: [1, 2] }, field: 'deniedLicenses' },
      ];

      for (const tc of testCases) {
        const json = JSON.stringify({ repos: [], policy: tc.policy });
        const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
        expect(res.ok).toBe(false);
        if (!res.ok) {
          expect(res.code).toBe('INVALID_POLICY_FIELD');
        }
      }
    });

    it('returns INTEGRITY_MISMATCH when one byte is flipped in snapshot repos', () => {
      const summary = makeRepoSummary('repo-intact');
      const v1Content = v1File({ repos: [summary] });

      // Flip one character in repoName
      const tampered = v1Content.replace('"repo-intact"', '"repo-tamper"');
      const res = parseSnapshotBytes(Buffer.from(tampered, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'INTEGRITY_MISMATCH',
        detail: 'Cryptographic digest mismatch',
      });
    });

    it('returns INVALID_INTEGRITY when digest algorithm is unknown', () => {
      const json = JSON.stringify({
        formatVersion: 1,
        repos: [],
        policy: {},
        integrity: {
          algorithm: 'sha512',
          digest: 'bad',
        },
      });
      const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'INVALID_INTEGRITY',
        detail: 'integrity must have algorithm "sha256" and string digest',
      });
    });

    it('throws FleetStoreUnsupportedVersionError for numbers > 1 (2, 999, 1.5)', () => {
      for (const v of [2, 999, 1.5]) {
        const json = JSON.stringify({ formatVersion: v, repos: [] });
        expect(() => parseSnapshotBytes(Buffer.from(json, 'utf8'))).toThrow(
          FleetStoreUnsupportedVersionError
        );
      }
    });

    it('returns INVALID_FORMAT_VERSION for non-number formatVersion ("1")', () => {
      const json = JSON.stringify({ formatVersion: '1', repos: [] });
      const res = parseSnapshotBytes(Buffer.from(json, 'utf8'));
      expect(res).toEqual({
        ok: false,
        code: 'INVALID_FORMAT_VERSION',
        detail: 'formatVersion must be a positive integer',
      });
    });
  });

  // A3. Policy merge: legacy file with partial policy
  describe('A3: Policy merge semantics', () => {
    it('merges partial policy from file over defaults and preserves explicit false', () => {
      fs.writeFileSync(
        primaryDb,
        JSON.stringify({
          repos: [],
          policy: {
            failOnSeverity: 'MEDIUM',
          },
        }),
        'utf8'
      );

      const store = new FleetStore({ storageFile: primaryDb });
      const loadedPolicy = store.getPolicy();

      expect(loadedPolicy.failOnSeverity).toBe('MEDIUM');
      expect(loadedPolicy.requireHmacAudit).toBe(true);
      expect(loadedPolicy.deniedLicenses).toEqual(['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0']);
      expect(loadedPolicy.blockUnreachableSca).toBe(false);
    });

    it('preserves requireHmacAudit false from file', () => {
      fs.writeFileSync(
        primaryDb,
        JSON.stringify({
          repos: [],
          policy: {
            requireHmacAudit: false,
          },
        }),
        'utf8'
      );

      const store = new FleetStore({ storageFile: primaryDb });
      expect(store.getPolicy().requireHmacAudit).toBe(false);
    });
  });

  // A4. Prototype safety
  describe('A4: Prototype pollution safety', () => {
    it('drops __proto__, constructor, prototype keys without polluting Object.prototype', () => {
      const maliciousJson = JSON.stringify({
        formatVersion: 1,
        __proto__: { pollutedRoot: 'injected' },
        constructor: { prototype: { pollutedCtor: 'injected' } },
        repos: [
          {
            repoName: 'evil-repo',
            __proto__: { pollutedRepo: 'injected' },
            branch: 'main',
            commitSha: '123',
            latestScanAt: '2026-11-04T00:00:00.000Z',
            riskGrade: 'A',
            riskScore: 100,
            activeCriticals: 0,
            activeHighs: 0,
            reachableCount: 0,
            suppressedCount: 0,
            reachabilitySuppressionPct: 0,
            componentCount: 0,
            compliant: true,
            vulnerabilities: [],
            sbomComponents: [],
          },
        ],
        policy: {
          policyVersion: '1.0',
          __proto__: { pollutedPolicy: 'injected' },
          failOnSeverity: 'HIGH',
        },
      });

      const initialKeyCount = Object.keys(Object.prototype).length;
      const res = parseSnapshotBytes(Buffer.from(maliciousJson, 'utf8'));

      expect(({} as Record<string, unknown>).pollutedRoot).toBeUndefined();
      expect(({} as Record<string, unknown>).pollutedCtor).toBeUndefined();
      expect(({} as Record<string, unknown>).pollutedRepo).toBeUndefined();
      expect(({} as Record<string, unknown>).pollutedPolicy).toBeUndefined();
      expect(Object.keys(Object.prototype).length).toBe(initialKeyCount);

      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(Object.prototype.hasOwnProperty.call(res.snapshot, '__proto__')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(res.snapshot, 'constructor')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(res.snapshot.repos[0], '__proto__')).toBe(
          false
        );
      }
    });
  });

  // A5. Serialize then parse round trip
  describe('A5: Serialize and parse round trip', () => {
    it('round trips state with deep-equal parse, matching SHA-256 digest, and 2-space indentation', () => {
      const summary = makeRepoSummary('roundtrip-repo');

      const state = {
        repos: [summary],
        policy: {
          policyVersion: '1.0',
          failOnSeverity: 'CRITICAL' as const,
          blockUnreachableSca: true,
          deniedLicenses: ['GPL-2.0'],
          requireHmacAudit: false,
          updatedAt: '2026-11-04T00:00:00.000Z',
        },
        updatedAt: '2026-11-04T00:00:00.000Z',
      };

      const serialized = serializeSnapshot(state);
      const text = serialized.buffer.toString('utf8');

      // Verify 2-space indentation
      expect(text.startsWith('{\n  "formatVersion": 1,')).toBe(true);

      // Verify independently computed digest
      const independentDigest = crypto
        .createHash('sha256')
        .update(
          JSON.stringify({
            formatVersion: 1,
            repos: state.repos,
            policy: state.policy,
          }),
          'utf8'
        )
        .digest('hex');
      expect(serialized.digest).toBe(independentDigest);

      // Verify round-trip parse
      const parsed = parseSnapshotBytes(serialized.buffer);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        expect(parsed.snapshot.formatVersion).toBe(1);
        expect(parsed.snapshot.repos).toEqual(state.repos);
        expect(parsed.snapshot.policy).toEqual(state.policy);
        expect(parsed.snapshot.integrity?.digest).toBe(independentDigest);
      }
    });
  });
});
