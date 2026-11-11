/**
 * LAYER C: Docker Windows Bind-Spec Oracle Verification Suite
 *
 * Enforces Anti-Fake-Test Law:
 * - Oracle implementation derived from Moby Windows volume specification parser
 *   (volume/mounts/windows_parser.go v27.0.0).
 * - Liveliness test proving oracle actively accepts valid drive specs and rejects
 *   legacy /c/... named-volume candidates.
 * - Offline Red/Green proof: baseline outputs fail oracle, remediated outputs pass.
 */

import { describe, it, expect } from 'vitest';
import { dockerWindowsBindSpecAccepts } from './fixtures/docker-windows-bind-oracle.js';
import { ContainerBackend } from '../src/backends/container-backend.js';
import { baselineTranslateHostPath } from './fixtures/translate-host-path.baseline.js';

describe('Layer C: Docker Windows Bind-Spec Oracle (Moby v27.0.0)', () => {
  // =========================================================================
  // C1 & C2: Prove the Oracle is live and accurately models Docker behavior
  // =========================================================================
  it('C2: Oracle is live: accepts valid drive paths and rejects named volume candidates', () => {
    // 1. Accepts valid Windows drive paths (both forward and backward slash)
    const validBindSpecs = [
      'C:/Users/dev/project:/work:rw',
      'C:\\Users\\dev\\project:/work:rw',
      'd:/data/app:/work:rw',
      'D:\\workspace\\test:/work:ro',
      'E:/José/Project:/work:rw',
    ];
    for (const spec of validBindSpecs) {
      const res = dockerWindowsBindSpecAccepts(spec);
      expect(res.accepted).toBe(true);
      expect(res.isBind).toBe(true);
      expect(res.isNamedVolume).toBe(false);
    }

    // 2. Rejects legacy /c/... form because Docker treats it as a named volume with invalid slashes
    const legacyRes = dockerWindowsBindSpecAccepts('/c/Users/dev/project:/work:rw');
    expect(legacyRes.accepted).toBe(false);
    expect(legacyRes.isNamedVolume).toBe(true);
    expect(legacyRes.reason).toContain('includes invalid characters for a local volume name');

    // 3. Rejects relative paths without drive (treated as invalid named volume)
    const relRes = dockerWindowsBindSpecAccepts('Users/dev:/work:rw');
    expect(relRes.accepted).toBe(false);
    expect(relRes.isNamedVolume).toBe(true);
    expect(relRes.reason).toContain('includes invalid characters for a local volume name');

    // 4. Rejects UNC sources
    const uncRes = dockerWindowsBindSpecAccepts('\\\\server\\share\\data:/work:rw');
    expect(uncRes.accepted).toBe(false);
    expect(uncRes.reason).toContain('UNC network paths');
  });

  // =========================================================================
  // C3: Offline Red/Green Proof (A1 outputs pass oracle, baseline fails)
  // =========================================================================
  it('C3: Offline Red/Green proof: all remediated A1 outputs pass oracle, baseline fails', () => {
    const a1Inputs = [
      'C:\\Users\\dev\\project',
      'c:\\Users\\dev',
      'd:\\data\\app',
      'D:/data/app',
      'C:\\Program Files\\Project',
      'C:\\Users\\José\\Проект\\项目',
      'C:\\a\\b\\',
      'C:\\',
      'C:/',
      'C:\\a\\\\b',
      'C:\\a\\.\\b',
      'C:\\a\\..\\b',
      'C:/a\\b/c',
      '\\\\?\\C:\\Users\\x',
      'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\ss-1',
    ];

    for (const input of a1Inputs) {
      // 1. Remediated output assembled into mount spec
      const translated = ContainerBackend.translateHostPath(input, 'win32');
      const mountSpec = `${translated}:/work:rw`;
      const oracleResult = dockerWindowsBindSpecAccepts(mountSpec);

      // Must be accepted as a valid bind mount!
      expect(oracleResult.accepted).toBe(true);
      expect(oracleResult.isBind).toBe(true);

      // 2. Baseline output assembled into mount spec
      const baselineTranslated = baselineTranslateHostPath(input);
      const baselineMountSpec = `${baselineTranslated}:/work:rw`;
      const baselineOracleResult = dockerWindowsBindSpecAccepts(baselineMountSpec);

      // Baseline MUST be rejected by Docker Windows volume parser!
      expect(baselineOracleResult.accepted).toBe(false);
      expect(typeof baselineOracleResult.reason).toBe('string');
      expect(baselineOracleResult.reason!.length).toBeGreaterThan(0);
    }
  });

  // =========================================================================
  // C4: Fail-closed consistency check
  // =========================================================================
  it('C4: Oracle rejects invalid shapes that ContainerBackend refuses to emit', () => {
    const forbiddenShapes = [
      '\\\\server\\share\\data:/work:rw',
      '//server/share/data:/work:rw',
      '/c/Users/dev:/work:rw',
      '\\Users\\dev:/work:rw',
      'relative/path:/work:rw',
      'C:foo:/work:rw',
    ];

    for (const spec of forbiddenShapes) {
      const res = dockerWindowsBindSpecAccepts(spec);
      expect(res.accepted).toBe(false);
    }
  });
});
