import { describe, it, expect } from 'vitest';
import {
  loadToolsLock,
  resolveToolAsset,
  getKnownToolsFromLock,
  detectLibc,
} from '../src/tools-lock.js';

describe('Tools Lockfile SSoT Suite (Phase C)', () => {
  it('loads and validates tools.lock.json successfully', () => {
    const lock = loadToolsLock();
    expect(lock.schemaVersion).toBe(1);
    expect(typeof lock.updatedAt).toBe('string');
    expect(Object.keys(lock.tools).length).toBe(5);
    expect(lock.tools.opengrep).toBeDefined();
    expect(lock.tools.gitleaks).toBeDefined();
    expect(lock.tools['osv-scanner']).toBeDefined();
    expect(lock.tools.trivy).toBeDefined();
    expect(lock.tools.checkov).toBeDefined();
  });

  it('resolves tool asset for linux-x64 with libc specification', () => {
    const glibcRes = resolveToolAsset('opengrep', 'linux-x64', 'glibc');
    expect(glibcRes.asset).not.toBeNull();
    expect(glibcRes.asset!.url).toContain('manylinux');

    const muslRes = resolveToolAsset('opengrep', 'linux-x64', 'musl');
    expect(muslRes.asset).not.toBeNull();
    expect(muslRes.asset!.url).toContain('musllinux');
  });

  it('resolves tool asset for linux-arm64 with libc specification', () => {
    const glibcRes = resolveToolAsset('opengrep', 'linux-arm64', 'glibc');
    expect(glibcRes.asset).not.toBeNull();
    expect(glibcRes.asset!.url).toContain('manylinux_aarch64');

    const muslRes = resolveToolAsset('opengrep', 'linux-arm64', 'musl');
    expect(muslRes.asset).not.toBeNull();
    expect(muslRes.asset!.url).toContain('musllinux_aarch64');
  });

  it('resolves standard assets for darwin and win32', () => {
    const darwinArm = resolveToolAsset('gitleaks', 'darwin-arm64');
    expect(darwinArm.asset).not.toBeNull();
    expect(darwinArm.asset!.url).toContain('darwin_arm64');

    const win32X64 = resolveToolAsset('trivy', 'win32-x64');
    expect(win32X64.asset).not.toBeNull();
    expect(win32X64.asset!.url).toContain('windows-64bit');
  });

  it('normalizes arch synonyms (amd64/x86_64 to x64, aarch64 to arm64)', () => {
    const amd64 = resolveToolAsset('trivy', 'linux-amd64');
    expect(amd64.asset).not.toBeNull();
    expect(amd64.asset!.url).toContain('Linux-64bit');

    const x86_64 = resolveToolAsset('osv-scanner', 'linux-x86_64');
    expect(x86_64.asset).not.toBeNull();
    expect(x86_64.asset!.url).toContain('linux_amd64');

    const aarch64 = resolveToolAsset('trivy', 'linux-aarch64');
    expect(aarch64.asset).not.toBeNull();
    expect(aarch64.asset!.url).toContain('Linux-ARM64');
  });

  it('returns unsupportedReason for Python-based checkov', () => {
    const res = resolveToolAsset('checkov', 'linux-x64');
    expect(res.asset).toBeNull();
    expect(res.unsupportedReason).toContain('Python-based');
  });

  it('returns unsupportedReason for non-existent tool or platform', () => {
    const res1 = resolveToolAsset('unknown-tool', 'linux-x64');
    expect(res1.asset).toBeNull();
    expect(res1.unsupportedReason).toContain('not defined');

    const res2 = resolveToolAsset('trivy', 'solaris-sparc');
    expect(res2.asset).toBeNull();
    expect(res2.unsupportedReason).toContain('No precompiled distribution');
  });

  it('detectLibc returns undefined on non-linux platforms', () => {
    const res = detectLibc();
    if (process.platform === 'linux') {
      expect(['glibc', 'musl']).toContain(res);
    } else {
      expect(res).toBeUndefined();
    }
  });

  it('resolves tool asset for linux without explicit libc by falling back to glibc then musl', () => {
    const fallbackRes = resolveToolAsset('opengrep', 'linux-x64');
    expect(fallbackRes.asset).not.toBeNull();
    expect(fallbackRes.asset!.url).toContain('manylinux');
  });

  it('getKnownToolsFromLock produces backward-compatible KNOWN_TOOLS map', () => {
    const known = getKnownToolsFromLock();
    expect(Object.keys(known).length).toBe(5);
    expect(known.opengrep.name).toBe('opengrep');
    expect(known.trivy.version).toBe('0.76.0');
    expect(known.gitleaks.platforms['linux-x64']).toBeDefined();
  });

  it('loadToolsLock with customPath loads directly or throws on invalid path', () => {
    expect(() => loadToolsLock('/non/existent/path/to/tools.lock.json')).toThrow();
    const customLock = loadToolsLock('tools.lock.json');
    expect(customLock.schemaVersion).toBe(1);
  });

  it('loadToolsLock throws when no candidate paths exist', () => {
    expect(() =>
      loadToolsLock(undefined, ['/non/existent/candidate/path/tools.lock.json'])
    ).toThrow(/tools\.lock\.json not found in candidate paths/);
  });

  it('resolves tool asset when targetPlatform has exact key without libc suffix', () => {
    const res = resolveToolAsset('gitleaks', 'linux-x64');
    expect(res.asset).not.toBeNull();
    expect(res.asset!.url).toContain('linux_x64');
  });

  it('falls through to exact platform or musl when glibc key is absent', () => {
    // When libc is specified as musl on a tool with only exact platform (e.g. gitleaks)
    const res = resolveToolAsset('gitleaks', 'linux-x64', 'musl');
    expect(res.asset).not.toBeNull();
    expect(res.asset!.url).toContain('linux_x64');
  });
});
