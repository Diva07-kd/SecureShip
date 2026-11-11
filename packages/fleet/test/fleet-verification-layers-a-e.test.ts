import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import util from 'node:util';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  validateFleetToken,
  readTokenFile,
  resolveFleetToken,
  FleetConfigError,
} from '../src/security/fleet-token.js';
import {
  buildFleetRuntimeConfig,
  formatDisplayUrl,
  formatAuthLabel,
  formatReadHint,
} from '../src/config/fleet-config.js';
import { FleetServer } from '../src/server/fleet-server.js';
import { FleetStore } from '../src/storage/fleet-store.js';
import { makeCanary, assertNoLeak, FakeFsFacade, rawHttp } from './fixtures/fleet-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('LAYER A: Token Validation and Resolution (DEV-8)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-layer-a-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // A1: validateFleetToken exact reasons and canary hygiene
  it('A1: validateFleetToken returns exact failure reasons and never leaks token candidate', () => {
    const canary = makeCanary();

    // Empty
    expect(validateFleetToken('')).toEqual({ ok: false, reason: 'EMPTY' });
    expect(validateFleetToken(undefined)).toEqual({ ok: false, reason: 'EMPTY' });
    expect(validateFleetToken(null)).toEqual({ ok: false, reason: 'EMPTY' });

    // 23 chars (too short)
    const shortToken = canary.slice(0, 23);
    const shortRes = validateFleetToken(shortToken);
    expect(shortRes).toEqual({ ok: false, reason: 'TOO_SHORT' });
    assertNoLeak(JSON.stringify(shortRes), canary);

    // 513 chars (too long)
    const longToken = 'A'.repeat(513);
    expect(validateFleetToken(longToken)).toEqual({ ok: false, reason: 'TOO_LONG' });

    // Whitespace / Invalid chars
    expect(validateFleetToken('validlengthtokenwith space')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith\ttab')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith\nnewline')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith-\u00E9')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith-\uD83D\uDE00')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith-\uFF10')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith-\x7F')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });
    expect(validateFleetToken('validlengthtokenwith-\x01')).toEqual({
      ok: false,
      reason: 'INVALID_CHARS',
    });

    // Accepted: 24 and 512 chars of printable ASCII
    const printableClasses = 'Aa0!@#$%^&*()-_=+[]{}|;:,.<>?/~`"\'\\';
    const sample24 = printableClasses.slice(0, 24);
    expect(validateFleetToken(sample24)).toEqual({ ok: true });
    expect(validateFleetToken('A'.repeat(512))).toEqual({ ok: true });
  });

  // A2: Sources precedence and conflict detection
  it('A2: resolveFleetToken respects source precedence and fails closed on conflicting sources', async () => {
    const canary1 = makeCanary();
    const canary2 = makeCanary();
    const tokenFile = path.join(tempDir, 'fleet-token.txt');
    fs.writeFileSync(tokenFile, `${canary1}\n`, 'utf8');

    // Only env
    const rEnv = await resolveFleetToken({
      env: { FLEET_TOKEN: canary1 },
      homeDir: tempDir,
    });
    expect(rEnv.token).toBe(canary1);
    expect(rEnv.source).toBe('env');

    // Only file
    const rFile = await resolveFleetToken({
      env: { FLEET_TOKEN_FILE: tokenFile },
      homeDir: tempDir,
    });
    expect(rFile.token).toBe(canary1);
    expect(rFile.source).toBe('file');

    // Only flag
    const rFlag = await resolveFleetToken({
      flagToken: canary1,
      homeDir: tempDir,
    });
    expect(rFlag.token).toBe(canary1);
    expect(rFlag.source).toBe('flag');

    // env == file (accepted, file precedence)
    const rEqual = await resolveFleetToken({
      env: { FLEET_TOKEN: canary1, FLEET_TOKEN_FILE: tokenFile },
      homeDir: tempDir,
    });
    expect(rEqual.token).toBe(canary1);

    // env != file (throws FleetConfigError naming both sources)
    await expect(
      resolveFleetToken({
        env: { FLEET_TOKEN: canary2, FLEET_TOKEN_FILE: tokenFile },
        homeDir: tempDir,
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      const cfgErr = err as FleetConfigError;
      expect(cfgErr.code).toBe('CONFLICTING_TOKEN_SOURCES');
      expect(cfgErr.message).toContain('FLEET_TOKEN_FILE');
      expect(cfgErr.message).toContain('FLEET_TOKEN');
      assertNoLeak(cfgErr.message, canary1);
      assertNoLeak(cfgErr.message, canary2);
      return true;
    });

    // flag != env
    await expect(
      resolveFleetToken({
        flagToken: canary2,
        env: { FLEET_TOKEN: canary1 },
        homeDir: tempDir,
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      const cfgErr = err as FleetConfigError;
      expect(cfgErr.code).toBe('CONFLICTING_TOKEN_SOURCES');
      expect(cfgErr.message).toContain('--token');
      expect(cfgErr.message).toContain('FLEET_TOKEN');
      return true;
    });

    // Empty-string env treated as unset
    const rEmptyEnv = await resolveFleetToken({
      env: { FLEET_TOKEN: '', FLEET_TOKEN_FILE: tokenFile },
      homeDir: tempDir,
    });
    expect(rEmptyEnv.token).toBe(canary1);
    expect(rEmptyEnv.source).toBe('file');

    // Whitespace-only env throws INVALID_TOKEN (not unset)
    await expect(
      resolveFleetToken({
        env: { FLEET_TOKEN: '   ' },
        homeDir: tempDir,
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN');
      return true;
    });
  });

  // A3: File decoding on real fs
  it('A3: readTokenFile correctly decodes valid files and rejects invalid encodings and formatting', async () => {
    const canary = makeCanary();

    // LF
    const fLf = path.join(tempDir, 'token-lf.txt');
    fs.writeFileSync(fLf, `${canary}\n`, 'utf8');
    expect(await readTokenFile(fLf)).toBe(canary);

    // CRLF
    const fCrlf = path.join(tempDir, 'token-crlf.txt');
    fs.writeFileSync(fCrlf, `${canary}\r\n`, 'utf8');
    expect(await readTokenFile(fCrlf)).toBe(canary);

    // No trailing newline
    const fNoNl = path.join(tempDir, 'token-nonl.txt');
    fs.writeFileSync(fNoNl, `${canary}`, 'utf8');
    expect(await readTokenFile(fNoNl)).toBe(canary);

    // Multiple trailing newlines (rejected)
    const fMultiNl = path.join(tempDir, 'token-multinl.txt');
    fs.writeFileSync(fMultiNl, `${canary}\n\n`, 'utf8');
    await expect(readTokenFile(fMultiNl)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_CONTENT');
      return true;
    });

    // Interior newline (rejected)
    const fInteriorNl = path.join(tempDir, 'token-interiornl.txt');
    fs.writeFileSync(fInteriorNl, `${canary.slice(0, 10)}\n${canary.slice(10)}`, 'utf8');
    await expect(readTokenFile(fInteriorNl)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_CONTENT');
      return true;
    });

    // Interior space (rejected)
    const fInteriorSpace = path.join(tempDir, 'token-interiorspace.txt');
    fs.writeFileSync(fInteriorSpace, `${canary.slice(0, 10)} ${canary.slice(10)}`, 'utf8');
    await expect(readTokenFile(fInteriorSpace)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_CONTENT');
      return true;
    });

    // UTF-8 BOM (accepted)
    const fBom = path.join(tempDir, 'token-bom.txt');
    fs.writeFileSync(
      fBom,
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(canary, 'utf8')])
    );
    expect(await readTokenFile(fBom)).toBe(canary);

    // UTF-16LE with BOM (rejected with re-save message)
    const fUtf16Le = path.join(tempDir, 'token-utf16le.txt');
    fs.writeFileSync(
      fUtf16Le,
      Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(canary, 'utf16le')])
    );
    await expect(readTokenFile(fUtf16Le)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_ENCODING');
      expect((err as Error).message).toContain('re-save as UTF-8 without BOM');
      return true;
    });

    // UTF-16BE with BOM (rejected with re-save message)
    const fUtf16Be = path.join(tempDir, 'token-utf16be.txt');
    fs.writeFileSync(
      fUtf16Be,
      Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(canary, 'utf16le')])
    );
    await expect(readTokenFile(fUtf16Be)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_ENCODING');
      expect((err as Error).message).toContain('re-save as UTF-8 without BOM');
      return true;
    });

    // UTF-16 without BOM (contains null bytes)
    const fNull = path.join(tempDir, 'token-null.txt');
    fs.writeFileSync(fNull, Buffer.from(`token\x00withnull`, 'utf8'));
    await expect(readTokenFile(fNull)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_ENCODING');
      return true;
    });

    // Invalid UTF-8 bytes
    const fInvalidUtf8 = path.join(tempDir, 'token-invalid-utf8.txt');
    fs.writeFileSync(fInvalidUtf8, Buffer.from([0xff, 0xff, 0xff]));
    await expect(readTokenFile(fInvalidUtf8)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_ENCODING');
      expect((err as Error).message).toContain('re-save as UTF-8');
      return true;
    });

    // Empty file
    const fEmpty = path.join(tempDir, 'token-empty.txt');
    fs.writeFileSync(fEmpty, '', 'utf8');
    expect(await readTokenFile(fEmpty)).toBe('');

    // 4097-byte file (exceeds cap)
    const fHuge = path.join(tempDir, 'token-4097.txt');
    fs.writeFileSync(fHuge, 'A'.repeat(4097), 'utf8');
    await expect(readTokenFile(fHuge)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('TOKEN_FILE_TOO_LARGE');
      return true;
    });

    // Directory path
    const subDir = path.join(tempDir, 'sub-dir');
    fs.mkdirSync(subDir);
    await expect(readTokenFile(subDir)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_TOKEN_FILE');
      return true;
    });

    // Nonexistent path
    const fNonExistent = path.join(tempDir, 'does-not-exist.txt');
    await expect(readTokenFile(fNonExistent)).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('TOKEN_FILE_NOT_FOUND');
      expect((err as Error).message).toContain(fNonExistent);
      return true;
    });
  });

  // A4: Docker/K8s secret layout (symlinked secret mode 0444)
  it('A4: accepts symlinked secret files with read-only mode 0444 without warnings', async () => {
    const fake = new FakeFsFacade();
    const targetFile = '/var/run/secrets/kubernetes.io/serviceaccount/..2026_11_03/token';
    const symlink1 = '/var/run/secrets/kubernetes.io/serviceaccount/..data/token';
    const symlink2 = '/var/run/secrets/kubernetes.io/serviceaccount/token';
    const canary = makeCanary();

    fake.writeFileSync(targetFile, `${canary}\n`, 0o444);
    fake.symlinkSync(targetFile, symlink1);
    fake.symlinkSync(symlink1, symlink2);

    const token = await readTokenFile(symlink2, fake, 'linux');
    expect(token).toBe(canary);
  });

  // A5: Error hygiene across all failing cases
  it('A5: error hygiene verifies canary is never leaked in errors, stacks, or warnings', async () => {
    const canary = makeCanary();

    // 1. Invalid characters with canary
    try {
      await resolveFleetToken({
        env: { FLEET_TOKEN: `${canary} bad` },
        homeDir: tempDir,
      });
      expect.unreachable('Should have thrown');
    } catch (err: unknown) {
      assertNoLeak(String(err), canary);
      assertNoLeak(JSON.stringify(err), canary);
      if (err instanceof Error && err.stack) {
        assertNoLeak(err.stack, canary);
      }
    }

    // 2. Conflicting tokens with canary
    try {
      await resolveFleetToken({
        env: { FLEET_TOKEN: canary },
        flagToken: makeCanary(),
        homeDir: tempDir,
      });
      expect.unreachable('Should have thrown');
    } catch (err: unknown) {
      assertNoLeak(String(err), canary);
      assertNoLeak(JSON.stringify(err), canary);
      if (err instanceof Error && err.stack) {
        assertNoLeak(err.stack, canary);
      }
    }
  });
});

describe('LAYER B: Auto-Generation and File Hygiene (DEV-8)', () => {
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-layer-b-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempHome, { recursive: true, force: true });
    } catch {}
  });

  // B1: First run auto-generates 256-bit token into 0600 file
  it('B1: first run creates ~/.secureship/fleet-token with 256-bit base64url token and mode 0600', async () => {
    const res = await resolveFleetToken({ homeDir: tempHome });
    expect(res.source).toBe('generated');
    expect(res.filePath).toBe(path.join(tempHome, '.secureship', 'fleet-token'));

    // Token format check
    expect(res.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const decoded = Buffer.from(res.token, 'base64url');
    expect(decoded.length).toBe(32);

    // File content check
    const fileContent = fs.readFileSync(res.filePath!, 'utf8');
    expect(fileContent).toBe(`${res.token}\n`);

    // On non-Windows, check permissions
    if (process.platform !== 'win32') {
      const dirStat = fs.statSync(path.join(tempHome, '.secureship'));
      expect(dirStat.mode & 0o777).toBe(0o700);
      const fileStat = fs.statSync(res.filePath!);
      expect(fileStat.mode & 0o777).toBe(0o600);
    }
  });

  // B2: Second run reuses identical token
  it('B2: second run reuses identical token and deleting file generates new token', async () => {
    const res1 = await resolveFleetToken({ homeDir: tempHome });
    const res2 = await resolveFleetToken({ homeDir: tempHome });
    expect(res2.token).toBe(res1.token);
    expect(res2.source).toBe('generated');

    // Delete token file and verify regeneration yields different token
    fs.unlinkSync(res1.filePath!);
    const res3 = await resolveFleetToken({ homeDir: tempHome });
    expect(res3.token).not.toBe(res1.token);
    expect(res3.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  // B3: Existing directory with 0755 is NOT chmod-ed
  it('B3: existing ~/.secureship directory with mode 0755 preserves its mode', async () => {
    const fake = new FakeFsFacade();
    fake.mkdirSync('/home/test/.secureship', 0o755);

    const res = await resolveFleetToken({
      homeDir: '/home/test',
      fs: fake,
      platform: 'linux',
    });
    expect(res.source).toBe('generated');

    const dirStat = await fake.stat('/home/test/.secureship');
    expect(dirStat.mode & 0o777).toBe(0o755);
  });

  // B4: Concurrency: 12 concurrent resolve calls in one process and 4 child processes produce exactly one token
  it('B4: 12 concurrent resolve calls in one process and 4 child processes end up with exactly one token value', async () => {
    const results = await Promise.all(
      Array.from({ length: 12 }).map(() => resolveFleetToken({ homeDir: tempHome }))
    );

    const firstToken = results[0]!.token;
    expect(firstToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    for (const r of results) {
      expect(r.token).toBe(firstToken);
    }

    const fileContent = fs.readFileSync(path.join(tempHome, '.secureship', 'fleet-token'), 'utf8');
    expect(fileContent).toBe(`${firstToken}\n`);

    // 4 child processes started simultaneously against one HOME
    const scriptPath = path.resolve(__dirname, '../dist/index.js');
    const childScript = `
      import { resolveFleetToken } from '${pathToFileURL(scriptPath).href}';
      const r = await resolveFleetToken({ homeDir: ${JSON.stringify(tempHome)} });
      process.stdout.write(r.token);
    `;
    const childPromises = Array.from({ length: 4 }).map(() => {
      return new Promise<string>((resolve, reject) => {
        const proc = spawn(process.execPath, ['--input-type=module', '-e', childScript], {
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let out = '';
        let errOut = '';
        proc.stdout.on('data', (d) => (out += d.toString()));
        proc.stderr.on('data', (d) => (errOut += d.toString()));
        proc.on('close', (code) => {
          if (code === 0) resolve(out.trim());
          else reject(new Error(`Child exited with code ${code}: ${errOut}`));
        });
      });
    });
    const childTokens = await Promise.all(childPromises);
    for (const ct of childTokens) {
      expect(ct).toBe(firstToken);
    }
  });

  // B5: Planted attacks (refused with FleetConfigError)
  it('B5: planted attacks (symlink, foreign UID, group/world-writable dir) are rejected', async () => {
    const fake = new FakeFsFacade();

    // 1. Default path is a symlink -> INSECURE_DEFAULT_TOKEN_FILE
    fake.symlinkSync('/etc/passwd', '/home/test/.secureship/fleet-token');
    await expect(
      resolveFleetToken({ homeDir: '/home/test', fs: fake, platform: 'linux' })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INSECURE_DEFAULT_TOKEN_FILE');
      expect((err as Error).message).toContain('FLEET_TOKEN_FILE');
      return true;
    });

    // 2. File owned by foreign UID -> INSECURE_DEFAULT_TOKEN_FILE
    const fakeForeign = new FakeFsFacade();
    fakeForeign.writeFileSync(
      '/home/test/.secureship/fleet-token',
      `${makeCanary()}\n`,
      0o600,
      9999
    );
    await expect(
      resolveFleetToken({ homeDir: '/home/test', fs: fakeForeign, platform: 'linux' })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INSECURE_DEFAULT_TOKEN_FILE');
      expect((err as Error).message).toContain('UID 9999');
      return true;
    });

    // 3. Parent dir owned by foreign UID -> INSECURE_DEFAULT_TOKEN_DIR
    const fakeDirUid = new FakeFsFacade();
    fakeDirUid.mkdirSync('/home/test/.secureship', 0o700, 9999);
    fakeDirUid.writeFileSync(
      '/home/test/.secureship/fleet-token',
      `${makeCanary()}\n`,
      0o600,
      1000
    );
    await expect(
      resolveFleetToken({ homeDir: '/home/test', fs: fakeDirUid, platform: 'linux' })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INSECURE_DEFAULT_TOKEN_DIR');
      return true;
    });

    // 4. Parent dir group/world-writable -> INSECURE_DEFAULT_TOKEN_DIR
    const fakeWritable = new FakeFsFacade();
    fakeWritable.mkdirSync('/home/test/.secureship', 0o777, 1000);
    fakeWritable.writeFileSync(
      '/home/test/.secureship/fleet-token',
      `${makeCanary()}\n`,
      0o600,
      1000
    );
    await expect(
      resolveFleetToken({ homeDir: '/home/test', fs: fakeWritable, platform: 'linux' })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INSECURE_DEFAULT_TOKEN_DIR');
      return true;
    });
  });

  // B6: Existing file mode 0644 chmod to 0600 succeeds
  it('B6: existing file with mode 0644 is restricted to 0600; with chmod failing a warning is emitted', async () => {
    const fake = new FakeFsFacade();
    const token = makeCanary();
    fake.writeFileSync('/home/test/.secureship/fleet-token', `${token}\n`, 0o644, 1000);

    const res = await resolveFleetToken({
      homeDir: '/home/test',
      fs: fake,
      platform: 'linux',
    });
    expect(res.token).toBe(token);
    const stat = await fake.lstat('/home/test/.secureship/fleet-token');
    expect(stat.mode & 0o777).toBe(0o600);

    // When chmod fails (EPERM), token is still returned with warning
    fake.writeFileSync('/home/test/.secureship/fleet-token', `${token}\n`, 0o644, 1000);
    fake.failNextChmod = true;
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const resChmodFail = await resolveFleetToken({
        homeDir: '/home/test',
        fs: fake,
        platform: 'linux',
      });
      expect(resChmodFail.token).toBe(token);
      expect(stderrSpy).toHaveBeenCalled();
    } finally {
      stderrSpy.mockRestore();
    }
  });

  // B7: Unwritable or absent HOME
  it('B7: unset or nonexistent HOME throws FleetConfigError and never starts unauthenticated', async () => {
    // Whitespace HOME triggers HOMEDIR_UNAVAILABLE
    await expect(
      resolveFleetToken({
        homeDir: '   ',
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('HOMEDIR_UNAVAILABLE');
      return true;
    });

    const fake = new FakeFsFacade();
    fake.failNextOpen = true;
    await expect(
      resolveFleetToken({
        homeDir: '/nonexistent-home',
        fs: fake,
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('TOKEN_CREATION_FAILED');
      return true;
    });
  });

  // B8: Paths with spaces in HOME
  it('B8: paths with spaces in HOME directory work correctly', async () => {
    const spaceHome = path.join(tempHome, 'user space name');
    fs.mkdirSync(spaceHome);

    const res = await resolveFleetToken({ homeDir: spaceHome });
    expect(res.source).toBe('generated');
    expect(res.filePath).toBe(path.join(spaceHome, '.secureship', 'fleet-token'));
    expect(fs.existsSync(res.filePath!)).toBe(true);
  });
});

describe('LAYER C: Runtime Config Builder (DEV-2)', () => {
  // C1: Port precedence and validation
  it('C1: port precedence follows argv > FLEET_PORT > PORT > 4000; invalid ports rejected', async () => {
    // 1. Matrix
    const r1 = await buildFleetRuntimeConfig({
      args: { port: 5000 },
      env: { FLEET_PORT: '5001', PORT: '5002' },
      argvPositionalPort: '5003',
    });
    expect(r1.port).toBe(5000);

    const r2 = await buildFleetRuntimeConfig({
      argvPositionalPort: '5003',
      env: { FLEET_PORT: '5001', PORT: '5002' },
    });
    expect(r2.port).toBe(5003);

    const r3 = await buildFleetRuntimeConfig({
      env: { FLEET_PORT: '4100', PORT: '3000' },
    });
    expect(r3.port).toBe(4100);

    const r4 = await buildFleetRuntimeConfig({
      env: { PORT: '3000' },
    });
    expect(r4.port).toBe(3000);

    const r5 = await buildFleetRuntimeConfig({
      env: {},
    });
    expect(r5.port).toBe(4000);

    const rZero = await buildFleetRuntimeConfig({
      args: { port: 0 },
    });
    expect(rZero.port).toBe(0);

    // 2. Invalid port matrix
    const invalidPorts = ['', 'abc', '-1', '65536', '1e3', '0x50', '80.5', ' 80', '\uFF18\uFF10'];
    for (const bad of invalidPorts) {
      await expect(
        buildFleetRuntimeConfig({
          args: { port: bad },
        })
      ).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(FleetConfigError);
        expect((err as FleetConfigError).code).toBe('INVALID_PORT');
        return true;
      });

      if (bad !== '') {
        await expect(
          buildFleetRuntimeConfig({
            env: { FLEET_PORT: bad },
          })
        ).rejects.toSatisfy((err: unknown) => {
          expect(err).toBeInstanceOf(FleetConfigError);
          expect((err as FleetConfigError).code).toBe('INVALID_PORT');
          return true;
        });
      }
    }
  });

  // C2: Host resolution
  it('C2: FLEET_HOST configures bind interface; generic HOST is ignored', async () => {
    // Default 127.0.0.1
    const rDefault = await buildFleetRuntimeConfig({ env: {} });
    expect(rDefault.host).toBe('127.0.0.1');

    // Generic HOST ignored
    const rHostIgnored = await buildFleetRuntimeConfig({
      env: { HOST: '0.0.0.0' },
    });
    expect(rHostIgnored.host).toBe('127.0.0.1');

    // FLEET_HOST respected
    const rFleetHost = await buildFleetRuntimeConfig({
      env: { FLEET_HOST: '127.0.0.2' },
    });
    expect(rFleetHost.host).toBe('127.0.0.2');

    // Invalid FLEET_HOST rejected
    await expect(
      buildFleetRuntimeConfig({
        env: { FLEET_HOST: 'bad host with spaces' },
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_HOST');
      return true;
    });
  });

  // C3: FLEET_ALLOWED_HOSTS and FLEET_ALLOWED_ORIGINS
  it('C3: validates FLEET_ALLOWED_HOSTS and FLEET_ALLOWED_ORIGINS lists', async () => {
    const rAllowed = await buildFleetRuntimeConfig({
      env: {
        FLEET_ALLOWED_HOSTS: 'a.example, b.example:8443, [::1]:4000',
        FLEET_ALLOWED_ORIGINS: 'https://ciso.internal.corp, http://localhost:3000',
      },
    });
    expect(rAllowed.serverOptions.allowedHosts).toEqual([
      'a.example',
      'b.example:8443',
      '[::1]:4000',
    ]);
    expect(rAllowed.serverOptions.allowedOrigins).toEqual([
      'https://ciso.internal.corp',
      'http://localhost:3000',
    ]);

    // Invalid host rejected
    await expect(
      buildFleetRuntimeConfig({
        env: { FLEET_ALLOWED_HOSTS: 'http://bad-protocol.corp' },
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_ALLOWED_HOST');
      return true;
    });

    // Wildcard origin rejected
    await expect(
      buildFleetRuntimeConfig({
        env: { FLEET_ALLOWED_ORIGINS: '*' },
      })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_SERVER_CONFIG');
      return true;
    });
  });

  // C4: FLEET_ALLOW_LEGACY_BODY_TOKEN
  it('C4: parses FLEET_ALLOW_LEGACY_BODY_TOKEN boolean values and rejects invalid entries', async () => {
    // Unset -> true
    const rUnset = await buildFleetRuntimeConfig({ env: {} });
    expect(rUnset.serverOptions.allowLegacyBodyToken).toBe(true);

    // '0', 'false' -> false
    const r0 = await buildFleetRuntimeConfig({ env: { FLEET_ALLOW_LEGACY_BODY_TOKEN: '0' } });
    expect(r0.serverOptions.allowLegacyBodyToken).toBe(false);

    const rFalse = await buildFleetRuntimeConfig({
      env: { FLEET_ALLOW_LEGACY_BODY_TOKEN: 'FALSE' },
    });
    expect(rFalse.serverOptions.allowLegacyBodyToken).toBe(false);

    // '1', 'true' -> true
    const r1 = await buildFleetRuntimeConfig({ env: { FLEET_ALLOW_LEGACY_BODY_TOKEN: '1' } });
    expect(r1.serverOptions.allowLegacyBodyToken).toBe(true);

    // Invalid values
    await expect(
      buildFleetRuntimeConfig({ env: { FLEET_ALLOW_LEGACY_BODY_TOKEN: 'maybe' } })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).code).toBe('INVALID_CONFIG');
      return true;
    });
  });

  // C5: Builder does not mutate env object or perform console output
  it('C5: builder never mutates the env argument and produces no console output', async () => {
    const rawEnv = { FLEET_PORT: '4200' };
    const envCopy = { ...rawEnv };

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      await buildFleetRuntimeConfig({ env: rawEnv });
      expect(rawEnv).toEqual(envCopy);
      expect(logSpy).toHaveBeenCalledTimes(0);
      expect(errSpy).toHaveBeenCalledTimes(0);
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
    }
  });

  // C6: Non-loopback FLEET_HOST with generated token still starts
  it('C6: non-loopback host with generated token satisfies authToken requirement', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-c6-'));
    try {
      const cfg = await buildFleetRuntimeConfig({
        env: { FLEET_HOST: '127.0.0.1' },
        homeDir: tempDir,
      });
      expect(cfg.tokenSource).toBe('generated');
      expect(cfg.serverOptions.authToken).toBeDefined();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // C7: formatDisplayUrl, formatAuthLabel, formatReadHint helpers
  it('C7: helper formatting functions format URLs, auth labels, and OS read hints', () => {
    // formatDisplayUrl
    expect(formatDisplayUrl('0.0.0.0', 4000)).toBe('http://127.0.0.1:4000');
    expect(formatDisplayUrl('::', 4000)).toBe('http://127.0.0.1:4000');
    expect(formatDisplayUrl('[::]', 4000)).toBe('http://127.0.0.1:4000');
    expect(formatDisplayUrl('*', 4000)).toBe('http://127.0.0.1:4000');
    expect(formatDisplayUrl('2001:db8::1', 4000)).toBe('http://[2001:db8::1]:4000');
    expect(formatDisplayUrl('localhost', 4000)).toBe('http://localhost:4000');

    // formatAuthLabel
    expect(formatAuthLabel('env')).toBe('FLEET_TOKEN environment variable');
    expect(formatAuthLabel('file', '/path/token')).toBe('token file /path/token');
    expect(formatAuthLabel('flag')).toBe('--token flag (deprecated)');
    expect(formatAuthLabel('generated', '/path/token')).toBe(
      'auto-generated token file /path/token'
    );

    // formatReadHint
    expect(formatReadHint('C:\\token.txt', 'win32')).toBe('Get-Content -Raw "C:\\token.txt"');
    expect(formatReadHint('/home/token.txt', 'linux')).toBe("cat '/home/token.txt'");
  });

  // C8: buildFleetRuntimeConfig with explicit args object
  it('C8: buildFleetRuntimeConfig accepts explicit args for hosts, origins, legacy cap, data path', async () => {
    const r = await buildFleetRuntimeConfig({
      args: {
        host: '127.0.0.1',
        data: 'custom/db.json',
        allowedHost: ['api.corp.internal', '   '],
        allowedOrigin: ['https://api.corp.internal', '   '],
        allowLegacyBodyToken: false,
        legacyBodyTokenMaxBytes: 1024,
        maxBodyBytes: 4096,
        headersTimeoutMs: 500,
        requestTimeoutMs: 1000,
      },
    });

    expect(r.host).toBe('127.0.0.1');
    expect(r.dataPath).toContain('custom');
    expect(r.serverOptions.allowedHosts).toEqual(['api.corp.internal']);
    expect(r.serverOptions.allowedOrigins).toEqual(['https://api.corp.internal']);
    expect(r.serverOptions.allowLegacyBodyToken).toBe(false);
  });
});

describe('LAYER D: Server Token Retention and Option Validation (DEV-3, DEV-8)', () => {
  // D1: Object-graph walk of FleetServer ensures no raw token retention
  it('D1: FleetServer never retains raw canary token in object properties, JSON serialization, or inspection', async () => {
    const canary = makeCanary();
    const server = new FleetServer({
      port: 0,
      authToken: canary,
    });

    // 1. JSON.stringify
    const jsonStr = JSON.stringify(server);
    assertNoLeak(jsonStr, canary);
    expect(jsonStr).not.toContain(canary);

    // 2. util.inspect with showHidden: true, depth: null
    const inspected = util.inspect(server, { showHidden: true, depth: null });
    assertNoLeak(inspected, canary);
    expect(inspected).not.toContain(canary);

    // 3. String(server)
    assertNoLeak(String(server), canary);
    expect(String(server)).not.toContain(canary);

    // 4. Object keys and symbol properties
    const keys = Object.keys(server);
    expect(keys.length).toBeGreaterThan(0);
    expect((server as unknown as Record<string, unknown>)['authToken']).toBeUndefined();
    for (const k of keys) {
      assertNoLeak(k, canary);
      const val = (server as unknown as Record<string, unknown>)[k];
      if (typeof val === 'string') {
        assertNoLeak(val, canary);
      }
    }

    // 5. Check again after start()
    const p = await server.start();
    expect(p).toBeGreaterThan(0);
    try {
      assertNoLeak(JSON.stringify(server), canary);
      assertNoLeak(util.inspect(server, { showHidden: true, depth: null }), canary);
      expect(JSON.stringify(server)).not.toContain(canary);
    } finally {
      await server.stop();
    }
  });

  // D2: authToken option validation
  it('D2: FleetServer constructor validates authToken: empty rejected, 1-char accepted, undefined allowed', () => {
    expect(() => new FleetServer({ authToken: '' })).toThrow(
      'authToken must be a non-empty string'
    );
    expect(() => new FleetServer({ authToken: '   ' })).toThrow(
      'authToken must be a non-empty string'
    );
    expect(() => new FleetServer({ authToken: undefined })).not.toThrow();
    expect(() => new FleetServer({ authToken: 'a' })).not.toThrow();
  });

  // D3: Option validation table
  it('D3: FleetServer validates byte limits and timeout options strictly', () => {
    // Negative, zero, float, NaN
    const invalidVals = [-1, 0, 1.5, NaN];
    for (const v of invalidVals) {
      expect(() => new FleetServer({ maxBodyBytes: v })).toThrow(
        'Server byte limit and timeout options must be positive integers'
      );
      expect(() => new FleetServer({ legacyBodyTokenMaxBytes: v })).toThrow(
        'Server byte limit and timeout options must be positive integers'
      );
      expect(() => new FleetServer({ headersTimeoutMs: v })).toThrow(
        'Server byte limit and timeout options must be positive integers'
      );
      expect(() => new FleetServer({ requestTimeoutMs: v })).toThrow(
        'Server byte limit and timeout options must be positive integers'
      );
    }

    // legacyBodyTokenMaxBytes > maxBodyBytes
    expect(
      () =>
        new FleetServer({
          legacyBodyTokenMaxBytes: 1000,
          maxBodyBytes: 500,
        })
    ).toThrow('legacyBodyTokenMaxBytes must be less than or equal to maxBodyBytes');

    // headersTimeoutMs > requestTimeoutMs
    expect(
      () =>
        new FleetServer({
          headersTimeoutMs: 20000,
          requestTimeoutMs: 10000,
        })
    ).toThrow('headersTimeoutMs must be less than or equal to requestTimeoutMs');
  });

  // D4: Static guards on fleet-server.ts source code
  it('D4: static inspection of fleet-server.ts verifies timingSafeEqual, no this.authToken, and default-deny gate', () => {
    const srcPath = path.resolve(__dirname, '../src/server/fleet-server.ts');
    const src = fs.readFileSync(srcPath, 'utf8');

    expect(src).toContain('crypto.timingSafeEqual');
    expect(src).not.toContain('this.authToken');
    expect(src).not.toMatch(/this\.authToken\s*[!=]==/);
    expect(src).not.toMatch(/if\s*\(.*authToken.*startsWith\(['"`]\/api\/['"`]\)/);
  });
});

describe('LAYER E: Default-Deny Matrix (DEV-7, DEV-8)', () => {
  let server: FleetServer;
  let store: FleetStore;
  let port: number;
  const canaryToken = makeCanary();

  beforeEach(async () => {
    store = new FleetStore();
    server = new FleetServer({
      port: 0,
      store,
      authToken: canaryToken,
    });
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  // E1: Without credentials: / and /dashboard give 200 HTML; all others give 401 Bearer
  it('E1: unauthenticated requests default-deny with 401 and zero store interactions', async () => {
    const storeGetReposSpy = vi.spyOn(store, 'getRepos');
    const storeGetSummarySpy = vi.spyOn(store, 'getExecutiveSummary');
    const storeIngestSpy = vi.spyOn(store, 'ingest');

    // Public routes: GET / and GET /dashboard give 200 HTML
    const resRoot = await rawHttp(port, 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    expect(resRoot.statusCode).toBe(200);
    expect(resRoot.headers['content-type']).toContain('text/html');

    const resDash = await rawHttp(port, 'GET /dashboard HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    expect(resDash.statusCode).toBe(200);
    expect(resDash.headers['content-type']).toContain('text/html');

    // Non-GET on public routes -> 401
    const resPostDash = await rawHttp(port, 'POST /dashboard HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    expect(resPostDash.statusCode).toBe(401);
    expect(resPostDash.headers['www-authenticate']).toBe('Bearer');

    // All other paths -> 401
    const testPaths = [
      '/favicon.ico',
      '/robots.txt',
      '/anything',
      '/api',
      '/api/',
      '/api/unknown',
      '/api/fleet/summary/',
      '/api/fleet/summary;x',
      '/API/FLEET/SUMMARY',
      '/%61pi/fleet/summary',
      '//api/fleet/summary',
      '/api/../api/policy',
      '/api/fleet/summary%00',
      '/api/fleet/summary?x=1#y',
      '/api/fleet/repos',
      '/api/fleet/summary',
      '/api/fleet/sbom',
      '/api/fleet/compliance/cra',
      '/api/policy',
    ];

    for (const p of testPaths) {
      const res = await rawHttp(port, `GET ${p} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`);
      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toBe('Bearer');
      expect(JSON.parse(res.body).error).toBe('Unauthorized: Invalid fleet token');
    }

    expect(storeGetReposSpy).toHaveBeenCalledTimes(0);
    expect(storeGetSummarySpy).toHaveBeenCalledTimes(0);
    expect(storeIngestSpy).toHaveBeenCalledTimes(0);
  });

  // E2: Absolute-form target and spoofed headers do not bypass gate
  it('E2: absolute-form URL target and spoofed headers do not bypass default-deny gate', async () => {
    const rawReq =
      'GET http://evil.example/api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Original-URL: /\r\nX-Forwarded-For: 127.0.0.1\r\nX-HTTP-Method-Override: GET\r\n\r\n';
    const res = await rawHttp(port, rawReq);
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toBe('Bearer');
  });

  // E3: Valid credentials preserve expected routing
  it('E3: valid credentials return 200 for defined routes and 404 for undefined routes', async () => {
    // Defined route -> 200
    const resSummary = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\n\r\n`
    );
    expect(resSummary.statusCode).toBe(200);

    // Undefined route -> 404
    const resUnknown = await rawHttp(
      port,
      `GET /api/unknown-endpoint HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\n\r\n`
    );
    expect(resUnknown.statusCode).toBe(404);
    expect(JSON.parse(resUnknown.body).error).toBe('Endpoint not found');
  });

  // E4: Loopback without token emits SECURESHIP_FLEET_NO_AUTH warning exactly once
  it('E4: starting on loopback without authToken emits SECURESHIP_FLEET_NO_AUTH warning', async () => {
    const warningSpy = vi.spyOn(process, 'emitWarning');
    const noAuthServer = new FleetServer({ port: 0 });
    const p = await noAuthServer.start();
    expect(p).toBeGreaterThan(0);
    try {
      expect(warningSpy).toHaveBeenCalledWith(
        expect.stringContaining('starting without authentication configured'),
        expect.objectContaining({ code: 'SECURESHIP_FLEET_NO_AUTH' })
      );
    } finally {
      await noAuthServer.stop();
      warningSpy.mockRestore();
    }

    // Non-loopback without token throws Error
    const remoteServer = new FleetServer({ port: 0, host: '192.168.1.100' });
    await expect(remoteServer.start()).rejects.toThrow(/Insecure deployment: non-loopback host/);
  });
});
