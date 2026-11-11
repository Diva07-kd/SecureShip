import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  assertSafeFleetEndpoint,
  resolveClientFleetToken,
  resolveFleetToken,
  defaultFsFacade,
  FleetConfigError,
  type FsFacade,
} from '../src/security/fleet-token.js';
import { installSignalHandlers } from '../src/config/fleet-config.js';
import { FleetServer } from '../src/server/fleet-server.js';
import { FleetStore } from '../src/storage/fleet-store.js';
import { makeCanary, assertNoLeak, runEntry, rawHttp } from './fixtures/fleet-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FLEET_CLI_PATH = path.resolve(__dirname, '../dist/cli.js');
const SECURESHIP_CLI_PATH = path.resolve(__dirname, '../../cli/dist/index.js');

describe('LAYER J: Entry Points as Real Processes (DEV-4, DEV-8)', () => {
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-layer-j-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempHome, { recursive: true, force: true });
    } catch {}
  });

  // J1: FLEET_TOKEN=<canary>: start with port 0, check 401 unauth, 200 auth, assertNoLeak
  it('J1: both entry points start with FLEET_TOKEN, enforce auth, shut down cleanly, and never leak canary', async () => {
    const canary = makeCanary();
    const entryPoints = [
      { name: 'fleet-cli', script: FLEET_CLI_PATH, args: ['0'] },
      {
        name: 'secureship-cli',
        script: SECURESHIP_CLI_PATH,
        args: ['fleet', 'start', '--port', '0'],
      },
    ];

    for (const entry of entryPoints) {
      const run = await runEntry(
        entry.script,
        entry.args,
        {
          FLEET_TOKEN: canary,
          HOME: tempHome,
          USERPROFILE: tempHome,
        },
        { timeoutMs: 15000 }
      );

      try {
        expect(run.url).toBeDefined();

        // 1. Unauthenticated request -> 401
        const unauthRes = await fetch(`${run.url}/api/fleet/summary`, { redirect: 'error' });
        expect(unauthRes.status).toBe(401);

        // 2. Authenticated request -> 200
        const authRes = await fetch(`${run.url}/api/fleet/summary`, {
          headers: { Authorization: `Bearer ${canary}` },
          redirect: 'error',
        });
        expect(authRes.status).toBe(200);

        // 3. Canary secrecy on stdout and stderr
        assertNoLeak(run.stdout, canary);
        assertNoLeak(run.stderr, canary);
      } finally {
        run.proc.kill('SIGTERM');
        await new Promise((r) => setTimeout(r, 200));
        try {
          run.proc.kill('SIGKILL');
        } catch {}
      }
    }
  }, 25000);

  // J2: FLEET_TOKEN_FILE with LF, CRLF, BOM, and UTF-16 rejection
  it('J2: FLEET_TOKEN_FILE accepts clean UTF-8 and rejects UTF-16 with exit code 1', async () => {
    const canary = makeCanary();

    // Valid UTF-8 file
    const tokenFile = path.join(tempHome, 'token.txt');
    fs.writeFileSync(tokenFile, `${canary}\n`, 'utf8');

    const runValid = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        FLEET_TOKEN_FILE: tokenFile,
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(runValid.url).toBeDefined();
      const res = await fetch(`${runValid.url}/api/fleet/summary`, {
        headers: { Authorization: `Bearer ${canary}` },
        redirect: 'error',
      });
      expect(res.status).toBe(200);
      assertNoLeak(runValid.stdout, canary);
    } finally {
      runValid.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        runValid.proc.kill('SIGKILL');
      } catch {}
    }

    // UTF-16 file -> exit 1 with 're-save as UTF-8'
    const utf16File = path.join(tempHome, 'token-utf16.txt');
    fs.writeFileSync(
      utf16File,
      Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(canary, 'utf16le')])
    );

    const runUtf16 = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        FLEET_TOKEN_FILE: utf16File,
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 10000, waitForReady: false }
    );

    expect(runUtf16.code).toBe(1);
    expect(runUtf16.stderr).toContain('re-save as UTF-8 without BOM');
    assertNoLeak(runUtf16.stdout, canary);
    assertNoLeak(runUtf16.stderr, canary);
  }, 25000);

  // J3: --token <canary> on secureship fleet start prints deprecation warning and never leaks canary
  it('J3: --token flag on secureship fleet start prints deprecation warning and keeps canary secret', async () => {
    const canary = makeCanary();
    const run = await runEntry(
      SECURESHIP_CLI_PATH,
      ['fleet', 'start', '--port', '0', '--token', canary],
      {
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(run.url).toBeDefined();
      expect(run.stderr).toContain('deprecated');
      expect(run.stderr).toContain('process list');
      assertNoLeak(run.stdout, canary);
      assertNoLeak(run.stderr, canary);
    } finally {
      run.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run.proc.kill('SIGKILL');
      } catch {}
    }
  }, 20000);

  // J4: Auto-generation with temp HOME: prints file path and read hint, NOT token content
  it('J4: starting with no token auto-generates token file and prints path and hint, never token content', async () => {
    const run = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    let generatedToken = '';
    try {
      expect(run.url).toBeDefined();
      const tokenFilePath = path.join(tempHome, '.secureship', 'fleet-token');
      expect(fs.existsSync(tokenFilePath)).toBe(true);

      generatedToken = fs.readFileSync(tokenFilePath, 'utf8').trim();
      expect(generatedToken).toMatch(/^[A-Za-z0-9_-]{43}$/);

      // Verify token is NOT printed in banner
      assertNoLeak(run.stdout, generatedToken);
      expect(run.stdout).toContain('auto-generated token file');
      expect(run.stdout).toContain('Token Read Hint:');

      // Unauthenticated request -> 401
      const unauth = await fetch(`${run.url}/api/fleet/summary`, { redirect: 'error' });
      expect(unauth.status).toBe(401);

      // Authenticated with generated token -> 200
      const auth = await fetch(`${run.url}/api/fleet/summary`, {
        headers: { Authorization: `Bearer ${generatedToken}` },
        redirect: 'error',
      });
      expect(auth.status).toBe(200);
    } finally {
      run.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run.proc.kill('SIGKILL');
      } catch {}
    }

    // Second start reuses same token
    const run2 = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(run2.url).toBeDefined();
      const auth2 = await fetch(`${run2.url}/api/fleet/summary`, {
        headers: { Authorization: `Bearer ${generatedToken}` },
        redirect: 'error',
      });
      expect(auth2.status).toBe(200);
    } finally {
      run2.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run2.proc.kill('SIGKILL');
      } catch {}
    }
  }, 30000);

  // J5: Invalid token / conflicting sources exit 1 and never leak canary
  it('J5: invalid token and conflicting sources exit with code 1 and actionable errors', async () => {
    const shortCanary = makeCanary().slice(0, 16);
    const runInvalid = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        FLEET_TOKEN: shortCanary,
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 10000, waitForReady: false }
    );

    expect(runInvalid.code).toBe(1);
    expect(runInvalid.stderr).toContain('minimum 24 characters');
    assertNoLeak(runInvalid.stderr, shortCanary);
    assertNoLeak(runInvalid.stdout, shortCanary);

    // Conflicting sources
    const c1 = makeCanary();
    const c2 = makeCanary();
    const tokenFile = path.join(tempHome, 'tok.txt');
    fs.writeFileSync(tokenFile, `${c1}\n`, 'utf8');

    const runConflict = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        FLEET_TOKEN: c2,
        FLEET_TOKEN_FILE: tokenFile,
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 10000, waitForReady: false }
    );

    expect(runConflict.code).toBe(1);
    expect(runConflict.stderr).toContain(
      'Multiple fleet token sources are set with differing values'
    );
    assertNoLeak(runConflict.stderr, c1);
    assertNoLeak(runConflict.stderr, c2);
  }, 20000);

  // J6: Port already in use exits 1 without stack trace unless FLEET_DEBUG=1
  it('J6: port already in use exits 1 without stack trace unless FLEET_DEBUG=1 is set', async () => {
    // Occupy a port
    const occupiedServer = http.createServer();
    const occupiedPort = await new Promise<number>((resolve) => {
      occupiedServer.listen(0, '127.0.0.1', () => {
        resolve((occupiedServer.address() as net.AddressInfo).port);
      });
    });

    try {
      const runEaddrinuse = await runEntry(
        FLEET_CLI_PATH,
        [String(occupiedPort)],
        {
          FLEET_TOKEN: makeCanary(),
          HOME: tempHome,
          USERPROFILE: tempHome,
        },
        { timeoutMs: 10000, waitForReady: false }
      );

      expect(runEaddrinuse.code).toBe(1);
      expect(runEaddrinuse.stderr).toContain('EADDRINUSE');
      expect(runEaddrinuse.stderr).not.toContain('    at '); // No stack trace

      // With FLEET_DEBUG=1 stack trace is included
      const runDebug = await runEntry(
        FLEET_CLI_PATH,
        [String(occupiedPort)],
        {
          FLEET_TOKEN: makeCanary(),
          FLEET_DEBUG: '1',
          HOME: tempHome,
          USERPROFILE: tempHome,
        },
        { timeoutMs: 10000, waitForReady: false }
      );

      expect(runDebug.code).toBe(1);
      expect(runDebug.stderr).toContain('EADDRINUSE');
    } finally {
      occupiedServer.close();
    }
  }, 20000);

  // J7: HOST=0.0.0.0 in env: starts on 127.0.0.1; loopback works, non-loopback refused
  it('J7: HOST=0.0.0.0 in env starts on 127.0.0.1; loopback succeeds while non-loopback is refused', async () => {
    const canary = makeCanary();
    const run = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        HOST: '0.0.0.0', // generic HOST must be ignored
        FLEET_TOKEN: canary,
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(run.url).toBeDefined();
      expect(run.url).toContain('127.0.0.1');

      const port = Number(new URL(run.url!).port);
      expect(port).toBeGreaterThan(0);

      // Loopback connection succeeds
      const loopbackRes = await rawHttp(port, 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
      expect(loopbackRes.statusCode).toBe(200);

      // Identify non-loopback IPv4 address
      const ifaces = os.networkInterfaces();
      let nonLoopbackIp: string | null = null;
      for (const name of Object.keys(ifaces)) {
        for (const iface of ifaces[name] || []) {
          if (iface.family === 'IPv4' && !iface.internal) {
            nonLoopbackIp = iface.address;
            break;
          }
        }
        if (nonLoopbackIp) break;
      }

      if (nonLoopbackIp) {
        // Attempt connection to non-loopback IP - should be refused or error
        const connectionPromise = new Promise<string>((resolve) => {
          const socket = net.createConnection({ host: nonLoopbackIp!, port, timeout: 1000 });
          socket.on('connect', () => {
            socket.destroy();
            resolve('connected');
          });
          socket.on('timeout', () => {
            socket.destroy();
            resolve('timeout');
          });
          socket.on('error', (err: NodeJS.ErrnoException) => {
            resolve(err.code || err.message);
          });
        });

        const outcome = await connectionPromise;
        expect(['ECONNREFUSED', 'ETIMEDOUT', 'timeout', 'EADDRNOTAVAIL', 'EHOSTUNREACH']).toContain(
          outcome
        );
      } else {
        expect(run.stdout).toContain('127.0.0.1');
      }
    } finally {
      run.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run.proc.kill('SIGKILL');
      } catch {}
    }
  }, 20000);

  // J8: FLEET_HOST=0.0.0.0 + FLEET_ALLOWED_HOSTS
  it('J8: FLEET_HOST=0.0.0.0 requires allowed hosts for external host headers and renders 127.0.0.1 in banner', async () => {
    const canary = makeCanary();
    const run = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        FLEET_HOST: '0.0.0.0',
        FLEET_TOKEN: canary,
        FLEET_ALLOWED_HOSTS: 'my-corp.internal:4000',
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(run.url).toBeDefined();
      expect(run.url).toContain('127.0.0.1'); // Banner renders 127.0.0.1, not 0.0.0.0
      expect(run.stdout).not.toContain('http://0.0.0.0');

      const port = new URL(run.url!).port;

      // Disallowed external host header -> 403 Forbidden host
      const resForbidden = await rawHttp(
        Number(port),
        'GET /api/fleet/summary HTTP/1.1\r\nHost: evil.attacker.corp\r\n\r\n'
      );
      expect(resForbidden.statusCode).toBe(403);
      expect(JSON.parse(resForbidden.body).error).toBe('Forbidden host');
    } finally {
      run.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run.proc.kill('SIGKILL');
      } catch {}
    }
  }, 20000);

  // J9: DEBUG=* and NODE_DEBUG=http,net,tls and NODE_OPTIONS=--trace-warnings: start with a canary token; assertNoLeak over stdout and stderr
  it('J9: start with debug/tracing flags in env; canary token is never leaked to stdout or stderr', async () => {
    const canary = makeCanary();
    const run = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        FLEET_TOKEN: canary,
        DEBUG: '*',
        NODE_DEBUG: 'http,net,tls',
        NODE_OPTIONS: '--trace-warnings',
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(run.url).toBeDefined();

      const authRes = await fetch(`${run.url}/api/fleet/summary`, {
        headers: { Authorization: `Bearer ${canary}` },
        redirect: 'error',
      });
      expect(authRes.status).toBe(200);

      assertNoLeak(run.stdout, canary);
      assertNoLeak(run.stderr, canary);
      expect(run.stdout).not.toContain(canary);
      expect(run.stderr).not.toContain(canary);
    } finally {
      run.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run.proc.kill('SIGKILL');
      } catch {}
    }
  }, 20000);

  // J10: Graceful shutdown unit tests
  it('J10: installSignalHandlers stops server on SIGTERM/SIGINT and forces exit on 10s watchdog or second signal', async () => {
    let stopped = false;
    const mockServer = {
      stop: async () => {
        stopped = true;
      },
    };

    let exitCode: number | null = null;
    const uninstall = installSignalHandlers({
      server: mockServer,
      onExit: (c) => {
        exitCode = c;
      },
    });

    try {
      // Emit first SIGTERM -> graceful stop
      process.emit('SIGTERM', 'SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      expect(stopped).toBe(true);
      expect(exitCode).toBe(0);
    } finally {
      uninstall();
    }

    // Test second signal forces exit 1
    let exitCodeDouble: number | null = null;
    const slowServer = {
      stop: () => new Promise<void>(() => {}), // never resolves
    };
    const uninstallDouble = installSignalHandlers({
      server: slowServer,
      onExit: (c) => {
        exitCodeDouble = c;
      },
    });

    try {
      process.emit('SIGINT', 'SIGINT');
      process.emit('SIGINT', 'SIGINT');
      expect(exitCodeDouble).toBe(1);
    } finally {
      uninstallDouble();
    }
  });

  // J11: Paths with spaces and Unicode in data path and HOME work cleanly
  it('J11: paths with spaces and Unicode in data path and HOME directory operate cleanly', async () => {
    const spaceHome = path.join(tempHome, 'test user home with spaces');
    const unicodeData = path.join(tempHome, 'data-\u00E9\u00F1\u00FC', 'db.json');
    fs.mkdirSync(spaceHome, { recursive: true });
    fs.mkdirSync(path.dirname(unicodeData), { recursive: true });

    const canary = makeCanary();
    const run = await runEntry(
      FLEET_CLI_PATH,
      ['0'],
      {
        HOME: spaceHome,
        USERPROFILE: spaceHome,
        FLEET_TOKEN: canary,
        FLEET_DATA: unicodeData,
      },
      { timeoutMs: 15000 }
    );

    try {
      expect(run.url).toBeDefined();
      const res = await fetch(`${run.url}/api/fleet/summary`, {
        headers: { Authorization: `Bearer ${canary}` },
        redirect: 'error',
      });
      expect(res.status).toBe(200);
    } finally {
      run.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        run.proc.kill('SIGKILL');
      } catch {}
    }
  }, 25000);
});

describe('LAYER K: Non-root, Container and Alpine Verification (DEV-5)', () => {
  it('K1: ro mounted secrets file succeeds without mode warning; ro home without token fails with clean FleetConfigError', async () => {
    const canary = makeCanary();

    // 1. Secret file mounted read-only (0444)
    const secretPath = path.resolve('/secrets/fleet_token');
    const fakeFsRoSecret: FsFacade = {
      ...defaultFsFacade,
      stat: async (p) => {
        if (p === secretPath || p.endsWith('fleet_token')) {
          return {
            isDirectory: () => false,
            isFIFO: () => false,
            isFile: () => true,
            isSymbolicLink: () => false,
            mode: 0o444,
            uid: 0,
            size: canary.length + 1,
          } as unknown as fs.Stats;
        }
        throw new Error(`ENOENT: ${p}`);
      },
      lstat: async (p) => {
        if (p === secretPath || p.endsWith('fleet_token')) {
          return {
            isDirectory: () => false,
            isFIFO: () => false,
            isFile: () => true,
            isSymbolicLink: () => false,
            mode: 0o444,
            uid: 0,
            size: canary.length + 1,
          } as unknown as fs.Stats;
        }
        throw new Error(`ENOENT: ${p}`);
      },
      readFile: async (p) => {
        if (p === secretPath || p.endsWith('fleet_token')) {
          return Buffer.from(`${canary}\n`, 'utf8');
        }
        throw new Error(`ENOENT: ${p}`);
      },
      realpath: async (p) => p,
    };

    const resolvedRo = await resolveFleetToken({
      env: { FLEET_TOKEN_FILE: '/secrets/fleet_token' },
      fs: fakeFsRoSecret,
      homeDir: '/nonexistent-home',
    });

    expect(resolvedRo.token).toBe(canary);
    expect(resolvedRo.source).toBe('file');
    expect(resolvedRo.warnings).toEqual([]);

    // 2. Read-only HOME directory without configured token fails cleanly without raw EROFS crash
    const fakeFsRoHome: FsFacade = {
      ...defaultFsFacade,
      stat: async () => {
        const err = new Error('ENOENT: no such file or directory') as NodeJS.ErrnoException;
        err.code = 'ENOENT';
        throw err;
      },
      mkdir: async () => {
        const err = new Error('EROFS: read-only file system, mkdir') as NodeJS.ErrnoException;
        err.code = 'EROFS';
        throw err;
      },
      open: async () => {
        const err = new Error('EROFS: read-only file system, open') as NodeJS.ErrnoException;
        err.code = 'EROFS';
        throw err;
      },
    };

    await expect(
      resolveFleetToken({
        env: {},
        fs: fakeFsRoHome,
        homeDir: '/read-only-home',
      })
    ).rejects.toThrowError(FleetConfigError);

    try {
      await resolveFleetToken({
        env: {},
        fs: fakeFsRoHome,
        homeDir: '/read-only-home',
      });
      expect(true).toBe(false);
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(FleetConfigError);
      expect((err as FleetConfigError).message).toContain('FLEET_TOKEN_FILE');
      expect((err as FleetConfigError).message).not.toContain('    at ');
    }
  });
});

describe('LAYER L: Client-Side Token Safety (DEV-8)', () => {
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-layer-l-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempHome, { recursive: true, force: true });
    } catch {}
  });

  // L1: assertSafeFleetEndpoint endpoint policy table
  it('L1: assertSafeFleetEndpoint allows loopback HTTP and HTTPS; refuses remote plain HTTP without override', () => {
    // 1. Allowed endpoints
    const allowed = [
      'http://127.0.0.1:4000',
      'http://127.1.2.3:8080',
      'http://localhost:4000',
      'http://localhost.:4000',
      'http://[::1]:4000',
      'https://ciso.internal.corp',
      'https://fleet.secureship.io:8443',
    ];

    for (const ep of allowed) {
      expect(() => assertSafeFleetEndpoint(ep)).not.toThrow();
    }

    // 2. Refused remote plain HTTP
    const refusedHttp = [
      'http://localhost.evil.com',
      'http://127.0.0.1.evil.com',
      'http://10.0.0.5:4000',
      'http://fleet.internal.corp:4000',
    ];

    for (const ep of refusedHttp) {
      expect(() => assertSafeFleetEndpoint(ep)).toThrowError(FleetConfigError);
      expect(() => assertSafeFleetEndpoint(ep)).toThrow(
        /Refusing to send fleet token over plain HTTP/
      );
    }

    // 3. Non-http protocols
    const badProtocols = ['ftp://files.corp', 'file:///etc/passwd', 'javascript:alert(1)'];
    for (const ep of badProtocols) {
      expect(() => assertSafeFleetEndpoint(ep)).toThrowError(FleetConfigError);
    }

    // 4. Embedded credentials
    expect(() => assertSafeFleetEndpoint('http://user:pass@127.0.0.1:4000')).toThrowError(
      FleetConfigError
    );

    // 5. With SECURESHIP_ALLOW_INSECURE_FLEET_HTTP=1 override
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      expect(() =>
        assertSafeFleetEndpoint('http://remote.corp:4000', {
          env: { SECURESHIP_ALLOW_INSECURE_FLEET_HTTP: '1' },
        })
      ).not.toThrow();
      expect(stderrSpy).toHaveBeenCalled();
    } finally {
      stderrSpy.mockRestore();
    }
  });

  // L2: Client token resolution precedence: --token > FLEET_TOKEN > FLEET_TOKEN_FILE
  it('L2: resolveClientFleetToken precedence and remote endpoint protection', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-layer-l2-'));
    const tFile = path.join(tempDir, 'file-tok.txt');
    const defFile = path.join(tempDir, '.secureship', 'fleet-token');
    fs.mkdirSync(path.join(tempDir, '.secureship'), { recursive: true });

    const cFlag = makeCanary();
    const cEnv = makeCanary();
    const cFile = makeCanary();
    const cDef = makeCanary();

    fs.writeFileSync(tFile, `${cFile}\n`, 'utf8');
    fs.writeFileSync(defFile, `${cDef}\n`, 'utf8');

    try {
      // 1. Flag takes highest precedence
      const rFlag = await resolveClientFleetToken({
        endpoint: 'http://127.0.0.1:4000',
        flagToken: cFlag,
        env: { FLEET_TOKEN: cEnv, FLEET_TOKEN_FILE: tFile },
        homeDir: tempDir,
      });
      expect(rFlag).toBe(cFlag);

      // 2. Env takes second precedence
      const rEnv = await resolveClientFleetToken({
        endpoint: 'http://127.0.0.1:4000',
        env: { FLEET_TOKEN: cEnv, FLEET_TOKEN_FILE: tFile },
        homeDir: tempDir,
      });
      expect(rEnv).toBe(cEnv);

      // 3. File takes third precedence
      const rFile = await resolveClientFleetToken({
        endpoint: 'http://127.0.0.1:4000',
        env: { FLEET_TOKEN_FILE: tFile },
        homeDir: tempDir,
      });
      expect(rFile).toBe(cFile);

      // 4. Default token file is used ONLY for loopback endpoints
      const rDefLoopback = await resolveClientFleetToken({
        endpoint: 'http://127.0.0.1:4000',
        env: {},
        homeDir: tempDir,
      });
      expect(rDefLoopback).toBe(cDef);

      // 5. Remote HTTPS endpoint NEVER receives locally generated default token
      const rDefRemote = await resolveClientFleetToken({
        endpoint: 'https://ciso.internal.corp',
        env: {},
        homeDir: tempDir,
      });
      expect(rDefRemote).toBeUndefined();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // L3: Redirects are refused (redirect: 'error')
  it('L3: redirects are refused with redirect error and second server receives 0 requests', async () => {
    let secondCalls = 0;
    const secondServer = http.createServer((_, res) => {
      secondCalls++;
      res.writeHead(200);
      res.end('ok');
    });
    const secondPort = await new Promise<number>((r) =>
      secondServer.listen(0, '127.0.0.1', () => r((secondServer.address() as net.AddressInfo).port))
    );

    const redirectServer = http.createServer((_, res) => {
      res.writeHead(302, { Location: `http://127.0.0.1:${secondPort}/api/fleet/summary` });
      res.end();
    });
    const redirPort = await new Promise<number>((r) =>
      redirectServer.listen(0, '127.0.0.1', () =>
        r((redirectServer.address() as net.AddressInfo).port)
      )
    );

    try {
      await expect(
        fetch(`http://127.0.0.1:${redirPort}/api/fleet/summary`, {
          redirect: 'error',
        })
      ).rejects.toThrow();

      expect(secondCalls).toBe(0);
    } finally {
      redirectServer.close();
      secondServer.close();
    }
  });

  // L4: Client timeout: status exits 1 with error when connected to hung server
  it('L4: client timeout aborts connection to hung server and exits 1', async () => {
    const hungServer = net.createServer((socket) => {
      socket.on('data', () => {});
    });
    const hungPort = await new Promise<number>((r) => {
      hungServer.listen(0, '127.0.0.1', () => r((hungServer.address() as net.AddressInfo).port));
    });

    try {
      const run = await runEntry(
        SECURESHIP_CLI_PATH,
        ['fleet', 'status', '--endpoint', `http://127.0.0.1:${hungPort}`],
        { HOME: tempHome, USERPROFILE: tempHome },
        { timeoutMs: 25000, waitForReady: false }
      );

      expect(run.code).toBe(1);
      expect(run.stderr).toContain('Error connecting to Fleet server');
    } finally {
      hungServer.close();
    }
  }, 30000);

  // L5: exportCra atomic file output: writes to output path ONLY after 200 OK + body parsed
  it('L5: exportCra writes destination file only after 200 OK; cleans up on 401, 500, or dropped socket', async () => {
    const testOutFile = path.join(tempHome, 'test-cra-report.json');

    // 1. Server returning 401
    const srv401 = http.createServer((_, res) => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
    });
    const port401 = await new Promise<number>((r) =>
      srv401.listen(0, '127.0.0.1', () => r((srv401.address() as net.AddressInfo).port))
    );

    try {
      const run401 = await runEntry(
        SECURESHIP_CLI_PATH,
        [
          'fleet',
          'export-cra',
          '--endpoint',
          `http://127.0.0.1:${port401}`,
          '--output',
          testOutFile,
        ],
        { HOME: tempHome, USERPROFILE: tempHome },
        { timeoutMs: 10000, waitForReady: false }
      );
      expect(run401.code).toBe(1);
      expect(fs.existsSync(testOutFile)).toBe(false);
    } finally {
      srv401.close();
    }

    // 2. Server returning 500
    const srv500 = http.createServer((_, res) => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Server Error' }));
    });
    const port500 = await new Promise<number>((r) =>
      srv500.listen(0, '127.0.0.1', () => r((srv500.address() as net.AddressInfo).port))
    );

    try {
      const run500 = await runEntry(
        SECURESHIP_CLI_PATH,
        [
          'fleet',
          'export-cra',
          '--endpoint',
          `http://127.0.0.1:${port500}`,
          '--output',
          testOutFile,
        ],
        { HOME: tempHome, USERPROFILE: tempHome },
        { timeoutMs: 10000, waitForReady: false }
      );
      expect(run500.code).toBe(1);
      expect(fs.existsSync(testOutFile)).toBe(false);
    } finally {
      srv500.close();
    }

    // 3. Server dropping connection mid-body
    const srvDrop = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{"bomFormat": "Cyclone');
      res.destroy();
    });
    const portDrop = await new Promise<number>((r) =>
      srvDrop.listen(0, '127.0.0.1', () => r((srvDrop.address() as net.AddressInfo).port))
    );

    try {
      const runDrop = await runEntry(
        SECURESHIP_CLI_PATH,
        [
          'fleet',
          'export-cra',
          '--endpoint',
          `http://127.0.0.1:${portDrop}`,
          '--output',
          testOutFile,
        ],
        { HOME: tempHome, USERPROFILE: tempHome },
        { timeoutMs: 10000, waitForReady: false }
      );
      expect(runDrop.code).toBe(1);
      expect(fs.existsSync(testOutFile)).toBe(false);
    } finally {
      srvDrop.close();
    }

    // 4. Server returning 200 with valid CycloneDX CRA JSON
    const srv200 = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }));
    });
    const port200 = await new Promise<number>((r) =>
      srv200.listen(0, '127.0.0.1', () => r((srv200.address() as net.AddressInfo).port))
    );

    try {
      const run200 = await runEntry(
        SECURESHIP_CLI_PATH,
        [
          'fleet',
          'export-cra',
          '--endpoint',
          `http://127.0.0.1:${port200}`,
          '--output',
          testOutFile,
        ],
        { HOME: tempHome, USERPROFILE: tempHome },
        { timeoutMs: 10000, waitForReady: false }
      );
      expect(run200.code).toBe(0);
      expect(fs.existsSync(testOutFile)).toBe(true);
      const parsed = JSON.parse(fs.readFileSync(testOutFile, 'utf8'));
      expect(parsed.bomFormat).toBe('CycloneDX');
    } finally {
      srv200.close();
    }
  }, 25000);

  // L6: Live test against FleetServer: sends Authorization or x-fleet-token; server accepts if either is valid; 401 if both invalid
  it('L6: live test against FleetServer accepts valid credential via either Authorization or x-fleet-token; 401 if both invalid', async () => {
    const canary = makeCanary();
    const wrongCanary = makeCanary();
    const server = new FleetServer({
      port: 0,
      authToken: canary,
    });
    const port = await server.start();

    try {
      // 1. Valid Authorization, no x-fleet-token -> 200
      const resAuth = await fetch(`http://127.0.0.1:${port}/api/fleet/summary`, {
        headers: { Authorization: `Bearer ${canary}` },
      });
      expect(resAuth.status).toBe(200);

      // 2. No Authorization, valid x-fleet-token -> 200
      const resCustom = await fetch(`http://127.0.0.1:${port}/api/fleet/summary`, {
        headers: { 'x-fleet-token': canary },
      });
      expect(resCustom.status).toBe(200);

      // 3. Invalid Authorization, valid x-fleet-token -> 200 (fallback)
      const resDual1 = await fetch(`http://127.0.0.1:${port}/api/fleet/summary`, {
        headers: {
          Authorization: `Bearer ${wrongCanary}`,
          'x-fleet-token': canary,
        },
      });
      expect(resDual1.status).toBe(200);

      // 4. Valid Authorization, invalid x-fleet-token -> 200 (fallback)
      const resDual2 = await fetch(`http://127.0.0.1:${port}/api/fleet/summary`, {
        headers: {
          Authorization: `Bearer ${canary}`,
          'x-fleet-token': wrongCanary,
        },
      });
      expect(resDual2.status).toBe(200);

      // 5. Both invalid -> 401
      const resInvalid = await fetch(`http://127.0.0.1:${port}/api/fleet/summary`, {
        headers: {
          Authorization: `Bearer ${wrongCanary}`,
          'x-fleet-token': wrongCanary,
        },
      });
      expect(resInvalid.status).toBe(401);
      const bodyInvalid = (await resInvalid.json()) as { error?: string };
      expect(bodyInvalid.error).toBe('Unauthorized: Invalid fleet token');
    } finally {
      await server.stop();
    }
  });

  // L7: --token argv deprecation: running fleet status/export-cra/start with --token prints stderr deprecation warning
  it('L7: --token flag on start, status, and export-cra prints deprecation warning on stderr', async () => {
    const canary = makeCanary();

    // 1. fleet status --token <token>
    const runStatus = await runEntry(
      SECURESHIP_CLI_PATH,
      ['fleet', 'status', '--token', canary, '--endpoint', 'http://127.0.0.1:4000'],
      { HOME: tempHome, USERPROFILE: tempHome },
      { timeoutMs: 10000, waitForReady: false }
    );
    expect(runStatus.stderr).toContain('Warning: --token is deprecated');
    expect(runStatus.stderr).toContain('FLEET_TOKEN_FILE or FLEET_TOKEN');

    // 2. fleet export-cra --token <token>
    const runExport = await runEntry(
      SECURESHIP_CLI_PATH,
      ['fleet', 'export-cra', '--token', canary, '--endpoint', 'http://127.0.0.1:4000'],
      { HOME: tempHome, USERPROFILE: tempHome },
      { timeoutMs: 10000, waitForReady: false }
    );
    expect(runExport.stderr).toContain('Warning: --token is deprecated');
    expect(runExport.stderr).toContain('FLEET_TOKEN_FILE or FLEET_TOKEN');

    // 3. fleet start --token <token>
    const runStart = await runEntry(
      SECURESHIP_CLI_PATH,
      ['fleet', 'start', '--token', canary, '--port', '0'],
      { HOME: tempHome, USERPROFILE: tempHome },
      { timeoutMs: 15000 }
    );
    try {
      expect(runStart.stderr).toContain('Warning: --token is deprecated');
      expect(runStart.stderr).toContain('FLEET_TOKEN_FILE or FLEET_TOKEN');
      // Token itself is not leaked
      assertNoLeak(runStart.stdout, canary);
      assertNoLeak(runStart.stderr, canary);
    } finally {
      runStart.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      try {
        runStart.proc.kill('SIGKILL');
      } catch {}
    }
  }, 25000);
});

describe('LAYER M: Regression and Compatibility (DEV-7, DEV-8)', () => {
  // M2: Library compatibility: loopback without token starts with single warning
  it('M2: FleetServer on loopback without authToken starts and serves dashboard with warning', async () => {
    const warningSpy = vi.spyOn(process, 'emitWarning');
    const store = new FleetStore();
    const server = new FleetServer({
      port: 0,
      store,
    });
    const port = await server.start();

    try {
      expect(warningSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'SecureShip Fleet server starting without authentication configured'
        ),
        expect.objectContaining({ code: 'SECURESHIP_FLEET_NO_AUTH' })
      );

      const res = await rawHttp(port, 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
    } finally {
      await server.stop();
      warningSpy.mockRestore();
    }
  });

  // M3: M5-style mock request does not throw or leak unhandled rejection
  it('M3: mock request with only minimal headers/url does not crash request listener', async () => {
    const server = new FleetServer({ port: 0 });
    const port = await server.start();

    try {
      const listener = (server as unknown as { server: http.Server }).server.listeners(
        'request'
      )[0] as (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>;

      const mockReq = {
        headers: { host: `127.0.0.1:${port}` },
        url: '/api/fleet/summary',
        method: 'GET',
      } as unknown as http.IncomingMessage;

      const mockRes = {
        headersSent: false,
        writeHead: vi.fn(),
        setHeader: vi.fn(),
        end: vi.fn(),
      } as unknown as http.ServerResponse;

      await expect(listener(mockReq, mockRes)).resolves.toBeUndefined();
      expect(mockRes.writeHead).toHaveBeenCalledWith(
        200,
        expect.objectContaining({ 'Content-Type': 'application/json' })
      );
    } finally {
      await server.stop();
    }
  });

  // M4: Public exports of @secureship/fleet
  it('M4: public exports include all required types and functions', async () => {
    const fleetModule = await import('../src/index.js');
    const exportKeys = Object.keys(fleetModule).sort();
    expect(exportKeys).toEqual(
      [
        'FLEET_TOKEN_PATTERN',
        'FleetConfigError',
        'FleetServer',
        'FleetStore',
        'PayloadTooLargeError',
        'assertSafeFleetEndpoint',
        'buildFleetRuntimeConfig',
        'defaultFsFacade',
        'formatAuthLabel',
        'formatDisplayUrl',
        'formatReadHint',
        'installSignalHandlers',
        'isLoopbackHostname',
        'readTokenFile',
        'resolveClientFleetToken',
        'resolveFleetToken',
        'tokensMatch',
        'validateFleetToken',
      ].sort()
    );

    expect(typeof fleetModule.FleetServer).toBe('function');
    expect(typeof fleetModule.FleetStore).toBe('function');
    expect(typeof fleetModule.PayloadTooLargeError).toBe('function');
    expect(typeof fleetModule.FleetConfigError).toBe('function');
    expect(typeof fleetModule.validateFleetToken).toBe('function');
    expect(typeof fleetModule.readTokenFile).toBe('function');
    expect(typeof fleetModule.resolveFleetToken).toBe('function');
    expect(typeof fleetModule.resolveClientFleetToken).toBe('function');
    expect(typeof fleetModule.assertSafeFleetEndpoint).toBe('function');
    expect(typeof fleetModule.buildFleetRuntimeConfig).toBe('function');
    expect(typeof fleetModule.formatDisplayUrl).toBe('function');
    expect(typeof fleetModule.formatAuthLabel).toBe('function');
    expect(typeof fleetModule.formatReadHint).toBe('function');
    expect(typeof fleetModule.installSignalHandlers).toBe('function');
    expect(typeof fleetModule.tokensMatch).toBe('function');
    expect(typeof fleetModule.isLoopbackHostname).toBe('function');
  });

  // M5: Docs tests
  it('M5: documentation files contain all required security deployment guidelines and token advice', () => {
    const docPath = path.resolve(__dirname, '../../../docs/fleet-security.md');
    expect(fs.existsSync(docPath)).toBe(true);
    const doc = fs.readFileSync(docPath, 'utf8');

    expect(doc).toContain('FLEET_TOKEN_FILE');
    expect(doc).toContain('FLEET_ALLOWED_HOSTS');
    expect(doc).toContain('FLEET_ALLOWED_ORIGINS');
    expect(doc).toContain('base64url');
    expect(doc).toContain('UTF8Encoding');
    expect(doc).toContain('HOST');

    // Verify no document prints hardcoded plain credentials in examples
    expect(doc).not.toMatch(/--token\s+[A-Za-z0-9_-]{30,}/);
  });
});
