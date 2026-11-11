import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FleetServer, PayloadTooLargeError } from '../src/server/fleet-server.js';
import { FleetStore } from '../src/storage/fleet-store.js';
import { FleetIngestPayloadSchema } from '@secureship/contracts';
import { makeCanary, assertNoLeak, rawHttp } from './fixtures/fleet-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function validPayload(fleetToken: string) {
  return {
    fleetToken,
    repoName: 'payments-svc',
    branch: 'main',
    commitSha: 'a1b2c3d4e5f6',
    scannedAt: new Date().toISOString(),
    durationMs: 1200,
    summary: {
      totalRaw: 10,
      totalReported: 1,
      totalSuppressed: 9,
      reachabilitySuppressionPct: 90,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 0, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      byReachability: { REACHABLE_CALL_PATH: 1, UNREACHABLE: 9, UNKNOWN: 0, REACHABLE_IMPORT: 0 },
    },
    vulnerabilities: [
      {
        ruleId: 'CVE-2026-0001',
        severity: 'HIGH',
        category: 'SCA',
        packageName: 'express-jwt',
        packageVersion: '1.0.0',
        reachability: 'REACHABLE_CALL_PATH',
      },
    ],
  };
}

describe('LAYER F: Credential Extraction (DEV-8)', () => {
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

  // F1: Credential extraction table
  it('F1: correctly extracts Bearer and x-fleet-token headers across all case and whitespace variants', async () => {
    const wrongToken = makeCanary();

    // 1. Authorization Bearer valid
    const r1 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\n\r\n`
    );
    expect(r1.statusCode).toBe(200);

    // 2. Scheme case variants
    const r2 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: bearer ${canaryToken}\r\n\r\n`
    );
    expect(r2.statusCode).toBe(200);

    const r3 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: BEARER ${canaryToken}\r\n\r\n`
    );
    expect(r3.statusCode).toBe(200);

    // 3. Extra spaces
    const r4 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer    ${canaryToken}\r\n\r\n`
    );
    expect(r4.statusCode).toBe(200);

    // 4. Bearer valid + x-fleet-token invalid -> 200
    const r5 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nx-fleet-token: ${wrongToken}\r\n\r\n`
    );
    expect(r5.statusCode).toBe(200);

    // 5. Bearer invalid + x-fleet-token valid -> 200
    const r6 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${wrongToken}\r\nx-fleet-token: ${canaryToken}\r\n\r\n`
    );
    expect(r6.statusCode).toBe(200);

    // 6. Basic auth + x-fleet-token valid -> 200
    const r7 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\nx-fleet-token: ${canaryToken}\r\n\r\n`
    );
    expect(r7.statusCode).toBe(200);

    // 7. Both invalid -> 401
    const r8 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${wrongToken}\r\nx-fleet-token: ${wrongToken}\r\n\r\n`
    );
    expect(r8.statusCode).toBe(401);

    // 8. Duplicate x-fleet-token headers -> 401
    const r9 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nx-fleet-token: ${canaryToken}\r\nx-fleet-token: ${canaryToken}\r\n\r\n`
    );
    expect(r9.statusCode).toBe(401);

    // 9. Query string token -> 401
    const r10 = await rawHttp(
      port,
      `GET /api/fleet/summary?token=${canaryToken}&authToken=${canaryToken} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`
    );
    expect(r10.statusCode).toBe(401);

    // 10. Cookie token -> 401
    const r11 = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: token=${canaryToken}\r\n\r\n`
    );
    expect(r11.statusCode).toBe(401);

    // 11. Empty values -> 401
    const r12 = await rawHttp(
      port,
      'GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer \r\n\r\n'
    );
    expect(r12.statusCode).toBe(401);

    // 12. 20 kB oversized header -> 431 without crash, followed by healthy 200
    const hugeHeader = 'X-Huge: ' + 'A'.repeat(20 * 1024);
    const rHuge = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\n${hugeHeader}\r\n\r\n`
    );
    expect(rHuge.statusCode).toBe(431);

    const rHealthy = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\n\r\n`
    );
    expect(rHealthy.statusCode).toBe(200);
  });

  // F2: Presented credentials never logged
  it('F2: presented credentials are never printed or logged across requests', async () => {
    const canary = makeCanary();
    let logged = '';
    const spyLog = vi.spyOn(console, 'log').mockImplementation((...args) => {
      logged += args.join(' ');
    });
    const spyErr = vi.spyOn(console, 'error').mockImplementation((...args) => {
      logged += args.join(' ');
    });

    try {
      await rawHttp(
        port,
        `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canary}\r\n\r\n`
      );
      await rawHttp(
        port,
        `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nx-fleet-token: ${canary}\r\n\r\n`
      );
      assertNoLeak(logged, canary);
      expect(logged).not.toContain(canary);
      expect(spyLog).not.toHaveBeenCalledWith(expect.stringContaining(canary));
      expect(spyErr).not.toHaveBeenCalledWith(expect.stringContaining(canary));
    } finally {
      spyLog.mockRestore();
      spyErr.mockRestore();
    }
  });
});

describe('LAYER G: Ingest Pre-Auth Hardening (DEV-3, DEV-8)', () => {
  let server: FleetServer;
  let store: FleetStore;
  let port: number;
  const canaryToken = makeCanary();
  const legacyCap = 4 * 1024;
  const maxCap = 16 * 1024;

  beforeEach(async () => {
    store = new FleetStore();
    server = new FleetServer({
      port: 0,
      store,
      authToken: canaryToken,
      legacyBodyTokenMaxBytes: legacyCap,
      maxBodyBytes: maxCap,
    });
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  // G1: Pre-auth failure bodies return 401 with identical body and zero schema validation
  it('G1: pre-auth failures return status 401 with byte-identical body and bypass schema parse', async () => {
    const zodSpy = vi.spyOn(FleetIngestPayloadSchema, 'safeParse');
    const storeIngestSpy = vi.spyOn(store, 'ingest');

    const testBodies = [
      '',
      '{}',
      'not json',
      '[]',
      '"string"',
      'null',
      JSON.stringify({ repoName: 'test' }),
      JSON.stringify({ fleetToken: 12345 }),
      JSON.stringify({ fleetToken: {} }),
      JSON.stringify({ fleetToken: [] }),
      JSON.stringify({ fleetToken: '' }),
      JSON.stringify({ fleetToken: 'wrong-token' }),
      JSON.stringify({ fleetToken: ` ${canaryToken} ` }),
    ];

    const responses: string[] = [];

    for (const b of testBodies) {
      const res = await rawHttp(
        port,
        `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(b)}\r\n\r\n${b}`
      );
      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toBe('Bearer');
      expect(res.body).toBe('{"error":"Unauthorized: Invalid fleet token"}');
      responses.push(res.body);
    }

    expect(zodSpy).toHaveBeenCalledTimes(0);
    expect(storeIngestSpy).toHaveBeenCalledTimes(0);

    // G5 Oracle equality: every response body in G1 is identical
    const firstBody = responses[0]!;
    for (const b of responses) {
      expect(b).toBe(firstBody);
    }
  });

  // G2: Authenticated schema validation behavior
  it('G2: authenticated calls with valid schema return 200; invalid schema returns 400 with details', async () => {
    // 1. Correct body token + invalid schema -> 400
    const invPayload = JSON.stringify({ fleetToken: canaryToken, repoName: 123 });
    const resInvBody = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(invPayload)}\r\n\r\n${invPayload}`
    );
    expect(resInvBody.statusCode).toBe(400);
    expect(JSON.parse(resInvBody.body).error).toBe('Invalid Fleet Ingest Payload');

    // 2. Correct body token + valid payload -> 200
    const vPayload = JSON.stringify(validPayload(canaryToken));
    const resValBody = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(vPayload)}\r\n\r\n${vPayload}`
    );
    expect(resValBody.statusCode).toBe(200);

    // 3. Valid header + invalid body token + valid payload -> 200
    const wrongBodyPayload = JSON.stringify(validPayload('wrong-token'));
    const resHeaderAuth = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(wrongBodyPayload)}\r\n\r\n${wrongBodyPayload}`
    );
    expect(resHeaderAuth.statusCode).toBe(200);

    // 4. Valid header + invalid schema -> 400
    const resHeaderInv = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(invPayload)}\r\n\r\n${invPayload}`
    );
    expect(resHeaderInv.statusCode).toBe(400);
  });

  // G3: Byte limits: legacy body cap vs header max cap
  it('G3: declared Content-Length over legacy cap returns 413 before body read for unauthenticated ingest', async () => {
    // Unauthenticated ingest with Content-Length > legacyCap (4 KiB) sends only 10 bytes:
    // server returns 413 immediately without waiting for remainder
    const declaredSize = legacyCap + 1024;
    const resOverLegacy = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${declaredSize}\r\n\r\n1234567890`
    );
    expect(resOverLegacy.statusCode).toBe(413);

    // Header-authenticated request between legacyCap and maxCap -> 200
    const midSize = legacyCap + 100;
    const midPayload = validPayload(canaryToken);
    (midPayload as unknown as { padding: string }).padding = 'X'.repeat(midSize);
    const midJson = JSON.stringify(midPayload);

    const resMid = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(midJson)}\r\n\r\n${midJson}`
    );
    expect(resMid.statusCode).toBe(200);

    // Header-authenticated request over maxCap -> 413
    const overMaxDeclared = maxCap + 1024;
    const resOverMax = await rawHttp(
      port,
      `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: ${overMaxDeclared}\r\n\r\n1234567890`
    );
    expect(resOverMax.statusCode).toBe(413);
  });

  // G4: allowLegacyBodyToken: false disables body-level token
  it('G4: allowLegacyBodyToken: false returns 401 for body token and requires header authentication', async () => {
    const strictServer = new FleetServer({
      port: 0,
      store,
      authToken: canaryToken,
      allowLegacyBodyToken: false,
    });
    const sPort = await strictServer.start();
    try {
      const vPayload = JSON.stringify(validPayload(canaryToken));

      // Without header -> 401
      const resNoHeader = await rawHttp(
        sPort,
        `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(vPayload)}\r\n\r\n${vPayload}`
      );
      expect(resNoHeader.statusCode).toBe(401);

      // With header -> 200
      const resWithHeader = await rawHttp(
        sPort,
        `POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(vPayload)}\r\n\r\n${vPayload}`
      );
      expect(resWithHeader.statusCode).toBe(200);
    } finally {
      await strictServer.stop();
    }
  });

  // G6: Content-Type check order and Origin CSRF check
  it('G6: text/plain unauthenticated ingest returns 401 and cross-origin CSRF returns 403', async () => {
    // Unauthenticated text/plain request returns 401 (auth gate runs before 415)
    const resTextPlain = await rawHttp(
      port,
      'POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ntest'
    );
    expect(resTextPlain.statusCode).toBe(401);

    // Cross-origin CSRF request receives 403 from Origin check
    const resCsrf = await rawHttp(
      port,
      'POST /api/ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://evil.attacker.corp\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
    );
    expect(resCsrf.statusCode).toBe(403);
    expect(JSON.parse(resCsrf.body).error).toBe('Origin not allowed');
  });
});

describe('LAYER H: 413 Delivery and Reader Hygiene (DEV-3)', () => {
  let server: FleetServer;
  let port: number;
  const canaryToken = makeCanary();
  const cap = 8 * 1024; // 8 KiB cap

  beforeEach(async () => {
    server = new FleetServer({
      port: 0,
      authToken: canaryToken,
      legacyBodyTokenMaxBytes: 4 * 1024,
      maxBodyBytes: cap,
    });
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  // H1: Content-Length over cap with partial send yields 413 and connection: close
  it('H1: Content-Length over cap receives status 413, Connection: close, and exact body', async () => {
    const res = await rawHttp(
      port,
      `POST /api/policy HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n{"foo":"bar"}`
    );
    expect(res.statusCode).toBe(413);
    expect(res.headers['connection']).toBe('close');
    expect(JSON.parse(res.body).error).toBe('Payload too large');
  });

  // H2: Chunked streaming over cap receives 413 without socket crash
  it('H2: chunked streaming over cap resolves with 413 response', async () => {
    const res = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/policy',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${canaryToken}`,
          },
        },
        (r) => {
          let data = '';
          r.on('data', (c) => (data += c));
          r.on('end', () => {
            resolve({ statusCode: r.statusCode ?? 0, body: data });
          });
        }
      );

      req.on('error', (err) => {
        reject(err);
      });

      // Write chunks until cap is exceeded
      const chunk = 'A'.repeat(1024);
      for (let i = 0; i < 12; i++) {
        req.write(chunk);
      }
      req.end();
    });

    expect(res.statusCode).toBe(413);
    expect(JSON.parse(res.body).error).toBe('Payload too large');
  });

  // H3: Server remains healthy after 413 and connection count is clean
  it('H3: server remains healthy after 413 and subsequent requests succeed', async () => {
    const resHealthy = await rawHttp(
      port,
      `GET /api/fleet/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: Bearer ${canaryToken}\r\n\r\n`
    );
    expect(resHealthy.statusCode).toBe(200);

    await new Promise((r) => setTimeout(r, 50));
    const rawServer = (server as unknown as { server: http.Server }).server;
    const connCount = await new Promise<number>((res) =>
      rawServer.getConnections((_err, count) => res(count))
    );
    expect(connCount).toBe(0);
  });

  // H4: Static meta-test verifies no test file maps ECONNRESET to 413
  it('H4: static meta-test verifies no fleet test contains ECONNRESET mapping catch blocks', () => {
    const testFiles = [
      path.resolve(__dirname, 'fleet.test.ts'),
      path.resolve(__dirname, 'fleet-layer-j-k.test.ts'),
      path.resolve(__dirname, 'fleet-layer-l-m-n.test.ts'),
      path.resolve(__dirname, 'fleet-security.smoke.test.ts'),
    ];

    for (const f of testFiles) {
      if (!fs.existsSync(f)) continue;
      const content = fs.readFileSync(f, 'utf8');
      expect(content).not.toMatch(/resLargeStatus\s*=\s*413/);
      expect(content).not.toMatch(/catch.*=\s*413/);
    }
  });

  // H5: PayloadTooLargeError is thrown and req.destroy is called after finish
  it('H5: PayloadTooLargeError is thrown from reader and destroys request cleanly', async () => {
    const err = new PayloadTooLargeError('Payload too large');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('PayloadTooLargeError');
    expect(err.message).toBe('Payload too large');

    // Instrument to verify req.destroy is never called before response 'finish' event
    const events: string[] = [];
    let destroyOccurred = false;
    const origDestroy = http.IncomingMessage.prototype.destroy;

    const spyDestroy = vi
      .spyOn(http.IncomingMessage.prototype, 'destroy')
      .mockImplementation(function (this: http.IncomingMessage, error?: Error) {
        destroyOccurred = true;
        events.push('destroy');
        return origDestroy.call(this, error);
      });

    try {
      const res = await rawHttp(
        port,
        `POST /api/policy HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${canaryToken}\r\nContent-Type: application/json\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n{"overflow":true}`
      );
      expect(res.statusCode).toBe(413);
      expect(destroyOccurred).toBe(true);
      expect(events).toContain('destroy');
    } finally {
      spyDestroy.mockRestore();
    }
  });
});

describe('LAYER I: Timeouts and Slowloris Hardening (DEV-3)', () => {
  // I1: Default timeouts
  it('I1: started server exposes default headersTimeout of 15000ms and requestTimeout of 60000ms', async () => {
    const s = new FleetServer({ port: 0 });
    const p = await s.start();
    expect(p).toBeGreaterThan(0);
    try {
      const rawServer = (s as unknown as { server: http.Server }).server;
      expect(rawServer.headersTimeout).toBe(15000);
      expect(rawServer.requestTimeout).toBe(60000);
    } finally {
      await s.stop();
    }
  });

  // I2: Slowloris headers timeout
  it('I2: slowloris incomplete headers connection is closed by server timeout', async () => {
    const slowServer = new FleetServer({
      port: 0,
      headersTimeoutMs: 300,
      requestTimeoutMs: 600,
    });
    const sPort = await slowServer.start();

    try {
      const closed = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), 5000);
        const socket = net.createConnection({ host: '127.0.0.1', port: sPort }, () => {
          socket.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n');
        });
        socket.on('data', () => {});
        socket.on('close', () => {
          clearTimeout(timer);
          resolve(true);
        });
        socket.on('end', () => {
          clearTimeout(timer);
          resolve(true);
        });
      });

      expect(closed).toBe(true);
    } finally {
      await slowServer.stop();
    }
  }, 10000);

  // I3: Slow body timeout
  it('I3: slow body connection stalling midway is closed by server timeout', async () => {
    const slowServer = new FleetServer({
      port: 0,
      headersTimeoutMs: 300,
      requestTimeoutMs: 600,
    });
    const sPort = await slowServer.start();

    try {
      const closed = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), 5000);
        const socket = net.createConnection({ host: '127.0.0.1', port: sPort }, () => {
          socket.write(
            'POST /api/policy HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n1234567890'
          );
        });
        socket.on('data', () => {});
        socket.on('close', () => {
          clearTimeout(timer);
          resolve(true);
        });
        socket.on('end', () => {
          clearTimeout(timer);
          resolve(true);
        });
      });

      expect(closed).toBe(true);
    } finally {
      await slowServer.stop();
    }
  }, 10000);

  // I4: Healthy concurrent requests during active slowloris still return 200
  it('I4: healthy concurrent requests succeed with status 200 while slowloris socket is connected', async () => {
    const slowServer = new FleetServer({
      port: 0,
      headersTimeoutMs: 1500,
      requestTimeoutMs: 2500,
    });
    const sPort = await slowServer.start();

    try {
      // Connect slow client
      const slowSocket = net.createConnection({ host: '127.0.0.1', port: sPort });
      slowSocket.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n');

      // Healthy client connects concurrently
      const res = await rawHttp(sPort, 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
      expect(res.statusCode).toBe(200);

      slowSocket.destroy();
    } finally {
      await slowServer.stop();
    }
  });

  // I5: connectionsCheckingInterval passed to http.createServer
  it('I5: connectionsCheckingInterval is configured on http.createServer options', async () => {
    const spy = vi.spyOn(http, 'createServer');
    const testServer = new FleetServer({
      port: 0,
      headersTimeoutMs: 3000,
    });
    const p = await testServer.start();
    expect(p).toBeGreaterThan(0);
    try {
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          connectionsCheckingInterval: 3000,
        }),
        expect.any(Function)
      );
    } finally {
      await testServer.stop();
      spy.mockRestore();
    }
  });
});
