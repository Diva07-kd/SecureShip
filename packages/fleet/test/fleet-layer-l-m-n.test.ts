import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { FleetStore } from '../src/storage/fleet-store.js';
import { FleetServer } from '../src/server/fleet-server.js';
import { type FleetIngestPayload } from '@secureship/contracts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface RawHttpResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function rawRequest(
  port: number,
  options: {
    method?: string;
    path?: string;
    headers?: Record<string, string | number | undefined>;
    body?: string;
  }
): Promise<RawHttpResponse> {
  return new Promise((resolve, reject) => {
    const reqHeaders: Record<string, string | number> = {
      Host: `127.0.0.1:${port}`,
    };
    if (options.headers) {
      for (const [k, v] of Object.entries(options.headers)) {
        if (v !== undefined) reqHeaders[k] = v;
      }
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: options.path ?? '/',
        method: options.method ?? 'GET',
        headers: reqHeaders,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () =>
          resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: data })
        );
      }
    );
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function validIngestPayload(fleetToken: string): FleetIngestPayload {
  return {
    fleetToken,
    repoName: 'payments-svc',
    branch: 'main',
    commitSha: 'c1d2e3f4a5b6',
    scannedAt: new Date().toISOString(),
    durationMs: 1200,
    summary: {
      totalRaw: 10,
      totalReported: 1,
      totalSuppressed: 9,
      reachabilitySuppressionPct: 90,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 0, SCA: 1, SECRET: 0, IAC: 0 },
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

describe('LAYER L: Fleet Authentication Matrix (DEV-7, F-FLT-001 endpoint-auth)', () => {
  let tempDir: string;
  let tempFile: string;
  let store: FleetStore;
  let server: FleetServer;
  let port: number;
  const CORRECT_TOKEN = 'secret-fleet-bearer-token-xyz';

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fleet-l-'));
    tempFile = path.join(tempDir, 'fleet.json');
    store = new FleetStore({ storageFile: tempFile });
    server = new FleetServer({
      port: 0,
      store,
      authToken: CORRECT_TOKEN,
    });
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // L1: Route x credential matrix with exact statuses
  it('L1: verifies authentication matrix across all /api/* routes and credentials', async () => {
    const routes: Array<{ path: string; method: string; body?: string }> = [
      { path: '/api/fleet/repos', method: 'GET' },
      { path: '/api/fleet/summary', method: 'GET' },
      { path: '/api/fleet/sbom', method: 'GET' },
      { path: '/api/fleet/compliance/cra', method: 'GET' },
      { path: '/api/policy', method: 'GET' },
      { path: '/api/policy', method: 'POST', body: JSON.stringify({ failOnSeverity: 'HIGH' }) },
      { path: '/api/unknown', method: 'GET' }, // Unknown path must NOT leak route existence
    ];

    const invalidCredentials: Array<{
      desc: string;
      headers?: Record<string, string>;
      query?: string;
    }> = [
      { desc: 'no credentials' },
      { desc: 'wrong token', headers: { Authorization: 'Bearer wrong-token-123' } },
      { desc: 'short token', headers: { Authorization: 'Bearer x' } },
      { desc: '10 kB long token', headers: { Authorization: `Bearer ${'a'.repeat(10240)}` } },
      { desc: 'empty Bearer', headers: { Authorization: 'Bearer ' } },
      { desc: 'token in query param', query: `?token=${CORRECT_TOKEN}` },
      { desc: 'authToken query param', query: `?authToken=${CORRECT_TOKEN}` },
    ];

    for (const route of routes) {
      for (const cred of invalidCredentials) {
        const fullPath = route.path + (cred.query ?? '');
        const res = await rawRequest(port, {
          method: route.method,
          path: fullPath,
          headers: {
            'Content-Type': 'application/json',
            ...cred.headers,
          },
          body: route.body,
        });

        expect(res.statusCode).toBe(401);
        expect(res.headers['www-authenticate']).toBe('Bearer');
        const json = JSON.parse(res.body) as { error: string };
        expect(json.error).toContain('Unauthorized');
      }
    }

    // Valid credential formats
    // 1. Authorization: Bearer <correct>
    const resAuth = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: `Bearer ${CORRECT_TOKEN}` },
    });
    expect(resAuth.statusCode).toBe(200);

    // 2. Case-insensitive bearer scheme (bearer, BEARER)
    const resBearerLower = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: `bearer ${CORRECT_TOKEN}` },
    });
    expect(resBearerLower.statusCode).toBe(200);

    const resBearerUpper = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: `BEARER ${CORRECT_TOKEN}` },
    });
    expect(resBearerUpper.statusCode).toBe(200);

    // 3. x-fleet-token header
    const resXToken = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { 'x-fleet-token': CORRECT_TOKEN },
    });
    expect(resXToken.statusCode).toBe(200);
  });

  // L2: Unauthenticated requests never reach the store
  it('L2: unauthenticated requests never invoke any FleetStore method and leave policy unchanged', async () => {
    const initialPolicy = store.getPolicy();

    const ingestSpy = vi.spyOn(store, 'ingest');
    const summarySpy = vi.spyOn(store, 'getExecutiveSummary');
    const reposSpy = vi.spyOn(store, 'getRepos');
    const sbomSpy = vi.spyOn(store, 'searchSbom');
    const craSpy = vi.spyOn(store, 'generateCraComplianceReport');
    const getPolicySpy = vi.spyOn(store, 'getPolicy');
    const updatePolicySpy = vi.spyOn(store, 'updatePolicy');

    // Send unauthenticated requests to all endpoints
    await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    await rawRequest(port, { method: 'GET', path: '/api/fleet/summary' });
    await rawRequest(port, { method: 'GET', path: '/api/fleet/repos' });
    await rawRequest(port, { method: 'GET', path: '/api/fleet/sbom' });
    await rawRequest(port, { method: 'GET', path: '/api/fleet/compliance/cra' });
    await rawRequest(port, { method: 'GET', path: '/api/policy' });
    await rawRequest(port, {
      method: 'POST',
      path: '/api/policy',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ failOnSeverity: 'NONE' }),
    });

    // Zero calls to any store method
    expect(ingestSpy).not.toHaveBeenCalled();
    expect(summarySpy).not.toHaveBeenCalled();
    expect(reposSpy).not.toHaveBeenCalled();
    expect(sbomSpy).not.toHaveBeenCalled();
    expect(craSpy).not.toHaveBeenCalled();
    expect(getPolicySpy).not.toHaveBeenCalled();
    expect(updatePolicySpy).not.toHaveBeenCalled();

    // Policy unchanged
    expect(store.getPolicy()).toEqual(initialPolicy);
  });

  // L3: Ingest compatibility (D10)
  it('L3: ingest compatibility: header token and body token behaviors', async () => {
    // 1. Valid header token with empty or invalid body token is accepted
    const payloadWrongBody = validIngestPayload('wrong-body-token');
    const resHeaderOnly = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        Authorization: `Bearer ${CORRECT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payloadWrongBody),
    });
    expect(resHeaderOnly.statusCode).toBe(200);

    // 2. Valid body token without any auth header is accepted
    const payloadValidBody = validIngestPayload(CORRECT_TOKEN);
    const resBodyOnly = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payloadValidBody),
    });
    expect(resBodyOnly.statusCode).toBe(200);

    // 3. Schema error for authenticated caller returns 400
    const resSchemaErr = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        Authorization: `Bearer ${CORRECT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ invalid: 'payload' }),
    });
    expect(resSchemaErr.statusCode).toBe(400);
    const schemaJson = JSON.parse(resSchemaErr.body) as { error: string };
    expect(schemaJson.error).toContain('Invalid Fleet Ingest Payload');
  });

  // L4: Timing-safe comparison & static guard
  it('L4: timing-safe token comparison and static guard against direct string equality', async () => {
    // 1. Token differing only in last character -> 401 without throwing
    const nearToken = CORRECT_TOKEN.slice(0, -1) + 'w';
    const resNear = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: `Bearer ${nearToken}` },
    });
    expect(resNear.statusCode).toBe(401);

    // 2. Token of different length -> 401 without throwing
    const resLen = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: `Bearer ${CORRECT_TOKEN}extra` },
    });
    expect(resLen.statusCode).toBe(401);

    // 3. Empty token -> 401 without throwing
    const resEmpty = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: 'Bearer ' },
    });
    expect(resEmpty.statusCode).toBe(401);

    // 4. Static guard on fleet-server.ts
    const serverPath = path.resolve(__dirname, '../src/server/fleet-server.ts');
    const content = fs.readFileSync(serverPath, 'utf-8');

    // Uses timingSafeEqual
    expect(content).toContain('crypto.timingSafeEqual');

    // Contains no direct equality comparison against this.authToken
    expect(content).not.toMatch(/===\s*this\.authToken/);
    expect(content).not.toMatch(/this\.authToken\s*===/);
    expect(content).not.toMatch(/!==\s*this\.authToken/);
    expect(content).not.toMatch(/this\.authToken\s*!==/);
  });

  // L5: GET / and /dashboard return 200 HTML without a token and contain no fleet telemetry
  it('L5: GET / and /dashboard serve HTML without authentication and leak zero telemetry data', async () => {
    // Ingest data first so telemetry exists in store
    store.ingest(validIngestPayload(CORRECT_TOKEN));
    expect(store.getRepos()).toHaveLength(1);

    for (const p of ['/', '/dashboard']) {
      const res = await rawRequest(port, {
        method: 'GET',
        path: p,
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');

      // Contains cockpit UI title
      expect(res.body).toContain('SecureShip Fleet');

      // Contains no stored repository telemetry data in static server render
      expect(res.body).not.toContain('payments-svc');
      expect(res.body).not.toContain('CVE-2026-0001');
      expect(res.body).not.toContain('express-jwt');
    }
  });

  // L6: Ingest endpoint authenticates via body fleetToken when Authorization header is omitted
  it('L6: ingest authenticates via body fleetToken when header is omitted; rejects invalid body token', async () => {
    // 1. Valid body fleetToken with no Authorization header -> 200
    const payloadValid = validIngestPayload(CORRECT_TOKEN);
    const resValid = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payloadValid),
    });
    expect(resValid.statusCode).toBe(200);
    const jsonValid = JSON.parse(resValid.body) as { status: string };
    expect(jsonValid.status).toBe('success');

    // 2. Invalid body fleetToken with no Authorization header -> 401
    const payloadInvalid = validIngestPayload('wrong-body-token');
    const resInvalid = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payloadInvalid),
    });
    expect(resInvalid.statusCode).toBe(401);
    const jsonInvalid = JSON.parse(resInvalid.body) as { error: string };
    expect(jsonInvalid.error).toContain('Invalid fleet token');
  });

  // L7: Ingest HMAC-SHA256 signature verification and policy compliance
  it('L7: verifies ingest HMAC signature and enforces policy.requireHmacAudit', async () => {
    const payload = validIngestPayload(CORRECT_TOKEN);
    const computeHmac = (p: FleetIngestPayload) =>
      crypto
        .createHmac('sha256', p.fleetToken)
        .update(`${p.repoName}:${p.commitSha}:${p.durationMs}:${p.summary.totalReported}`)
        .digest('hex');

    // 1. Valid HMAC signature -> 200
    payload.signature = computeHmac(payload);
    const resValidSig = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${CORRECT_TOKEN}`,
      },
      body: JSON.stringify(payload),
    });
    expect(resValidSig.statusCode).toBe(200);

    // 2. Invalid HMAC signature with requireHmacAudit=true -> 400
    store.updatePolicy({ requireHmacAudit: true });
    payload.signature = 'bad-hmac-signature-deadbeef';
    const resBadSigStrict = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${CORRECT_TOKEN}`,
      },
      body: JSON.stringify(payload),
    });
    expect(resBadSigStrict.statusCode).toBe(400);
    const jsonBad = JSON.parse(resBadSigStrict.body) as { error: string };
    expect(jsonBad.error).toContain('Tamper-proof audit failed');

    // 3. Invalid HMAC signature with requireHmacAudit=false -> 200 (audit not required)
    store.updatePolicy({ requireHmacAudit: false });
    const resBadSigLax = await rawRequest(port, {
      method: 'POST',
      path: '/api/ingest',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${CORRECT_TOKEN}`,
      },
      body: JSON.stringify(payload),
    });
    expect(resBadSigLax.statusCode).toBe(200);
  });

  // L8: Global SBOM Search endpoint (GET /api/fleet/sbom)
  it('L8: searches fleet SBOM dependencies with query filtering and requires auth', async () => {
    store.ingest(validIngestPayload(CORRECT_TOKEN));

    // 1. Unauthenticated -> 401
    const resUnauth = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/sbom',
    });
    expect(resUnauth.statusCode).toBe(401);

    // 2. Authenticated with empty query -> 200
    const resAll = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/sbom',
      headers: {
        Authorization: `Bearer ${CORRECT_TOKEN}`,
      },
    });
    expect(resAll.statusCode).toBe(200);
    const allItems = JSON.parse(resAll.body);
    expect(Array.isArray(allItems)).toBe(true);

    // 3. Authenticated with search query -> 200
    const resQuery = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/sbom?q=express-jwt',
      headers: {
        Authorization: `Bearer ${CORRECT_TOKEN}`,
      },
    });
    expect(resQuery.statusCode).toBe(200);
    const queryItems = JSON.parse(resQuery.body);
    expect(Array.isArray(queryItems)).toBe(true);
  });
});

describe('LAYER M: Fleet Error Mapping and Headers (DEV-7)', () => {
  let tempDir: string;
  let tempFile: string;
  let store: FleetStore;
  let server: FleetServer;
  let port: number;
  const AUTH_TOKEN = 'tok-layer-m-secret';

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fleet-m-'));
    tempFile = path.join(tempDir, 'fleet.json');
    store = new FleetStore({ storageFile: tempFile });
    server = new FleetServer({
      port: 0,
      store,
      authToken: AUTH_TOKEN,
    });
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // M1: Error mapping: 400 for invalid JSON, 413 for oversized body, 500 without leaking stack/details
  it('M1: maps JSON syntax errors to 400, oversized payloads to 413, and exceptions to sanitized 500', async () => {
    // 1. Invalid JSON body -> 400 { error: 'Invalid JSON body' }
    const resBadJson = await rawRequest(port, {
      method: 'POST',
      path: '/api/policy',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
      body: '{{malformed json',
    });
    expect(resBadJson.statusCode).toBe(400);
    const badJson = JSON.parse(resBadJson.body) as { error: string };
    expect(badJson).toEqual({ error: 'Invalid JSON body' });

    // 2. Oversized body > 10 MiB payload cap -> 413 { error: 'Payload too large' }
    const hugeChunk = 'x'.repeat(1024 * 1024); // 1 MiB chunk

    // Variant A: Content-Length header variant (> 10 MiB)
    const resLargeCl = await new Promise<RawHttpResponse>((resolve, reject) => {
      let responded = false;
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/policy',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${AUTH_TOKEN}`,
            'Content-Length': 11 * 1024 * 1024,
          },
        },
        (res) => {
          responded = true;
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () =>
            resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: data })
          );
          res.on('close', () => {
            resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: data });
          });
        }
      );
      req.on('error', (err) => {
        if (!responded) {
          reject(err);
        }
      });
      req.write(hugeChunk.repeat(11));
      req.end();
    });
    expect(resLargeCl.statusCode).toBe(413);

    // Variant B: Chunked streaming overrun without Content-Length (> 10 MiB)
    const resLargeChunked = await new Promise<RawHttpResponse>((resolve, reject) => {
      let responded = false;
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/policy',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${AUTH_TOKEN}`,
          },
        },
        (res) => {
          responded = true;
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () =>
            resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: data })
          );
          res.on('close', () => {
            resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: data });
          });
        }
      );
      req.on('error', (err) => {
        if (!responded) {
          reject(err);
        }
      });
      for (let i = 0; i < 11; i++) {
        req.write(hugeChunk);
      }
      req.end();
    });
    expect(resLargeChunked.statusCode).toBe(413);

    // 3. Forced store exception -> 500 { error: 'Internal server error' } with no stack or message leak
    vi.spyOn(store, 'getExecutiveSummary').mockImplementation(() => {
      throw new Error('FATAL_DATABASE_CORRUPTION_SECRET_INTERNAL_KEY_9999');
    });

    const res500 = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: {
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
    });
    expect(res500.statusCode).toBe(500);
    const json500 = JSON.parse(res500.body) as { error: string };
    expect(json500).toEqual({ error: 'Internal server error' });
    expect(res500.body).not.toContain('FATAL_DATABASE_CORRUPTION');
    expect(res500.body).not.toContain('Error:');
    expect(res500.body).not.toContain('at ');
  });

  // M2: Security headers present on every response; Cache-Control: no-store on /api/*
  it('M2: sets required security headers on all responses and Cache-Control: no-store on /api/*', async () => {
    // 1. Static page /
    const resRoot = await rawRequest(port, { method: 'GET', path: '/' });
    expect(resRoot.headers['x-content-type-options']).toBe('nosniff');
    expect(resRoot.headers['x-frame-options']).toBe('DENY');
    expect(resRoot.headers['referrer-policy']).toBe('no-referrer');
    expect(resRoot.headers['vary']).toBe('Origin');

    // 2. API endpoint /api/fleet/summary
    const resApi = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(resApi.headers['x-content-type-options']).toBe('nosniff');
    expect(resApi.headers['x-frame-options']).toBe('DENY');
    expect(resApi.headers['referrer-policy']).toBe('no-referrer');
    expect(resApi.headers['vary']).toBe('Origin');
    expect(resApi.headers['cache-control']).toBe('no-store');
  });

  // M3: POST /api/policy with non-object body gives 400, policy unchanged
  it('M3: POST /api/policy rejects non-object bodies with 400 and preserves policy', async () => {
    const initialPolicy = store.getPolicy();
    const nonObjectBodies = [
      JSON.stringify(['array', 'of', 'items']),
      JSON.stringify('scalar-string-value'),
      JSON.stringify(12345),
      JSON.stringify(null),
      JSON.stringify(true),
    ];

    for (const body of nonObjectBodies) {
      const res = await rawRequest(port, {
        method: 'POST',
        path: '/api/policy',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${AUTH_TOKEN}`,
        },
        body,
      });

      expect(res.statusCode).toBe(400);
      const json = JSON.parse(res.body) as { error: string };
      expect(json.error).toBe('Invalid policy payload: must be a plain object');
      expect(store.getPolicy()).toEqual(initialPolicy);
    }
  });

  // M4: FleetServer lifecycle edge cases and error event handling
  it('M4: handles server lifecycle methods, getUrl, start idempotency, and error events', async () => {
    // 1. getUrl returns valid HTTP URL with bound host and port
    const url = server.getUrl();
    expect(url).toBe(`http://127.0.0.1:${port}`);

    // 2. Calling start() again on already running server is idempotent and returns existing port
    const portAgain = await server.start();
    expect(portAgain).toBe(port);

    // 3. Calling stop() when server is not running is safe and resolves
    const idleServer = new FleetServer({ port: 0 });
    await expect(idleServer.stop()).resolves.toBeUndefined();

    // 4. Server error event on listen (e.g. port collision / EADDRINUSE) rejects start() promise
    const collidingServer = new FleetServer({ port, authToken: 'another-token' });
    await expect(collidingServer.start()).rejects.toThrow();
  });

  // M5: Request processing error branches and body edge cases
  it('M5: handles empty JSON body, syntax errors, and internal error branches', async () => {
    // 1. Empty body string on POST /api/policy resolves to {} and updates policy
    const resEmptyBody = await rawRequest(port, {
      method: 'POST',
      path: '/api/policy',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
      body: '',
    });
    expect(resEmptyBody.statusCode).toBe(200);

    // 2. SyntaxError in JSON body -> 400 Invalid JSON body
    const resSyntaxError = await rawRequest(port, {
      method: 'POST',
      path: '/api/policy',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
      body: '{"invalid": json',
    });
    expect(resSyntaxError.statusCode).toBe(400);
    expect(JSON.parse(resSyntaxError.body).error).toBe('Invalid JSON body');

    // 3. Internal error thrown as string -> 500 Internal server error
    vi.spyOn(store, 'getRepos').mockImplementationOnce(() => {
      throw 'string error message';
    });
    const resStringErr = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/repos',
      headers: {
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
    });
    expect(resStringErr.statusCode).toBe(500);
    expect(JSON.parse(resStringErr.body).error).toBe('Internal server error');

    // 4. Internal error thrown as generic Error -> 500 Internal server error
    vi.spyOn(store, 'getRepos').mockImplementationOnce(() => {
      throw new Error('database failure');
    });
    const resErr = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/repos',
      headers: {
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
    });
    expect(resErr.statusCode).toBe(500);
    expect(JSON.parse(resErr.body).error).toBe('Internal server error');

    // 5. headersSent guard: error thrown when headersSent=true returns without crashing
    const requestListener = (server as unknown as { server: http.Server }).server.listeners(
      'request'
    )[0] as (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>;
    const mockReq = {
      headers: { host: `127.0.0.1:${port}` },
      url: '/api/fleet/repos',
      method: 'GET',
    } as unknown as http.IncomingMessage;
    const mockRes = {
      headersSent: true,
      setHeader: vi.fn(),
      writeHead: vi.fn(() => {
        throw new Error('write error');
      }),
      end: vi.fn(),
    } as unknown as http.ServerResponse;
    await expect(requestListener(mockReq, mockRes)).resolves.toBeUndefined();

    // 6. 404 for unknown endpoint with valid auth
    const resNotFound = await rawRequest(port, {
      method: 'GET',
      path: '/api/nonexistent',
      headers: {
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
    });
    expect(resNotFound.statusCode).toBe(404);
    expect(JSON.parse(resNotFound.body).error).toBe('Endpoint not found');
  });

  // M6: Host resolution, IPv6 formatting, and constructor options validation
  it('M6: handles IPv6 bracketed hosts, non-wildcard host binding, and options validation', async () => {
    // 1. IPv6 bracketed host header [::1]:port is accepted on loopback
    const resIpv6 = await rawRequest(port, {
      method: 'GET',
      path: '/api/fleet/summary',
      headers: {
        Host: `[::1]:${port}`,
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
    });
    expect(resIpv6.statusCode).toBe(200);

    // 2. Non-wildcard bound host matching host header
    const hostServer = new FleetServer({
      host: '127.0.0.1',
      port: 0,
      authToken: 'test-token',
    });
    const hostPort = await hostServer.start();
    try {
      const resBound = await rawRequest(hostPort, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Host: `127.0.0.1:${hostPort}`,
          Authorization: 'Bearer test-token',
        },
      });
      expect(resBound.statusCode).toBe(200);
    } finally {
      await hostServer.stop();
    }

    // 3. Constructor validates allowedOrigins (rejects wildcard, non-http(s), invalid URL)
    expect(
      () =>
        new FleetServer({
          allowedOrigins: ['*'],
        })
    ).toThrow("Wildcard '*' origin is not allowed in allowedOrigins");

    expect(
      () =>
        new FleetServer({
          allowedOrigins: ['ftp://bad-protocol.corp'],
        })
    ).toThrow('Invalid origin in allowedOrigins');

    expect(
      () =>
        new FleetServer({
          allowedOrigins: ['https://valid.domain.corp/with-subpath'],
        })
    ).toThrow('Invalid origin in allowedOrigins');

    expect(
      () =>
        new FleetServer({
          allowedOrigins: ['not-a-url'],
        })
    ).toThrow('Invalid origin in allowedOrigins');
  });
});

describe('LAYER N: Dashboard Security Static Guards (DEV-8)', () => {
  it('N1: ciso-dashboard.html adheres to token handling, authentication, and export rules', () => {
    const dashboardPath = path.resolve(__dirname, '../src/ui/ciso-dashboard.html');
    const html = fs.readFileSync(dashboardPath, 'utf-8');

    // 1. Sends Authorization header through single helper apiFetch
    expect(html).toContain('async function apiFetch(');
    expect(html).toContain("headers.set('Authorization', `Bearer ${inMemoryFleetToken}`)");

    // 2. Handles 401 by prompting user
    expect(html).toContain('if (res.status === 401)');
    expect(html).toContain("prompt('Enter Fleet Bearer Token:')");

    // 3. Contains no ?token= or ?authToken=
    expect(html).not.toContain('?token=');
    expect(html).not.toContain('?authToken=');

    // 4. Never calls localStorage, sessionStorage, or document.cookie
    expect(html).not.toMatch(/localStorage/i);
    expect(html).not.toMatch(/sessionStorage/i);
    expect(html).not.toMatch(/document\.cookie/i);

    // 5. CRA download uses fetch plus a Blob and object URL
    expect(html).toContain("apiFetch('/api/fleet/compliance/cra')");
    expect(html).toContain('await res.blob()');
    expect(html).toContain('URL.createObjectURL(blob)');
    expect(html).toContain('URL.revokeObjectURL(url)');
  });

  // N2: Dashboard HTML gracefully falls back to built-in minimal cockpit when filesystem read fails
  it('N2: getDashboardHtml falls back to built-in fallback HTML when file reading fails', () => {
    const s = new FleetServer({ port: 0 });

    // Spy on fs.existsSync to simulate missing template files
    const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const htmlFallback = (s as unknown as { getDashboardHtml(): string }).getDashboardHtml();
    expect(htmlFallback).toContain('<!DOCTYPE html>');
    expect(htmlFallback).toContain('SecureShip Fleet CISO Cockpit');
    expect(htmlFallback).toContain('Dashboard active and listening for telemetry.');
    existsSpy.mockRestore();

    // Spy on fs.existsSync to throw error to exercise catch block
    const throwSpy = vi.spyOn(fs, 'existsSync').mockImplementation(() => {
      throw new Error('disk read fault');
    });
    const htmlCatch = (s as unknown as { getDashboardHtml(): string }).getDashboardHtml();
    expect(htmlCatch).toContain('<!DOCTYPE html>');
    expect(htmlCatch).toContain('SecureShip Fleet CISO Cockpit');
    throwSpy.mockRestore();
  });
});
