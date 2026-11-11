import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FleetStore } from '../src/storage/fleet-store.js';
import { FleetServer } from '../src/server/fleet-server.js';

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
    overrideHost?: string;
  }
): Promise<RawHttpResponse> {
  return new Promise((resolve, reject) => {
    const reqHeaders: Record<string, string | number> = {};
    if (options.headers) {
      for (const [k, v] of Object.entries(options.headers)) {
        if (v !== undefined) {
          reqHeaders[k] = v;
        }
      }
    }

    if (options.overrideHost !== undefined) {
      reqHeaders['Host'] = options.overrideHost;
    } else if (!reqHeaders['Host'] && !reqHeaders['host']) {
      reqHeaders['Host'] = `127.0.0.1:${port}`;
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
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            body: data,
          });
        });
      }
    );

    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

describe('LAYER J: Fleet CORS Hardening (DEV-7)', () => {
  let tempDir: string;
  let tempFile: string;
  let store: FleetStore;
  let server: FleetServer;
  let port: number;

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fleet-j-'));
    tempFile = path.join(tempDir, 'fleet.json');
    store = new FleetStore({ storageFile: tempFile });
    server = new FleetServer({
      port: 0,
      store,
      authToken: 'test-fleet-token-secret-123',
    });
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // J1: Allowed origins get exact ACAO, Vary: Origin, and exact Allow-Methods / Allow-Headers
  it('J1: allowed origins receive exact echoed ACAO, Vary: Origin, and CORS allow headers', async () => {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://localhost:3000',
      'http://127.0.0.1:5173',
      'http://[::1]:8080',
    ];

    for (const origin of allowedOrigins) {
      const res = await rawRequest(port, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Origin: origin,
          Authorization: 'Bearer test-fleet-token-secret-123',
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe(origin);
      expect(res.headers['vary']).toBe('Origin');
      expect(res.headers['access-control-allow-methods']).toBe('GET, POST, OPTIONS');
      expect(res.headers['access-control-allow-headers']).toBe(
        'Content-Type, Authorization, x-fleet-token'
      );
    }
  });

  // J2: Rejected origins get NO ACAO header and 403 on /api/*
  it('J2: rejected origins receive 403 on /api/* and NO Access-Control-Allow-Origin header', async () => {
    const rejectedOrigins = [
      'https://evil-attacker.com',
      'http://localhost.evil.com',
      'http://127.0.0.1.evil.com',
      'null',
      'http://localhost:3000/', // Trailing slash is invalid origin format
      'ftp://localhost',
      '', // Empty string
    ];

    for (const origin of rejectedOrigins) {
      const res = await rawRequest(port, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Origin: origin,
          Authorization: 'Bearer test-fleet-token-secret-123',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      const body = JSON.parse(res.body) as { error: string };
      expect(body.error).toBe('Origin not allowed');
    }
  });

  // J3: No response in any test carries ACAO '*' or Access-Control-Allow-Credentials
  it('J3: responses never carry wildcard Access-Control-Allow-Origin or Allow-Credentials', async () => {
    const paths = ['/', '/dashboard', '/api/fleet/summary', '/api/policy', '/api/unknown'];
    for (const p of paths) {
      const res = await rawRequest(port, {
        method: 'GET',
        path: p,
        headers: {
          Authorization: 'Bearer test-fleet-token-secret-123',
        },
      });

      expect(res.headers['access-control-allow-origin']).not.toBe('*');
      expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    }
  });

  // J4: OPTIONS preflights
  it('J4: OPTIONS preflight gives 204 for allowed origin, 403 for disallowed origin, and 204 without CORS headers when no Origin', async () => {
    // 1. Allowed origin OPTIONS -> 204 with CORS headers
    const allowedRes = await rawRequest(port, {
      method: 'OPTIONS',
      path: '/api/fleet/summary',
      headers: {
        Origin: 'http://localhost:3000',
      },
    });
    expect(allowedRes.statusCode).toBe(204);
    expect(allowedRes.headers['access-control-allow-origin']).toBe('http://localhost:3000');
    expect(allowedRes.headers['access-control-allow-methods']).toBe('GET, POST, OPTIONS');

    // 2. Disallowed origin OPTIONS -> 403 with NO ACAO header
    const disallowedRes = await rawRequest(port, {
      method: 'OPTIONS',
      path: '/api/fleet/summary',
      headers: {
        Origin: 'https://evil.example',
      },
    });
    expect(disallowedRes.statusCode).toBe(403);
    expect(disallowedRes.headers['access-control-allow-origin']).toBeUndefined();

    // 3. No Origin OPTIONS -> 204 without CORS headers
    const noOriginRes = await rawRequest(port, {
      method: 'OPTIONS',
      path: '/api/fleet/summary',
    });
    expect(noOriginRes.statusCode).toBe(204);
    expect(noOriginRes.headers['access-control-allow-origin']).toBeUndefined();
  });

  // J5: Custom allowedOrigins
  it('J5: custom allowedOrigins permits specified origin and same-origin dashboard, while rejecting default origins', async () => {
    const customServer = new FleetServer({
      port: 0,
      store,
      authToken: 'corp-auth-tok',
      allowedOrigins: ['https://dash.corp.example'],
      allowedHosts: ['dash.corp.example'],
    });
    const cPort = await customServer.start();

    try {
      // 1. Configured custom origin is allowed
      const resCustom = await rawRequest(cPort, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Origin: 'https://dash.corp.example',
          Host: `dash.corp.example:${cPort}`,
          Authorization: 'Bearer corp-auth-tok',
        },
      });
      expect(resCustom.statusCode).toBe(200);
      expect(resCustom.headers['access-control-allow-origin']).toBe('https://dash.corp.example');

      // 2. Default localhost:3000 is NOT allowed when custom allowedOrigins is configured
      const resLocal = await rawRequest(cPort, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Origin: 'http://localhost:3000',
          Host: `dash.corp.example:${cPort}`,
          Authorization: 'Bearer corp-auth-tok',
        },
      });
      expect(resLocal.statusCode).toBe(403);
      expect(resLocal.headers['access-control-allow-origin']).toBeUndefined();

      // 3. Same-origin dashboard request (Origin equal to http://<Host>) IS allowed
      const sameOrigin = `http://127.0.0.1:${cPort}`;
      const resSame = await rawRequest(cPort, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Origin: sameOrigin,
          Host: `127.0.0.1:${cPort}`,
          Authorization: 'Bearer corp-auth-tok',
        },
      });
      expect(resSame.statusCode).toBe(200);
      expect(resSame.headers['access-control-allow-origin']).toBe(sameOrigin);
    } finally {
      await customServer.stop();
    }
  });

  // J6: Constructor validation
  it('J6: constructor throws fail-closed for hostile or invalid allowedOrigins entries', () => {
    const hostileOrigins = [
      '*',
      'https://x.example/', // Trailing slash
      'x.example', // Missing scheme
      'javascript:alert(1)', // Dangerous pseudo-protocol
      'data:text/html,evil',
      'ftp://corp.internal',
    ];

    for (const origin of hostileOrigins) {
      expect(() => {
        new FleetServer({ allowedOrigins: [origin] });
      }).toThrow();
    }
  });
});

describe('LAYER K: CSRF & DNS-Rebinding Hardening (DEV-7)', () => {
  let tempDir: string;
  let tempFile: string;
  let store: FleetStore;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fleet-k-'));
    tempFile = path.join(tempDir, 'fleet.json');
    store = new FleetStore({ storageFile: tempFile });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // K1: Simple-request CSRF: POST /api/policy with text/plain and evil origin -> 403, policy unchanged
  it('K1: simple-request CSRF via text/plain and malicious origin returns 403 and leaves policy unchanged', async () => {
    const initialPolicy = store.getPolicy();

    // 1. Run with authToken unset
    const serverNoToken = new FleetServer({ port: 0, store });
    const portNoToken = await serverNoToken.start();

    try {
      const resNoToken = await rawRequest(portNoToken, {
        method: 'POST',
        path: '/api/policy',
        headers: {
          'Content-Type': 'text/plain',
          Origin: 'https://evil.example',
        },
        body: JSON.stringify({ failOnSeverity: 'NONE' }),
      });
      expect(resNoToken.statusCode).toBe(403);
      expect(store.getPolicy()).toEqual(initialPolicy);
    } finally {
      await serverNoToken.stop();
    }

    // 2. Run with authToken set
    const serverWithToken = new FleetServer({ port: 0, store, authToken: 'sec-tok-k1' });
    const portWithToken = await serverWithToken.start();

    try {
      const resWithToken = await rawRequest(portWithToken, {
        method: 'POST',
        path: '/api/policy',
        headers: {
          'Content-Type': 'text/plain',
          Origin: 'https://evil.example',
          Authorization: 'Bearer sec-tok-k1',
        },
        body: JSON.stringify({ failOnSeverity: 'NONE' }),
      });
      expect(resWithToken.statusCode).toBe(403);
      expect(store.getPolicy()).toEqual(initialPolicy);
    } finally {
      await serverWithToken.stop();
    }
  });

  // K2: Non-JSON Content-Type rejected with 415; application/json accepted
  it('K2: POST with text/plain gives 415 and leaves policy unchanged; application/json is accepted', async () => {
    const server = new FleetServer({ port: 0, store, authToken: 'sec-tok-k2' });
    const port = await server.start();
    const initialPolicy = store.getPolicy();

    try {
      // 1. No Origin, text/plain -> 415
      const resTextPlain = await rawRequest(port, {
        method: 'POST',
        path: '/api/policy',
        headers: {
          'Content-Type': 'text/plain',
          Authorization: 'Bearer sec-tok-k2',
        },
        body: JSON.stringify({ failOnSeverity: 'NONE' }),
      });
      expect(resTextPlain.statusCode).toBe(415);
      expect(store.getPolicy()).toEqual(initialPolicy);

      // 2. No Origin, application/json; charset=utf-8 -> accepted (200)
      const resJson = await rawRequest(port, {
        method: 'POST',
        path: '/api/policy',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Authorization: 'Bearer sec-tok-k2',
        },
        body: JSON.stringify({ failOnSeverity: 'CRITICAL' }),
      });
      expect(resJson.statusCode).toBe(200);
      expect(store.getPolicy().failOnSeverity).toBe('CRITICAL');
    } finally {
      await server.stop();
    }
  });

  // K3: DNS rebinding: Host: evil.example:PORT -> 403 Forbidden host with no store method called
  it('K3: DNS-rebinding request with forged Host returns 403 and never invokes store methods', async () => {
    const updateSpy = vi.spyOn(store, 'updatePolicy');
    const getSummarySpy = vi.spyOn(store, 'getExecutiveSummary');

    const server = new FleetServer({
      port: 0,
      store,
      authToken: 'sec-tok-k3',
      allowedHosts: ['corp-allowed.example.com'],
    });
    const port = await server.start();

    try {
      // 1. Rebound host header evil.example:PORT -> 403 Forbidden host
      const resEvil = await rawRequest(port, {
        method: 'GET',
        path: '/api/fleet/summary',
        overrideHost: `evil.example:${port}`,
        headers: {
          Origin: `http://evil.example:${port}`,
          Authorization: 'Bearer sec-tok-k3',
        },
      });
      expect(resEvil.statusCode).toBe(403);
      const evilJson = JSON.parse(resEvil.body) as { error: string };
      expect(evilJson.error).toBe('Forbidden host');
      expect(getSummarySpy).not.toHaveBeenCalled();
      expect(updateSpy).not.toHaveBeenCalled();

      // 2. Allowed loopback hosts return 200
      const allowedHosts = [
        `localhost:${port}`,
        `127.0.0.1:${port}`,
        `[::1]:${port}`,
        `corp-allowed.example.com:${port}`,
      ];

      for (const h of allowedHosts) {
        const resAllowed = await rawRequest(port, {
          method: 'GET',
          path: '/api/fleet/summary',
          overrideHost: h,
          headers: {
            Authorization: 'Bearer sec-tok-k3',
          },
        });
        expect(resAllowed.statusCode).toBe(200);
      }

      // 3. Missing host header -> rejected 403
      const resMissingHost = await new Promise<RawHttpResponse>((resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port,
            path: '/api/fleet/summary',
            method: 'GET',
            headers: {
              Authorization: 'Bearer sec-tok-k3',
            },
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
        // Remove Host header
        req.removeHeader('host');
        req.end();
      });
      // Missing Host header is rejected (400 by HTTP/1.1 parser or 403 by host validator)
      expect([400, 403]).toContain(resMissingHost.statusCode);
    } finally {
      await server.stop();
    }
  });

  // K4: Backward compatibility with authToken UNSET on loopback: local clients work while browser attacks remain blocked
  it('K4: unauthenticated loopback server allows local CLI clients while blocking browser attacks', async () => {
    const server = new FleetServer({ port: 0, store }); // No authToken
    const port = await server.start();

    try {
      // 1. Normal local CLI client (no Origin, JSON) works
      const resLocal = await rawRequest(port, {
        method: 'GET',
        path: '/api/fleet/summary',
      });
      expect(resLocal.statusCode).toBe(200);

      // 2. Browser attack with malicious Origin is STILL blocked with 403
      const resAttackOrigin = await rawRequest(port, {
        method: 'GET',
        path: '/api/fleet/summary',
        headers: {
          Origin: 'https://evil-browser-site.org',
        },
      });
      expect(resAttackOrigin.statusCode).toBe(403);

      // 3. DNS rebinding is STILL blocked with 403
      const resAttackHost = await rawRequest(port, {
        method: 'GET',
        path: '/api/fleet/summary',
        overrideHost: `evil.com:${port}`,
      });
      expect(resAttackHost.statusCode).toBe(403);
    } finally {
      await server.stop();
    }
  });

  // K5: Non-loopback host requires authToken; loopback succeeds without token
  it('K5: non-loopback host rejects start() if authToken is unset; succeeds when authToken is set', async () => {
    // 1. 0.0.0.0 without authToken rejects
    const serverInsecure0 = new FleetServer({ host: '0.0.0.0', port: 0 });
    await expect(serverInsecure0.start()).rejects.toThrow(
      "Insecure deployment: non-loopback host '0.0.0.0' requires authToken to be configured"
    );

    // 2. 10.0.0.5 without authToken rejects
    const serverInsecure10 = new FleetServer({ host: '10.0.0.5', port: 0 });
    await expect(serverInsecure10.start()).rejects.toThrow(
      "Insecure deployment: non-loopback host '10.0.0.5' requires authToken to be configured"
    );

    // 3. Loopback 127.0.0.1 without authToken succeeds
    const serverLoopback = new FleetServer({ host: '127.0.0.1', port: 0 });
    const p1 = await serverLoopback.start();
    expect(p1).toBeGreaterThan(0);
    await serverLoopback.stop();

    // 4. 0.0.0.0 WITH authToken succeeds
    const serverSecure = new FleetServer({
      host: '0.0.0.0',
      port: 0,
      authToken: 'valid-secret-token',
    });
    const p2 = await serverSecure.start();
    expect(p2).toBeGreaterThan(0);
    await serverSecure.stop();
  });
});
