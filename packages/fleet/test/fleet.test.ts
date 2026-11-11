import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { FleetStore } from '../src/storage/fleet-store.js';
import { FleetServer } from '../src/server/fleet-server.js';
import {
  type FleetIngestPayload,
  type FleetRepoSummary,
  type FleetExecutiveSummary,
  type FleetPolicy,
} from '@secureship/contracts';

describe('SecureShip Fleet & CISO Cockpit Suite', () => {
  let tempDir: string;
  let tempFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fleet-test-'));
    tempFile = path.join(tempDir, 'fleet.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('FleetStore ingests repo metadata, calculates reachable-weighted risk score, and computes grade', () => {
    const store = new FleetStore({ storageFile: tempFile });

    const payload: FleetIngestPayload = {
      fleetToken: 'corp-secret-token',
      repoName: 'payments-microservice',
      branch: 'main',
      commitSha: 'a1b2c3d4e5f6',
      scannedAt: new Date().toISOString(),
      durationMs: 4200,
      summary: {
        totalRaw: 100,
        totalReported: 5,
        totalSuppressed: 95,
        bySeverity: {
          CRITICAL: 1,
          HIGH: 2,
          MEDIUM: 2,
          LOW: 0,
          INFO: 0,
        },
        byCategory: {
          SAST: 1,
          SCA: 4,
          SECRET: 0,
          IAC: 0,
        },
        byReachability: {
          REACHABLE_CALL_PATH: 1,
          UNREACHABLE: 95,
          UNKNOWN: 0,
          REACHABLE_IMPORT: 4,
        },
        reachabilitySuppressionPct: 95,
      },
      vulnerabilities: [
        {
          ruleId: 'CVE-2026-9999',
          severity: 'CRITICAL',
          category: 'SCA',
          packageName: 'express-auth',
          packageVersion: '1.0.0',
          reachability: 'REACHABLE_CALL_PATH',
          title: 'Reachable Critical RCE',
        },
        {
          ruleId: 'CVE-2026-8888',
          severity: 'HIGH',
          category: 'SCA',
          packageName: 'lodash-dev',
          packageVersion: '4.17.20',
          reachability: 'UNREACHABLE',
          title: 'Unreachable Dev High',
        },
      ],
      sbom: {
        totalComponents: 42,
        compliantCount: 42,
        nonCompliantCount: 0,
        components: [
          {
            name: 'express-auth',
            version: '1.0.0',
            ecosystem: 'npm',
            license: 'MIT',
            compliant: true,
          },
        ],
      },
    };

    const summary = store.ingest(payload);

    expect(summary.repoName).toBe('payments-microservice');
    // Score calculation: 100 - (1 reachable critical * 25) - (1 unreachable high * 2) - (2 mediums * 1) = 71 -> Grade C
    expect(summary.riskScore).toBe(71);
    expect(summary.riskGrade).toBe('C');
    expect(summary.activeCriticals).toBe(1);
    expect(summary.reachableCount).toBe(1);
    expect(summary.reachabilitySuppressionPct).toBe(95);

    // Verify persistence to disk
    expect(fs.existsSync(tempFile)).toBe(true);
    const reloaded = new FleetStore({ storageFile: tempFile });
    expect(reloaded.getRepos()).toHaveLength(1);
    expect(reloaded.getRepo('payments-microservice')?.riskScore).toBe(71);
  });

  it('FleetStore generates multi-repo Executive Summary with dead-code suppression rate', () => {
    const store = new FleetStore();

    // Ingest clean repo
    store.ingest({
      fleetToken: 'token',
      repoName: 'frontend-app',
      branch: 'main',
      commitSha: '1111111',
      scannedAt: '2026-10-24T10:00:00Z',
      durationMs: 1500,
      summary: {
        totalRaw: 50,
        totalReported: 0,
        totalSuppressed: 50,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0 },
        reachabilitySuppressionPct: 100,
      },
      vulnerabilities: [],
    });

    // Ingest moderate repo
    store.ingest({
      fleetToken: 'token',
      repoName: 'auth-service',
      branch: 'main',
      commitSha: '2222222',
      scannedAt: '2026-10-24T11:00:00Z',
      durationMs: 2500,
      summary: {
        totalRaw: 80,
        totalReported: 2,
        totalSuppressed: 78,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SCA: 1, SECRET: 0, IAC: 0 },
        reachabilitySuppressionPct: 97.5,
      },
      vulnerabilities: [
        {
          ruleId: 'SEC-101',
          severity: 'HIGH',
          category: 'SAST',
          reachability: 'REACHABLE_CALL_PATH',
        },
      ],
    });

    const exec = store.getExecutiveSummary();
    expect(exec.totalRepos).toBe(2);
    // frontend-app: 100, auth-service: 100 - (1 reachable high * 12) - 1 med = 87
    // average: (100 + 87) / 2 = 94 -> Grade A
    expect(exec.enterpriseScore).toBe(94);
    expect(exec.enterpriseGrade).toBe('A');
    expect(exec.totalCriticals).toBe(0);
    expect(exec.totalHighs).toBe(1);
    expect(exec.deadCodeSuppressionRate).toBeGreaterThan(95);
  });

  it('FleetStore searches global SBOM across all monitored repositories', () => {
    const store = new FleetStore();

    store.ingest({
      fleetToken: 'token',
      repoName: 'service-alpha',
      branch: 'main',
      commitSha: 'aaa',
      scannedAt: new Date().toISOString(),
      durationMs: 1000,
      summary: {
        totalRaw: 10,
        totalReported: 0,
        totalSuppressed: 10,
        reachabilitySuppressionPct: 100,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      },
      vulnerabilities: [],
      sbom: {
        totalComponents: 2,
        compliantCount: 2,
        nonCompliantCount: 0,
        components: [
          { name: 'fast-uri', version: '3.1.8', ecosystem: 'npm', license: 'MIT', compliant: true },
          { name: 'tinypool', version: '1.1.1', ecosystem: 'npm', license: 'MIT', compliant: true },
        ],
      },
    });

    const match = store.searchSbom('tinypool');
    expect(match).toHaveLength(1);
    expect(match[0]?.repo).toBe('service-alpha');
    expect(match[0]?.component.name).toBe('tinypool');

    const empty = store.searchSbom('non-existent-package');
    expect(empty).toHaveLength(0);
  });

  it('FleetStore generates EU Cyber Resilience Act (CRA) CycloneDX 1.5 compliance report', () => {
    const store = new FleetStore();

    store.ingest({
      fleetToken: 'token',
      repoName: 'core-banking',
      branch: 'main',
      commitSha: '999999',
      scannedAt: new Date().toISOString(),
      durationMs: 1000,
      summary: {
        totalRaw: 10,
        totalReported: 0,
        totalSuppressed: 10,
        reachabilitySuppressionPct: 100,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      },
      vulnerabilities: [],
      sbom: {
        totalComponents: 1,
        compliantCount: 1,
        nonCompliantCount: 0,
        components: [
          {
            name: 'crypto-shield',
            version: '2.0.0',
            ecosystem: 'npm',
            license: 'Apache-2.0',
            compliant: true,
          },
        ],
      },
    });

    const report = store.generateCraComplianceReport() as {
      bomFormat: string;
      specVersion: string;
      declarations: { attestations: Array<{ summary: string }> };
    };

    expect(report.bomFormat).toBe('CycloneDX');
    expect(report.specVersion).toBe('1.5');
    expect(report.declarations.attestations[0]?.summary).toContain('EU Cyber Resilience Act');
  });

  it('FleetServer starts, serves endpoints, ingests telemetry, and responds with CISO cockpit', async () => {
    const store = new FleetStore();
    const server = new FleetServer({ port: 0, store, authToken: 'test-fleet-token' });
    const port = await server.start();
    expect(port).toBeGreaterThan(0);

    const baseUrl = `http://127.0.0.1:${port}`;
    const authHeaders = { Authorization: 'Bearer test-fleet-token' };

    // 1. Ingest valid telemetry (using body fleetToken)
    const ingestPayload: FleetIngestPayload = {
      fleetToken: 'test-fleet-token',
      repoName: 'api-gateway',
      branch: 'prod',
      commitSha: 'def456',
      scannedAt: new Date().toISOString(),
      durationMs: 1800,
      summary: {
        totalRaw: 40,
        totalReported: 1,
        totalSuppressed: 39,
        reachabilitySuppressionPct: 97.5,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
        byReachability: { REACHABLE_IMPORT: 1, UNREACHABLE: 39 },
      },
      vulnerabilities: [
        {
          ruleId: 'CVE-2026-0001',
          severity: 'HIGH',
          category: 'SCA',
          packageName: 'axios',
          packageVersion: '0.21.1',
          reachability: 'REACHABLE_IMPORT',
        },
      ],
    };

    const postRes = await fetch(`${baseUrl}/api/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ingestPayload),
    });
    expect(postRes.status).toBe(200);
    const postJson = (await postRes.json()) as { status: string; repo: FleetRepoSummary };
    expect(postJson.status).toBe('success');
    expect(postJson.repo.repoName).toBe('api-gateway');

    // 2. Query summary with Authorization header
    const sumRes = await fetch(`${baseUrl}/api/fleet/summary`, { headers: authHeaders });
    expect(sumRes.status).toBe(200);
    const sumJson = (await sumRes.json()) as FleetExecutiveSummary;
    expect(sumJson.totalRepos).toBe(1);

    // 3. Query repos with Authorization header
    const reposRes = await fetch(`${baseUrl}/api/fleet/repos`, { headers: authHeaders });
    expect(reposRes.status).toBe(200);
    const reposJson = (await reposRes.json()) as FleetRepoSummary[];
    expect(reposJson).toHaveLength(1);

    // 4. Download CRA report with Authorization header
    const craRes = await fetch(`${baseUrl}/api/fleet/compliance/cra`, { headers: authHeaders });
    expect(craRes.status).toBe(200);
    expect(craRes.headers.get('content-type')).toContain('application/json');
    const craJson = (await craRes.json()) as { bomFormat: string; specVersion: string };
    expect(craJson.bomFormat).toBe('CycloneDX');

    // 5. Query and update policy with Authorization header
    const policyGet = await fetch(`${baseUrl}/api/policy`, { headers: authHeaders });
    expect(policyGet.status).toBe(200);
    const policyPost = await fetch(`${baseUrl}/api/policy`, {
      method: 'POST',
      headers: { ...authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ failOnSeverity: 'CRITICAL' }),
    });
    expect(policyPost.status).toBe(200);
    const updatedPolicy = (await policyPost.json()) as FleetPolicy;
    expect(updatedPolicy.failOnSeverity).toBe('CRITICAL');

    // 6. Serve HTML Cockpit (unauthenticated)
    const htmlRes = await fetch(`${baseUrl}/`);
    expect(htmlRes.status).toBe(200);
    expect(htmlRes.headers.get('content-type')).toContain('text/html');
    const htmlText = await htmlRes.text();
    expect(htmlText).toContain('SecureShip Fleet');

    await server.stop();
  });

  it('FleetServer requires authentication for /api/* routes when authToken is configured', async () => {
    const store = new FleetStore();
    const server = new FleetServer({ port: 0, store, authToken: 'correct-token' });
    const port = await server.start();
    const baseUrl = `http://127.0.0.1:${port}`;

    // Missing token
    const noAuthRes = await fetch(`${baseUrl}/api/fleet/summary`);
    expect(noAuthRes.status).toBe(401);
    expect(noAuthRes.headers.get('www-authenticate')).toBe('Bearer');

    // Wrong token
    const wrongAuthRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      headers: { Authorization: 'Bearer bad-token' },
    });
    expect(wrongAuthRes.status).toBe(401);

    // Query param token is forbidden (D11)
    const queryTokenRes = await fetch(`${baseUrl}/api/fleet/summary?authToken=correct-token`);
    expect(queryTokenRes.status).toBe(401);

    // x-fleet-token alternative header works
    const xTokenRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      headers: { 'x-fleet-token': 'correct-token' },
    });
    expect(xTokenRes.status).toBe(200);

    // POST /api/ingest with Authorization header and empty fleetToken in body works (D10)
    const ingestRes = await fetch(`${baseUrl}/api/ingest`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer correct-token',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fleetToken: '',
        repoName: 'auth-header-repo',
        branch: 'main',
        commitSha: '1234567',
        scannedAt: new Date().toISOString(),
        durationMs: 500,
        summary: {
          totalRaw: 0,
          totalReported: 0,
          totalSuppressed: 0,
          reachabilitySuppressionPct: 0,
          bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
          byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
        },
        vulnerabilities: [],
      }),
    });
    expect(ingestRes.status).toBe(200);

    await server.stop();
  });

  it('FleetServer enforces Content-Type application/json on POST requests', async () => {
    const store = new FleetStore();
    const server = new FleetServer({ port: 0, store, authToken: 'test-token' });
    const port = await server.start();
    const baseUrl = `http://127.0.0.1:${port}`;
    const headers = { Authorization: 'Bearer test-token' };

    // POST with text/plain rejected with 415
    const textPlainRes = await fetch(`${baseUrl}/api/policy`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'text/plain' },
      body: JSON.stringify({ failOnSeverity: 'CRITICAL' }),
    });
    expect(textPlainRes.status).toBe(415);

    // POST without Content-Type rejected with 415
    const noContentTypeRes = await fetch(`${baseUrl}/api/policy`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ failOnSeverity: 'CRITICAL' }),
    });
    expect(noContentTypeRes.status).toBe(415);

    // POST with non-object JSON body rejected with 400
    const nonObjectRes = await fetch(`${baseUrl}/api/policy`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify('scalar-string'),
    });
    expect(nonObjectRes.status).toBe(400);

    await server.stop();
  });

  it('FleetServer rejects malicious origins and enforces allowedOrigins whitelist', async () => {
    const store = new FleetStore();
    const server = new FleetServer({
      port: 0,
      store,
      authToken: 'test-token',
      allowedOrigins: ['http://localhost:3000', 'https://ciso.internal.corp'],
    });
    const port = await server.start();
    const baseUrl = `http://127.0.0.1:${port}`;
    const authHeaders = { Authorization: 'Bearer test-token' };

    // Disallowed origin on preflight OPTIONS returns 403 and NO Access-Control-Allow-Origin
    const evilOptionsRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'GET',
      },
    });
    expect(evilOptionsRes.status).toBe(403);
    expect(evilOptionsRes.headers.get('access-control-allow-origin')).toBeNull();

    // Disallowed origin on GET /api/* returns 403 and NO Access-Control-Allow-Origin
    const evilGetRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      headers: {
        ...authHeaders,
        Origin: 'https://evil-attacker.com',
      },
    });
    expect(evilGetRes.status).toBe(403);
    expect(evilGetRes.headers.get('access-control-allow-origin')).toBeNull();

    // Literal 'null' origin returns 403
    const nullOriginRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      headers: {
        ...authHeaders,
        Origin: 'null',
      },
    });
    expect(nullOriginRes.status).toBe(403);
    expect(nullOriginRes.headers.get('access-control-allow-origin')).toBeNull();

    // Cross-scheme HTTPS origin against unencrypted HTTP server is rejected when not in allowedOrigins
    const httpsSchemeRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      headers: {
        ...authHeaders,
        Origin: `https://127.0.0.1:${port}`,
      },
    });
    expect(httpsSchemeRes.status).toBe(403);
    expect(httpsSchemeRes.headers.get('access-control-allow-origin')).toBeNull();

    // Allowed origin on preflight OPTIONS returns 204 with echoed Access-Control-Allow-Origin
    const goodOptionsRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:3000',
        'Access-Control-Request-Method': 'GET',
      },
    });
    expect(goodOptionsRes.status).toBe(204);
    expect(goodOptionsRes.headers.get('access-control-allow-origin')).toBe('http://localhost:3000');

    // Allowed origin on GET /api/* returns 200 with echoed Access-Control-Allow-Origin
    const goodGetRes = await fetch(`${baseUrl}/api/fleet/summary`, {
      headers: {
        ...authHeaders,
        Origin: 'http://localhost:3000',
      },
    });
    expect(goodGetRes.status).toBe(200);
    expect(goodGetRes.headers.get('access-control-allow-origin')).toBe('http://localhost:3000');

    await server.stop();
  });

  it('FleetServer rejects DNS rebinding and forged Host headers', async () => {
    const store = new FleetStore();
    const server = new FleetServer({ port: 0, store, authToken: 'test-token' });
    const port = await server.start();

    // Forged Host header returns 403 Forbidden host
    const res = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/fleet/summary',
          method: 'GET',
          headers: {
            Host: 'evil-attacker.internal.domain:4000',
            Authorization: 'Bearer test-token',
          },
        },
        (resp) => {
          let data = '';
          resp.on('data', (chunk) => {
            data += chunk;
          });
          resp.on('end', () => {
            resolve({ statusCode: resp.statusCode ?? 0, body: data });
          });
        }
      );
      req.on('error', reject);
      req.end();
    });

    expect(res.statusCode).toBe(403);
    const parsed = JSON.parse(res.body) as { error: string };
    expect(parsed.error).toBe('Forbidden host');

    await server.stop();
  });

  it('FleetServer validates configuration fail-closed', async () => {
    // Wildcard origin is rejected
    expect(() => new FleetServer({ allowedOrigins: ['*'] })).toThrow(
      "Wildcard '*' origin is not allowed in allowedOrigins"
    );

    // Invalid origin scheme is rejected
    expect(() => new FleetServer({ allowedOrigins: ['ftp://bad-origin.com'] })).toThrow(
      'Invalid origin in allowedOrigins'
    );

    // Non-loopback host without authToken cannot be started
    const insecureServer = new FleetServer({ host: '0.0.0.0', port: 0 });
    await expect(insecureServer.start()).rejects.toThrow(
      "Insecure deployment: non-loopback host '0.0.0.0' requires authToken to be configured"
    );
  });
});
