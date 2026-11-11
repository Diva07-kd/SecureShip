import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FleetServer, FleetStore } from '@secureship/fleet';
import { FleetClient } from '../src/utils/fleet-client.js';
import { FleetCommand } from '../src/commands/fleet.js';
import type { ScanReport } from '@secureship/contracts';

describe('SecureShip Fleet CLI & Telemetry E2E Suite (Phase 6)', () => {
  let tempDir: string;
  let tempDb: string;
  let server: FleetServer;
  let serverUrl: string;
  const token = 'corporate-fleet-secret-key-42';

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fleet-cli-test-'));
    tempDb = path.join(tempDir, 'fleet-db.json');

    const store = new FleetStore({ storageFile: tempDb, dbPath: tempDb });
    server = new FleetServer({
      port: 0,
      host: '127.0.0.1',
      store,
      authToken: token,
    });

    const port = await server.start();
    serverUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    await server.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('FleetClient pushes zero-code telemetry with HMAC-SHA256 signature to Fleet server', async () => {
    const dummyReport = {
      schemaVersion: '1.2' as const,
      target: tempDir,
      mode: 'FULL' as const,
      durationMs: 3100,
      timestamp: new Date().toISOString(),
      tool: { name: 'secureship', version: '1.0.0-beta.1' },
      scanners: [
        {
          name: 'opengrep' as const,
          status: 'SUCCESS' as const,
          durationMs: 1200,
          rawFindingCount: 1,
        },
      ],
      findings: [
        {
          id: 'test-1',
          ruleId: 'SS-SAST-001',
          severity: 'HIGH' as const,
          category: 'SAST' as const,
          title: 'Direct command injection',
          description: 'Untrusted user input executed directly',
          location: {
            filePath: 'src/handler.ts',
            startLine: 14,
            endLine: 14,
          },
          reachability: 'REACHABLE_CALL_PATH' as const,
          confidence: 'HIGH' as const,
        },
      ],
      suppressed: [],
      summary: {
        totalRaw: 1,
        totalReported: 1,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        suppressedByReason: {},
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      },
    } as unknown as ScanReport;

    const result = await FleetClient.pushTelemetry({
      targetDir: tempDir,
      report: dummyReport,
      fleetUrl: serverUrl,
      fleetToken: token,
      repoName: 'billing-api',
      isJson: true,
    });

    expect(result.success).toBe(true);
    expect(result.repoSummary).toBeDefined();
    expect(result.repoSummary?.repoName).toBe('billing-api');
    expect(result.repoSummary?.riskGrade).toBe('B');
    expect(result.repoSummary?.riskScore).toBe(88); // 100 - (1 reachable high * 12) = 88
    expect(result.repoSummary?.signature).toBeDefined();
  });

  it('FleetCommand.status queries executive summary and prints status successfully', async () => {
    // 1. Ingest a repo first
    const dummyReport = {
      schemaVersion: '1.2' as const,
      target: tempDir,
      mode: 'FULL' as const,
      durationMs: 1200,
      timestamp: new Date().toISOString(),
      tool: { name: 'secureship', version: '1.0.0-beta.1' },
      scanners: [],
      findings: [],
      suppressed: [],
      summary: {
        totalRaw: 10,
        totalReported: 0,
        totalSuppressed: 10,
        totalOutOfScope: 0,
        suppressedByReason: {},
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      },
    } as unknown as ScanReport;

    await FleetClient.pushTelemetry({
      targetDir: tempDir,
      report: dummyReport,
      fleetUrl: serverUrl,
      fleetToken: token,
      repoName: 'clean-frontend',
      isJson: true,
    });

    // 2. Query status via FleetCommand
    const exitCode = await FleetCommand.status({
      endpoint: serverUrl,
      token,
      json: true,
    });

    expect(exitCode).toBe(0);
  });

  it('FleetCommand.exportCra downloads valid EU CRA CycloneDX 1.5 JSON report', async () => {
    const craOutputFile = path.join(tempDir, 'test-cra-report.json');

    const exitCode = await FleetCommand.exportCra({
      endpoint: serverUrl,
      token,
      output: craOutputFile,
    });

    expect(exitCode).toBe(0);
    expect(fs.existsSync(craOutputFile)).toBe(true);

    const reportContent = JSON.parse(fs.readFileSync(craOutputFile, 'utf-8'));
    expect(reportContent.bomFormat).toBe('CycloneDX');
    expect(reportContent.specVersion).toBe('1.5');
    expect(reportContent.metadata.properties).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'cra:regulation' })])
    );
  });

  it('FleetServer rejects unauthorized telemetry missing valid token', async () => {
    const dummyReport = {
      schemaVersion: '1.2' as const,
      target: tempDir,
      mode: 'FULL' as const,
      durationMs: 500,
      timestamp: new Date().toISOString(),
      tool: { name: 'secureship', version: '1.0.0' },
      scanners: [],
      findings: [],
      suppressed: [],
      summary: {
        totalRaw: 0,
        totalReported: 0,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        suppressedByReason: {},
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      },
    } as unknown as ScanReport;

    const result = await FleetClient.pushTelemetry({
      targetDir: tempDir,
      report: dummyReport,
      fleetUrl: serverUrl,
      fleetToken: 'wrong-invalid-token',
      repoName: 'unauthorized-repo',
      isJson: true,
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('401');
  });
});
