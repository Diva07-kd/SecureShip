/**
 * Standalone reproduction scripts for Report-Only Defects (3.a - 3.e)
 * NOT to be committed as passing product tests (to avoid enshrining defects).
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  FleetStore,
  resolveFleetToken,
  buildFleetRuntimeConfig,
} from '../../packages/fleet/dist/index.js';
import type { FleetIngestPayload } from '@secureship/contracts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * 3.a Repo-resident config trust: secureship.config.json in a scanned target repo can define
 * fleet.reportTo, fleet.policySync, and fleet.fleetToken.
 */
export function reproDefect3a(): boolean {
  const scanCmdPath = path.resolve(__dirname, '../../packages/cli/src/commands/scan.ts');
  if (!fs.existsSync(scanCmdPath)) return false;
  const content = fs.readFileSync(scanCmdPath, 'utf-8');
  return content.includes('config.fleet?.reportTo') && content.includes('config.fleet?.fleetToken');
}

/**
 * 3.b packages/cli/src/commands/scan.ts exposes --fleet-token on argv without --fleet-token-file alternative.
 */
export function reproDefect3b(): boolean {
  const cliIndexPath = path.resolve(__dirname, '../../packages/cli/src/index.ts');
  const content = fs.readFileSync(cliIndexPath, 'utf-8');
  const hasArgvToken = content.includes(".option('--fleet-token <token>'");
  const hasTokenFile = content.includes(".option('--fleet-token-file");
  return hasArgvToken && !hasTokenFile;
}

/**
 * 3.c FleetStore creates fleet-db.json with default umask (world-readable on POSIX hosts).
 */
export function reproDefect3c(): boolean {
  if (process.platform === 'win32') return true;
  const tmp = path.join(os.tmpdir(), 'fleet-db-test.json');
  const store = new FleetStore({ storageFile: tmp });
  const payload: FleetIngestPayload = {
    fleetToken: 'test-token',
    repoName: 'test-repo',
    branch: 'main',
    commitSha: 'a'.repeat(40),
    scannedAt: new Date().toISOString(),
    durationMs: 120,
    summary: {
      totalRaw: 1,
      totalReported: 1,
      totalSuppressed: 0,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 1, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      reachabilitySuppressionPct: 0,
    },
    vulnerabilities: [],
  };
  store.ingest(payload);
  const mode = fs.statSync(tmp).mode & 0o777;
  fs.unlinkSync(tmp);
  return mode !== 0o600;
}

/**
 * 3.d FleetServer does not support in-process TLS termination (requires reverse proxy).
 */
export function reproDefect3d(): boolean {
  const serverPath = path.resolve(__dirname, '../../packages/fleet/src/server/fleet-server.ts');
  const serverCode = fs.readFileSync(serverPath, 'utf-8');
  return (
    serverCode.includes("import http from 'node:http'") &&
    !serverCode.includes("import https from 'node:https'")
  );
}

/**
 * 3.e Empty-string env vars (FLEET_PORT='', FLEET_HOST='') fall back to defaults rather than erroring.
 */
export async function reproDefect3e(): Promise<boolean> {
  const resolved = await resolveFleetToken({ env: { FLEET_TOKEN: '' }, homeDir: '' });
  const config = await buildFleetRuntimeConfig({ env: { FLEET_PORT: '', FLEET_HOST: '' } });
  return resolved.token !== undefined && config.port === 4000 && config.host === '127.0.0.1';
}

async function main() {
  console.log('--- SecureShip Fleet Report-Only Defect Reproductions ---');
  console.log('3.a Repo-resident config trust      :', reproDefect3a());
  console.log('3.b Scan argv token exposure        :', reproDefect3b());
  console.log('3.c World-readable fleet-db.json    :', reproDefect3c());
  console.log('3.d Plain HTTP Fleet server         :', reproDefect3d());
  console.log('3.e Empty env fallback to defaults  :', await reproDefect3e());
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  main().catch(console.error);
}
