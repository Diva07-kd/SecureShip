import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { DoctorCommand } from '../src/commands/doctor.js';

describe('Doctor Command Phase C Enhancements (WP-C2)', () => {
  let tempHome: string;
  let tempDb: string;
  let stdoutOutput: string[] = [];
  const originalEnv = { ...process.env };
  const originalLog = console.log;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-doctor-home-'));
    tempDb = path.join(tempHome, 'db');
    fs.mkdirSync(tempDb, { recursive: true });

    process.env.SECURESHIP_HOME = tempHome;
    process.env.SECURESHIP_DB_DIR = tempDb;

    stdoutOutput = [];
    console.log = vi.fn((...args: unknown[]) => {
      stdoutOutput.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    console.log = originalLog;
    process.env = { ...originalEnv };
    try {
      fs.rmSync(tempHome, { recursive: true, force: true });
    } catch {}
  });

  it('prints container status, process identity, and storage directories with writability', async () => {
    delete process.env.SECURESHIP_CONTAINER;
    await DoctorCommand.run();

    const output = stdoutOutput.join('\n');
    expect(output).toContain('SecureShip Environment & Security Doctor');
    expect(output).toContain('OS Platform:');
    expect(output).toContain('Container:');
    expect(output).toContain('Process ID:');
    expect(output).toContain('SecureShip Storage Directories:');
    expect(output).toContain('SECURESHIP_HOME');
    expect(output).toContain('Tool Candidate Dirs');
    expect(output).toContain('Vulnerability DB Dir');
    expect(output).toContain('Writable ✔');
    expect(output).toContain('Offline Vulnerability Database:');
  });

  it('detects container environment when SECURESHIP_CONTAINER=1', async () => {
    process.env.SECURESHIP_CONTAINER = '1';
    await DoctorCommand.run();

    const output = stdoutOutput.join('\n');
    expect(output).toContain('Container Detected');
  });

  it('displays offline DB details when CURRENT pointer and manifest are present', async () => {
    const generationId = 'gen-20261026-test';
    const genDir = path.join(tempDb, 'generations', generationId);
    fs.mkdirSync(genDir, { recursive: true });

    const manifest = {
      schemaVersion: '1.0',
      bundleId: 'bundle-20261026-offline',
      createdAt: '2026-10-26T12:00:00.000Z',
      upstreamUpdatedAt: '2026-10-26T10:00:00.000Z',
      importedAt: '2026-10-26T12:05:00.000Z',
      signatureValid: true,
    };
    fs.writeFileSync(path.join(genDir, 'manifest.json'), JSON.stringify(manifest), 'utf-8');
    fs.writeFileSync(path.join(tempDb, 'CURRENT'), generationId, 'utf-8');

    await DoctorCommand.run();

    const output = stdoutOutput.join('\n');
    expect(output).toContain('Offline Vulnerability Database:');
    expect(output).toContain('gen-20261026-test');
    expect(output).toContain('bundle-20261026-offline');
    expect(output).toContain('Verified Ed25519 Signature');
  });
});
