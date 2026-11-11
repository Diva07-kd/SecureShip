import { describe, it, expect, vi } from 'vitest';
import { ReachabilitySymbolsCommand } from '../src/commands/reachability-symbols.js';

describe('CLI reachability symbols Command (Deliverable 2)', () => {
  it('outputs valid JSON containing all 18 entries and integrity status under --json', async () => {
    let output = '';
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation((msg?: unknown) => {
      output += String(msg) + '\n';
    });

    await ReachabilitySymbolsCommand.run({ json: true });

    consoleLogSpy.mockRestore();

    const parsed = JSON.parse(output);
    expect(parsed.ok).toBe(true);
    expect(parsed.integrity.verified).toBe(true);
    expect(parsed.integrity.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(parsed.dataset.id).toBe('secureship-curated-vulnerable-symbols-v1');
    expect(parsed.dataset.entryCount).toBeGreaterThanOrEqual(18);
    expect(parsed.entries.length).toBeGreaterThanOrEqual(18);

    // Verify key entries exist
    const packages = parsed.entries.map((e: { package: string }) => e.package);
    expect(packages).toContain('lodash');
    expect(packages).toContain('underscore');
    expect(packages).toContain('requests');
    expect(packages).toContain('django');
  });

  it('outputs human-readable table and notice when --json is omitted', async () => {
    let output = '';
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation((msg?: unknown) => {
      output += String(msg) + '\n';
    });

    await ReachabilitySymbolsCommand.run({});

    consoleLogSpy.mockRestore();

    expect(output).toContain('SecureShip Curated Vulnerable Symbols Database');
    expect(output).toContain('Integrity:');
    expect(output).toContain('VERIFIED');
    expect(output).toContain('CVE-2021-23337');
    expect(output).toContain('lodash');
    expect(output).toContain('Function-level analysis is static and best-effort');
  });
});
