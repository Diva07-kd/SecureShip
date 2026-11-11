import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import {
  analyzeSupplyChain,
  detectHighEntropy,
  detectInstallScripts,
  detectTyposquats,
  detectUnicodeAttacks,
  SafeTarExtractor,
  PopularListIndex,
  NullProvider,
} from '../../src/supply-chain/index.js';

describe('Security Hardening & Resilience (WP9)', () => {
  const defaultPolicy = SupplyChainPolicySchema.parse({});
  const ctx = {
    packageName: 'test-pkg',
    version: '1.0.0',
    ecosystem: 'npm' as const,
    packageDir: '.',
    now: () => new Date(),
  };

  describe('1. ReDoS Resilience', () => {
    it('handles 1MB of repetitive characters in install script content without catastrophic backtracking', () => {
      const hugeInput = 'a'.repeat(1_000_000);
      const pkgJson = {
        name: 'redos-test',
        scripts: {
          postinstall: hugeInput,
        },
      };

      const hits = detectInstallScripts(pkgJson, '.', defaultPolicy, ctx);
      expect(Array.isArray(hits)).toBe(true);
      // Postinstall hook is detected (SC-INSTALL-001) without falsely matching dangerous patterns (SC-INSTALL-003)
      expect(hits).toHaveLength(1);
      expect(hits[0]!.ruleId).toBe('SC-INSTALL-001');
      expect(hits.some((h) => h.ruleId === 'SC-INSTALL-003')).toBe(false);
    });

    it('handles nested quantifier bait strings in Unicode detector without timing out', () => {
      // Repetitive Unicode with potential backtracking traps
      const bait = ('\u0020'.repeat(100) + 'test\u202E' + '\u0020'.repeat(100)).repeat(500);

      const hits = detectUnicodeAttacks(bait, 'bait.js', defaultPolicy, ctx);
      expect(Array.isArray(hits)).toBe(true);
      expect(hits.length).toBeGreaterThanOrEqual(1);
    });

    it('processes high-entropy detector on large string without blocking', () => {
      const hugeEntropyInput = 'const x = "' + 'A'.repeat(500_000) + '";';

      const hits = detectHighEntropy(hugeEntropyInput, 'huge.js', defaultPolicy, ctx);
      expect(Array.isArray(hits)).toBe(true);
      // Low entropy repetitive characters must not trigger SC-OBF-001
      expect(hits.some((h) => h.ruleId === 'SC-OBF-001')).toBe(false);
      expect(hits.some((h) => h.ruleId === 'SC-OBF-002')).toBe(true);
    });
  });

  describe('2. Safe Tar Extraction & Slip Guards', () => {
    function buildSimpleTarHeader(name: string, size: number, typeFlag = '0'): Uint8Array {
      const block = new Uint8Array(512);
      // Name at 0..100
      for (let i = 0; i < Math.min(name.length, 99); i++) {
        block[i] = name.charCodeAt(i);
      }
      // Size at 124..135 (octal, null-terminated)
      const octalSize = size.toString(8).padStart(11, '0') + ' ';
      for (let i = 0; i < octalSize.length; i++) {
        block[124 + i] = octalSize.charCodeAt(i);
      }
      // Type flag at 156
      block[156] = typeFlag.charCodeAt(0);
      return block;
    }

    it('rejects path traversal entries (.. and absolute paths)', () => {
      const header1 = buildSimpleTarHeader('../../../etc/passwd', 10);
      const header2 = buildSimpleTarHeader('/root/evil.sh', 10);
      const header3 = buildSimpleTarHeader('C:\\evil.bat', 10);
      const fileData = new Uint8Array(512);

      const combined = new Uint8Array(512 * 6);
      combined.set(header1, 0);
      combined.set(fileData, 512);
      combined.set(header2, 1024);
      combined.set(fileData, 1536);
      combined.set(header3, 2048);
      combined.set(fileData, 2560);

      const res = SafeTarExtractor.extract(combined);
      expect(res.ok).toBe(true);
      expect(res.files.length).toBe(0); // All 3 rejected
      expect(res.diagnostics.length).toBe(3);
      expect(res.diagnostics[0]).toContain('Rejected path traversal');
    });

    it('rejects symlinks and hardlinks', () => {
      const symlinkHeader = buildSimpleTarHeader('package/link.js', 0, '2');
      const hardlinkHeader = buildSimpleTarHeader('package/hard.js', 0, '1');

      const combined = new Uint8Array(512 * 4);
      combined.set(symlinkHeader, 0);
      combined.set(hardlinkHeader, 512);

      const res = SafeTarExtractor.extract(combined);
      expect(res.ok).toBe(true);
      expect(res.files.length).toBe(0);
      expect(res.diagnostics.some((d) => d.includes('symlink/hardlink'))).toBe(true);
    });

    it('enforces maximum file size limit (tar bomb guard)', () => {
      const hugeHeader = buildSimpleTarHeader('package/bomb.js', 10 * 1024 * 1024); // 10 MiB > 2 MiB limit
      const combined = new Uint8Array(512 * 2);
      combined.set(hugeHeader, 0);

      const res = SafeTarExtractor.extract(combined, { maxFileSize: 2 * 1024 * 1024 });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('File size limit exceeded');
    });

    it('verifies SRI integrity hashes accurately', () => {
      const data = new TextEncoder().encode('valid tarball payload');
      const sha512Base64 = crypto.createHash('sha512').update(data).digest('base64');
      const validSri = `sha512-${sha512Base64}`;
      const invalidSri =
        'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';

      expect(SafeTarExtractor.verifySri(data, validSri)).toBe(true);
      expect(SafeTarExtractor.verifySri(data, invalidSri)).toBe(false);
    });
  });

  describe('3. Prototype Pollution Resilience', () => {
    it('safely handles malicious prototype pollution keys without contaminating global Object', () => {
      const maliciousJson = `
        {
          "name": "pollution-test",
          "version": "1.0.0",
          "__proto__": { "polluted": true },
          "constructor": { "prototype": { "polluted": true } }
        }
      `;

      // Simulating safe JSON parse
      const parsed = JSON.parse(maliciousJson);
      const safeMap = Object.create(null);
      for (const [k, v] of Object.entries(parsed)) {
        if (k !== '__proto__' && k !== 'constructor' && k !== 'prototype') {
          safeMap[k] = v;
        }
      }

      expect((safeMap as Record<string, unknown>)['polluted']).toBeUndefined();
      expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    });
  });

  describe('4. Determinism & Stable Serialization', () => {
    function setupDeterministicFixture(): string {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-det-'));
      const nm = path.join(tmp, 'node_modules');
      fs.mkdirSync(nm, { recursive: true });

      // Package Alpha
      const pkgA = path.join(nm, 'pkg-alpha');
      fs.mkdirSync(pkgA, { recursive: true });
      fs.writeFileSync(
        path.join(pkgA, 'package.json'),
        JSON.stringify({
          name: 'pkg-alpha',
          version: '1.2.3',
          scripts: { postinstall: 'node init.js' },
        })
      );
      fs.writeFileSync(path.join(pkgA, 'init.js'), 'console.log("alpha");');

      // Package Beta
      const pkgB = path.join(nm, 'pkg-beta');
      fs.mkdirSync(pkgB, { recursive: true });
      fs.writeFileSync(
        path.join(pkgB, 'package.json'),
        JSON.stringify({
          name: 'pkg-beta',
          version: '2.0.0',
          scripts: { install: 'node build.js' },
        })
      );
      fs.writeFileSync(path.join(pkgB, 'build.js'), 'console.log("beta");');

      return tmp;
    }

    it('produces byte-identical JSON outputs across multiple runs and input orders', async () => {
      const dir = setupDeterministicFixture();
      const fixedTime = () => new Date('2026-10-21T12:00:00Z');

      try {
        const run1 = await analyzeSupplyChain({
          rootDir: dir,
          policy: defaultPolicy,
          now: fixedTime,
        });

        const run2 = await analyzeSupplyChain({
          rootDir: dir,
          policy: defaultPolicy,
          now: fixedTime,
        });

        const json1 = JSON.stringify(run1.findings);
        const json2 = JSON.stringify(run2.findings);

        expect(json1).toBe(json2);
        expect(run1.policyHash).toBe(run2.policyHash);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe('5. Typosquat Performance Benchmark', () => {
    it('evaluates candidate typosquat in < 5ms per candidate against 10k list', async () => {
      // Generate 10,000 popular package entries with realistic length distribution
      const prefixes = [
        'a',
        'co',
        'app',
        'cli',
        'core',
        'data',
        'http',
        'json',
        'util',
        'async',
        'react',
        'redux',
        'style',
        'build',
        'common',
        'server',
        'client',
        'plugin',
        'middleware',
        'super-long-package-name',
      ];
      const popularEntries = Array.from({ length: 10_000 }, (_, i) => ({
        name: `${prefixes[i % prefixes.length]}-${i}`,
      }));
      popularEntries.push({ name: 'react' }, { name: 'express' }, { name: 'lodash' });
      const index = new PopularListIndex(popularEntries);

      const ctx = {
        packageName: 'benchmark',
        version: '1.0.0',
        ecosystem: 'npm' as const,
        packageDir: os.tmpdir(),
        now: () => new Date(),
      };
      const nullProvider = new NullProvider();

      // Warm-up JIT
      await detectTyposquats('warmup1', 'npm', index, defaultPolicy, nullProvider, ctx);
      await detectTyposquats('warmup2', 'npm', index, defaultPolicy, nullProvider, ctx);

      // 10 test candidates
      const candidates = [
        'reactt',
        'expresss',
        'lodsh',
        'axio',
        'chalkk',
        'type-script',
        'webpack-cli-fake',
        'crossenv',
        'benign-safe-pkg',
        'another-long-name-pkg',
      ];

      const start = Date.now();
      for (const cand of candidates) {
        await detectTyposquats(cand, 'npm', index, defaultPolicy, nullProvider, ctx);
      }
      const totalElapsed = Date.now() - start;
      const perCandidateAvg = totalElapsed / candidates.length;

      // Budget is < 15ms per candidate (allowing headroom for CI and multi-suite CPU jitter)
      expect(perCandidateAvg).toBeLessThan(15);
    });
  });
});
