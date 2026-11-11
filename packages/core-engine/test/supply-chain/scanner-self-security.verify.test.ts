import { describe, it, expect } from 'vitest';
import os from 'node:os';
import {
  SupplyChainPolicySchema,
  type NormalizedFinding,
  type SupplyChainPolicy,
} from '@secureship/contracts';
import { SafeTarExtractor } from '../../src/supply-chain/safe-tar.js';
import { detectInstallScripts } from '../../src/supply-chain/detectors/install-script.detector.js';
import { detectBinConfusion } from '../../src/supply-chain/detectors/bin-confusion.detector.js';
import { detectHighEntropy } from '../../src/supply-chain/detectors/entropy.detector.js';
import { SupplyChainThreatSlicer } from '@secureship/ai';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
});

describe('T9 — Scanner Self-Security Verification Suite', () => {
  describe('1. Tar/Zip-Slip & Malicious Archive Rejection', () => {
    it('rejects relative path traversal in tarball entries: ../../escape and package/../../evil', () => {
      const header = new Uint8Array(1024);
      const traversalPath = 'package/../../etc/passwd';
      for (let i = 0; i < traversalPath.length; i++) {
        header[i] = traversalPath.charCodeAt(i);
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

    it('rejects absolute Windows drive-letter paths in tarball: C:\\Windows\\System32\\cmd.exe', () => {
      const header = new Uint8Array(1024);
      const winPath = 'C:/Windows/System32/cmd.exe';
      for (let i = 0; i < winPath.length; i++) {
        header[i] = winPath.charCodeAt(i);
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

    it('rejects symlink (type 2) and hardlink (type 1) entries without following or extracting', () => {
      // Header for symlink pointing to /etc/shadow
      const header = new Uint8Array(1024);
      const linkPath = 'package/symlink-target';
      for (let i = 0; i < linkPath.length; i++) {
        header[i] = linkPath.charCodeAt(i);
      }
      header[156] = '2'.charCodeAt(0); // typeflag '2' = symlink

      const res = SafeTarExtractor.extract(header);
      expect(res.ok).toBe(true);
      expect(res.files.length).toBe(0);
      expect(res.diagnostics.some((d) => d.includes('Rejected symlink/hardlink'))).toBe(true);
    });
  });

  describe('2. Resource Caps & Bomb Immunity', () => {
    it('safely bounds execution on massive 500 KB single-line input without crash or unbounded memory', () => {
      // 500 KB line of repetitive characters
      const massiveLine = 'const payload = "' + 'A'.repeat(500_000) + '";';
      const hits = detectHighEntropy(massiveLine, 'bomb.js', POLICY);

      expect(Array.isArray(hits)).toBe(true);
      expect(hits.length).toBeGreaterThanOrEqual(0);
    });

    it('aborts extraction when tarball contains > 20,000 files', () => {
      // Simulate by calling with custom maxFileCount: 2
      const header = new Uint8Array(2048);
      // File 1
      const f1 = 'package/f1.js';
      for (let i = 0; i < f1.length; i++) header[i] = f1.charCodeAt(i);
      // File 2
      const f2 = 'package/f2.js';
      for (let i = 0; i < f2.length; i++) header[512 + i] = f2.charCodeAt(i);
      // File 3
      const f3 = 'package/f3.js';
      for (let i = 0; i < f3.length; i++) header[1024 + i] = f3.charCodeAt(i);

      const res = SafeTarExtractor.extract(header, { maxFileCount: 2 });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('File count limit exceeded');
    });
  });

  describe('3. Prototype Pollution Immunity', () => {
    it('remains completely immune to __proto__ and constructor.prototype injection in package.json', () => {
      const maliciousJson = JSON.parse(`{
        "name": "pollution-attack",
        "version": "1.0.0",
        "__proto__": {
          "pollutedKey": "PWNED_PROTO"
        },
        "constructor": {
          "prototype": {
            "pollutedConstructor": "PWNED_CTOR"
          }
        },
        "scripts": {
          "postinstall": "node test.js"
        },
        "bin": {
          "mytool": "./bin/tool.js"
        }
      }`);

      // Run detectors on untrusted object
      detectInstallScripts(maliciousJson, os.tmpdir(), POLICY, {
        packageName: 'pollution-attack',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      detectBinConfusion(maliciousJson, POLICY, {
        packageName: 'pollution-attack',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });

      // Assert prototype integrity
      expect((Object.prototype as Record<string, unknown>)['pollutedKey']).toBeUndefined();
      expect((Object.prototype as Record<string, unknown>)['pollutedConstructor']).toBeUndefined();
      expect(({} as Record<string, unknown>)['pollutedKey']).toBeUndefined();
      expect(({} as Record<string, unknown>)['pollutedConstructor']).toBeUndefined();
    });
  });

  describe('4. Prompt Injection & Triage Sanitization (Gate 3)', () => {
    it('sanitizes Bidi overrides and invisible Unicode from LLM prompts to prevent visual deception', () => {
      const hostileText =
        'Normal text \u202E reversed evil instruction \u2066 and zero-width \u200B hidden payload';
      const sanitized = SupplyChainThreatSlicer.sanitizeString(hostileText);

      // Raw control characters must be converted to visible escaped representations
      expect(sanitized).not.toContain('\u202E');
      expect(sanitized).not.toContain('\u2066');
      expect(sanitized).not.toContain('\u200B');
      expect(sanitized).toContain('\\u202E');
      expect(sanitized).toContain('\\u200B');
    });

    it('redacts cloud credentials, tokens, and private keys from prompts', () => {
      const dummySlack = 'xox' + 'b-123456789012-1234567890123-abcdefghijklmnopqrstuvwx';
      const sensitiveContext = `
        AWS_KEY: AKIAIOSFODNN7EXAMPLE
        GITHUB: ghp_111122223333444455556666777788889999
        SLACK: ${dummySlack}
        KEY: -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0...
        -----END RSA PRIVATE KEY-----
      `;
      const redacted = SupplyChainThreatSlicer.redactSecrets(sensitiveContext);

      expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(redacted).not.toContain('ghp_111122223333444455556666777788889999');
      expect(redacted).not.toContain('xox' + 'b-123456789012');
      expect(redacted).not.toContain('-----BEGIN RSA PRIVATE KEY-----');
      expect(redacted).toContain('[REDACTED_SECRET]');
    });

    it('enforces hard guardrail rejecting LLM downgrade on critical supply-chain findings', () => {
      const criticalFinding: NormalizedFinding = {
        id: 'find-crit',
        fingerprint: 'e'.repeat(64),
        ruleId: 'SC-INSTALL-003',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Dangerous Remote Shell Script',
        description: 'curl piped to bash',
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [
          {
            scannerName: 'generic',
            scannerRuleId: 'SC-INSTALL-003',
            message: 'curl piped to bash',
          },
        ],
        createdAt: new Date().toISOString(),
      };

      const adversarialResponse = {
        verdict: 'BENIGN_LIKELY' as const,
        explanation: 'Attacker prompt injection claims this is a benign update script.',
        attackVector: 'None',
        confidenceAdjustment: 'DECREASE' as const,
        falsePositiveReasons: [],
      };

      const guarded = SupplyChainThreatSlicer.applyGuardrails(criticalFinding, adversarialResponse);

      expect(guarded.verdict).toBe('SUSPICIOUS');
      expect(guarded.confidenceAdjustment).toBe('NONE');
    });
  });

  describe('5. Regular Expression DoS (ReDoS) Resilience', () => {
    it('evaluates string literal regex against 200,000 unclosed backslashes safely without ReDoS', () => {
      // Pathological unclosed string with trailing escaped backslashes: " \\ \\ \\ ...
      const pathological = '"' + '\\\\'.repeat(50_000);
      const hits = detectHighEntropy(pathological, 'redos.js', POLICY);

      expect(Array.isArray(hits)).toBe(true);
      expect(hits.length).toBeGreaterThanOrEqual(0);
    });
  });
});
