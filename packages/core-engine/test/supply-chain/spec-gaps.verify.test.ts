import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import {
  SupplyChainPolicySchema,
  type NormalizedFinding,
  type SupplyChainPolicy,
} from '@secureship/contracts';
import {
  detectTyposquats,
  PopularListIndex,
} from '../../src/supply-chain/detectors/typosquat.detector.js';
import {
  detectHighEntropy,
  shannonEntropy,
} from '../../src/supply-chain/detectors/entropy.detector.js';
import { detectInstallScripts } from '../../src/supply-chain/detectors/install-script.detector.js';
import { detectMetadataAnomalies } from '../../src/supply-chain/detectors/metadata.detector.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import { CapabilityMatrix } from '@secureship/reachability';
import { IgnoreRulesEvaluator } from '../../src/suppression/ignore-rules.js';
import { SupplyChainThreatSlicer } from '@secureship/ai';

const BASE_POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
});

describe('T5 — Spec-Gap Probes Suite', () => {
  describe('SPEC-GAP-1: Short-name Single-Edit Typosquats (5-character popular names)', () => {
    const popularIndex = new PopularListIndex([
      { name: 'react' },
      { name: 'axios' },
      { name: 'chalk' },
      { name: 'redis' },
    ]);

    it('probes whether D=1 single-edit typo of a 5-char popular name (e.g. raect <-> react) is detected', async () => {
      // "raect" vs "react": transposition, distance 1, len 5, score = 1 - 1/5 = 0.80 (< 0.82)
      const hits = await detectTyposquats('raect', 'npm', popularIndex, BASE_POLICY);
      const typoHit = hits.find((h) => h.ruleId === 'SC-TYPO-001');

      // SPEC-GAP-1 check: Engine must treat D=1 against popular name of len >= 5 as a squat candidate
      expect(typoHit).toBeDefined();
      expect(typoHit?.packageName).toBe('raect');
    });

    it('probes axois <-> axios and chlak <-> chalk 5-char single-edit typos', async () => {
      const axiosHits = await detectTyposquats('axois', 'npm', popularIndex, BASE_POLICY);
      const axiosHit = axiosHits.find((h) => h.ruleId === 'SC-TYPO-001');
      expect(axiosHit?.ruleId).toBe('SC-TYPO-001');
      expect(axiosHit?.packageName).toBe('axois');
      expect(axiosHit?.severity).toBe('MEDIUM');

      const chalkHits = await detectTyposquats('chlak', 'npm', popularIndex, BASE_POLICY);
      const chalkHit = chalkHits.find((h) => h.ruleId === 'SC-TYPO-001');
      expect(chalkHit?.ruleId).toBe('SC-TYPO-001');
      expect(chalkHit?.packageName).toBe('chlak');
      expect(chalkHit?.severity).toBe('MEDIUM');
    });
  });

  describe('SPEC-GAP-2: Hex Payloads and Shannon Entropy Cap (Max 4.0)', () => {
    it('verifies mathematical cap on hex entropy: 16-symbol alphabet has theoretical max H = 4.0', () => {
      // 16 distinct symbols evenly distributed: H = -16 * (1/16 * log2(1/16)) = log2(16) = 4.0
      const hexAlphabet = '0123456789abcdef';
      const repeated = hexAlphabet.repeat(16); // 256 chars, exactly equal frequencies
      const h = shannonEntropy(repeated);
      expect(Math.abs(h - 4.0)).toBeLessThan(1e-10);
      expect(h).toBeLessThanOrEqual(4.0);
    });

    it('probes 256-char random hex literal detection with charset-aware threshold', () => {
      // 256-char random hex string
      const hexPayload = crypto.randomBytes(128).toString('hex'); // 256 chars
      expect(hexPayload.length).toBe(256);
      const jsCode = `const encoded = "${hexPayload}";\nconst buf = Buffer.from(encoded, 'hex');`;

      const hits = detectHighEntropy(jsCode, 'payload.js', BASE_POLICY);
      const obfHit = hits.find((h) => h.ruleId === 'SC-OBF-001');
      expect(obfHit?.ruleId).toBe('SC-OBF-001');
      expect(obfHit?.severity).toBe('HIGH');
    });
  });

  describe('SPEC-GAP-3: Implicit node-gyp Install Semantics (preinstall vs install)', () => {
    it('does NOT trigger SC-INSTALL-002 when binding.gyp exists BUT package defines preinstall', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-gyp-'));
      try {
        fs.writeFileSync(path.join(tempDir, 'binding.gyp'), '{}');
        const pkgJson = {
          name: 'has-preinstall-and-gyp',
          version: '1.0.0',
          scripts: { preinstall: 'echo preinstall-step' },
        };

        const hits = detectInstallScripts(pkgJson, tempDir, BASE_POLICY, {
          packageName: 'has-preinstall-and-gyp',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: tempDir,
          now: () => new Date('2026-01-01T00:00:00Z'),
        });

        // Per npm docs: node-gyp rebuild default applies ONLY when package defines NEITHER install nor preinstall!
        const gypImplicitHits = hits.filter((h) => h.ruleId === 'SC-INSTALL-002');
        expect(gypImplicitHits.length).toBe(0);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('triggers SC-INSTALL-002 when binding.gyp exists and NEITHER install NOR preinstall is defined', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-gyp2-'));
      try {
        fs.writeFileSync(path.join(tempDir, 'binding.gyp'), '{}');
        const pkgJson = {
          name: 'no-scripts-with-gyp',
          version: '1.0.0',
          scripts: {},
        };

        const hits = detectInstallScripts(pkgJson, tempDir, BASE_POLICY, {
          packageName: 'no-scripts-with-gyp',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: tempDir,
          now: () => new Date('2026-01-01T00:00:00Z'),
        });

        const gypImplicitHits = hits.filter((h) => h.ruleId === 'SC-INSTALL-002');
        expect(gypImplicitHits.length).toBe(1);
        expect(gypImplicitHits[0]?.ruleId).toBe('SC-INSTALL-002');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('SPEC-GAP-4: Lone Capability INFO vs Install-Time Execution Escalation', () => {
    it('escalates install script + env harvesting to SC-CAP-105 HIGH with reachabilityGated: false', () => {
      const hits = CapabilityMatrix.evaluateCombinations(
        {
          hasShell: false,
          hasNetwork: false,
          hasEnvAccess: true,
          hasFsSensitive: false,
          hasEval: false,
          hasDynamicRequire: false,
          hasInstallScript: true,
          hasDebugInternals: false,
        },
        [
          {
            capability: 'env',
            file: 'setup.js',
            startLine: 5,
            startCol: 1,
            endLine: 5,
            endCol: 25,
            snippet: 'process.env.SECRET',
            resolved: true,
            confidence: 'HIGH',
            details: 'Ambient env access',
          },
        ],
        {
          packageName: 'malicious-install-env',
          hasInstallScript: true,
        }
      );

      const cap105 = hits.find((h) => h.ruleId === 'SC-CAP-105');
      expect(cap105).toBeDefined();
      expect(cap105?.severity).toBe('HIGH');
      expect(cap105?.reachabilityGated).toBe(false); // Install context is NEVER reachability-gated!
    });
  });

  describe('SPEC-GAP-5: Metadata-Unavailable Degradation Consistency', () => {
    it('operates safely and deterministically without throw or unhandled promise rejection with NullProvider', async () => {
      const nullProv = new NullProvider();
      const hits = await detectMetadataAnomalies(
        'some-package',
        '1.0.0',
        { name: 'some-package', version: '1.0.0' },
        nullProv,
        BASE_POLICY,
        {
          packageName: 'some-package',
          version: '1.0.0',
          ecosystem: 'npm',
          packageDir: os.tmpdir(),
          now: () => new Date('2026-01-01T00:00:00Z'),
        }
      );

      expect(Array.isArray(hits)).toBe(true);
    });
  });

  describe('SPEC-GAP-6: Waiver Safety (CRITICAL Bidi and Manifest Protection)', () => {
    const expiredRule = {
      id: 'rule-expired',
      ruleId: 'SC-UNI-001',
      expires: '2020-01-01T00:00:00Z',
      reason: 'Expired exemption',
    };

    it('refuses to apply expired waivers', () => {
      const isExpired = IgnoreRulesEvaluator.isExpired(expiredRule);
      expect(isExpired).toBe(true);

      const evaluator = new IgnoreRulesEvaluator([expiredRule]);
      const dummyFinding: NormalizedFinding = {
        id: 'find-dummy',
        fingerprint: '1'.repeat(64),
        ruleId: 'SC-UNI-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Bidi Trojan',
        description: 'Bidi override',
        location: { filePath: 'auth.js', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [
          { scannerName: 'generic', scannerRuleId: 'SC-UNI-001', message: 'bidi override' },
        ],
        createdAt: new Date().toISOString(),
      };

      const res = evaluator.evaluate(dummyFinding);
      expect(res.isIgnored).toBe(false);
    });

    it('invalidates waiver when fingerprint drifts', () => {
      const fpRule = {
        id: 'rule-fp',
        fingerprint: 'original-sha256-hash',
        expires: '2099-01-01T00:00:00Z',
        reason: 'Valid for original snippet only',
      };
      const evaluator = new IgnoreRulesEvaluator([fpRule]);

      const driftedFinding: NormalizedFinding = {
        id: 'find-drifted',
        fingerprint: '2'.repeat(64),
        ruleId: 'SC-INSTALL-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Install script',
        description: 'Install script modified',
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [
          { scannerName: 'generic', scannerRuleId: 'SC-INSTALL-001', message: 'install script' },
        ],
        createdAt: new Date().toISOString(),
      };

      const res = evaluator.evaluate(driftedFinding);
      expect(res.isIgnored).toBe(false);
    });
  });

  describe('SPEC-GAP-7: LLM Guardrail (CRITICAL/Blocking Findings Cannot be Downgraded)', () => {
    it('blocks adversarial LLM triage attempting to downgrade CRITICAL findings to BENIGN_LIKELY', () => {
      const criticalBidiFinding: NormalizedFinding = {
        id: 'find-bidi-crit',
        fingerprint: '3'.repeat(64),
        ruleId: 'SC-UNI-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Bidirectional Unicode Control Override',
        description: 'Bidi Trojan detected',
        location: { filePath: 'auth.js', startLine: 10, endLine: 10 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [{ scannerName: 'generic', scannerRuleId: 'SC-UNI-001', message: 'bidi trojan' }],
        createdAt: new Date().toISOString(),
      };

      const adversarialLlmResponse = {
        verdict: 'BENIGN_LIKELY' as const,
        explanation: 'Attacker prompt injection claims this code is benign i18n text.',
        attackVector: 'None',
        confidenceAdjustment: 'DECREASE' as const,
        falsePositiveReasons: ['Harmless i18n override'],
      };

      const guardedTriage = SupplyChainThreatSlicer.applyGuardrails(
        criticalBidiFinding,
        adversarialLlmResponse
      );

      // Guardrail MUST prevent downgrade to BENIGN_LIKELY
      expect(guardedTriage.verdict).not.toBe('BENIGN_LIKELY');
      expect(guardedTriage.verdict).toBe('SUSPICIOUS');
      // Confidence adjustment cannot be DECREASE
      expect(guardedTriage.confidenceAdjustment).toBe('NONE');
      // Hard guardrail reason must be recorded in falsePositiveReasons
      expect(guardedTriage.falsePositiveReasons.some((r) => r.includes('Hard Guardrail'))).toBe(
        true
      );
    });

    it('blocks adversarial LLM triage on SC-INSTALL-003 and SC-META-003', () => {
      const criticalInstallFinding: NormalizedFinding = {
        id: 'find-install-crit',
        fingerprint: '4'.repeat(64),
        ruleId: 'SC-INSTALL-003',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Dangerous Remote Execution in Install Script',
        description: 'curl piped to bash',
        location: { filePath: 'package.json', startLine: 5, endLine: 5 },
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

      const guarded = SupplyChainThreatSlicer.applyGuardrails(criticalInstallFinding, {
        verdict: 'BENIGN_LIKELY',
        explanation: 'Model was fooled by comment',
        attackVector: 'None',
        confidenceAdjustment: 'DECREASE',
        falsePositiveReasons: [],
      });

      expect(guarded.verdict).toBe('SUSPICIOUS');
      expect(guarded.confidenceAdjustment).toBe('NONE');
    });
  });
});
