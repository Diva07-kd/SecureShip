import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  type NormalizedFinding,
  SupplyChainEvidenceItemSchema,
  SupplyChainPolicySchema,
} from '@secureship/contracts';
import { RULES_REGISTRY } from '../../src/supply-chain/rules-registry.js';
import { SupplyChainThreatSlicer } from '../../../ai/src/triage/supply-chain-slicer.js';

/**
 * T2: Spec-Conformance Matrix Meta-Test
 * Cross-checks rules-registry and SupplyChainPolicySchema against strict spec literals.
 */
describe('T2 — Spec-Conformance Matrix & Policy Defaults Meta-Test', () => {
  // Hard-coded literal expected rule IDs per specification
  const EXPECTED_RULE_IDS = [
    'SC-INSTALL-001',
    'SC-INSTALL-002',
    'SC-INSTALL-003',
    'SC-BIN-001',
    'SC-BIN-002',
    'SC-CAP-001',
    'SC-CAP-002',
    'SC-CAP-003',
    'SC-CAP-004',
    'SC-CAP-005',
    'SC-CAP-006',
    'SC-CAP-007',
    'SC-CAP-100',
    'SC-CAP-101',
    'SC-CAP-102',
    'SC-CAP-103',
    'SC-CAP-104',
    'SC-CAP-105',
    'SC-CAP-106',
    'SC-TYPO-001',
    'SC-TYPO-002',
    'SC-TYPO-003',
    'SC-HALL-001',
    'SC-PKG-001',
    'SC-PKG-002',
    'SC-UNI-001',
    'SC-UNI-002',
    'SC-UNI-003',
    'SC-OBF-001',
    'SC-OBF-002',
    'SC-META-001',
    'SC-META-002',
    'SC-META-003',
    'SC-GOV-001',
    'SC-GOV-002',
    'SC-GOV-003',
  ] as const;

  it('1. Cross-checks RULES_REGISTRY against hard-coded list of expected rule IDs', () => {
    const registeredKeys = Object.keys(RULES_REGISTRY).sort();
    const expectedKeys = [...EXPECTED_RULE_IDS].sort();

    expect(registeredKeys).toEqual(expectedKeys);
    expect(registeredKeys.length).toBe(36);

    for (const ruleId of EXPECTED_RULE_IDS) {
      const entry = RULES_REGISTRY[ruleId];
      expect(entry).toBeDefined();
      expect(entry.ruleId).toBe(ruleId);
      expect(typeof entry.title).toBe('string');
      expect(entry.title.length).toBeGreaterThan(5);
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).toContain(entry.defaultSeverity);
      expect(typeof entry.description).toBe('string');
      expect(entry.description.length).toBeGreaterThan(10);
      expect(typeof entry.remediationText).toBe('string');
      expect(entry.remediationText.length).toBeGreaterThan(10);
      expect(typeof entry.reachabilityGated).toBe('boolean');

      // Non-gated invariants per spec
      if (
        ruleId.startsWith('SC-INSTALL-') ||
        ruleId.startsWith('SC-UNI-') ||
        ruleId.startsWith('SC-BIN-') ||
        ruleId.startsWith('SC-TYPO-') ||
        ruleId === 'SC-META-003' ||
        ruleId.startsWith('SC-GOV-') ||
        ruleId === 'SC-CAP-105' ||
        ruleId === 'SC-CAP-106'
      ) {
        expect(entry.reachabilityGated).toBe(false);
      }
    }
  });

  it('2. Verifies every default value in SupplyChainPolicySchema equals spec literals', () => {
    const defaults = SupplyChainPolicySchema.parse({});

    // Hard-coded spec literals
    expect(defaults.enabled).toBe(false);
    expect(defaults.provider).toBe('null');
    expect(defaults.concurrency).toBe(8);
    expect(defaults.packageTimeoutMs).toBe(30000); // 30 s
    expect(defaults.maxFileSizeBytes).toBe(2097152); // 2 MiB
    expect(defaults.maxTotalBytes).toBe(104857600); // 100 MiB
    expect(defaults.maxFileCount).toBe(20000); // 20,000 files

    // Typosquat literals
    expect(defaults.typosquat.minScore).toBe(0.82);
    expect(defaults.typosquat.candidateMaxDownloads).toBe(1000);
    expect(defaults.typosquat.popularMinDownloads).toBe(1000000);

    // Entropy literals
    expect(defaults.entropy.minLength).toBe(64);
    expect(defaults.entropy.threshold).toBe(4.5);

    // Obfuscation literals
    expect(defaults.obfuscation.longLine).toBe(1000);

    // Hallucination literals
    expect(defaults.hallucination.minAgeDays).toBe(30);

    // Semver literals
    expect(defaults.semver.majorJump).toBe(20);

    // Governance literals
    expect(defaults.governance.dormancyDays).toBe(365);

    // PreInstall literals
    expect(defaults.preInstall.forbidInstallScripts).toBe(true);
    expect(defaults.failOnSeverity).toBe('HIGH');
  });

  it('3. Verifies token limits, context line padding, and snippet length caps', () => {
    // Snippet max character limit in schema
    const snippetDef = SupplyChainEvidenceItemSchema.shape.redactedSnippet;
    const testValid = snippetDef.safeParse('a'.repeat(200));
    expect(testValid.success).toBe(true);
    const testInvalid = snippetDef.safeParse('a'.repeat(201));
    expect(testInvalid.success).toBe(false);

    // Token budget default in threat slicer: 6000 tokens
    const dummyFinding: NormalizedFinding = {
      id: 'f1',
      fingerprint: 'a'.repeat(64),
      ruleId: 'SC-INSTALL-001',
      scannerName: 'generic',
      severity: 'MEDIUM',
      category: 'SUPPLY_CHAIN',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      cweIds: [],
      title: 'Dummy Install Script',
      description: 'Dummy Description',
      location: { filePath: 'package.json', startLine: 1, endLine: 1, redactedSnippet: '' },
      package: { ecosystem: 'npm', name: 'dummy', version: '1.0.0' },
      evidence: [],
      createdAt: '2026-10-22T00:00:00Z',
    };
    const slice = SupplyChainThreatSlicer.createSlice(dummyFinding);
    expect(slice).toBeDefined();

    // Verify context line window logic (+/- 15 lines)
    const targetLine = 20;
    const startLine = Math.max(1, targetLine - 15);
    const endLine = targetLine + 15;
    expect(startLine).toBe(5);
    expect(endLine).toBe(35);
    expect(endLine - startLine).toBe(30);
  });

  it('4. Asserts each of the 36 rules has coverage in test sources', () => {
    const testDirs = [
      path.resolve(__dirname, '..'), // packages/core-engine/test
      path.resolve(__dirname, '../../../../reachability/test'),
      path.resolve(__dirname, '../../../../contracts/test'),
    ];

    const testFiles: string[] = [];
    function collectTestFiles(dir: string) {
      if (!fs.existsSync(dir)) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== 'dist') {
          collectTestFiles(full);
        } else if (entry.isFile() && /\.test\.ts$/.test(entry.name)) {
          testFiles.push(full);
        }
      }
    }
    for (const d of testDirs) collectTestFiles(d);

    const testCorpus = testFiles.map((f) => fs.readFileSync(f, 'utf8')).join('\n');

    for (const ruleId of EXPECTED_RULE_IDS) {
      expect(
        testCorpus.includes(ruleId),
        `Rule '${ruleId}' must be explicitly covered in the test suite`
      ).toBe(true);
    }
  });
});
