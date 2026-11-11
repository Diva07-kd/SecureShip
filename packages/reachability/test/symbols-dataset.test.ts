import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import {
  SymbolDatasetLoader,
  VulnerableSymbolDatasetSchema,
  SymbolEntryPointSchema,
  isEligibleForHighPruning,
  extractVulnerableSymbols,
  extractVulnerableSymbol,
  isValidHeuristicSymbol,
  HEURISTIC_STOPLIST,
  type VulnerableSymbolEntry,
} from '../src/symbols/index.js';

describe('Vulnerable Symbols Dataset & Loader Suite (Deliverable 2)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-symbols-test-'));
    SymbolDatasetLoader.resetCache();
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
    SymbolDatasetLoader.resetCache();
  });

  it('loads and validates the bundled vulnerable symbols dataset and manifest', () => {
    const result = SymbolDatasetLoader.loadBundledDataset();
    expect(result.ok).toBe(true);
    expect(result.dataset).toBeDefined();
    expect(result.manifest).toBeDefined();
    expect(result.dataset?.entries.length).toBeGreaterThanOrEqual(18);
    expect(result.manifest?.entryCount).toBe(result.dataset?.entries.length);

    // Verify all 18 entries adhere strictly to the Zod schema
    const parsed = VulnerableSymbolDatasetSchema.parse(result.dataset);
    expect(parsed.entries.length).toBe(result.dataset?.entries.length);
  });

  it('detects cryptographic tampering and fails closed (AC7)', () => {
    const bundledDir = SymbolDatasetLoader.getBundledDataDirectory();
    const dataContent = fs.readFileSync(path.join(bundledDir, 'vulnerable-symbols.json'), 'utf-8');
    const manifestContent = fs.readFileSync(
      path.join(bundledDir, 'vulnerable-symbols.manifest.json'),
      'utf-8'
    );

    // Create a copy in tempDir
    const tempDataPath = path.join(tempDir, 'vulnerable-symbols.json');
    const tempManifestPath = path.join(tempDir, 'vulnerable-symbols.manifest.json');

    // Tamper with data file by adding a space or modifying a character
    const tampered = dataContent.replace('lodash', 'tampered-pkg');
    fs.writeFileSync(tempDataPath, tampered, 'utf-8');
    fs.writeFileSync(tempManifestPath, manifestContent, 'utf-8');

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = SymbolDatasetLoader.loadAndVerifyDataset(tempDataPath, tempManifestPath);

    expect(result.ok).toBe(false);
    expect(result.dataset).toBeNull();
    expect(result.error).toContain('Integrity check failed');
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Tampered or corrupted dataset ignored')
    );
    consoleWarnSpy.mockRestore();
  });

  it('fails closed when manifest is corrupted or contains invalid JSON', () => {
    const tempDataPath = path.join(tempDir, 'vulnerable-symbols.json');
    const tempManifestPath = path.join(tempDir, 'vulnerable-symbols.manifest.json');

    fs.writeFileSync(
      tempDataPath,
      JSON.stringify({ version: '1.0', datasetId: 'test', entries: [] }),
      'utf-8'
    );
    fs.writeFileSync(tempManifestPath, '{ invalid json', 'utf-8');

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = SymbolDatasetLoader.loadAndVerifyDataset(tempDataPath, tempManifestPath);

    expect(result.ok).toBe(false);
    expect(result.dataset).toBeNull();
    expect(result.error).toContain('Failed to parse manifest');
    consoleWarnSpy.mockRestore();
  });

  it('fails closed when dataset file contains invalid JSON syntax', () => {
    const tempDataPath = path.join(tempDir, 'vulnerable-symbols.json');
    fs.writeFileSync(tempDataPath, '{ invalid json syntax', 'utf-8');

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = SymbolDatasetLoader.loadAndVerifyDataset(tempDataPath);

    expect(result.ok).toBe(false);
    expect(result.dataset).toBeNull();
    expect(result.error).toContain('Invalid JSON syntax in dataset');
    consoleWarnSpy.mockRestore();
  });

  it('fails closed when dataset file fails schema validation', () => {
    const tempDataPath = path.join(tempDir, 'vulnerable-symbols.json');
    fs.writeFileSync(
      tempDataPath,
      JSON.stringify({ version: '1.0', datasetId: 'bad-schema', entries: [{ id: '' }] }),
      'utf-8'
    );

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = SymbolDatasetLoader.loadAndVerifyDataset(tempDataPath);

    expect(result.ok).toBe(false);
    expect(result.dataset).toBeNull();
    expect(result.error).toContain('Dataset schema validation failed');
    consoleWarnSpy.mockRestore();
  });

  it('returns error when dataset file does not exist', () => {
    const missingPath = path.join(tempDir, 'nonexistent.json');
    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = SymbolDatasetLoader.loadAndVerifyDataset(missingPath);

    expect(result.ok).toBe(false);
    expect(result.error).toContain('Symbol dataset file not found');
    consoleWarnSpy.mockRestore();
  });

  it('loads custom dataset outside repository when valid', () => {
    const bundled = SymbolDatasetLoader.loadBundledDataset();
    expect(bundled.dataset).toBeDefined();

    const customPath = path.join(tempDir, 'custom-symbols.json');
    fs.writeFileSync(customPath, JSON.stringify(bundled.dataset), 'utf-8');

    const result = SymbolDatasetLoader.loadDataset(customPath, '/some/other/repo');
    expect(result.ok).toBe(true);
    expect(result.dataset?.entries.length).toBe(bundled.dataset?.entries.length);
  });

  it('enforces trust model F6: strictly rejects repository-resident datasets with warning', () => {
    const repoFakeDir = path.join(tempDir, 'my-repo');
    const dotSecureship = path.join(repoFakeDir, '.secureship');
    fs.mkdirSync(dotSecureship, { recursive: true });

    const plantedPath = path.join(dotSecureship, 'symbols.json');
    fs.writeFileSync(
      plantedPath,
      JSON.stringify({ version: '1.0', datasetId: 'planted', entries: [] }),
      'utf-8'
    );

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = SymbolDatasetLoader.loadDataset(plantedPath, repoFakeDir);

    expect(result.ok).toBe(false);
    expect(result.dataset).toBeNull();
    expect(result.error).toBe('Repo-resident dataset rejected by trust model');
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining('located inside the repository or .secureship/ directory')
    );
    consoleWarnSpy.mockRestore();
  });

  it('validates schema requirements for entry points and METHOD via array', () => {
    // Valid FUNCTION
    expect(
      SymbolEntryPointSchema.parse({
        module: '.',
        export: 'template',
        kind: 'FUNCTION',
      })
    ).toBeDefined();

    // Valid METHOD with via
    expect(
      SymbolEntryPointSchema.parse({
        module: '.',
        export: 'evaluate',
        kind: 'METHOD',
        via: ['traverse'],
      })
    ).toBeDefined();

    // Invalid METHOD without via
    expect(() =>
      SymbolEntryPointSchema.parse({
        module: '.',
        export: 'evaluate',
        kind: 'METHOD',
      })
    ).toThrow('entryPoints of kind METHOD must specify a non-empty via array');

    // Invalid METHOD with empty via
    expect(() =>
      SymbolEntryPointSchema.parse({
        module: '.',
        export: 'evaluate',
        kind: 'METHOD',
        via: [],
      })
    ).toThrow();
  });

  it('evaluates isEligibleForHighPruning accurately', () => {
    const baseEntry: VulnerableSymbolEntry = {
      id: 'CVE-TEST-1',
      aliases: [],
      ecosystem: 'npm',
      package: 'test-pkg',
      entryPoints: [{ module: '.', export: 'testFn', kind: 'FUNCTION' }],
      triggeredOn: 'CALL',
      entryPointsComplete: true,
      sourceUrls: ['https://example.com/advisory'],
      fixCommitUrls: ['https://example.com/fix'],
      verifiedAt: '2026-10-25',
      verifiedBy: 'SecOps',
      notes: 'test',
    };

    expect(isEligibleForHighPruning(baseEntry)).toBe(true);

    // IMPORT_TIME is not eligible for HIGH pruning
    expect(isEligibleForHighPruning({ ...baseEntry, triggeredOn: 'IMPORT_TIME' })).toBe(false);

    // UNKNOWN trigger is not eligible for HIGH pruning
    expect(isEligibleForHighPruning({ ...baseEntry, triggeredOn: 'UNKNOWN' })).toBe(false);

    // Incomplete entry points is not eligible for HIGH pruning
    expect(isEligibleForHighPruning({ ...baseEntry, entryPointsComplete: false })).toBe(false);

    // METHOD without via is not eligible for HIGH pruning
    expect(
      isEligibleForHighPruning({
        ...baseEntry,
        entryPoints: [{ module: '.', export: 'method', kind: 'METHOD' }],
      })
    ).toBe(false);
  });
});

describe('Candidate Extractor & Precedence Suite (Deliverable 2)', () => {
  function createFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
    return {
      id: 'finding-1',
      fingerprint: 'a'.repeat(64),
      ruleId: 'GHSA-35jh-r3h4-6jhm',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: {
        filePath: 'package.json',
        startLine: 1,
        endLine: 1,
      },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Command Injection in lodash',
      description: 'Lodash vulnerable to code injection via template function.',
      cweIds: ['CWE-94'],
      package: {
        ecosystem: 'npm',
        name: 'lodash',
        version: '4.17.20',
      },
      evidence: [
        {
          scannerName: 'trivy',
          scannerRuleId: 'CVE-2021-23337',
          message: 'lodash vulnerable to command injection',
        },
      ],
      createdAt: new Date().toISOString(),
      ...overrides,
    };
  }

  it('Tier 1: Precedence goes to STRUCTURED_ADVISORY when metadata is present', () => {
    const finding = createFinding({
      evidence: [
        {
          scannerName: 'trivy',
          scannerRuleId: 'CVE-2021-23337',
          message: 'lodash template injection',
          metadata: {
            affected_functions: ['template', 'templateSettings'],
          },
        },
      ],
    });

    const candidates = extractVulnerableSymbols(finding);
    expect(candidates).toHaveLength(2);
    expect(candidates[0]?.symbol).toBe('template');
    expect(candidates[0]?.source).toBe('STRUCTURED_ADVISORY');
    expect(candidates[0]?.confidence).toBe('HIGH');
    expect(candidates[1]?.symbol).toBe('templateSettings');
    expect(candidates[1]?.source).toBe('STRUCTURED_ADVISORY');

    // extractVulnerableSymbol wrapper returns first symbol
    expect(extractVulnerableSymbol(finding)).toBe('template');
  });

  it('Tier 2: Resolves from CURATED_DB when structured metadata is absent', () => {
    const finding = createFinding({
      evidence: [
        {
          scannerName: 'trivy',
          scannerRuleId: 'CVE-2021-23337',
          message: 'Vulnerable to command injection',
        },
      ],
    });

    const candidates = extractVulnerableSymbols(finding);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    const symbols = candidates.map((c) => c.symbol);
    expect(symbols).toContain('template');
    expect(candidates[0]?.source).toBe('CURATED_DB');
    expect(candidates[0]?.confidence).toBe('HIGH');
  });

  it('Tier 3: Extracts from HEURISTIC_TEXT when structured metadata and curated DB do not match', () => {
    const finding = createFinding({
      id: 'custom-cve-9999',
      ruleId: 'custom-rule-9999',
      package: {
        ecosystem: 'npm',
        name: 'custom-unregistered-library',
        version: '1.0.0',
      },
      evidence: [
        {
          scannerName: 'trivy',
          scannerRuleId: 'CVE-CUSTOM-9999',
          message: 'custom vuln',
        },
      ],
      title: 'Prototype pollution in custom-unregistered-library',
      description:
        'The vulnerability occurs when calling method custom_deep_merge with malicious payload.',
    });

    const candidates = extractVulnerableSymbols(finding);
    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates.some((c) => c.symbol === 'custom_deep_merge')).toBe(true);
    for (const c of candidates) {
      expect(c.source).toBe('HEURISTIC_TEXT');
      expect(c.confidence).toBe('LOW'); // Heuristic candidates are LOW forever
    }
  });

  it('Hardening traps: Rejects ordinary English words from stoplist', () => {
    for (const word of [
      'is',
      'of',
      'to',
      'in',
      'the',
      'an',
      'and',
      'or',
      'via',
      'when',
      'that',
      'this',
      'js',
    ]) {
      expect(isValidHeuristicSymbol(word)).toBe(false);
      expect(HEURISTIC_STOPLIST.has(word)).toBe(true);
    }
  });

  it('Hardening traps: Rejects prose like "method of", "function in", and "Node.js ("', () => {
    const finding = createFinding({
      id: 'custom-cve-8888',
      ruleId: 'custom-rule-8888',
      package: {
        ecosystem: 'npm',
        name: 'test-parser',
        version: '1.0.0',
      },
      title: 'In Node.js (v18.0.0), a bug exists',
      description:
        'A flaw in method of parsing occurs when function in tokenizer runs. Use `safeTokenize()`.',
    });

    const candidates = extractVulnerableSymbols(finding);
    const symbols = candidates.map((c) => c.symbol);

    // Stoplist words "of" and "in" must NOT be extracted
    expect(symbols).not.toContain('of');
    expect(symbols).not.toContain('in');
    expect(symbols).not.toContain('js');
    expect(symbols).not.toContain('node');

    // Valid symbol from backticks `safeTokenize()` must be extracted
    expect(symbols).toContain('safeTokenize');
  });

  it('Hardening traps: Call-form prefix must match the package name or conventional aliases', () => {
    const finding = createFinding({
      id: 'custom-cve-7777',
      ruleId: 'custom-rule-7777',
      package: {
        ecosystem: 'npm',
        name: 'super-fetch',
        version: '1.0.0',
      },
      title: 'SSRF in super-fetch',
      description:
        'Triggered when calling super-fetch.fetchUrl(url). Also console.log(err) might print error.',
    });

    const candidates = extractVulnerableSymbols(finding);
    const symbols = candidates.map((c) => c.symbol);

    // fetchUrl prefix matches super-fetch => accepted
    expect(symbols).toContain('fetchUrl');

    // console.log prefix is "console", which does not match super-fetch => rejected
    expect(symbols).not.toContain('log');
  });

  it('Validates identifier syntax and length limits (2..64)', () => {
    expect(isValidHeuristicSymbol('a')).toBe(false); // Too short
    expect(isValidHeuristicSymbol('a'.repeat(65))).toBe(false); // Too long
    expect(isValidHeuristicSymbol('123abc_')).toBe(false); // Invalid start
    expect(isValidHeuristicSymbol('hello-world')).toBe(false); // Invalid hyphen in identifier
    expect(isValidHeuristicSymbol('validIdentifier123')).toBe(true);
    expect(isValidHeuristicSymbol('_privateHelper')).toBe(true);
    expect(isValidHeuristicSymbol('$jquerySymbol')).toBe(true);
  });
});
