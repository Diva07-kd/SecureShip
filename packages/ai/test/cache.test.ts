import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import type { AiTriage } from '@secureship/contracts';
import type { SlicedFindingContext } from '@secureship/context-slicer';
import { AiCache } from '../src/cache/ai-cache.js';

describe('AiCache External HMAC Suite (A8)', () => {
  let tempDir: string;
  let cache: AiCache;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-cache-test-'));
    cache = new AiCache(true, tempDir);
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  const sampleSlice: SlicedFindingContext = {
    skipped: false,
    findingId: 'f-1',
    ruleId: 'xss',
    category: 'SAST',
    severity: 'MEDIUM',
    filePath: 'src/view.ts',
    startLine: 10,
    endLine: 12,
    primarySlice: '10 | function render() {\n11 |   return sanitize(html);\n12 | }',
    primarySliceLines: { start: 10, end: 12 },
    usageSites: [],
    scannerMessage: 'Potential XSS',
    contentHash: 'hash-abc',
    estimatedTokens: 50,
    truncated: false,
    filesSent: ['src/view.ts'],
  };

  const sampleTriage: AiTriage = {
    verdict: 'LIKELY_FALSE_POSITIVE',
    confidence: 'HIGH',
    rationale: 'Output is properly escaped.',
    citations: [{ file: 'src/view.ts', line: 11, quote: 'return sanitize(html);' }],
    model: 'gpt-4o',
    promptVersion: '1.0.0',
    cached: false,
  };

  it('stores and retrieves cache entry when HMAC and citations match', () => {
    const key = AiCache.computeKey('openai', 'gpt-4o', '1.0.0', '1.2', 'hash-abc', 0);
    cache.set(key, sampleTriage);

    const retrieved = cache.get(key, sampleSlice);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.cached).toBe(true);
    expect(retrieved?.verdict).toBe('LIKELY_FALSE_POSITIVE');
  });

  it('rejects tampered cache file where HMAC is invalid', () => {
    const key = AiCache.computeKey('openai', 'gpt-4o', '1.0.0', '1.2', 'hash-abc', 0);
    cache.set(key, sampleTriage);

    const filePath = path.join(tempDir, `${key}.json`);
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    // Tamper with rationale without updating HMAC
    raw.data.rationale = 'Tampered rationale!';
    fs.writeFileSync(filePath, JSON.stringify(raw));

    const retrieved = cache.get(key, sampleSlice);
    expect(retrieved).toBeNull();
  });

  it('re-verifies citations on read and rejects if citations no longer match current slice', () => {
    const key = AiCache.computeKey('openai', 'gpt-4o', '1.0.0', '1.2', 'hash-abc', 0);
    cache.set(key, sampleTriage);

    // Current slice has modified code that no longer contains the citation
    const modifiedSlice: SlicedFindingContext = {
      ...sampleSlice,
      primarySlice: '10 | function render() {\n11 |   return rawUnsafe(html);\n12 | }',
    };

    const retrieved = cache.get(key, modifiedSlice);
    // Must be rejected because citations failed re-verification
    expect(retrieved).toBeNull();
  });

  it('handles disabled cache and missing files', () => {
    const disabledCache = new AiCache(false, tempDir);
    const key = AiCache.computeKey('openai', 'gpt-4o', '1.0.0', '1.2', 'hash-abc', 0);
    disabledCache.set(key, sampleTriage);
    expect(disabledCache.get(key, sampleSlice)).toBeNull();

    // Missing key on enabled cache returns null
    expect(cache.get('nonexistent-key', sampleSlice)).toBeNull();
  });

  it('rejects cache entry with mismatched version or corrupted JSON', () => {
    const key = AiCache.computeKey('openai', 'gpt-4o', '1.0.0', '1.2', 'hash-abc', 0);
    cache.set(key, sampleTriage);

    const filePath = path.join(tempDir, `${key}.json`);

    // Version mismatch
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    raw.version = '0.9.0';
    fs.writeFileSync(filePath, JSON.stringify(raw));
    expect(cache.get(key, sampleSlice)).toBeNull();

    // Corrupted JSON
    fs.writeFileSync(filePath, 'invalid json');
    expect(cache.get(key, sampleSlice)).toBeNull();
  });

  it('provides machine key with >= 32 characters', () => {
    const key = AiCache.getMachineKey();
    expect(typeof key).toBe('string');
    expect(key.length).toBeGreaterThanOrEqual(32);
  });
});
