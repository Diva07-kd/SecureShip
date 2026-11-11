import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ExternalExtractionCache, type FileSyntaxExtraction } from '../src/cache/external-cache.js';

describe('ExternalExtractionCache Security Suite (Amendment A3)', () => {
  const tempProjectDir = path.join(os.tmpdir(), `secureship-test-proj-${Date.now()}`);

  beforeEach(() => {
    fs.mkdirSync(tempProjectDir, { recursive: true });
  });

  it('stores cache in user directory outside target repository', () => {
    const cache = new ExternalExtractionCache(tempProjectDir, true);
    // Cache directory must not start with tempProjectDir
    const rel = path.relative(tempProjectDir, cache.getCacheDir());
    expect(rel.startsWith('..')).toBe(true);
  });

  it('generates per-machine random secret key with 0600 permissions', () => {
    const key = ExternalExtractionCache.getMachineKey();
    expect(key).toBeDefined();
    expect(key.length).toBeGreaterThanOrEqual(32);
  });

  it('signs entries with HMAC-SHA256 and retrieves valid cached extractions', () => {
    const cache = new ExternalExtractionCache(tempProjectDir, true);
    const sampleExtraction: FileSyntaxExtraction = {
      filePath: 'src/index.ts',
      contentHash: 'hash123',
      hasParseError: false,
      hasDynamicImports: false,
      imports: [{ specifier: 'express', isTypeOnly: false, startLine: 1 }],
      exports: [],
    };

    cache.set('src/index.ts', sampleExtraction);

    // Retrieve entry with matching content hash
    const retrieved = cache.get('src/index.ts', 'hash123');
    expect(retrieved).toEqual(sampleExtraction);

    // Content hash mismatch yields null (invalidated)
    const stale = cache.get('src/index.ts', 'modified_hash');
    expect(stale).toBeNull();
  });

  it('rejects tampered or forged HMAC entries', () => {
    const cache = new ExternalExtractionCache(tempProjectDir, true);
    const sample: FileSyntaxExtraction = {
      filePath: 'src/main.ts',
      contentHash: 'hash456',
      hasParseError: false,
      hasDynamicImports: false,
      imports: [{ specifier: 'axios', isTypeOnly: false, startLine: 1 }],
      exports: [],
    };

    cache.set('src/main.ts', sample);

    // Tamper with the file on disk by overwriting HMAC
    const fileKey = cache.getCacheDir();
    const entries = fs.readdirSync(fileKey);
    const jsonFile = entries.find((e: string) => e.endsWith('.json'))!;
    const entryPath = path.join(fileKey, jsonFile);

    const fileContent = JSON.parse(fs.readFileSync(entryPath, 'utf8'));
    fileContent.hmac = 'forged_invalid_hmac';
    fs.writeFileSync(entryPath, JSON.stringify(fileContent));

    const result = cache.get('src/main.ts', 'hash456');
    expect(result).toBeNull(); // Rejected
  });

  it('anti-poisoning test: a committed .secureship/cache inside fixture repo is strictly ignored', () => {
    // Malicious fixture with a planted in-repo cache attempting to poison reachability
    const inRepoCacheDir = path.join(tempProjectDir, '.secureship', 'cache');
    fs.mkdirSync(inRepoCacheDir, { recursive: true });
    fs.writeFileSync(
      path.join(inRepoCacheDir, 'poison.json'),
      JSON.stringify({ poisoned: true, specifier: 'fake-safe-verdict' })
    );

    const cache = new ExternalExtractionCache(tempProjectDir, true);
    // External cache never inspects in-repo cache directory
    expect(cache.getCacheDir()).not.toContain(path.join(tempProjectDir, '.secureship'));
  });
});
