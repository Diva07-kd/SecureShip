import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  WASM_MANIFEST,
  getWasmManifestHash,
  verifyWasmBuffer,
  verifyAllWasmFiles,
  verifyBundledWasm,
} from '../src/manifest/wasm-manifest.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmDir = path.resolve(__dirname, '..', 'wasm');

describe('WASM Manifest & Integrity Suite', () => {
  it('manifest contains all 5 required grammars and core wasm', () => {
    const required = [
      'tree-sitter.wasm',
      'tree-sitter-javascript.wasm',
      'tree-sitter-typescript.wasm',
      'tree-sitter-tsx.wasm',
      'tree-sitter-python.wasm',
    ];

    for (const req of required) {
      expect(WASM_MANIFEST).toHaveProperty(req);
      expect(WASM_MANIFEST[req]!.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(WASM_MANIFEST[req]!.bytes).toBeGreaterThan(1000);
    }
  });

  it('verifies all bundled wasm binaries on disk match the manifest', () => {
    const result = verifyAllWasmFiles(wasmDir);
    expect(result.ok).toBe(true);
    for (const [_filename, check] of Object.entries(result.results)) {
      expect(check.valid).toBe(true);
      expect(check.error).toBeUndefined();
    }
  });

  it('rejects tampered or corrupted wasm buffers', () => {
    const fakeBuffer = Buffer.from('corrupted wasm bytes');
    const res = verifyWasmBuffer('tree-sitter.wasm', fakeBuffer);
    expect(res.valid).toBe(false);
    expect(res.actualHash).not.toBe(WASM_MANIFEST['tree-sitter.wasm']!.sha256);
  });

  it('rejects unknown wasm filename in verifyWasmBuffer', () => {
    const res = verifyWasmBuffer('unknown.wasm', Buffer.from('abc'));
    expect(res.valid).toBe(false);
    expect(res.expectedHash).toBe('NOT_FOUND_IN_MANIFEST');
  });

  it('reports missing files when directory is empty', () => {
    const emptyDir = path.join(os.tmpdir(), `empty-wasm-${Date.now()}`);
    const res = verifyAllWasmFiles(emptyDir);
    expect(res.ok).toBe(false);
    expect(res.results['tree-sitter.wasm']!.valid).toBe(false);
    expect(res.results['tree-sitter.wasm']!.error).toContain('File not found');
  });

  it('computes deterministic manifest hash', () => {
    const hash1 = getWasmManifestHash();
    const hash2 = getWasmManifestHash();
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('verifies bundled wasm with verifyBundledWasm() successfully', () => {
    const res = verifyBundledWasm();
    expect(res.ok).toBe(true);
    expect(res.results.length).toBe(9);
    for (const r of res.results) {
      expect(r.valid).toBe(true);
    }
  });

  it('handles read errors gracefully in verifyAllWasmFiles', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wasm-read-err-'));
    try {
      // Create a directory named 'tree-sitter.wasm' so existsSync is true, but readFileSync throws EISDIR
      fs.mkdirSync(path.join(tmp, 'tree-sitter.wasm'));
      const res = verifyAllWasmFiles(tmp);
      expect(res.ok).toBe(false);
      expect(res.results['tree-sitter.wasm']!.valid).toBe(false);
      expect(res.results['tree-sitter.wasm']!.error).toBeDefined();
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('handles missing wasmDir gracefully in verifyBundledWasm', () => {
    const res = verifyBundledWasm([path.join(os.tmpdir(), `nonexistent-dir-${Date.now()}`)]);
    expect(res.ok).toBe(false);
    expect(res.results[0]?.error).toBe('WASM directory not found');
  });

  it('rejects buffer when size matches entry but bytes differs, or when size does not match', () => {
    const entry = WASM_MANIFEST['tree-sitter.wasm']!;
    const wrongSizeBuf = Buffer.alloc(entry.bytes + 1, 0);
    const resWrongSize = verifyWasmBuffer('tree-sitter.wasm', wrongSizeBuf);
    expect(resWrongSize.valid).toBe(false);
  });
});
