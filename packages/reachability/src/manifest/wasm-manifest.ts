import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getStandaloneExecDir } from '../standalone-exec.js';

export interface WasmBinaryInfo {
  filename: string;
  sha256: string;
  bytes: number;
  upstreamRepo: string;
  version: string;
  license: string;
}

export const WASM_MANIFEST: Record<string, WasmBinaryInfo> = {
  'tree-sitter.wasm': {
    filename: 'tree-sitter.wasm',
    sha256: '29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f',
    bytes: 188635,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter',
    version: '0.22.6',
    license: 'MIT',
  },
  'tree-sitter-javascript.wasm': {
    filename: 'tree-sitter-javascript.wasm',
    sha256: '63812b9e275d26851264734868d27a1656bd44a2ef6eb3e85e6b03728c595ab5',
    bytes: 647334,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-javascript',
    version: '0.20.3',
    license: 'MIT',
  },
  'tree-sitter-typescript.wasm': {
    filename: 'tree-sitter-typescript.wasm',
    sha256: '8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f',
    bytes: 2342690,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-typescript',
    version: '0.20.5',
    license: 'MIT',
  },
  'tree-sitter-tsx.wasm': {
    filename: 'tree-sitter-tsx.wasm',
    sha256: '6aa3b2c70e76f5d48eafef1093e9c4de383e13f2fdde2f4e9b98a378f6a8f1b6',
    bytes: 2411272,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-typescript',
    version: '0.20.5',
    license: 'MIT',
  },
  'tree-sitter-python.wasm': {
    filename: 'tree-sitter-python.wasm',
    sha256: '9056d0fb0c337810d019fae350e8167786119da98f0f282aceae7ab89ee8253b',
    bytes: 476105,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-python',
    version: '0.21.0',
    license: 'MIT',
  },
  'tree-sitter-go.wasm': {
    filename: 'tree-sitter-go.wasm',
    sha256: '9963ca89b616eaf04b08a43bc1fb0f07b85395bec313330851f1f1ead2f755b6',
    bytes: 235957,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-go',
    version: '0.20.0',
    license: 'MIT',
  },
  'tree-sitter-java.wasm': {
    filename: 'tree-sitter-java.wasm',
    sha256: '637aac4415fb39a211a4f4292d63c66b5ce9c32fa2cd35464af4f681d91b9a1f',
    bytes: 430239,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-java',
    version: '0.20.2',
    license: 'MIT',
  },
  'tree-sitter-rust.wasm': {
    filename: 'tree-sitter-rust.wasm',
    sha256: '4409921a70d0aa5bec7d1d7ce809a557a8ee1cf6ace901e3ac6a76e62cfea903',
    bytes: 818756,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-rust',
    version: '0.21.2',
    license: 'MIT',
  },
  'tree-sitter-c_sharp.wasm': {
    filename: 'tree-sitter-c_sharp.wasm',
    sha256: '6266a7e32d68a3459104d994dc848df15d5672b0ea8e86d327274b694f8e6991',
    bytes: 3978594,
    upstreamRepo: 'https://github.com/tree-sitter/tree-sitter-c-sharp',
    version: '0.20.0',
    license: 'MIT',
  },
};

/**
 * Deterministic hash of the entire manifest table, used for cache invalidation.
 */
export function getWasmManifestHash(): string {
  const serialized = Object.keys(WASM_MANIFEST)
    .sort()
    .map((k) => `${k}:${WASM_MANIFEST[k]!.sha256}:${WASM_MANIFEST[k]!.bytes}`)
    .join('|');
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

/**
 * Computes the SHA-256 hash of a buffer.
 */
export function computeSha256(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex').toLowerCase();
}

/**
 * Verifies a WASM buffer against the manifest.
 */
export function verifyWasmBuffer(
  filename: string,
  buffer: Buffer
): { valid: boolean; actualHash: string; expectedHash: string } {
  const entry = WASM_MANIFEST[filename];
  if (!entry) {
    return {
      valid: false,
      actualHash: computeSha256(buffer),
      expectedHash: 'NOT_FOUND_IN_MANIFEST',
    };
  }
  const actualHash = computeSha256(buffer);
  return {
    valid: actualHash === entry.sha256 && buffer.length === entry.bytes,
    actualHash,
    expectedHash: entry.sha256,
  };
}

/**
 * Validates all WASM binaries in the specified directory against the manifest.
 */
export function verifyAllWasmFiles(wasmDir: string): {
  ok: boolean;
  results: Record<
    string,
    { valid: boolean; actualHash?: string; expectedHash?: string; error?: string }
  >;
} {
  const results: Record<
    string,
    { valid: boolean; actualHash?: string; expectedHash?: string; error?: string }
  > = {};
  let allOk = true;

  for (const [filename, info] of Object.entries(WASM_MANIFEST)) {
    const fullPath = path.join(wasmDir, filename);
    if (!fs.existsSync(fullPath)) {
      results[filename] = {
        valid: false,
        expectedHash: info.sha256,
        error: `File not found: ${fullPath}`,
      };
      allOk = false;
      continue;
    }

    try {
      const buf = fs.readFileSync(fullPath);
      const res = verifyWasmBuffer(filename, buf);
      results[filename] = res;
      if (!res.valid) {
        allOk = false;
      }
    } catch (err) {
      results[filename] = {
        valid: false,
        expectedHash: info.sha256,
        error: err instanceof Error ? err.message : String(err),
      };
      allOk = false;
    }
  }

  return { ok: allOk, results };
}

export interface WasmCandidateOptions {
  envDir?: string;
  moduleDir?: string;
  cwd?: string;
  execDir?: string | null;
}

const defaultModuleDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * Returns absolute, de-duplicated candidate directories to search for bundled WASM grammars.
 *
 * Search candidate order:
 * 1. SECURESHIP_WASM_DIR (if set)
 * 2. The 5 existing module-relative candidates, in their current order
 * 3. path.join(execDir, 'wasm') when execDir is non-null
 * 4. The existing cwd-based candidate `packages/reachability/wasm`
 */
export function getWasmSearchCandidates(opts?: WasmCandidateOptions): string[] {
  const envDir = opts?.envDir !== undefined ? opts.envDir : process.env.SECURESHIP_WASM_DIR;
  const moduleDir = opts?.moduleDir !== undefined ? opts.moduleDir : defaultModuleDir;
  const cwd = opts?.cwd !== undefined ? opts.cwd : process.cwd();
  const execDir = opts?.execDir !== undefined ? opts.execDir : getStandaloneExecDir();

  const candidates: string[] = [];

  // 1. SECURESHIP_WASM_DIR (if set)
  if (envDir) {
    candidates.push(path.resolve(envDir));
  }

  // 2. The 5 existing module-relative candidates, in their current order
  candidates.push(path.resolve(moduleDir, 'wasm'));
  candidates.push(path.resolve(moduleDir, '..', 'wasm'));
  candidates.push(path.resolve(moduleDir, '..', 'dist', 'wasm'));
  candidates.push(path.resolve(moduleDir, '..', '..', 'wasm'));
  candidates.push(path.resolve(moduleDir, '..', '..', 'packages', 'reachability', 'wasm'));

  // 3. path.join(execDir, 'wasm') when execDir is non-null
  if (execDir) {
    candidates.push(path.resolve(execDir, 'wasm'));
  }

  // 4. The existing cwd-based candidate packages/reachability/wasm
  candidates.push(path.resolve(cwd, 'packages', 'reachability', 'wasm'));

  return Array.from(new Set(candidates));
}

/**
 * Verifies all bundled WASM files by discovering the bundled wasm directory.
 */
export function verifyBundledWasm(candidatesOverride?: string[]): {
  ok: boolean;
  results: Array<{
    filename: string;
    valid: boolean;
    expectedSize: number;
    expectedHash: string;
    actualHash?: string;
    error?: string;
  }>;
} {
  const candidates = candidatesOverride ?? getWasmSearchCandidates();
  let wasmDir = '';
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'tree-sitter.wasm'))) {
      wasmDir = c;
      break;
    }
  }

  if (!wasmDir) {
    return {
      ok: false,
      results: Object.keys(WASM_MANIFEST).map((k) => ({
        filename: k,
        valid: false,
        expectedSize: WASM_MANIFEST[k]!.bytes,
        expectedHash: WASM_MANIFEST[k]!.sha256,
        error: 'WASM directory not found',
      })),
    };
  }

  const check = verifyAllWasmFiles(wasmDir);
  const results = Object.entries(check.results).map(([filename, res]) => ({
    filename,
    valid: res.valid,
    expectedSize: WASM_MANIFEST[filename]?.bytes ?? 0,
    expectedHash: res.expectedHash ?? WASM_MANIFEST[filename]?.sha256 ?? '',
    actualHash: res.actualHash,
    error: res.error,
  }));
  return { ok: check.ok, results };
}
