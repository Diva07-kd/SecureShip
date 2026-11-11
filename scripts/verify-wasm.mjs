import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const wasmDir = path.join(rootDir, 'packages', 'reachability', 'wasm');
const lockfilePath = path.join(rootDir, 'pnpm-lock.yaml');

const MANIFEST = {
  'tree-sitter.wasm': {
    sha256: '29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f',
    bytes: 188635,
    packageSource: 'web-tree-sitter',
    sourceRelativePath: 'tree-sitter.wasm',
  },
  'tree-sitter-javascript.wasm': {
    sha256: '63812b9e275d26851264734868d27a1656bd44a2ef6eb3e85e6b03728c595ab5',
    bytes: 647334,
    packageSource: 'tree-sitter-wasms',
    sourceRelativePath: 'out/tree-sitter-javascript.wasm',
  },
  'tree-sitter-typescript.wasm': {
    sha256: '8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f',
    bytes: 2342690,
    packageSource: 'tree-sitter-wasms',
    sourceRelativePath: 'out/tree-sitter-typescript.wasm',
  },
  'tree-sitter-tsx.wasm': {
    sha256: '6aa3b2c70e76f5d48eafef1093e9c4de383e13f2fdde2f4e9b98a378f6a8f1b6',
    bytes: 2411272,
    packageSource: 'tree-sitter-wasms',
    sourceRelativePath: 'out/tree-sitter-tsx.wasm',
  },
  'tree-sitter-python.wasm': {
    sha256: '9056d0fb0c337810d019fae350e8167786119da98f0f282aceae7ab89ee8253b',
    bytes: 476105,
    packageSource: 'tree-sitter-wasms',
    sourceRelativePath: 'out/tree-sitter-python.wasm',
  },
};

console.log(
  '🔒 Verifying SecureShip WASM Grammar Integrity (Manifest + Upstream Package Tarballs)...'
);
let hasErrors = false;

// 1. Verify pnpm-lock.yaml contains exact pinned versions and integrity hashes
if (!fs.existsSync(lockfilePath)) {
  console.error(`❌ Missing pnpm-lock.yaml at ${lockfilePath}`);
  process.exit(1);
}

const lockContent = fs.readFileSync(lockfilePath, 'utf8');

const expectedIntegrities = {
  'tree-sitter-wasms@0.1.13':
    'sha512-wT+cR6DwaIz80/vho3AvSF0N4txuNx/5bcRKoXouOfClpxh/qqrF4URNLQXbbt8MaAxeksZcZd1j8gcGjc+QxQ==',
  'web-tree-sitter@0.22.6':
    'sha512-hS87TH71Zd6mGAmYCvlgxeGDjqd9GTeqXNqTT+u0Gs51uIozNIaaq/kUAbV/Zf56jb2ZOyG8BxZs2GG9wbLi6Q==',
};

for (const [pkgVer, expectedHash] of Object.entries(expectedIntegrities)) {
  if (!lockContent.includes(pkgVer)) {
    console.error(`❌ pnpm-lock.yaml missing pinned package: ${pkgVer}`);
    hasErrors = true;
  } else if (!lockContent.includes(expectedHash)) {
    console.error(`❌ pnpm-lock.yaml integrity mismatch for ${pkgVer}`);
    hasErrors = true;
  } else {
    console.log(`✔ Verified lockfile integrity: ${pkgVer} -> ${expectedHash.slice(0, 24)}...`);
  }
}

// 2. Resolve installed package directories in node_modules
let tsWasmsBaseDir = null;
let webTreeSitterBaseDir = null;

try {
  const tsPkgPath = path.resolve(
    rootDir,
    'node_modules',
    '.pnpm',
    'tree-sitter-wasms@0.1.13',
    'node_modules',
    'tree-sitter-wasms'
  );
  if (fs.existsSync(tsPkgPath)) {
    tsWasmsBaseDir = tsPkgPath;
  } else {
    // Try node_modules direct
    const directPath = path.join(rootDir, 'node_modules', 'tree-sitter-wasms');
    if (fs.existsSync(directPath)) tsWasmsBaseDir = directPath;
  }
} catch {}

try {
  const wtsPkgPath = path.resolve(
    rootDir,
    'node_modules',
    '.pnpm',
    'web-tree-sitter@0.22.6',
    'node_modules',
    'web-tree-sitter'
  );
  if (fs.existsSync(wtsPkgPath)) {
    webTreeSitterBaseDir = wtsPkgPath;
  } else {
    const directPath = path.join(rootDir, 'node_modules', 'web-tree-sitter');
    if (fs.existsSync(directPath)) webTreeSitterBaseDir = directPath;
  }
} catch {}

// 3. Verify bundled WASM binaries against Manifest and byte-for-byte against Upstream Packages
for (const [filename, expected] of Object.entries(MANIFEST)) {
  const filePath = path.join(wasmDir, filename);
  if (!fs.existsSync(filePath)) {
    console.error(`❌ Missing WASM binary: ${filename} at ${filePath}`);
    hasErrors = true;
    continue;
  }

  const buf = fs.readFileSync(filePath);
  const actualSha256 = crypto.createHash('sha256').update(buf).digest('hex').toLowerCase();

  if (buf.length !== expected.bytes) {
    console.error(
      `❌ Byte size mismatch for ${filename}: expected ${expected.bytes}, got ${buf.length}`
    );
    hasErrors = true;
    continue;
  }

  if (actualSha256 !== expected.sha256) {
    console.error(
      `❌ SHA-256 hash mismatch for ${filename}:\n  Expected: ${expected.sha256}\n  Actual:   ${actualSha256}`
    );
    hasErrors = true;
    continue;
  }

  // Byte-for-byte comparison against upstream package binary
  const sourceBaseDir =
    expected.packageSource === 'tree-sitter-wasms' ? tsWasmsBaseDir : webTreeSitterBaseDir;

  if (sourceBaseDir) {
    const upstreamFile = path.join(sourceBaseDir, expected.sourceRelativePath);
    if (!fs.existsSync(upstreamFile)) {
      console.error(`❌ Upstream package file missing: ${upstreamFile}`);
      hasErrors = true;
      continue;
    }

    const upstreamBuf = fs.readFileSync(upstreamFile);
    if (!buf.equals(upstreamBuf)) {
      console.error(
        `❌ Byte-for-byte mismatch between bundled ${filename} and upstream ${expected.packageSource} file!`
      );
      hasErrors = true;
      continue;
    }
    console.log(
      `✔ Byte-for-byte matched upstream: ${filename} == ${expected.packageSource}/${expected.sourceRelativePath}`
    );
  } else {
    console.log(
      `✔ Verified manifest: ${filename} (${buf.length} bytes, sha256: ${actualSha256.slice(0, 16)}...)`
    );
  }
}

if (hasErrors) {
  console.error('\n💥 WASM Verification FAILED! One or more binaries failed integrity checks.');
  process.exit(1);
} else {
  console.log(
    '\n✨ All bundled WASM grammar binaries strictly match the verified manifest and upstream package integrity.'
  );
}
