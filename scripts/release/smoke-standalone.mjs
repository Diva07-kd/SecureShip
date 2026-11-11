#!/usr/bin/env node
import { parseArgs } from 'node:util';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { execSync, spawnSync } from 'node:child_process';

const options = {
  archive: { type: 'string' },
  target: { type: 'string' },
};

const { values, positionals } = parseArgs({ options, allowPositionals: true });

const archiveArg = values.archive || positionals[0];
const targetArg = values.target || positionals[1];

if (!archiveArg || !targetArg) {
  console.error('Usage: smoke-standalone.mjs --archive <path> --target <target>');
  process.exit(1);
}

const archivePath = path.resolve(archiveArg);
const target = targetArg;

if (!fs.existsSync(archivePath)) {
  console.error(`Archive not found at: ${archivePath}`);
  process.exit(1);
}

console.log(`\n🔍 Running SecureShip standalone smoke test on: ${archivePath} (target: ${target})`);

// 1. Extract archive into temporary directory containing a space
const extractBase = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship smoke test space '));
console.log(`Extracting into path with spaces: ${extractBase}`);

try {
  if (archivePath.endsWith('.zip')) {
    if (process.platform === 'win32') {
      const escapedArchive = archivePath.replace(/'/g, "''");
      const escapedDest = extractBase.replace(/'/g, "''");
      const psCmd = `powershell -NoProfile -NonInteractive -Command "Expand-Archive -Path '${escapedArchive}' -DestinationPath '${escapedDest}' -Force"`;
      execSync(psCmd, { stdio: 'inherit' });
    } else {
      execSync(`unzip -q "${archivePath}" -d "${extractBase}"`, { stdio: 'inherit' });
    }
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${extractBase}"`, { stdio: 'inherit' });
  }
} catch (err) {
  console.error(`Extraction failed: ${err.message}`);
  process.exit(1);
}

const stageDir = path.join(extractBase, `secureship-${target}`);
const binName = target === 'win32-x64' ? 'secureship.exe' : 'secureship';
const binPath = path.join(stageDir, binName);

if (!fs.existsSync(binPath)) {
  console.error(`Extracted binary not found at: ${binPath}`);
  process.exit(1);
}

if (process.platform !== 'win32') {
  fs.chmodSync(binPath, 0o755);
}

// 2. Create empty cwd elsewhere
const emptyCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-empty-cwd-'));

// 3. Run Check 1: <bin> --version -> exit 0
function runBin(args, opts = {}) {
  const options = {
    cwd: emptyCwd,
    encoding: 'utf-8',
    timeout: 120000,
    maxBuffer: 20 * 1024 * 1024,
    ...opts,
  };
  let res = spawnSync(binPath, args, options);
  if (res.error && process.platform === 'win32') {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
    res = spawnSync(binPath, args, options);
  }
  return res;
}

// 3. Run Check 1: <bin> --version -> exit 0
console.log('Running Check 1: version check...');
const res1 = runBin(['--version']);

if (res1.status === 0 && (res1.stdout || '').trim().length > 0) {
  console.log(`PASS: [Check 1] --version exited 0 (${res1.stdout.trim()})`);
} else {
  console.error(
    `FAIL: [Check 1] --version exited with code ${res1.status}, signal: ${res1.signal}, error: ${res1.error?.message || 'none'}:\n${res1.stderr || res1.stdout}`
  );
  process.exit(1);
}

// 4. Run Check 2: WASM integrity verification on tiny fixture
console.log('Running Check 2: WASM grammar discovery and verification...');
const tinyFixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-tiny-js-'));
fs.writeFileSync(path.join(tinyFixtureDir, 'index.js'), 'const a = 1;\nconsole.log(a);\n');

const res2 = runBin(['scan', tinyFixtureDir, '--no-color']);
const combinedOut2 = (res2.stdout || '') + '\n' + (res2.stderr || '');

if (
  combinedOut2.includes('WASM directory not found') ||
  combinedOut2.includes('Integrity check failed') ||
  res2.signal !== null ||
  res2.status !== 0
) {
  console.error(
    `FAIL: [Check 2] WASM verification failed (status=${res2.status}, error=${res2.error?.message || 'none'}):\n${combinedOut2}`
  );
  process.exit(1);
}
console.log('PASS: [Check 2] WASM grammar discovery and integrity check succeeded');

// 5. Run Check 3: Scan of fixture project with lodash@4.17.20 and _.template
console.log('Running Check 3: Lodash reachability & symbol dataset verification...');
const lodashFixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-lodash-'));
fs.writeFileSync(
  path.join(lodashFixtureDir, 'package.json'),
  JSON.stringify(
    {
      name: 'smoke-fixture-project',
      version: '1.0.0',
      dependencies: {
        lodash: '4.17.20',
      },
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(lodashFixtureDir, 'index.js'),
  "import _ from 'lodash';\nconst compiled = _.template('hello <%= user %>!');\nconsole.log(compiled({ user: 'world' }));\n"
);

const res3 = runBin(['scan', lodashFixtureDir, '--no-color']);
const combinedOut3 = (res3.stdout || '') + '\n' + (res3.stderr || '');

const forbiddenSubstrings = [
  'WASM directory not found',
  'ENOENT',
  'Symbol dataset file not found',
  'Integrity check failed',
  'NOT from the bundled',
];

for (const forbidden of forbiddenSubstrings) {
  if (combinedOut3.includes(forbidden)) {
    console.error(
      `FAIL: [Check 3] Output contained forbidden substring: "${forbidden}"\n\nFull Output:\n${combinedOut3}`
    );
    process.exit(1);
  }
}

if (res3.signal !== null) {
  console.error(
    `FAIL: [Check 3] Process was terminated by signal ${res3.signal}\n\nFull Output:\n${combinedOut3}`
  );
  process.exit(1);
}

console.log(
  'PASS: [Check 3] Lodash fixture scan passed with no errors, missing assets, or fallback warnings'
);

// Cleanup temporary directories
try {
  fs.rmSync(extractBase, { recursive: true, force: true });
  fs.rmSync(emptyCwd, { recursive: true, force: true });
  fs.rmSync(tinyFixtureDir, { recursive: true, force: true });
  fs.rmSync(lodashFixtureDir, { recursive: true, force: true });
} catch {
  // best-effort cleanup
}

console.log('\n🎉 All standalone smoke tests PASSED!\n');
process.exit(0);
