#!/usr/bin/env node
import { parseArgs } from 'node:util';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const options = {
  target: { type: 'string' },
  binary: { type: 'string' },
  assets: { type: 'string' },
  out: { type: 'string' },
};

const { values } = parseArgs({ options, allowPositionals: true });

const target = values.target;
const binaryPath = values.binary ? path.resolve(values.binary) : '';
const assetsDir = values.assets ? path.resolve(values.assets) : '';
const outDir = values.out ? path.resolve(values.out) : '';

if (!target || !binaryPath || !assetsDir || !outDir) {
  console.error(
    'Usage: package-standalone.mjs --target <linux-x64|darwin-arm64|darwin-x64|win32-x64> --binary <path> --assets <packages/cli/dist> --out <dir>'
  );
  process.exit(1);
}

const validTargets = ['linux-x64', 'darwin-arm64', 'darwin-x64', 'win32-x64'];
if (!validTargets.includes(target)) {
  console.error(`Invalid target: ${target}. Must be one of: ${validTargets.join(', ')}`);
  process.exit(1);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..', '..');

// Required root documentation files
const requiredDocs = ['LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md'];
for (const doc of requiredDocs) {
  const docPath = path.join(rootDir, doc);
  if (!fs.existsSync(docPath)) {
    console.error(`Missing required root document: ${docPath}`);
    process.exit(1);
  }
}

// Check source assets
const srcWasmDir = path.join(assetsDir, 'wasm');
const srcDataDir = path.join(assetsDir, 'data');
const srcRulesDir = path.join(assetsDir, 'rules', 'secureship-sast');
const srcToolsLock = path.join(assetsDir, 'tools.lock.json');

if (!fs.existsSync(srcWasmDir)) {
  console.error(`Missing assets wasm directory: ${srcWasmDir}`);
  process.exit(1);
}
if (!fs.existsSync(srcDataDir)) {
  console.error(`Missing assets data directory: ${srcDataDir}`);
  process.exit(1);
}
if (!fs.existsSync(srcRulesDir)) {
  console.error(`Missing assets rules directory: ${srcRulesDir}`);
  process.exit(1);
}
if (!fs.existsSync(srcToolsLock)) {
  console.error(`Missing assets tools lock file: ${srcToolsLock}`);
  process.exit(1);
}
if (!fs.existsSync(binaryPath)) {
  console.error(`Binary not found at: ${binaryPath}`);
  process.exit(1);
}

const binStat = fs.statSync(binaryPath);
if (binStat.size === 0) {
  console.error(`Binary is empty at: ${binaryPath}`);
  process.exit(1);
}

// Stage directory setup
const stageName = `secureship-${target}`;
const stageDir = path.join(outDir, stageName);
const isWin = target === 'win32-x64';
const archiveName = isWin ? `${stageName}.zip` : `${stageName}.tar.gz`;
const archivePath = path.join(outDir, archiveName);
const sha256Path = `${archivePath}.sha256`;

// Idempotent: remove stale stage and archive
if (fs.existsSync(stageDir)) {
  fs.rmSync(stageDir, { recursive: true, force: true });
}
if (fs.existsSync(archivePath)) {
  fs.rmSync(archivePath, { force: true });
}
if (fs.existsSync(sha256Path)) {
  fs.rmSync(sha256Path, { force: true });
}

fs.mkdirSync(stageDir, { recursive: true });

// 1. Copy binary
const destBinName = isWin ? 'secureship.exe' : 'secureship';
const destBinPath = path.join(stageDir, destBinName);
fs.copyFileSync(binaryPath, destBinPath);
if (process.platform !== 'win32') {
  fs.chmodSync(destBinPath, 0o755);
}

// 2. Copy wasm files (*.wasm only, deterministically sorted)
const stageWasmDir = path.join(stageDir, 'wasm');
fs.mkdirSync(stageWasmDir, { recursive: true });
const wasmFiles = fs
  .readdirSync(srcWasmDir)
  .filter((f) => f.endsWith('.wasm'))
  .sort();
if (wasmFiles.length === 0) {
  console.error(`No WASM files found in ${srcWasmDir}`);
  process.exit(1);
}
for (const file of wasmFiles) {
  fs.copyFileSync(path.join(srcWasmDir, file), path.join(stageWasmDir, file));
}

// 3. Copy data files (*.json only, deterministically sorted)
const stageDataDir = path.join(stageDir, 'data');
fs.mkdirSync(stageDataDir, { recursive: true });
const dataFiles = fs
  .readdirSync(srcDataDir)
  .filter((f) => f.endsWith('.json'))
  .sort();
if (dataFiles.length === 0) {
  console.error(`No data files found in ${srcDataDir}`);
  process.exit(1);
}
for (const file of dataFiles) {
  fs.copyFileSync(path.join(srcDataDir, file), path.join(stageDataDir, file));
}

// 4. Copy rules (YAML only: *.yaml and *.yml, preserving relative structure)
const stageRulesDir = path.join(stageDir, 'rules', 'secureship-sast');
fs.mkdirSync(stageRulesDir, { recursive: true });

function countYamlFiles(dir) {
  if (!fs.existsSync(dir)) return 0;
  let count = 0;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      count += countYamlFiles(fullPath);
    } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
      count++;
    }
  }
  return count;
}

function copyYamlRecursively(src, dest) {
  const entries = fs
    .readdirSync(src, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      if (countYamlFiles(srcPath) > 0) {
        fs.mkdirSync(destPath, { recursive: true });
        copyYamlRecursively(srcPath, destPath);
      }
    } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}
copyYamlRecursively(srcRulesDir, stageRulesDir);

// 5. Copy tools.lock.json
fs.copyFileSync(srcToolsLock, path.join(stageDir, 'tools.lock.json'));

// 6. Copy root documentation
for (const doc of requiredDocs) {
  fs.copyFileSync(path.join(rootDir, doc), path.join(stageDir, doc));
}

// --- Pre-Archive Verifications ---
console.log('Verifying staged standalone distribution before archiving...');

// a. Verify all wasm files against WASM manifest using reachability package
const reachabilityPkgPath = path.join(rootDir, 'packages', 'reachability', 'dist', 'index.js');
if (!fs.existsSync(reachabilityPkgPath)) {
  console.error(`Reachability package dist not found at ${reachabilityPkgPath}. Build repo first.`);
  process.exit(1);
}
const reachability = await import(pathToFileURL(reachabilityPkgPath).href);
if (typeof reachability.verifyAllWasmFiles !== 'function') {
  console.error('verifyAllWasmFiles is not exported by @secureship/reachability');
  process.exit(1);
}
const wasmVerification = reachability.verifyAllWasmFiles(stageWasmDir);
if (!wasmVerification.ok) {
  console.error(
    'Pre-archive verification failed: One or more WASM files failed manifest integrity:'
  );
  for (const [file, res] of Object.entries(wasmVerification.results)) {
    if (!res.valid) {
      console.error(`  - ${file}: ${res.error ?? 'Integrity mismatch'}`);
    }
  }
  process.exit(1);
}
console.log('✔ All WASM files verified against WASM manifest');

// b. Verify data/vulnerable-symbols.json SHA-256 equals manifest
const stagedDataFile = path.join(stageDataDir, 'vulnerable-symbols.json');
const stagedManifestFile = path.join(stageDataDir, 'vulnerable-symbols.manifest.json');
if (!fs.existsSync(stagedDataFile) || !fs.existsSync(stagedManifestFile)) {
  console.error('Pre-archive verification failed: missing vulnerable-symbols.json or manifest');
  process.exit(1);
}
const dataRaw = fs.readFileSync(stagedDataFile);
const actualDataSha = crypto.createHash('sha256').update(dataRaw).digest('hex').toLowerCase();
const manifestObj = JSON.parse(fs.readFileSync(stagedManifestFile, 'utf-8'));
if (actualDataSha !== manifestObj.sha256.toLowerCase()) {
  console.error(
    `Pre-archive verification failed: vulnerable-symbols.json SHA-256 mismatch.\n  Expected: ${manifestObj.sha256}\n  Actual:   ${actualDataSha}`
  );
  process.exit(1);
}
console.log('✔ Vulnerable symbols dataset verified against manifest');

// c. Verify rules YAML count >= 1 and equals source count
const sourceRulesDir = path.join(rootDir, 'rules', 'secureship-sast');
const sourceYamlCount = countYamlFiles(sourceRulesDir);
const stagedYamlCount = countYamlFiles(stageRulesDir);
if (stagedYamlCount < 1) {
  console.error('Pre-archive verification failed: staged rules directory contains 0 YAML files');
  process.exit(1);
}
if (stagedYamlCount !== sourceYamlCount) {
  console.error(
    `Pre-archive verification failed: staged rules YAML count (${stagedYamlCount}) does not match source count (${sourceYamlCount})`
  );
  process.exit(1);
}
console.log(`✔ SAST rules verified: ${stagedYamlCount} YAML files matching source`);

// d. Verify binary exists, is non-empty, and executable on POSIX
if (!fs.existsSync(destBinPath)) {
  console.error(`Pre-archive verification failed: binary does not exist at ${destBinPath}`);
  process.exit(1);
}
const destStat = fs.statSync(destBinPath);
if (destStat.size === 0) {
  console.error(`Pre-archive verification failed: binary is empty at ${destBinPath}`);
  process.exit(1);
}
if (process.platform !== 'win32') {
  fs.chmodSync(destBinPath, 0o755);
  const mode = fs.statSync(destBinPath).mode;
  if ((mode & 0o111) === 0) {
    console.error(
      `Pre-archive verification failed: binary is not executable (mode ${mode.toString(8)})`
    );
    process.exit(1);
  }
}
console.log(`✔ Binary verified: ${destBinName} (${destStat.size} bytes, executable)`);

// --- Create Archive ---
console.log(`Creating archive: ${archivePath}...`);
if (isWin) {
  if (process.platform === 'win32') {
    const escapedStage = stageDir.replace(/'/g, "''");
    const escapedArchive = archivePath.replace(/'/g, "''");
    const psCmd = `powershell -NoProfile -NonInteractive -Command "Compress-Archive -Path '${escapedStage}' -DestinationPath '${escapedArchive}' -Force"`;
    execSync(psCmd, { stdio: 'inherit' });
  } else {
    // Cross-packaging win32 zip on POSIX
    try {
      execSync(`zip -r "${archivePath}" "${stageName}"`, { cwd: outDir, stdio: 'inherit' });
    } catch {
      execSync(`tar -a -cf "${archivePath}" -C "${outDir}" "${stageName}"`, { stdio: 'inherit' });
    }
  }
} else {
  // tar -czf on POSIX (or Windows bsdtar)
  execSync(`tar -czf "${archivePath}" -C "${outDir}" "${stageName}"`, { stdio: 'inherit' });
}

if (!fs.existsSync(archivePath) || fs.statSync(archivePath).size === 0) {
  console.error(`Failed to produce archive: ${archivePath}`);
  process.exit(1);
}

// --- Write Checksum ---
const archiveBuf = fs.readFileSync(archivePath);
const archiveHash = crypto.createHash('sha256').update(archiveBuf).digest('hex').toLowerCase();
fs.writeFileSync(sha256Path, `${archiveHash}\n`, 'utf-8');

console.log(`✔ Successfully packaged: ${archivePath}`);
console.log(`✔ SHA-256 checksum: ${archiveHash} -> ${sha256Path}`);
