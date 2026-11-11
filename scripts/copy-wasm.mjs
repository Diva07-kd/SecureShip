#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const wasmSrcDir = path.join(rootDir, 'packages', 'reachability', 'wasm');
const wasmDestDir = path.join(rootDir, 'packages', 'cli', 'dist', 'wasm');

if (!fs.existsSync(wasmSrcDir)) {
  console.error(`Source WASM directory does not exist: ${wasmSrcDir}`);
  process.exit(1);
}

fs.mkdirSync(wasmDestDir, { recursive: true });

const files = fs.readdirSync(wasmSrcDir).filter((f) => f.endsWith('.wasm'));
for (const file of files) {
  const src = path.join(wasmSrcDir, file);
  const dest = path.join(wasmDestDir, file);
  fs.copyFileSync(src, dest);
}

const lockSrc = path.join(rootDir, 'tools.lock.json');
const lockDest = path.join(rootDir, 'packages', 'cli', 'dist', 'tools.lock.json');
if (fs.existsSync(lockSrc)) {
  fs.copyFileSync(lockSrc, lockDest);
  console.log(`✔ Copied tools.lock.json to packages/cli/dist/tools.lock.json`);
}

console.log(`✔ Copied ${files.length} WASM grammar files to packages/cli/dist/wasm/`);

function copyAssetDir(src, dest, filter) {
  if (!fs.existsSync(src)) {
    console.error(`Source directory does not exist: ${src}`);
    process.exit(1);
  }

  if (fs.existsSync(dest)) {
    fs.rmSync(dest, { recursive: true, force: true });
  }

  fs.mkdirSync(path.dirname(dest), { recursive: true });

  fs.cpSync(src, dest, {
    recursive: true,
    force: true,
    filter,
  });
}

function getFilesRecursively(dir, filter) {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      result.push(...getFilesRecursively(fullPath, filter));
    } else if (filter(fullPath)) {
      result.push(fullPath);
    }
  }
  return result;
}

// Asset 1: packages/reachability/data -> packages/cli/dist/data (*.json only)
const dataSrcDir = path.join(rootDir, 'packages', 'reachability', 'data');
const dataDestDir = path.join(rootDir, 'packages', 'cli', 'dist', 'data');

if (!fs.existsSync(dataSrcDir)) {
  console.error(`Source directory does not exist: ${dataSrcDir}`);
  process.exit(1);
}

copyAssetDir(dataSrcDir, dataDestDir, (source) => {
  if (fs.statSync(source).isDirectory()) {
    return true;
  }
  return source.endsWith('.json');
});

const copiedDataFiles = getFilesRecursively(dataDestDir, (p) => p.endsWith('.json'));
console.log(`✔ Copied ${copiedDataFiles.length} symbol dataset files to packages/cli/dist/data/`);

// Asset 2: rules/secureship-sast -> packages/cli/dist/rules/secureship-sast (*.yaml and *.yml only)
const rulesSrcDir = path.join(rootDir, 'rules', 'secureship-sast');
const rulesDestDir = path.join(rootDir, 'packages', 'cli', 'dist', 'rules', 'secureship-sast');

if (!fs.existsSync(rulesSrcDir)) {
  console.error(`Source directory does not exist: ${rulesSrcDir}`);
  process.exit(1);
}

copyAssetDir(rulesSrcDir, rulesDestDir, (source) => {
  if (fs.statSync(source).isDirectory()) {
    return true;
  }
  return source.endsWith('.yaml') || source.endsWith('.yml');
});

const sourceRuleFiles = getFilesRecursively(
  rulesSrcDir,
  (p) => p.endsWith('.yaml') || p.endsWith('.yml')
);
const copiedRuleFiles = getFilesRecursively(
  rulesDestDir,
  (p) => p.endsWith('.yaml') || p.endsWith('.yml')
);
console.log(
  `✔ Copied ${copiedRuleFiles.length} SAST rule files to packages/cli/dist/rules/secureship-sast/`
);

// Post-copy self-verification
const distDataFile = path.join(dataDestDir, 'vulnerable-symbols.json');
const distManifestFile = path.join(dataDestDir, 'vulnerable-symbols.manifest.json');

// a. dist/data contains vulnerable-symbols.json AND vulnerable-symbols.manifest.json
if (!fs.existsSync(distDataFile) || !fs.existsSync(distManifestFile)) {
  console.error(
    `Self-verification failed: dist/data is missing vulnerable-symbols.json or vulnerable-symbols.manifest.json`
  );
  process.exit(1);
}

// b. SHA-256 of dist/data/vulnerable-symbols.json equals the sha256 field of dist/data/vulnerable-symbols.manifest.json
const rawData = fs.readFileSync(distDataFile);
const actualHash = crypto.createHash('sha256').update(rawData).digest('hex');
let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(distManifestFile, 'utf-8'));
} catch (err) {
  console.error(`Self-verification failed: Malformed JSON in ${distManifestFile}: ${err.message}`);
  process.exit(1);
}
if (manifest.sha256 !== actualHash) {
  console.error(
    `Self-verification failed: SHA-256 mismatch for ${distDataFile}. Expected ${manifest.sha256}, got ${actualHash}`
  );
  process.exit(1);
}

// c. dist/rules/secureship-sast contains >=1 YAML file and its YAML file count equals the source count
if (copiedRuleFiles.length < 1) {
  console.error(`Self-verification failed: dist/rules/secureship-sast contains no YAML files.`);
  process.exit(1);
}
if (copiedRuleFiles.length !== sourceRuleFiles.length) {
  console.error(
    `Self-verification failed: dist/rules/secureship-sast YAML count (${copiedRuleFiles.length}) does not match source count (${sourceRuleFiles.length}).`
  );
  process.exit(1);
}
