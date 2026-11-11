import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..');
const dataDir = path.join(projectRoot, 'packages/reachability/data');
const dataPath = path.join(dataDir, 'vulnerable-symbols.json');
const manifestPath = path.join(dataDir, 'vulnerable-symbols.manifest.json');

console.log('--- Verifying Vulnerable Symbols Dataset & Cryptographic Manifest ---');

if (!fs.existsSync(dataPath)) {
  console.error(`FAIL: Dataset file not found at ${dataPath}`);
  process.exit(1);
}

if (!fs.existsSync(manifestPath)) {
  console.error(`FAIL: Manifest file not found at ${manifestPath}`);
  process.exit(1);
}

const rawBytes = fs.readFileSync(dataPath);
const actualHash = crypto.createHash('sha256').update(rawBytes).digest('hex');

const manifestRaw = fs.readFileSync(manifestPath, 'utf-8');
let manifest;
try {
  manifest = JSON.parse(manifestRaw);
} catch (err) {
  console.error(`FAIL: Malformed JSON in manifest: ${err.message}`);
  process.exit(1);
}

// 1. Integrity check
console.log(`Checking SHA-256 Digest...`);
console.log(`  Actual:   ${actualHash}`);
console.log(`  Expected: ${manifest.sha256}`);

if (actualHash !== manifest.sha256) {
  console.error(`FAIL: SHA-256 hash mismatch! Dataset may be corrupted or tampered.`);
  process.exit(1);
}

if (rawBytes.length !== manifest.bytes) {
  console.error(`FAIL: Byte count mismatch! File: ${rawBytes.length}, Manifest: ${manifest.bytes}`);
  process.exit(1);
}

let dataset;
try {
  dataset = JSON.parse(rawBytes.toString('utf-8'));
} catch (err) {
  console.error(`FAIL: Malformed JSON in dataset: ${err.message}`);
  process.exit(1);
}

if (dataset.entries.length !== manifest.entryCount) {
  console.error(
    `FAIL: Entry count mismatch! Dataset: ${dataset.entries.length}, Manifest: ${manifest.entryCount}`
  );
  process.exit(1);
}

console.log(
  `Checking ${dataset.entries.length} entries for schema, uniqueness, URLs, and completeness...`
);

const seenIds = new Set();
const seenAliases = new Map();
let errorCount = 0;

for (let i = 0; i < dataset.entries.length; i++) {
  const entry = dataset.entries[i];
  const prefix = `[Entry ${i + 1} (${entry.id || 'NO-ID'})]`;

  if (!entry.id || typeof entry.id !== 'string') {
    console.error(`${prefix} Missing or non-string id`);
    errorCount++;
  } else if (seenIds.has(entry.id)) {
    console.error(`${prefix} Duplicate entry ID: ${entry.id}`);
    errorCount++;
  } else {
    seenIds.add(entry.id);
  }

  if (!['npm', 'pypi'].includes(entry.ecosystem)) {
    console.error(`${prefix} Invalid ecosystem: ${entry.ecosystem}`);
    errorCount++;
  }

  if (!entry.package || typeof entry.package !== 'string') {
    console.error(`${prefix} Missing or non-string package name`);
    errorCount++;
  }

  if (!Array.isArray(entry.entryPoints) || entry.entryPoints.length === 0) {
    console.error(`${prefix} entryPoints must be a non-empty array`);
    errorCount++;
  } else {
    for (const ep of entry.entryPoints) {
      if (!ep.module || typeof ep.module !== 'string') {
        console.error(`${prefix} Invalid entryPoint module: ${JSON.stringify(ep)}`);
        errorCount++;
      }
      if (!ep.export || typeof ep.export !== 'string') {
        console.error(`${prefix} Invalid entryPoint export: ${JSON.stringify(ep)}`);
        errorCount++;
      }
      if (!['FUNCTION', 'CLASS', 'METHOD', 'PROPERTY'].includes(ep.kind)) {
        console.error(`${prefix} Invalid entryPoint kind: ${ep.kind}`);
        errorCount++;
      }
      if (ep.kind === 'METHOD') {
        if (!Array.isArray(ep.via) || ep.via.length === 0) {
          console.error(`${prefix} Entry point kind METHOD requires non-empty via array`);
          errorCount++;
        }
      }
    }
  }

  if (!['CALL', 'IMPORT_TIME', 'UNKNOWN'].includes(entry.triggeredOn)) {
    console.error(`${prefix} Invalid triggeredOn: ${entry.triggeredOn}`);
    errorCount++;
  }

  if (typeof entry.entryPointsComplete !== 'boolean') {
    console.error(`${prefix} entryPointsComplete must be a boolean`);
    errorCount++;
  }

  // URL format verification
  if (!Array.isArray(entry.sourceUrls) || entry.sourceUrls.length === 0) {
    console.error(`${prefix} sourceUrls must be a non-empty array`);
    errorCount++;
  } else {
    for (const u of entry.sourceUrls) {
      try {
        const parsed = new URL(u);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          console.error(`${prefix} Invalid URL protocol in sourceUrl: ${u}`);
          errorCount++;
        }
      } catch {
        console.error(`${prefix} Malformed sourceUrl: ${u}`);
        errorCount++;
      }
    }
  }

  if (!Array.isArray(entry.fixCommitUrls) || entry.fixCommitUrls.length === 0) {
    console.error(`${prefix} fixCommitUrls must be a non-empty array`);
    errorCount++;
  } else {
    for (const u of entry.fixCommitUrls) {
      try {
        const parsed = new URL(u);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          console.error(`${prefix} Invalid URL protocol in fixCommitUrl: ${u}`);
          errorCount++;
        }
      } catch {
        console.error(`${prefix} Malformed fixCommitUrl: ${u}`);
        errorCount++;
      }
    }
  }

  if (!entry.verifiedAt || !/^\d{4}-\d{2}-\d{2}$/.test(entry.verifiedAt)) {
    console.error(`${prefix} verifiedAt must be in YYYY-MM-DD format: ${entry.verifiedAt}`);
    errorCount++;
  }

  if (!entry.verifiedBy || typeof entry.verifiedBy !== 'string') {
    console.error(`${prefix} Missing verifiedBy`);
    errorCount++;
  }

  // Alias collision tracking
  if (Array.isArray(entry.aliases)) {
    for (const alias of entry.aliases) {
      if (seenAliases.has(alias)) {
        console.warn(
          `[WARN] Alias '${alias}' seen in multiple entries: ${seenAliases.get(alias)} and ${entry.id}`
        );
      } else {
        seenAliases.set(alias, entry.id);
      }
    }
  }
}

if (errorCount > 0) {
  console.error(`FAIL: Verification failed with ${errorCount} errors.`);
  process.exit(1);
}

console.log(
  `SUCCESS: All ${dataset.entries.length} entries passed schema, integrity, and completeness verification.`
);
process.exit(0);
