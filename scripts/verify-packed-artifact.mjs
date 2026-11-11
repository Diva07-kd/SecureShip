#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const cliDir = path.resolve(repoRoot, 'packages/cli');

export function verifyPackedArtifact(targetCliDir = cliDir) {
  const tempPackDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-pack-verify-'));

  try {
    // Run npm pack into temp directory
    const packOutput = execSync(
      `npm pack "${targetCliDir}" --json --pack-destination "${tempPackDir}"`,
      {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );

    const parsedPack = JSON.parse(packOutput.trim());
    const metadata = Array.isArray(parsedPack) ? parsedPack[0] : parsedPack;

    const tarballFilename =
      metadata.filename ||
      `${metadata.name.replace('@', '').replace('/', '-')}-${metadata.version}.tgz`;
    const tarballPath = path.join(tempPackDir, tarballFilename);

    const tarballSize =
      metadata.size || (fs.existsSync(tarballPath) ? fs.statSync(tarballPath).size : 0);
    const unpackedSize = metadata.unpackedSize || 0;
    const entryCount = metadata.entryCount || 0;

    const files = (metadata.files || []).map((f) => f.path.replace(/\\/g, '/'));
    const fileSet = new Set(files);

    const violations = [];

    // F1. Mandatory files validation
    const mandatoryFiles = [
      'dist/index.js',
      'dist/data/vulnerable-symbols.json',
      'dist/data/vulnerable-symbols.manifest.json',
      'dist/tools.lock.json',
      'README.md',
      'LICENSE',
      'package.json',
    ];

    for (const mf of mandatoryFiles) {
      if (!fileSet.has(mf)) {
        violations.push(`Missing mandatory file in packed tarball: '${mf}'`);
      }
    }

    // WASM files check (must have at least tree-sitter.wasm and tree-sitter-javascript.wasm)
    const wasmFiles = files.filter((f) => f.startsWith('dist/wasm/') && f.endsWith('.wasm'));
    if (wasmFiles.length === 0) {
      violations.push('No WASM files found in dist/wasm/ in packed tarball');
    }

    // SAST rules check (must contain .yml/.yaml rules)
    const ruleFiles = files.filter(
      (f) =>
        f.startsWith('dist/rules/secureship-sast/') && (f.endsWith('.yml') || f.endsWith('.yaml'))
    );
    if (ruleFiles.length === 0) {
      violations.push('No SAST rule files found in dist/rules/secureship-sast/ in packed tarball');
    }

    // Forbidden files check: NO src/, test/, .env*, gitleaks-report*
    for (const f of files) {
      if (f.startsWith('src/') || f.includes('/src/')) {
        violations.push(`Forbidden source file included in tarball: '${f}'`);
      }
      if (f.startsWith('test/') || f.includes('/test/')) {
        violations.push(`Forbidden test file included in tarball: '${f}'`);
      }
      if (f.startsWith('.env') || f.includes('/.env')) {
        violations.push(`Forbidden environment file included in tarball: '${f}'`);
      }
      if (f.includes('gitleaks-report')) {
        violations.push(`Forbidden audit report file included in tarball: '${f}'`);
      }
    }

    // Check sourcemaps (.map files)
    const mapFiles = files.filter((f) => f.endsWith('.map'));

    // Extract packed package.json to verify dependencies
    const extractDir = path.join(tempPackDir, 'extracted');
    fs.mkdirSync(extractDir, { recursive: true });
    execSync(`tar -xzf "${tarballPath}" -C "${extractDir}"`, { stdio: 'ignore' });

    const extractedPkgJsonPath = path.join(extractDir, 'package', 'package.json');
    const packedPackageJson = JSON.parse(fs.readFileSync(extractedPkgJsonPath, 'utf-8'));

    // F2. Zero @secureship/* in runtime/optional/peer dependencies
    const runtimeSecureship = Object.keys(packedPackageJson.dependencies || {}).filter((k) =>
      k.startsWith('@secureship/')
    );
    const optionalSecureship = Object.keys(packedPackageJson.optionalDependencies || {}).filter(
      (k) => k.startsWith('@secureship/')
    );
    const peerSecureship = Object.keys(packedPackageJson.peerDependencies || {}).filter((k) =>
      k.startsWith('@secureship/')
    );

    if (runtimeSecureship.length > 0) {
      violations.push(
        `Packed package.json contains @secureship/* dependencies: ${runtimeSecureship.join(', ')}`
      );
    }
    if (optionalSecureship.length > 0) {
      violations.push(
        `Packed package.json contains @secureship/* optionalDependencies: ${optionalSecureship.join(', ')}`
      );
    }
    if (peerSecureship.length > 0) {
      violations.push(
        `Packed package.json contains @secureship/* peerDependencies: ${peerSecureship.join(', ')}`
      );
    }

    return {
      success: violations.length === 0,
      tarballName: tarballFilename,
      tarballSize,
      unpackedSize,
      entryCount,
      files,
      intentionallyShippedMaps: mapFiles,
      violations,
      packageJson: packedPackageJson,
    };
  } finally {
    try {
      fs.rmSync(tempPackDir, { recursive: true, force: true });
    } catch {}
  }
}

// CLI entry
if (
  import.meta.url === `file://${process.argv[1]}` ||
  (process.argv[1] &&
    process.argv[1].replace(/\\/g, '/').endsWith('scripts/verify-packed-artifact.mjs'))
) {
  console.log('📦 SecureShip Release Verification — Packed Artifact Auditor (Layer F)\n');
  const result = verifyPackedArtifact();

  console.log(`Tarball Name     : ${result.tarballName}`);
  console.log(
    `Tarball Size     : ${result.tarballSize} bytes (~${(result.tarballSize / (1024 * 1024)).toFixed(2)} MB)`
  );
  console.log(
    `Unpacked Size    : ${result.unpackedSize} bytes (~${(result.unpackedSize / (1024 * 1024)).toFixed(2)} MB)`
  );
  console.log(`Total Files      : ${result.entryCount}`);
  console.log(
    `Shipped .map     : ${result.intentionallyShippedMaps.length} files (tsup sourcemap: true)`
  );
  console.log(`Violations       : ${result.violations.length}`);

  if (result.violations.length > 0) {
    console.error('\n❌ PACKED ARTIFACT VERIFICATION FAILED:');
    for (const v of result.violations) {
      console.error(`  - ${v}`);
    }
    process.exit(1);
  } else {
    console.log(
      '\n✔ PACKED ARTIFACT VERIFIED CLEAN: Zero @secureship/* dependencies, all assets present.'
    );
    process.exit(0);
  }
}
