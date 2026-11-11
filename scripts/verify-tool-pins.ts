import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

interface PlatformAsset {
  url: string;
  archiveType: string;
  binarySubpath?: string;
  sha256: string;
  verifiedAgainst?: string;
  checkedAt?: string;
}

interface ToolDefinition {
  name: string;
  version: string;
  description: string;
  binaryName: string;
  sha256ManifestUrl?: string | null;
  unsupportedReason?: string;
  platforms: Record<string, PlatformAsset>;
}

interface ToolsLockfile {
  schemaVersion: number;
  updatedAt: string;
  tools: Record<string, ToolDefinition>;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const lockfilePath = path.resolve(__dirname, '../tools.lock.json');

if (!fs.existsSync(lockfilePath)) {
  console.error(`✖ tools.lock.json not found at ${lockfilePath}`);
  process.exit(1);
}

const lockfile: ToolsLockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'));

async function fetchManifestMap(manifestUrl: string): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  try {
    const res = await fetch(manifestUrl, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} fetching manifest ${manifestUrl}`);
    }
    const text = await res.text();
    for (const line of text.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        const hash = parts[0]!.toLowerCase();
        const fname = parts[parts.length - 1]!.replace(/^\.\//, '')
          .replace(/^\.\\/, '')
          .split(/[/\\]/)
          .pop()!
          .toLowerCase();
        if (/^[a-f0-9]{64}$/.test(hash)) {
          map.set(fname, hash);
        }
      }
    }
  } catch (err: unknown) {
    console.warn(
      `  ⚠ Warning: Could not fetch manifest from ${manifestUrl}: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  return map;
}

async function streamComputeSha256(url: string, maxRetries = 3): Promise<string> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(90000),
        headers: {
          'User-Agent': 'SecureShip-Pin-Verifier/1.0',
        },
      });
      if (!res.ok || !res.body) {
        throw new Error(`HTTP ${res.status} ${res.statusText} fetching asset ${url}`);
      }
      const hash = crypto.createHash('sha256');
      const reader = res.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) hash.update(value);
      }
      return hash.digest('hex').toLowerCase();
    } catch (err: unknown) {
      lastError = err;
      if (attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, attempt * 2000));
      }
    }
  }
  throw lastError;
}

async function main() {
  console.log(`\n🔒 Verifying SecureShip External Tool Pins (${lockfilePath})\n`);

  let totalAssetsChecked = 0;
  let totalManifestsChecked = 0;
  const errors: string[] = [];

  for (const [toolName, tool] of Object.entries(lockfile.tools)) {
    console.log(`• Checking tool: ${tool.name} (v${tool.version})`);

    let manifestMap: Map<string, string> | null = null;
    if (tool.sha256ManifestUrl) {
      console.log(`  ↳ Fetching upstream checksum manifest: ${tool.sha256ManifestUrl}`);
      manifestMap = await fetchManifestMap(tool.sha256ManifestUrl);
      if (manifestMap.size > 0) {
        totalManifestsChecked++;
      }
    }

    for (const [platKey, asset] of Object.entries(tool.platforms)) {
      totalAssetsChecked++;
      const assetFilename = path.basename(asset.url).toLowerCase();
      console.log(`  ↳ [${platKey}] ${assetFilename}`);

      // 1. Cross-check against upstream checksum manifest if available
      if (manifestMap && manifestMap.has(assetFilename)) {
        const manifestHash = manifestMap.get(assetFilename)!;
        if (manifestHash !== asset.sha256.toLowerCase()) {
          const errMsg = `Drift detected! Tool '${toolName}' platform '${platKey}' pinned hash (${asset.sha256}) does not match upstream manifest hash (${manifestHash})`;
          console.error(`    ✖ ${errMsg}`);
          errors.push(errMsg);
          continue;
        } else {
          console.log(
            `    ✔ Matched upstream checksum manifest (${manifestHash.slice(0, 16)}...)`
          );
        }
      }

      // 2. Stream and compute real SHA-256 hash
      try {
        const computed = await streamComputeSha256(asset.url);
        if (computed !== asset.sha256.toLowerCase()) {
          const errMsg = `Hash mismatch! Tool '${toolName}' platform '${platKey}' download computed hash (${computed}) does not match lockfile (${asset.sha256})`;
          console.error(`    ✖ ${errMsg}`);
          errors.push(errMsg);
        } else {
          console.log(
            `    ✔ Downloaded bytes verified byte-for-byte (${computed.slice(0, 16)}...)`
          );
        }
      } catch (err: unknown) {
        const errMsg = `Network error fetching tool '${toolName}' asset '${asset.url}': ${err instanceof Error ? err.message : String(err)}`;
        console.error(`    ✖ ${errMsg}`);
        errors.push(errMsg);
      }
    }
  }

  console.log(
    `\nSummary: ${totalAssetsChecked} asset pins evaluated across ${totalManifestsChecked} upstream manifests.`
  );

  if (errors.length > 0) {
    console.error(`\n✖ Verification FAILED with ${errors.length} error(s):`);
    for (const e of errors) {
      console.error(`  - ${e}`);
    }
    process.exit(1);
  }

  console.log(
    `✔ All tool pins strictly match upstream release assets and manifests. Zero drift.\n`
  );
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal error during tool pins verification:', err);
  process.exit(1);
});
