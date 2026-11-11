import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { getWasmManifestHash } from '../manifest/wasm-manifest.js';
import type { FileSymbolUsage } from '../symbol-usage/symbol-usage.types.js';

export interface FileSyntaxExtraction {
  filePath: string;
  contentHash: string;
  hasParseError: boolean;
  hasDynamicImports: boolean;
  imports: Array<{
    specifier: string;
    isTypeOnly: boolean;
    startLine: number;
  }>;
  exports: Array<{
    specifier: string;
    isTypeOnly: boolean;
  }>;
  symbolUsage?: FileSymbolUsage;
}

export interface CacheEntry {
  version: string;
  manifestHash: string;
  contentHash: string;
  data: FileSyntaxExtraction;
  hmac: string;
}

export class ExternalExtractionCache {
  public static readonly ANALYZER_VERSION = '2.0.0';
  private static machineKey: string | null = null;
  private readonly cacheDir: string;
  private readonly enabled: boolean;

  constructor(targetDir: string, enabled = true) {
    this.enabled = enabled;
    const realTarget = fs.existsSync(targetDir)
      ? fs.realpathSync(path.resolve(targetDir))
      : path.resolve(targetDir);
    const targetHash = crypto.createHash('sha256').update(realTarget).digest('hex').slice(0, 16);
    this.cacheDir = ExternalExtractionCache.getCacheDirectory(targetHash);

    if (this.enabled) {
      try {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      } catch {
        // Ignored
      }
    }
  }

  public getCacheDir(): string {
    return this.cacheDir;
  }

  /**
   * Resolves the user-level cache directory outside the target repository.
   */
  public static getCacheDirectory(targetHash: string): string {
    const base =
      process.platform === 'win32'
        ? process.env.LOCALAPPDATA
          ? path.join(process.env.LOCALAPPDATA, 'secureship', 'cache')
          : path.join(os.homedir(), '.secureship', 'cache')
        : process.env.XDG_CACHE_HOME
          ? path.join(process.env.XDG_CACHE_HOME, 'secureship', 'cache')
          : path.join(os.homedir(), '.cache', 'secureship', 'cache');

    return path.join(base, targetHash);
  }

  /**
   * Retrieves or initializes the per-machine secret key (mode 0600).
   */
  public static getMachineKey(): string {
    if (ExternalExtractionCache.machineKey) {
      return ExternalExtractionCache.machineKey;
    }

    const keyDir =
      process.platform === 'win32'
        ? process.env.LOCALAPPDATA
          ? path.join(process.env.LOCALAPPDATA, 'secureship')
          : path.join(os.homedir(), '.secureship')
        : process.env.XDG_CACHE_HOME
          ? path.join(process.env.XDG_CACHE_HOME, 'secureship')
          : path.join(os.homedir(), '.cache', 'secureship');

    const keyPath = path.join(keyDir, '.machine-secret');

    try {
      if (fs.existsSync(keyPath)) {
        const key = fs.readFileSync(keyPath, 'utf8').trim();
        if (key.length >= 32) {
          ExternalExtractionCache.machineKey = key;
          return key;
        }
      }
    } catch {
      // Create new key if read fails
    }

    const newKey = crypto.randomBytes(32).toString('hex');
    try {
      fs.mkdirSync(keyDir, { recursive: true });
      fs.writeFileSync(keyPath, newKey, { encoding: 'utf8', mode: 0o600 });
      // Extra safety for posix chmod
      if (process.platform !== 'win32') {
        try {
          fs.chmodSync(keyPath, 0o600);
        } catch {
          // Ignored
        }
      }
    } catch {
      // In-memory fallback if disk write fails
    }

    ExternalExtractionCache.machineKey = newKey;
    return newKey;
  }

  /**
   * Computes HMAC-SHA256 signature for a cache entry payload.
   */
  public static computeHmac(payload: string): string {
    const key = ExternalExtractionCache.getMachineKey();
    return crypto.createHmac('sha256', key).update(payload).digest('hex');
  }

  /**
   * Retrieves a verified cache entry, rejecting missing, corrupted, or forged entries.
   */
  public get(relativeFilePath: string, currentContentHash: string): FileSyntaxExtraction | null {
    if (!this.enabled) return null;

    const fileKey = crypto.createHash('sha256').update(relativeFilePath).digest('hex');
    const entryPath = path.join(this.cacheDir, `${fileKey}.json`);

    try {
      if (!fs.existsSync(entryPath)) return null;

      const raw = fs.readFileSync(entryPath, 'utf8');
      const entry = JSON.parse(raw) as CacheEntry;

      if (
        entry.version !== ExternalExtractionCache.ANALYZER_VERSION ||
        entry.manifestHash !== getWasmManifestHash() ||
        entry.contentHash !== currentContentHash
      ) {
        return null;
      }

      // Verify HMAC integrity
      const payload = `${entry.version}:${entry.manifestHash}:${entry.contentHash}:${JSON.stringify(entry.data)}`;
      const expectedHmac = ExternalExtractionCache.computeHmac(payload);

      if (entry.hmac !== expectedHmac) {
        // Tampered or corrupted entry: reject
        return null;
      }

      return entry.data;
    } catch {
      return null;
    }
  }

  /**
   * Atomically writes an extraction entry signed with HMAC.
   */
  public set(relativeFilePath: string, extraction: FileSyntaxExtraction): void {
    if (!this.enabled) return;

    const fileKey = crypto.createHash('sha256').update(relativeFilePath).digest('hex');
    const entryPath = path.join(this.cacheDir, `${fileKey}.json`);
    const tmpPath = path.join(
      this.cacheDir,
      `${fileKey}.${crypto.randomBytes(4).toString('hex')}.tmp`
    );

    const manifestHash = getWasmManifestHash();
    const payload = `${ExternalExtractionCache.ANALYZER_VERSION}:${manifestHash}:${extraction.contentHash}:${JSON.stringify(extraction)}`;
    const hmac = ExternalExtractionCache.computeHmac(payload);

    const entry: CacheEntry = {
      version: ExternalExtractionCache.ANALYZER_VERSION,
      manifestHash,
      contentHash: extraction.contentHash,
      data: extraction,
      hmac,
    };

    try {
      fs.writeFileSync(tmpPath, JSON.stringify(entry), { encoding: 'utf8' });
      fs.renameSync(tmpPath, entryPath);
    } catch {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {
        // Ignored
      }
    }
  }
}
