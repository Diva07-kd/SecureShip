import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import type { AiTriage } from '@secureship/contracts';
import type { SlicedFindingContext } from '@secureship/context-slicer';
import { CitationVerifier } from '../triage/citation-verifier.js';

export interface AiCacheEntry {
  version: string;
  key: string;
  data: AiTriage;
  hmac: string;
}

export class AiCache {
  public static readonly CACHE_VERSION = '1.0.0';
  private static machineKey: string | null = null;
  private readonly cacheDir: string;
  private readonly enabled: boolean;

  constructor(enabled = true, explicitCacheDir?: string) {
    this.enabled = enabled;
    this.cacheDir = explicitCacheDir || AiCache.resolveCacheDirectory();

    if (this.enabled) {
      try {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      } catch {
        // Ignored
      }
    }
  }

  public static computeKey(
    provider: string,
    model: string,
    promptVersion: string,
    schemaVersion: string,
    sliceHash: string,
    sampleVariant = 0
  ): string {
    return crypto
      .createHash('sha256')
      .update(
        `${provider}:${model}:${promptVersion}:${schemaVersion}:${sliceHash}:${sampleVariant}`
      )
      .digest('hex');
  }

  public get(key: string, currentSlice: SlicedFindingContext): AiTriage | null {
    if (!this.enabled) return null;

    const filePath = path.join(this.cacheDir, `${key}.json`);
    if (!fs.existsSync(filePath)) return null;

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const entry = JSON.parse(content) as AiCacheEntry;

      // 1. Verify entry structure
      if (entry.version !== AiCache.CACHE_VERSION || !entry.data || !entry.hmac) {
        return null;
      }

      // 2. Verify HMAC integrity signature
      const expectedHmac = this.computeHmac(JSON.stringify(entry.data));
      if (!crypto.timingSafeEqual(Buffer.from(entry.hmac), Buffer.from(expectedHmac))) {
        return null;
      }

      // 3. Re-verify citations against current slice on read (A8)
      const citationCheck = CitationVerifier.verifyCitations(
        entry.data.citations,
        currentSlice,
        entry.data.verdict === 'LIKELY_FALSE_POSITIVE'
      );
      if (!citationCheck.valid) {
        return null;
      }

      return {
        ...entry.data,
        cached: true,
      };
    } catch {
      return null;
    }
  }

  public set(key: string, data: AiTriage): void {
    if (!this.enabled) return;

    try {
      const jsonStr = JSON.stringify(data);
      const hmac = this.computeHmac(jsonStr);

      const entry: AiCacheEntry = {
        version: AiCache.CACHE_VERSION,
        key,
        data,
        hmac,
      };

      const filePath = path.join(this.cacheDir, `${key}.json`);
      fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), {
        encoding: 'utf-8',
        mode: 0o600,
      });
    } catch {
      // Ignored
    }
  }

  private computeHmac(data: string): string {
    const key = AiCache.getMachineKey();
    return crypto.createHmac('sha256', key).update(data).digest('hex');
  }

  public static getMachineKey(): string {
    if (AiCache.machineKey) return AiCache.machineKey;

    const baseDir =
      process.platform === 'win32'
        ? process.env.LOCALAPPDATA
          ? path.join(process.env.LOCALAPPDATA, 'secureship')
          : path.join(os.homedir(), '.secureship')
        : process.env.XDG_CACHE_HOME
          ? path.join(process.env.XDG_CACHE_HOME, 'secureship')
          : path.join(os.homedir(), '.cache', 'secureship');

    const keyPath = path.join(baseDir, '.machine-secret');

    try {
      if (fs.existsSync(keyPath)) {
        const existing = fs.readFileSync(keyPath, 'utf-8').trim();
        if (existing.length >= 32) {
          AiCache.machineKey = existing;
          return existing;
        }
      }
    } catch {}

    const newKey = crypto.randomBytes(32).toString('hex');
    try {
      fs.mkdirSync(baseDir, { recursive: true });
      fs.writeFileSync(keyPath, newKey, { encoding: 'utf-8', mode: 0o600 });
      if (process.platform !== 'win32') {
        try {
          fs.chmodSync(keyPath, 0o600);
        } catch {}
      }
    } catch {}

    AiCache.machineKey = newKey;
    return newKey;
  }

  private static resolveCacheDirectory(): string {
    const base =
      process.platform === 'win32'
        ? process.env.LOCALAPPDATA
          ? path.join(process.env.LOCALAPPDATA, 'secureship', 'cache', 'ai')
          : path.join(os.homedir(), '.secureship', 'cache', 'ai')
        : process.env.XDG_CACHE_HOME
          ? path.join(process.env.XDG_CACHE_HOME, 'secureship', 'cache', 'ai')
          : path.join(os.homedir(), '.cache', 'secureship', 'cache', 'ai');

    return base;
  }
}
