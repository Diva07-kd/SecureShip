import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import type { PatchProposal } from '@secureship/contracts';
import { AiCache } from './ai-cache.js';

export interface FixCacheEntry {
  version: string;
  key: string;
  data: PatchProposal;
  hmac: string;
}

export class FixCache {
  public static readonly CACHE_VERSION = '1.0.0';
  private readonly cacheDir: string;
  private readonly enabled: boolean;

  constructor(enabled = true, explicitCacheDir?: string) {
    this.enabled = enabled;
    this.cacheDir = explicitCacheDir || FixCache.resolveCacheDirectory();

    if (this.enabled) {
      try {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      } catch {
        // Ignored
      }
    }
  }

  public static computeKey(
    fingerprint: string,
    sliceHash: string,
    model: string,
    promptVersion: string,
    attempt: number
  ): string {
    return crypto
      .createHash('sha256')
      .update(`fix:${fingerprint}:${sliceHash}:${model}:${promptVersion}:${attempt}`)
      .digest('hex');
  }

  public get(key: string): PatchProposal | null {
    if (!this.enabled) return null;

    const filePath = path.join(this.cacheDir, `${key}.json`);
    if (!fs.existsSync(filePath)) return null;

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const entry = JSON.parse(content) as FixCacheEntry;

      if (entry.version !== FixCache.CACHE_VERSION || !entry.data || !entry.hmac) {
        return null;
      }

      const expectedHmac = this.computeHmac(JSON.stringify(entry.data));
      if (!crypto.timingSafeEqual(Buffer.from(entry.hmac), Buffer.from(expectedHmac))) {
        return null;
      }

      return entry.data;
    } catch {
      return null;
    }
  }

  public set(key: string, data: PatchProposal): void {
    if (!this.enabled) return;

    try {
      const jsonStr = JSON.stringify(data);
      const hmac = this.computeHmac(jsonStr);

      const entry: FixCacheEntry = {
        version: FixCache.CACHE_VERSION,
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

  private static resolveCacheDirectory(): string {
    const baseDir =
      process.platform === 'win32'
        ? process.env.LOCALAPPDATA
          ? path.join(process.env.LOCALAPPDATA, 'secureship')
          : path.join(os.homedir(), '.secureship')
        : process.env.XDG_CACHE_HOME
          ? path.join(process.env.XDG_CACHE_HOME, 'secureship')
          : path.join(os.homedir(), '.cache', 'secureship');

    return path.join(baseDir, 'cache', 'fixes');
  }
}
