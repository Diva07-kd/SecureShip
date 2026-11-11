import fs from 'node:fs';
import path from 'node:path';
import type { DetectorContext } from '../internal/types.js';
import type {
  MetadataProvider,
  Packument,
  ProviderError,
  PublisherInfo,
  Result,
} from './provider.interface.js';

export class SnapshotProvider implements MetadataProvider {
  private readonly snapshotDir: string;
  private readonly inMemoryPackuments = new Map<string, Packument>();
  private readonly inMemoryDownloads = new Map<string, number>();
  private readonly inMemoryPublishers = new Map<string, PublisherInfo | null>();
  private readonly inMemoryTarballs = new Map<string, Uint8Array>();

  constructor(snapshotDir?: string) {
    this.snapshotDir = snapshotDir ?? '';
  }

  public setPackument(ecosystem: string, name: string, packument: Packument): void {
    this.inMemoryPackuments.set(`${ecosystem}:${name}`, packument);
  }

  public setWeeklyDownloads(ecosystem: string, name: string, count: number): void {
    this.inMemoryDownloads.set(`${ecosystem}:${name}`, count);
  }

  public setPublisher(
    ecosystem: string,
    name: string,
    version: string,
    publisher: PublisherInfo | null
  ): void {
    this.inMemoryPublishers.set(`${ecosystem}:${name}@${version}`, publisher);
  }

  public setTarball(ecosystem: string, name: string, version: string, tarball: Uint8Array): void {
    this.inMemoryTarballs.set(`${ecosystem}:${name}@${version}`, tarball);
  }

  private resolveSnapshotFilePath(ecosystem: string, name: string): string | null {
    if (!this.snapshotDir || !fs.existsSync(this.snapshotDir)) {
      return null;
    }
    // Handle scoped packages: e.g. @scope/foo -> @scope/foo.json or @scope_foo.json or scope__foo.json
    const safeName = name.replace('/', '__');
    const directPath = path.join(this.snapshotDir, ecosystem, `${name}.json`);
    if (fs.existsSync(directPath)) return directPath;

    const safePath = path.join(this.snapshotDir, ecosystem, `${safeName}.json`);
    if (fs.existsSync(safePath)) return safePath;

    return null;
  }

  public async getPackument(
    ecosystem: 'npm' | 'pypi',
    name: string,
    _ctx: DetectorContext
  ): Promise<Result<Packument, ProviderError>> {
    const memoryKey = `${ecosystem}:${name}`;
    if (this.inMemoryPackuments.has(memoryKey)) {
      return { ok: true, value: this.inMemoryPackuments.get(memoryKey)! };
    }

    const filePath = this.resolveSnapshotFilePath(ecosystem, name);
    if (filePath) {
      try {
        const raw = fs.readFileSync(filePath, 'utf-8');
        const parsed = JSON.parse(raw) as Packument;
        return { ok: true, value: parsed };
      } catch (err) {
        return {
          ok: false,
          error: {
            code: 'INVALID_RESPONSE',
            message: `Corrupt snapshot file at ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
          },
        };
      }
    }

    return {
      ok: false,
      error: {
        code: 'NOT_FOUND',
        message: `Snapshot not found for package ${name} (${ecosystem})`,
      },
    };
  }

  public async getWeeklyDownloads(
    ecosystem: 'npm' | 'pypi',
    name: string,
    ctx: DetectorContext
  ): Promise<Result<number, ProviderError>> {
    const memoryKey = `${ecosystem}:${name}`;
    if (this.inMemoryDownloads.has(memoryKey)) {
      return { ok: true, value: this.inMemoryDownloads.get(memoryKey)! };
    }

    // Attempt to infer from packument or return default
    const packumentRes = await this.getPackument(ecosystem, name, ctx);
    if (packumentRes.ok) {
      return { ok: true, value: 50_000 };
    }

    return {
      ok: false,
      error: {
        code: 'NOT_FOUND',
        message: `Download count snapshot not found for package ${name}`,
      },
    };
  }

  public async getPublisher(
    ecosystem: 'npm' | 'pypi',
    name: string,
    version: string,
    ctx: DetectorContext
  ): Promise<Result<PublisherInfo | null, ProviderError>> {
    const memoryKey = `${ecosystem}:${name}@${version}`;
    if (this.inMemoryPublishers.has(memoryKey)) {
      return { ok: true, value: this.inMemoryPublishers.get(memoryKey)! };
    }

    const packumentRes = await this.getPackument(ecosystem, name, ctx);
    if (packumentRes.ok) {
      const maintainer = packumentRes.value.maintainers?.[0];
      if (maintainer) {
        return {
          ok: true,
          value: {
            username: maintainer.name,
            email: maintainer.email,
            verified: true,
          },
        };
      }
    }

    return {
      ok: false,
      error: {
        code: 'NOT_FOUND',
        message: `Publisher snapshot not found for ${name}@${version}`,
      },
    };
  }

  public async getTarball(
    ecosystem: 'npm' | 'pypi',
    name: string,
    version: string,
    _ctx: DetectorContext
  ): Promise<Result<Uint8Array, ProviderError>> {
    const memoryKey = `${ecosystem}:${name}@${version}`;
    if (this.inMemoryTarballs.has(memoryKey)) {
      return { ok: true, value: this.inMemoryTarballs.get(memoryKey)! };
    }

    return {
      ok: false,
      error: {
        code: 'NOT_FOUND',
        message: `Tarball snapshot not found for ${name}@${version}`,
      },
    };
  }
}
