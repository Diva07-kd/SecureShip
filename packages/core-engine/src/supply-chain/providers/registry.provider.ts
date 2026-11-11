import type { DetectorContext } from '../internal/types.js';
import type {
  MetadataProvider,
  Packument,
  ProviderError,
  PublisherInfo,
  Result,
} from './provider.interface.js';

export class RegistryProvider implements MetadataProvider {
  private readonly registryUrl: string;

  constructor(registryUrl?: string) {
    this.registryUrl = registryUrl ?? 'https://registry.npmjs.org';
  }

  public async getPackument(
    _ecosystem: 'npm' | 'pypi',
    _name: string,
    _ctx: DetectorContext
  ): Promise<Result<Packument, ProviderError>> {
    // Phase 1: offline-safe fallback; full network retry & disk caching in Phase 2
    return {
      ok: false,
      error: {
        code: 'UNAVAILABLE',
        message: `Registry querying disabled in offline execution (${this.registryUrl})`,
      },
    };
  }

  public async getWeeklyDownloads(
    _ecosystem: 'npm' | 'pypi',
    _name: string,
    _ctx: DetectorContext
  ): Promise<Result<number, ProviderError>> {
    return {
      ok: false,
      error: {
        code: 'UNAVAILABLE',
        message: 'Registry download querying disabled in offline execution',
      },
    };
  }

  public async getPublisher(
    _ecosystem: 'npm' | 'pypi',
    _name: string,
    _version: string,
    _ctx: DetectorContext
  ): Promise<Result<PublisherInfo | null, ProviderError>> {
    return {
      ok: false,
      error: {
        code: 'UNAVAILABLE',
        message: 'Registry publisher querying disabled in offline execution',
      },
    };
  }

  public async getTarball(
    _ecosystem: 'npm' | 'pypi',
    _name: string,
    _version: string,
    _ctx: DetectorContext
  ): Promise<Result<Uint8Array, ProviderError>> {
    return {
      ok: false,
      error: {
        code: 'UNAVAILABLE',
        message: 'Tarball download querying disabled in offline execution',
      },
    };
  }
}
