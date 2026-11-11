import type { DetectorContext } from '../internal/types.js';
import type {
  MetadataProvider,
  Packument,
  ProviderError,
  PublisherInfo,
  Result,
} from './provider.interface.js';

export class NullProvider implements MetadataProvider {
  public async getPackument(
    _ecosystem: 'npm' | 'pypi',
    _name: string,
    _ctx: DetectorContext
  ): Promise<Result<Packument, ProviderError>> {
    return {
      ok: false,
      error: {
        code: 'UNAVAILABLE',
        message: 'NullProvider: no metadata source configured',
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
        message: 'NullProvider: no metadata source configured',
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
        message: 'NullProvider: no metadata source configured',
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
        message: 'NullProvider: no metadata source configured',
      },
    };
  }
}
