import type { DetectorContext } from '../internal/types.js';

export type ProviderErrorCode =
  | 'UNAVAILABLE'
  | 'NOT_FOUND'
  | 'NETWORK_ERROR'
  | 'INVALID_RESPONSE'
  | 'TIMEOUT';

export interface ProviderError {
  code: ProviderErrorCode;
  message: string;
}

export type Result<T, E = ProviderError> = { ok: true; value: T } | { ok: false; error: E };

export interface Maintainer {
  name: string;
  email?: string;
}

export interface PackumentVersion {
  name: string;
  version: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  bin?: string | Record<string, string>;
  dist?: {
    tarball?: string;
    shasum?: string;
    integrity?: string;
  };
  _hasShrinkwrap?: boolean;
}

export interface Packument {
  name: string;
  versions: Record<string, PackumentVersion>;
  time: Record<string, string>;
  maintainers: Maintainer[];
  distTags?: Record<string, string>;
  description?: string;
}

export interface PublisherInfo {
  username: string;
  email?: string;
  verified?: boolean;
  registeredDate?: string;
}

export interface MetadataProvider {
  getPackument(
    ecosystem: 'npm' | 'pypi',
    name: string,
    ctx: DetectorContext
  ): Promise<Result<Packument, ProviderError>>;

  getWeeklyDownloads(
    ecosystem: 'npm' | 'pypi',
    name: string,
    ctx: DetectorContext
  ): Promise<Result<number, ProviderError>>;

  getPublisher(
    ecosystem: 'npm' | 'pypi',
    name: string,
    version: string,
    ctx: DetectorContext
  ): Promise<Result<PublisherInfo | null, ProviderError>>;

  getTarball(
    ecosystem: 'npm' | 'pypi',
    name: string,
    version: string,
    ctx: DetectorContext
  ): Promise<Result<Uint8Array, ProviderError>>;
}
