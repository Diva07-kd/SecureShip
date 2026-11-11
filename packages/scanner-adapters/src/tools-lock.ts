import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

export const SupportedPlatformSchema = z.enum(['win32', 'darwin', 'linux']);
export type SupportedPlatform = z.infer<typeof SupportedPlatformSchema>;

export const SupportedArchSchema = z.enum(['x64', 'arm64']);
export type SupportedArch = z.infer<typeof SupportedArchSchema>;

export const LibcTypeSchema = z.enum(['glibc', 'musl']);
export type LibcType = z.infer<typeof LibcTypeSchema>;

/**
 * Detects whether the host runtime is using glibc or musl on Linux.
 */
export function detectLibc(): LibcType | undefined {
  if (process.platform !== 'linux') return undefined;
  try {
    const proc = process as unknown as {
      report?: { getReport?: () => { header?: { glibcVersionRuntime?: string } } };
    };
    const report = proc.report?.getReport?.();
    if (report?.header?.glibcVersionRuntime) return 'glibc';
  } catch {}
  try {
    if (fs.existsSync('/etc/alpine-release')) return 'musl';
  } catch {}
  return 'glibc';
}

export const PlatformArchKeySchema = z.enum([
  'linux-x64',
  'linux-x64-glibc',
  'linux-x64-musl',
  'linux-arm64',
  'linux-arm64-glibc',
  'linux-arm64-musl',
  'darwin-x64',
  'darwin-arm64',
  'win32-x64',
]);
export type PlatformArchKey = z.infer<typeof PlatformArchKeySchema>;

export const ToolNameSchema = z.enum(['opengrep', 'gitleaks', 'trivy', 'osv-scanner', 'checkov']);
export type ToolName = z.infer<typeof ToolNameSchema>;

export const ArchiveTypeSchema = z.enum(['tar.gz', 'zip', 'binary']);
export type ArchiveType = z.infer<typeof ArchiveTypeSchema>;

export const ToolLockAssetSchema = z.object({
  url: z.string().url(),
  archiveType: ArchiveTypeSchema,
  binarySubpath: z.string().optional(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/i, 'Must be a 64-character lowercase SHA-256 hex string'),
  verifiedAgainst: z.string().optional(),
  checkedAt: z.string().optional(),
  supported: z.boolean().default(true),
  reason: z.string().optional(),
});
export type ToolLockAsset = z.infer<typeof ToolLockAssetSchema>;

export const ToolLockDefinitionSchema = z.object({
  name: ToolNameSchema,
  description: z.string(),
  version: z.string(),
  binaryName: z.string(),
  sha256ManifestUrl: z.string().url().nullable().optional(),
  unsupportedReason: z.string().optional(),
  platforms: z.record(z.string(), ToolLockAssetSchema),
});
export type ToolLockDefinition = z.infer<typeof ToolLockDefinitionSchema>;

export const ToolsLockfileSchema = z.object({
  $schema: z.string().optional(),
  schemaVersion: z.number().int().positive(),
  updatedAt: z.string(),
  tools: z.record(ToolNameSchema, ToolLockDefinitionSchema),
});
export type ToolsLockfile = z.infer<typeof ToolsLockfileSchema>;

let cachedLockfile: ToolsLockfile | null = null;

export function _resetToolsLockCacheForTesting(): void {
  cachedLockfile = null;
}

/**
 * Loads and validates tools.lock.json from disk.
 */
export function loadToolsLock(
  customPath?: string,
  candidatePathsOverride?: string[]
): ToolsLockfile {
  if (customPath) {
    const raw = fs.readFileSync(path.resolve(customPath), 'utf-8');
    return ToolsLockfileSchema.parse(JSON.parse(raw));
  }

  if (cachedLockfile !== null && !candidatePathsOverride) {
    return cachedLockfile;
  }

  let dirname = '';
  try {
    dirname = path.dirname(fileURLToPath(import.meta.url));
  } catch {
    dirname = process.cwd();
  }

  const candidatePaths = candidatePathsOverride ?? [
    path.resolve(dirname, 'tools.lock.json'),
    path.resolve(dirname, '../tools.lock.json'),
    path.resolve(dirname, '../src/tools.lock.json'),
    path.resolve(dirname, '../../tools.lock.json'),
    path.resolve(dirname, '../../../tools.lock.json'),
    path.resolve(dirname, '../../scanner-adapters/dist/tools.lock.json'),
    path.resolve(dirname, '../../scanner-adapters/src/tools.lock.json'),
    path.resolve(dirname, '../scanner-adapters/dist/tools.lock.json'),
    path.resolve(process.cwd(), 'tools.lock.json'),
    path.resolve(process.cwd(), 'packages/scanner-adapters/src/tools.lock.json'),
    path.resolve(process.cwd(), 'packages/scanner-adapters/dist/tools.lock.json'),
  ];

  for (const c of candidatePaths) {
    try {
      if (fs.existsSync(c)) {
        const raw = fs.readFileSync(c, 'utf-8');
        cachedLockfile = ToolsLockfileSchema.parse(JSON.parse(raw));
        return cachedLockfile;
      }
    } catch {
      // Continue searching
    }
  }

  throw new Error(
    `tools.lock.json not found in candidate paths. Ensure the lockfile exists at the workspace root or in @secureship/scanner-adapters.`
  );
}

/**
 * Resolves a platform asset for a tool given target platform and optional libc.
 */
export function resolveToolAsset(
  toolName: ToolName | string,
  targetPlatform: string,
  libc?: LibcType
): { asset: ToolLockAsset | null; unsupportedReason?: string } {
  const lock = loadToolsLock();
  const tool = lock.tools[toolName as ToolName];
  if (!tool) {
    return {
      asset: null,
      unsupportedReason: `Tool '${toolName}' is not defined in tools.lock.json`,
    };
  }

  if (tool.unsupportedReason && Object.keys(tool.platforms).length === 0) {
    return { asset: null, unsupportedReason: tool.unsupportedReason };
  }

  // Normalize targetPlatform architecture synonyms (amd64/x86_64 -> x64, aarch64 -> arm64)
  const normalizedPlatform = targetPlatform
    .replace(/-amd64\b/g, '-x64')
    .replace(/-x86_64\b/g, '-x64')
    .replace(/-aarch64\b/g, '-arm64');

  // 1. If libc is explicitly specified on linux, try exact plat-arch-libc key
  if (libc && normalizedPlatform.startsWith('linux-')) {
    const libcKey = `${normalizedPlatform}-${libc}`;
    if (tool.platforms[libcKey]) {
      return { asset: tool.platforms[libcKey]! };
    }
  }

  // 2. Try exact normalizedPlatform key
  if (tool.platforms[normalizedPlatform]) {
    return { asset: tool.platforms[normalizedPlatform]! };
  }

  // 3. Fallback for linux without explicit libc: glibc first, then musl
  if (normalizedPlatform.startsWith('linux-')) {
    const glibcKey = `${normalizedPlatform}-glibc`;
    if (tool.platforms[glibcKey]) {
      return { asset: tool.platforms[glibcKey]! };
    }
    const muslKey = `${normalizedPlatform}-musl`;
    if (tool.platforms[muslKey]) {
      return { asset: tool.platforms[muslKey]! };
    }
  }

  return {
    asset: null,
    unsupportedReason: `No precompiled distribution available for tool '${toolName}' on platform '${targetPlatform}'.`,
  };
}

export interface LegacyToolDefinition {
  name: ToolName;
  description: string;
  version: string;
  binaryName: string;
  sha256ManifestUrl?: string;
  unsupportedReason?: string;
  platforms: Record<string, ToolLockAsset>;
}

/**
 * Returns a legacy KNOWN_TOOLS map for backward compatibility with CLI and existing tests.
 */
export function getKnownToolsFromLock(): Record<ToolName, LegacyToolDefinition> {
  const lock = loadToolsLock();
  const result: Partial<Record<ToolName, LegacyToolDefinition>> = {};

  for (const [name, tool] of Object.entries(lock.tools)) {
    result[name as ToolName] = {
      name: tool.name,
      description: tool.description,
      version: tool.version,
      binaryName: tool.binaryName,
      sha256ManifestUrl: tool.sha256ManifestUrl ?? undefined,
      unsupportedReason: tool.unsupportedReason,
      platforms: tool.platforms,
    };
  }

  return result as Record<ToolName, LegacyToolDefinition>;
}
