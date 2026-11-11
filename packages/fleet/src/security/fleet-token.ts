import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

/**
 * Standard printable ASCII token pattern (24-512 chars, no spaces).
 */
export const FLEET_TOKEN_PATTERN = /^[\x21-\x7E]{24,512}$/;

/**
 * Specific typed configuration and token errors.
 * Never includes raw token secrets in message or properties.
 */
export class FleetConfigError extends Error {
  public readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'FleetConfigError';
    this.code = code;
  }
}

export type TokenValidationFailureReason = 'EMPTY' | 'TOO_SHORT' | 'TOO_LONG' | 'INVALID_CHARS';

export type TokenValidationResult =
  | { ok: true }
  | { ok: false; reason: TokenValidationFailureReason };

/**
 * Validates a fleet token candidate against security constraints (D2).
 * Reason messages never echo the token value.
 */
export function validateFleetToken(value: unknown): TokenValidationResult {
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, reason: 'EMPTY' };
  }
  if (/[^\x21-\x7E]/.test(value)) {
    return { ok: false, reason: 'INVALID_CHARS' };
  }
  if (value.length < 24) {
    return { ok: false, reason: 'TOO_SHORT' };
  }
  if (value.length > 512) {
    return { ok: false, reason: 'TOO_LONG' };
  }
  return { ok: true };
}

/**
 * File system facade interface for hermetic testing of POSIX permissions,
 * file creation flags, and UID checks without needing root.
 */
export interface FsFacade {
  lstat(p: string): Promise<fsSync.Stats>;
  stat(p: string): Promise<fsSync.Stats>;
  realpath(p: string): Promise<string>;
  readFile(p: string): Promise<Buffer>;
  open(
    p: string,
    flags: string | number,
    mode?: number
  ): Promise<{
    write(buf: Uint8Array): Promise<unknown>;
    close(): Promise<void>;
  }>;
  mkdir(p: string, opts?: { recursive?: boolean; mode?: number }): Promise<string | undefined>;
  chmod(p: string, mode: number): Promise<void>;
  getuid?(): number;
}

export const defaultFsFacade: FsFacade = {
  lstat: (p) => fs.lstat(p),
  stat: (p) => fs.stat(p),
  realpath: (p) => fs.realpath(p),
  readFile: (p) => fs.readFile(p),
  open: async (p, flags, mode) => {
    const handle = await fs.open(p, flags, mode);
    return {
      write: (buf) => handle.write(buf),
      close: () => handle.close(),
    };
  },
  mkdir: (p, opts) => fs.mkdir(p, opts),
  chmod: (p, mode) => fs.chmod(p, mode),
  getuid: typeof process.getuid === 'function' ? () => process.getuid!() : undefined,
};

/**
 * Reads and validates a token file (D5).
 * Works seamlessly with Docker/Kubernetes secret mounts (symlinks, mode 0444).
 * Rejects UTF-16, oversized files (>4096 bytes), and interior whitespace.
 */
export async function readTokenFile(
  filePath: string,
  fsFacade: FsFacade = defaultFsFacade,
  platform: NodeJS.Platform = process.platform
): Promise<string> {
  const resolvedPath = path.resolve(filePath);

  let fileStat: fsSync.Stats;
  try {
    fileStat = await fsFacade.stat(resolvedPath);
  } catch (err: unknown) {
    throw new FleetConfigError(
      'TOKEN_FILE_NOT_FOUND',
      `Cannot read fleet token file at '${resolvedPath}': ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (!fileStat.isFile()) {
    throw new FleetConfigError(
      'INVALID_TOKEN_FILE',
      `Fleet token path '${resolvedPath}' is not a regular file`
    );
  }

  if (fileStat.size > 4096) {
    throw new FleetConfigError(
      'TOKEN_FILE_TOO_LARGE',
      `Fleet token file '${resolvedPath}' exceeds maximum allowed size of 4096 bytes (size: ${fileStat.size})`
    );
  }

  // Check world-readable warning on POSIX when not a symlinked secret mount
  if (platform !== 'win32' && (fileStat.mode & 0o004) !== 0) {
    try {
      const real = await fsFacade.realpath(resolvedPath);
      // Only warn if the resolved realpath is identical to resolvedPath (not a symlinked secret mount)
      if (real === resolvedPath) {
        process.stderr.write(
          `Warning: Fleet token file '${resolvedPath}' is world-readable (mode 0${(fileStat.mode & 0o777).toString(8)}).\n`
        );
      }
    } catch {
      // Ignore realpath check failure
    }
  }

  let buf: Buffer;
  try {
    buf = await fsFacade.readFile(resolvedPath);
  } catch (err: unknown) {
    throw new FleetConfigError(
      'TOKEN_FILE_READ_ERROR',
      `Failed to read fleet token file '${resolvedPath}': ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (buf.length > 4096) {
    throw new FleetConfigError(
      'TOKEN_FILE_TOO_LARGE',
      `Fleet token file '${resolvedPath}' exceeds maximum allowed size of 4096 bytes`
    );
  }

  // Reject UTF-16 (BOM FF FE / FE FF or any NUL byte)
  if (
    (buf.length >= 2 &&
      ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff))) ||
    buf.includes(0x00)
  ) {
    throw new FleetConfigError(
      'INVALID_TOKEN_ENCODING',
      `Fleet token file '${resolvedPath}' contains UTF-16 encoding or null bytes. Please re-save as UTF-8 without BOM.`
    );
  }

  // Strip one UTF-8 BOM if present (EF BB BF)
  let cleanBuf = buf;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    cleanBuf = buf.subarray(3);
  }

  let text: string;
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
    text = decoder.decode(cleanBuf);
  } catch {
    throw new FleetConfigError(
      'INVALID_TOKEN_ENCODING',
      `Fleet token file '${resolvedPath}' contains invalid UTF-8 bytes. Please re-save as UTF-8.`
    );
  }

  // Strip a single trailing line break (\r\n, \n, or \r)
  if (text.endsWith('\r\n')) {
    text = text.slice(0, -2);
  } else if (text.endsWith('\n') || text.endsWith('\r')) {
    text = text.slice(0, -1);
  }

  // Reject any interior whitespace or newline
  if (/\s/.test(text)) {
    throw new FleetConfigError(
      'INVALID_TOKEN_CONTENT',
      `Fleet token file '${resolvedPath}' contains whitespace or newline characters. Tokens must be printable ASCII with no spaces.`
    );
  }

  return text;
}

/**
 * Checks whether a given hostname is loopback (D12).
 * Loopback: 'localhost' (including trailing dot), '::1', '[::1]', 127.0.0.0/8.
 */
export function isLoopbackHostname(h: string): boolean {
  if (!h || typeof h !== 'string') return false;
  let hostLower = h.toLowerCase().trim();
  if (hostLower.endsWith('.')) {
    hostLower = hostLower.slice(0, -1);
  }
  if (hostLower === 'localhost' || hostLower === '::1' || hostLower === '[::1]') {
    return true;
  }
  if (hostLower.startsWith('127.')) {
    const parts = hostLower.split('.');
    if (parts.length === 4) {
      return parts.every((p) => {
        const n = Number(p);
        return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
      });
    }
  }
  return false;
}

export interface AssertSafeFleetEndpointOptions {
  allowInsecure?: boolean;
  env?: Record<string, string | undefined>;
}

/**
 * Validates endpoint safety before client transmission (D12).
 * Refuses non-loopback plain HTTP unless explicitly opted in.
 * Never leaks credentials in error or warning messages.
 */
export function assertSafeFleetEndpoint(
  endpoint: string,
  opts: AssertSafeFleetEndpointOptions = {}
): URL {
  if (!endpoint || typeof endpoint !== 'string') {
    throw new FleetConfigError('INVALID_ENDPOINT', 'Fleet endpoint URL must be a non-empty string');
  }

  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch (err: unknown) {
    throw new FleetConfigError(
      'INVALID_ENDPOINT',
      `Invalid fleet endpoint URL: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new FleetConfigError(
      'INVALID_ENDPOINT_PROTOCOL',
      `Fleet endpoint protocol must be 'http:' or 'https:', received '${parsed.protocol}'`
    );
  }

  if (parsed.username || parsed.password) {
    throw new FleetConfigError(
      'INVALID_ENDPOINT_CREDENTIALS',
      'Fleet endpoint URL must not contain embedded user credentials'
    );
  }

  if (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) {
    const envAllow =
      opts.env?.SECURESHIP_ALLOW_INSECURE_FLEET_HTTP ??
      (typeof process !== 'undefined'
        ? process.env.SECURESHIP_ALLOW_INSECURE_FLEET_HTTP
        : undefined);
    const isAllowed =
      opts.allowInsecure === true ||
      envAllow === '1' ||
      (typeof envAllow === 'string' && envAllow.toLowerCase() === 'true');

    if (!isAllowed) {
      throw new FleetConfigError(
        'INSECURE_REMOTE_HTTP_ENDPOINT',
        `Refusing to send fleet token over plain HTTP to non-loopback host '${parsed.hostname}'. Use HTTPS or set SECURESHIP_ALLOW_INSECURE_FLEET_HTTP=1 to override.`
      );
    }

    process.stderr.write(
      `Warning: Sending fleet credentials over plain HTTP to remote host "${parsed.hostname}".\n`
    );
  }

  return parsed;
}

export type FleetTokenSource = 'file' | 'env' | 'flag' | 'generated';

export interface ResolveFleetTokenInput {
  env?: Record<string, string | undefined>;
  flagToken?: string;
  flagTokenFile?: string;
  homeDir?: string;
  platform?: NodeJS.Platform;
  fs?: FsFacade;
}

export interface ResolveFleetTokenResult {
  token: string;
  source: FleetTokenSource;
  filePath?: string;
  warnings: string[];
}

/**
 * Resolves the server authentication token across sources (D3, D4, D5).
 * Sources:
 * 1. --token-file / FLEET_TOKEN_FILE
 * 2. FLEET_TOKEN
 * 3. --token (deprecated)
 * 4. Auto-generated token file at <homedir>/.secureship/fleet-token (mode 0600)
 */
export async function resolveFleetToken(
  input: ResolveFleetTokenInput = {}
): Promise<ResolveFleetTokenResult> {
  const env = input.env ?? (typeof process !== 'undefined' ? process.env : {});
  const fsFacade = input.fs ?? defaultFsFacade;
  const platform = input.platform ?? process.platform;
  const warnings: string[] = [];

  const configuredSources: Array<{
    name: string;
    value: string;
    source: FleetTokenSource;
    filePath?: string;
  }> = [];

  // 1. --token-file flag
  if (input.flagTokenFile !== undefined) {
    if (typeof input.flagTokenFile !== 'string' || input.flagTokenFile.trim().length === 0) {
      throw new FleetConfigError('INVALID_TOKEN_FILE', 'Fleet token file path cannot be empty');
    }
    const valFromFile = await readTokenFile(input.flagTokenFile, fsFacade, platform);
    configuredSources.push({
      name: '--token-file',
      value: valFromFile,
      source: 'file',
      filePath: path.resolve(input.flagTokenFile),
    });
  }

  // 2. FLEET_TOKEN_FILE environment variable (empty string treated as unset per D3)
  if (typeof env.FLEET_TOKEN_FILE === 'string' && env.FLEET_TOKEN_FILE.trim().length > 0) {
    const valFromFile = await readTokenFile(env.FLEET_TOKEN_FILE.trim(), fsFacade, platform);
    configuredSources.push({
      name: 'FLEET_TOKEN_FILE',
      value: valFromFile,
      source: 'file',
      filePath: path.resolve(env.FLEET_TOKEN_FILE.trim()),
    });
  }

  // 3. FLEET_TOKEN environment variable (empty string treated as unset per D3)
  if (typeof env.FLEET_TOKEN === 'string' && env.FLEET_TOKEN.length > 0) {
    let tokenEnv = env.FLEET_TOKEN;
    if (tokenEnv.endsWith('\r\n')) {
      tokenEnv = tokenEnv.slice(0, -2);
    } else if (tokenEnv.endsWith('\n') || tokenEnv.endsWith('\r')) {
      tokenEnv = tokenEnv.slice(0, -1);
    }
    configuredSources.push({
      name: 'FLEET_TOKEN',
      value: tokenEnv,
      source: 'env',
    });
  }

  // 4. --token flag (DEPRECATED)
  if (input.flagToken !== undefined) {
    let tokenFlag = typeof input.flagToken === 'string' ? input.flagToken : '';
    if (tokenFlag.endsWith('\r\n')) {
      tokenFlag = tokenFlag.slice(0, -2);
    } else if (tokenFlag.endsWith('\n') || tokenFlag.endsWith('\r')) {
      tokenFlag = tokenFlag.slice(0, -1);
    }
    const warnMsg =
      'Warning: --token is deprecated. It is visible to other users via the process list and shell history. Use FLEET_TOKEN_FILE or FLEET_TOKEN instead.';
    warnings.push(warnMsg);
    process.stderr.write(`${warnMsg}\n`);

    configuredSources.push({
      name: '--token',
      value: tokenFlag,
      source: 'flag',
    });
  }

  // Conflict detection: if two or more sources are set and their values differ, fail closed
  if (configuredSources.length > 1) {
    for (let i = 1; i < configuredSources.length; i++) {
      const first = configuredSources[0]!;
      const current = configuredSources[i]!;
      if (first.value !== current.value) {
        throw new FleetConfigError(
          'CONFLICTING_TOKEN_SOURCES',
          `Multiple fleet token sources are set with differing values: ${first.name} and ${current.name}. Ensure all token sources agree or specify only one.`
        );
      }
    }
  }

  // If at least one source was explicitly configured
  if (configuredSources.length > 0) {
    const chosen = configuredSources[0]!;
    const validation = validateFleetToken(chosen.value);
    if (!validation.ok) {
      const reasonDetail =
        validation.reason === 'EMPTY'
          ? 'token is empty'
          : validation.reason === 'TOO_SHORT'
            ? 'token is too short (minimum 24 characters)'
            : validation.reason === 'TOO_LONG'
              ? 'token is too long (maximum 512 characters)'
              : 'token contains invalid characters (must be printable ASCII without spaces)';
      throw new FleetConfigError(
        'INVALID_TOKEN',
        `Invalid fleet token from ${chosen.name}: ${reasonDetail}.`
      );
    }
    return {
      token: chosen.value,
      source: chosen.source,
      filePath: chosen.filePath,
      warnings,
    };
  }

  // Auto-generation when no source is set (D4)
  const home = input.homeDir || (typeof os.homedir === 'function' ? os.homedir() : '');
  if (!home || home.trim().length === 0) {
    throw new FleetConfigError(
      'HOMEDIR_UNAVAILABLE',
      'Cannot determine user home directory to create auto-generated token file. Please configure FLEET_TOKEN_FILE or FLEET_TOKEN.'
    );
  }

  const defaultDir = path.join(home, '.secureship');
  const defaultFile = path.join(defaultDir, 'fleet-token');

  // Check / create directory
  let dirExists = false;
  try {
    const dirStat = await fsFacade.stat(defaultDir);
    dirExists = dirStat.isDirectory();
  } catch {
    dirExists = false;
  }

  if (!dirExists) {
    try {
      await fsFacade.mkdir(defaultDir, { recursive: true, mode: 0o700 });
      if (platform !== 'win32') {
        try {
          await fsFacade.chmod(defaultDir, 0o700);
        } catch {
          // ignore chmod failure if filesystem does not support it
        }
      }
    } catch (err: unknown) {
      throw new FleetConfigError(
        'TOKEN_CREATION_FAILED',
        `Failed to create directory '${defaultDir}' for auto-generated token: ${err instanceof Error ? err.message : String(err)}. Please configure FLEET_TOKEN_FILE or FLEET_TOKEN.`
      );
    }
  }

  // 32 cryptographically secure random bytes encoded as base64url (43 chars)
  const autoToken = crypto.randomBytes(32).toString('base64url');

  let fileCreated = false;
  try {
    const handle = await fsFacade.open(defaultFile, 'wx', 0o600);
    try {
      await handle.write(Buffer.from(`${autoToken}\n`, 'utf8'));
    } finally {
      await handle.close();
    }
    fileCreated = true;
  } catch (err: unknown) {
    const errCode = (err as { code?: string })?.code;
    if (errCode === 'EEXIST') {
      // File exists or lost the race
      fileCreated = false;
    } else {
      throw new FleetConfigError(
        'TOKEN_CREATION_FAILED',
        `Failed to create auto-generated token file at '${defaultFile}': ${err instanceof Error ? err.message : String(err)}. Please configure FLEET_TOKEN_FILE or FLEET_TOKEN.`
      );
    }
  }

  if (fileCreated) {
    return {
      token: autoToken,
      source: 'generated',
      filePath: defaultFile,
      warnings,
    };
  }

  // Reuse existing default token file with POSIX security validations (D4)
  if (platform !== 'win32') {
    let fileLstat: fsSync.Stats;
    try {
      fileLstat = await fsFacade.lstat(defaultFile);
    } catch (err: unknown) {
      throw new FleetConfigError(
        'DEFAULT_TOKEN_ACCESS_ERROR',
        `Failed to inspect default token file '${defaultFile}': ${err instanceof Error ? err.message : String(err)}`
      );
    }

    if (fileLstat.isSymbolicLink() || !fileLstat.isFile()) {
      throw new FleetConfigError(
        'INSECURE_DEFAULT_TOKEN_FILE',
        `Default token file '${defaultFile}' is a symlink or non-regular file. Remove it or configure FLEET_TOKEN_FILE.`
      );
    }

    const currentUid = fsFacade.getuid
      ? fsFacade.getuid()
      : typeof process.getuid === 'function'
        ? process.getuid!()
        : undefined;

    if (currentUid !== undefined && fileLstat.uid !== currentUid) {
      throw new FleetConfigError(
        'INSECURE_DEFAULT_TOKEN_FILE',
        `Default token file '${defaultFile}' is owned by UID ${fileLstat.uid}, expected UID ${currentUid}. Defending against planted token.`
      );
    }

    // Parent directory check
    let dirStat: fsSync.Stats;
    try {
      dirStat = await fsFacade.stat(defaultDir);
    } catch (err: unknown) {
      throw new FleetConfigError(
        'DEFAULT_TOKEN_DIR_ACCESS_ERROR',
        `Failed to inspect default token directory '${defaultDir}': ${err instanceof Error ? err.message : String(err)}`
      );
    }

    if (currentUid !== undefined && dirStat.uid !== currentUid) {
      throw new FleetConfigError(
        'INSECURE_DEFAULT_TOKEN_DIR',
        `Default token directory '${defaultDir}' is owned by UID ${dirStat.uid}, expected UID ${currentUid}.`
      );
    }

    if ((dirStat.mode & 0o022) !== 0) {
      throw new FleetConfigError(
        'INSECURE_DEFAULT_TOKEN_DIR',
        `Default token directory '${defaultDir}' is group- or world-writable (mode 0${(dirStat.mode & 0o777).toString(8)}).`
      );
    }

    // Try chmod 0o600 if group/other bits are set
    if ((fileLstat.mode & 0o077) !== 0) {
      try {
        await fsFacade.chmod(defaultFile, 0o600);
      } catch {
        process.stderr.write(
          `Warning: Unable to restrict permissions on default token file '${defaultFile}' to 0600.\n`
        );
      }
    }
  }

  // Bounded retry (10 x 20ms) to read valid token in case of concurrent creator writing
  let resolvedExistingToken = '';
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const candidate = await readTokenFile(defaultFile, fsFacade, platform);
      const v = validateFleetToken(candidate);
      if (v.ok) {
        resolvedExistingToken = candidate;
        break;
      }
    } catch {
      // Retry
    }
    await new Promise((r) => setTimeout(r, 20));
  }

  if (!resolvedExistingToken) {
    throw new FleetConfigError(
      'INVALID_DEFAULT_TOKEN_FILE',
      `Default token file at '${defaultFile}' does not contain a valid token after initialization retry. Remove it or configure FLEET_TOKEN_FILE.`
    );
  }

  return {
    token: resolvedExistingToken,
    source: 'generated',
    filePath: defaultFile,
    warnings,
  };
}

export interface ResolveClientFleetTokenInput {
  endpoint: string;
  flagToken?: string;
  flagTokenFile?: string;
  env?: Record<string, string | undefined>;
  homeDir?: string;
  platform?: NodeJS.Platform;
  fs?: FsFacade;
  allowInsecure?: boolean;
}

/**
 * Resolves the client authentication token for CLI subcommands (status, export-cra) (D13).
 * Sources:
 * 1. --token flag (deprecated warning)
 * 2. FLEET_TOKEN
 * 3. FLEET_TOKEN_FILE / --token-file
 * 4. Default token file <homedir>/.secureship/fleet-token ONLY if endpoint is loopback.
 * Non-loopback endpoints never receive the locally generated default token.
 */
export async function resolveClientFleetToken(
  input: ResolveClientFleetTokenInput
): Promise<string | undefined> {
  const env = input.env ?? (typeof process !== 'undefined' ? process.env : {});
  const fsFacade = input.fs ?? defaultFsFacade;
  const platform = input.platform ?? process.platform;

  const url = assertSafeFleetEndpoint(input.endpoint, {
    allowInsecure: input.allowInsecure,
    env,
  });
  const isLoopback = isLoopbackHostname(url.hostname);

  // 1. --token flag
  if (typeof input.flagToken === 'string' && input.flagToken.length > 0) {
    let t = input.flagToken;
    if (t.endsWith('\r\n')) t = t.slice(0, -2);
    else if (t.endsWith('\n') || t.endsWith('\r')) t = t.slice(0, -1);
    process.stderr.write(
      'Warning: --token is deprecated. It is visible to other users via the process list and shell history. Use FLEET_TOKEN_FILE or FLEET_TOKEN instead.\n'
    );
    return t;
  }

  // 2. FLEET_TOKEN
  if (typeof env.FLEET_TOKEN === 'string' && env.FLEET_TOKEN.length > 0) {
    let t = env.FLEET_TOKEN;
    if (t.endsWith('\r\n')) t = t.slice(0, -2);
    else if (t.endsWith('\n') || t.endsWith('\r')) t = t.slice(0, -1);
    return t;
  }

  // 3. FLEET_TOKEN_FILE / flagTokenFile
  const fileCandidate =
    input.flagTokenFile ||
    (typeof env.FLEET_TOKEN_FILE === 'string' && env.FLEET_TOKEN_FILE.trim().length > 0
      ? env.FLEET_TOKEN_FILE.trim()
      : undefined);

  if (fileCandidate) {
    return await readTokenFile(fileCandidate, fsFacade, platform);
  }

  // 4. Default auto-generated token file (LOOPBACK ONLY)
  if (isLoopback) {
    const home = input.homeDir || (typeof os.homedir === 'function' ? os.homedir() : '');
    if (home) {
      const defaultPath = path.join(home, '.secureship', 'fleet-token');
      try {
        const fileStat = await fsFacade.stat(defaultPath);
        if (fileStat.isFile()) {
          const t = await readTokenFile(defaultPath, fsFacade, platform);
          const v = validateFleetToken(t);
          if (v.ok) return t;
        }
      } catch {
        // Default file does not exist, return undefined
      }
    }
  }

  return undefined;
}
