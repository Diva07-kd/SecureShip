import path from 'node:path';
import {
  FleetConfigError,
  FsFacade,
  resolveFleetToken,
  type FleetTokenSource,
} from '../security/fleet-token.js';
import { FleetServer, type FleetServerOptions } from '../server/fleet-server.js';

export interface FleetRuntimeConfigArgs {
  port?: number | string;
  host?: string;
  data?: string;
  token?: string;
  tokenFile?: string;
  allowedHost?: string[];
  allowedOrigin?: string[];
  allowLegacyBodyToken?: boolean;
  legacyBodyTokenMaxBytes?: number;
  maxBodyBytes?: number;
  headersTimeoutMs?: number;
  requestTimeoutMs?: number;
}

export interface ShutdownOptions {
  server: { stop(): Promise<void> };
  onExit?: (code: number) => void;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
}

/**
 * Installs graceful shutdown signal handlers for SIGINT, SIGTERM (and SIGBREAK on win32) (DEV-4).
 * A second signal, or a 10s watchdog timer, forces exit 1.
 */
export function installSignalHandlers(options: ShutdownOptions): () => void {
  const {
    server,
    onExit = (code: number) => process.exit(code),
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = options;

  let isShuttingDown = false;
  let forceTimer: ReturnType<typeof setTimeout> | null = null;

  const handleSignal = async () => {
    if (isShuttingDown) {
      if (forceTimer) clearTimeoutFn(forceTimer);
      onExit(1);
      return;
    }
    isShuttingDown = true;

    forceTimer = setTimeoutFn(() => {
      onExit(1);
    }, 10000);
    if (typeof (forceTimer as unknown as { unref?: () => void })?.unref === 'function') {
      (forceTimer as unknown as { unref: () => void }).unref();
    }

    try {
      await server.stop();
      if (forceTimer) clearTimeoutFn(forceTimer);
      onExit(0);
    } catch {
      if (forceTimer) clearTimeoutFn(forceTimer);
      onExit(1);
    }
  };

  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
  if (process.platform === 'win32') {
    signals.push('SIGBREAK' as NodeJS.Signals);
  }

  for (const sig of signals) {
    process.on(sig, handleSignal);
  }

  return () => {
    for (const sig of signals) {
      process.removeListener(sig, handleSignal);
    }
    if (forceTimer) clearTimeoutFn(forceTimer);
  };
}

export interface FleetRuntimeConfigInput {
  env?: Record<string, string | undefined>;
  args?: FleetRuntimeConfigArgs;
  argvPositionalPort?: string;
  homeDir?: string;
  platform?: NodeJS.Platform;
  fs?: FsFacade;
}

export interface FleetRuntimeConfigResult {
  port: number;
  host: string;
  dataPath: string;
  token: string;
  tokenSource: FleetTokenSource;
  tokenFilePath?: string;
  serverOptions: FleetServerOptions;
  warnings: string[];
}

const ALLOWED_HOST_PATTERN = /^[A-Za-z0-9.-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/;

/**
 * Formats a display URL where wildcard addresses (0.0.0.0, ::) are rendered as 127.0.0.1
 * and raw IPv6 literals are properly bracketed (D14).
 */
export function formatDisplayUrl(host: string, port: number): string {
  let displayHost = host.trim();
  const lower = displayHost.toLowerCase();
  if (lower === '0.0.0.0' || lower === '::' || lower === '[::]' || lower === '*') {
    displayHost = '127.0.0.1';
  } else if (displayHost.includes(':') && !displayHost.startsWith('[')) {
    displayHost = `[${displayHost}]`;
  }
  return `http://${displayHost}:${port}`;
}

/**
 * Returns a standardized human-readable label for the resolved token source (D14).
 * Never leaks token contents.
 */
export function formatAuthLabel(source: FleetTokenSource, filePath?: string): string {
  switch (source) {
    case 'env':
      return 'FLEET_TOKEN environment variable';
    case 'file':
      return `token file ${filePath ?? ''}`.trim();
    case 'flag':
      return '--token flag (deprecated)';
    case 'generated':
      return `auto-generated token file ${filePath ?? ''}`.trim();
  }
}

/**
 * Returns an OS-appropriate command hint to inspect an auto-generated token file (D14).
 */
export function formatReadHint(
  filePath: string,
  platform: NodeJS.Platform = process.platform
): string {
  if (platform === 'win32') {
    return `Get-Content -Raw "${filePath}"`;
  }
  return `cat '${filePath}'`;
}

/**
 * Validates and builds the immutable runtime configuration for FleetServer (DEV-2).
 *
 * Environment Precedence:
 * - Port: explicit arg > FLEET_PORT > PORT > 4000
 * - Host: explicit arg > FLEET_HOST > '127.0.0.1' (generic HOST is ignored)
 * - Data: explicit arg > FLEET_DATA > .secureship/fleet-db.json
 * - Token: --token-file / FLEET_TOKEN_FILE > FLEET_TOKEN > --token > auto-generated 0600 file
 */
export async function buildFleetRuntimeConfig(
  input: FleetRuntimeConfigInput = {}
): Promise<FleetRuntimeConfigResult> {
  const env = input.env ?? (typeof process !== 'undefined' ? process.env : {});
  const args = input.args ?? {};
  const warnings: string[] = [];

  // 1. Port resolution & validation
  const rawPortCandidate =
    args.port !== undefined && args.port !== null
      ? args.port
      : input.argvPositionalPort !== undefined && input.argvPositionalPort !== null
        ? input.argvPositionalPort
        : typeof env.FLEET_PORT === 'string' && env.FLEET_PORT !== ''
          ? env.FLEET_PORT
          : typeof env.PORT === 'string' && env.PORT !== ''
            ? env.PORT
            : 4000;

  let portNumber: number;
  if (typeof rawPortCandidate === 'number') {
    if (!Number.isInteger(rawPortCandidate) || rawPortCandidate < 0 || rawPortCandidate > 65535) {
      throw new FleetConfigError(
        'INVALID_PORT',
        `Invalid port '${rawPortCandidate}': port must be an integer between 0 and 65535.`
      );
    }
    portNumber = rawPortCandidate;
  } else if (typeof rawPortCandidate === 'string') {
    if (!/^(0|[1-9]\d*)$/.test(rawPortCandidate)) {
      throw new FleetConfigError(
        'INVALID_PORT',
        `Invalid port '${rawPortCandidate}': port must be a plain decimal integer between 0 and 65535.`
      );
    }
    const parsed = Number(rawPortCandidate);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
      throw new FleetConfigError(
        'INVALID_PORT',
        `Invalid port '${rawPortCandidate}': port must be between 0 and 65535.`
      );
    }
    portNumber = parsed;
  } else {
    throw new FleetConfigError('INVALID_PORT', 'Invalid port configuration.');
  }

  // 2. Host resolution & validation (generic HOST variable is deliberately ignored)
  const rawHostCandidate =
    args.host !== undefined && args.host !== null
      ? args.host
      : typeof env.FLEET_HOST === 'string' && env.FLEET_HOST !== ''
        ? env.FLEET_HOST
        : '127.0.0.1';

  if (
    typeof rawHostCandidate !== 'string' ||
    rawHostCandidate.length === 0 ||
    /\s/.test(rawHostCandidate)
  ) {
    throw new FleetConfigError(
      'INVALID_HOST',
      `Invalid host '${rawHostCandidate}': host cannot be empty or contain whitespace.`
    );
  }
  const host = rawHostCandidate;

  // 3. Data path resolution
  const rawDataCandidate =
    args.data !== undefined && args.data !== null && args.data.trim() !== ''
      ? args.data.trim()
      : env.FLEET_DATA !== undefined && env.FLEET_DATA.trim() !== ''
        ? env.FLEET_DATA.trim()
        : path.resolve('.secureship', 'fleet-db.json');

  const dataPath = path.resolve(rawDataCandidate);

  // 4. Allowed hosts validation
  const allowedHostsSet = new Set<string>();
  if (Array.isArray(args.allowedHost)) {
    for (const h of args.allowedHost) {
      if (typeof h === 'string' && h.trim().length > 0) {
        allowedHostsSet.add(h.trim());
      }
    }
  }
  if (typeof env.FLEET_ALLOWED_HOSTS === 'string' && env.FLEET_ALLOWED_HOSTS.trim().length > 0) {
    for (const h of env.FLEET_ALLOWED_HOSTS.split(',')) {
      const trimmed = h.trim();
      if (trimmed.length > 0) {
        allowedHostsSet.add(trimmed);
      }
    }
  }
  for (const h of allowedHostsSet) {
    if (!ALLOWED_HOST_PATTERN.test(h)) {
      throw new FleetConfigError(
        'INVALID_ALLOWED_HOST',
        `Invalid allowed host '${h}': host must match standard hostname or IP pattern.`
      );
    }
  }
  const allowedHosts = allowedHostsSet.size > 0 ? Array.from(allowedHostsSet) : undefined;

  // 5. Allowed origins validation
  const allowedOriginsSet = new Set<string>();
  if (Array.isArray(args.allowedOrigin)) {
    for (const o of args.allowedOrigin) {
      if (typeof o === 'string' && o.trim().length > 0) {
        allowedOriginsSet.add(o.trim());
      }
    }
  }
  if (
    typeof env.FLEET_ALLOWED_ORIGINS === 'string' &&
    env.FLEET_ALLOWED_ORIGINS.trim().length > 0
  ) {
    for (const o of env.FLEET_ALLOWED_ORIGINS.split(',')) {
      const trimmed = o.trim();
      if (trimmed.length > 0) {
        allowedOriginsSet.add(trimmed);
      }
    }
  }
  const allowedOrigins = allowedOriginsSet.size > 0 ? Array.from(allowedOriginsSet) : undefined;

  // 6. Legacy body token configuration
  let allowLegacyBodyToken = true;
  if (args.allowLegacyBodyToken !== undefined) {
    allowLegacyBodyToken = args.allowLegacyBodyToken;
  } else if (
    typeof env.FLEET_ALLOW_LEGACY_BODY_TOKEN === 'string' &&
    env.FLEET_ALLOW_LEGACY_BODY_TOKEN.trim().length > 0
  ) {
    const val = env.FLEET_ALLOW_LEGACY_BODY_TOKEN.trim().toLowerCase();
    if (val === '0' || val === 'false') {
      allowLegacyBodyToken = false;
    } else if (val === '1' || val === 'true') {
      allowLegacyBodyToken = true;
    } else {
      throw new FleetConfigError(
        'INVALID_CONFIG',
        `Invalid FLEET_ALLOW_LEGACY_BODY_TOKEN setting '${env.FLEET_ALLOW_LEGACY_BODY_TOKEN}': must be 'true' or 'false'.`
      );
    }
  }

  // 7. Token resolution
  const tokenResult = await resolveFleetToken({
    env,
    flagToken: args.token,
    flagTokenFile: args.tokenFile,
    homeDir: input.homeDir,
    platform: input.platform,
    fs: input.fs,
  });

  warnings.push(...tokenResult.warnings);

  const serverOptions: FleetServerOptions = {
    port: portNumber,
    host,
    authToken: tokenResult.token,
    allowedHosts,
    allowedOrigins,
    allowLegacyBodyToken,
    legacyBodyTokenMaxBytes: args.legacyBodyTokenMaxBytes,
    maxBodyBytes: args.maxBodyBytes,
    headersTimeoutMs: args.headersTimeoutMs,
    requestTimeoutMs: args.requestTimeoutMs,
  };

  // Validate origins and server options using FleetServer constructor contract
  try {
    new FleetServer(serverOptions);
  } catch (err: unknown) {
    throw new FleetConfigError(
      'INVALID_SERVER_CONFIG',
      err instanceof Error ? err.message : String(err)
    );
  }

  return {
    port: portNumber,
    host,
    dataPath,
    token: tokenResult.token,
    tokenSource: tokenResult.source,
    tokenFilePath: tokenResult.filePath,
    serverOptions,
    warnings,
  };
}
