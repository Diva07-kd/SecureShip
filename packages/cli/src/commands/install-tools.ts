import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import stream from 'node:stream/promises';
import { Readable } from 'node:stream';
import pc from 'picocolors';
import { z } from 'zod';
import {
  getKnownToolsFromLock,
  resolveToolAsset,
  SupportedPlatformSchema,
  SupportedArchSchema,
  LibcTypeSchema,
  ToolNameSchema,
  type SupportedPlatform,
  type SupportedArch,
  type LibcType,
  type ToolName,
  type ToolLockAsset,
  getDefaultToolDir,
  checkDirWritable,
} from '@secureship/scanner-adapters';
import { SafeArchiveExtractor } from '@secureship/scanner-adapters';

export {
  SupportedPlatformSchema,
  SupportedArchSchema,
  LibcTypeSchema,
  ToolNameSchema,
  type SupportedPlatform,
  type SupportedArch,
  type LibcType,
  type ToolName,
};

export interface PlatformAsset {
  url: string;
  archiveType: 'tar.gz' | 'zip' | 'binary';
  binarySubpath?: string;
  sha256: string;
  verifiedAgainst?: string;
  checkedAt?: string;
}

export interface ToolDefinition {
  name: ToolName;
  description: string;
  version: string;
  binaryName: string;
  sha256ManifestUrl?: string | null;
  unsupportedReason?: string;
  platforms: Record<string, PlatformAsset>;
}

// Authoritative Single Source of Truth loaded from tools.lock.json
export const KNOWN_TOOLS: Record<ToolName, ToolDefinition> = getKnownToolsFromLock();

export const InstallToolsOptionsSchema = z.object({
  tools: z.array(z.string()).optional(),
  dir: z.string().optional(),
  targetPlatform: z.string().optional(),
  libc: LibcTypeSchema.optional(),
  force: z.boolean().default(false),
  dryRun: z.boolean().default(false),
  json: z.boolean().default(false),
  verbose: z.boolean().default(false),
  silent: z.boolean().default(false),
});
export type InstallToolsOptions = z.infer<typeof InstallToolsOptionsSchema>;

export interface ToolInstallResult {
  tool: string;
  status: 'installed' | 'skipped' | 'failed' | 'manual-required';
  path?: string;
  version?: string;
  error?: string;
  durationMs?: number;
}

const ALLOWED_REDIRECT_HOSTS = new Set([
  'github.com',
  'api.github.com',
  'objects.githubusercontent.com',
  'raw.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'localhost',
  '127.0.0.1',
  '::1',
  ...(process.env.VITEST === 'true' || process.env.NODE_ENV === 'test' ? ['example.com'] : []),
]);

const MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024; // 200 MB
const PER_REQUEST_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 3;

export class InstallToolsCommand {
  public static getDefaultInstallDir(): string {
    return getDefaultToolDir();
  }

  public static getCurrentPlatformKey(): `${SupportedPlatform}-${SupportedArch}` | null {
    const rawPlatform = process.platform;
    const rawArch = process.arch;

    const platResult = SupportedPlatformSchema.safeParse(rawPlatform);
    const archResult = SupportedArchSchema.safeParse(rawArch);

    if (!platResult.success || !archResult.success) {
      return null;
    }

    return `${platResult.data}-${archResult.data}`;
  }

  public static async run(options: Partial<InstallToolsOptions> = {}): Promise<number> {
    const rawOptions = { ...options };
    if (typeof rawOptions.tools === 'string') {
      rawOptions.tools = (rawOptions.tools as unknown as string)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    }
    const parsed = InstallToolsOptionsSchema.parse(rawOptions);
    const isQuiet = parsed.json || parsed.silent;
    const targetDir = path.resolve(parsed.dir || InstallToolsCommand.getDefaultInstallDir());

    // Validate directory writability
    if (!parsed.dryRun) {
      const writability = checkDirWritable(targetDir);
      if (!writability.writable) {
        if (!parsed.silent) {
          if (parsed.json) {
            console.log(JSON.stringify({ success: false, error: writability.error }));
          } else {
            console.error(pc.red(`✖ ${writability.error}`));
          }
        }
        return 1;
      }
    }

    const platformKey = parsed.targetPlatform || InstallToolsCommand.getCurrentPlatformKey();

    if (!isQuiet) {
      console.log(pc.bold(pc.cyan('\n⚙ SecureShip Zero-Telemetry Tool Installer\n')));
      console.log(`Target Directory : ${pc.bold(targetDir)}`);
      console.log(
        `Platform Target  : ${pc.bold(platformKey ?? 'Unknown')}${parsed.libc ? ` (${parsed.libc})` : ''}`
      );
      if (parsed.dryRun) {
        console.log(pc.yellow('Running in DRY-RUN mode. No changes will be written to disk.\n'));
      }
    }

    if (!platformKey) {
      const err = `Unsupported platform '${process.platform}' or architecture '${process.arch}'.`;
      if (!parsed.silent) {
        if (parsed.json) {
          console.log(JSON.stringify({ success: false, error: err }));
        } else {
          console.error(pc.red(`✖ ${err}`));
        }
      }
      return 1;
    }

    // Determine target tools
    const selectedToolNames: ToolName[] = [];
    if (parsed.tools && parsed.tools.length > 0) {
      for (const t of parsed.tools) {
        const lower = t.trim().toLowerCase();
        const check = ToolNameSchema.safeParse(lower);
        if (check.success) {
          selectedToolNames.push(check.data);
        } else if (!isQuiet) {
          console.warn(pc.yellow(`⚠ Unknown tool '${t}' requested; skipping.`));
        }
      }
    } else {
      selectedToolNames.push('opengrep', 'gitleaks', 'trivy', 'osv-scanner', 'checkov');
    }

    const results: ToolInstallResult[] = [];

    for (const toolName of selectedToolNames) {
      const startTime = Date.now();
      const toolDef = KNOWN_TOOLS[toolName];

      if (toolName === 'checkov') {
        results.push({
          tool: toolName,
          status: 'manual-required',
          error: 'Checkov is Python-based. Run `pip install checkov` or use a virtual environment.',
          durationMs: Date.now() - startTime,
        });
        if (!isQuiet) {
          console.log(
            `  ${pc.yellow('ℹ')} ${pc.bold(toolName.padEnd(14))} Python-based tool. Recommendation: 'pip install checkov'`
          );
        }
        continue;
      }

      // Resolve platform asset honoring libc if specified
      const resolution = resolveToolAsset(toolName, platformKey, parsed.libc);
      const asset = resolution.asset;

      if (!asset) {
        const reason =
          resolution.unsupportedReason ??
          `No precompiled binary distribution available for ${platformKey}.`;
        results.push({
          tool: toolName,
          status: 'failed',
          error: reason,
          durationMs: Date.now() - startTime,
        });
        if (!isQuiet) {
          console.log(`  ${pc.red('✖')} ${pc.bold(toolName.padEnd(14))} ${reason}`);
        }
        continue;
      }

      const isTargetWindows = platformKey.startsWith('win32');
      const ext = isTargetWindows ? '.exe' : '';
      const destBinaryPath = path.join(targetDir, `${toolDef.binaryName}${ext}`);

      // Check if already installed
      if (!parsed.force && fs.existsSync(destBinaryPath)) {
        results.push({
          tool: toolName,
          status: 'skipped',
          path: destBinaryPath,
          version: toolDef.version,
          durationMs: Date.now() - startTime,
        });
        if (!isQuiet) {
          console.log(
            `  ${pc.gray('✔')} ${pc.bold(toolName.padEnd(14))} Already installed (use --force to overwrite)`
          );
        }
        continue;
      }

      if (parsed.dryRun) {
        results.push({
          tool: toolName,
          status: 'installed',
          path: destBinaryPath,
          version: toolDef.version,
          durationMs: 0,
        });
        if (!isQuiet) {
          console.log(
            `  ${pc.cyan('○')} ${pc.bold(toolName.padEnd(14))} [DRY RUN] Would download ${asset.url}`
          );
        }
        continue;
      }

      if (!isQuiet) {
        process.stdout.write(
          `  ⏳ ${pc.bold(toolName.padEnd(14))} Downloading ${toolDef.version}... `
        );
      }

      try {
        await InstallToolsCommand.downloadAndInstallAsset(
          asset,
          destBinaryPath,
          targetDir,
          toolDef,
          parsed
        );
        results.push({
          tool: toolName,
          status: 'installed',
          path: destBinaryPath,
          version: toolDef.version,
          durationMs: Date.now() - startTime,
        });
        if (!isQuiet) {
          console.log(pc.green('✔ Verified & Installed'));
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        results.push({
          tool: toolName,
          status: 'failed',
          error: msg,
          durationMs: Date.now() - startTime,
        });
        if (!isQuiet) {
          console.log(pc.red(`✖ Failed: ${msg}`));
        }
      }
    }

    if (parsed.silent) {
      // Complete silence when called programmatically
    } else if (parsed.json) {
      console.log(
        JSON.stringify(
          {
            success: results.every((r) => r.status !== 'failed'),
            targetDir,
            results,
          },
          null,
          2
        )
      );
    } else {
      InstallToolsCommand.printPathAdvice(targetDir);
    }

    const hasFailures = results.some((r) => r.status === 'failed');
    return hasFailures ? 1 : 0;
  }

  /**
   * Fetches upstream SHA-256 checksum manifest for cross-checking against the bundled pin.
   */
  public static async fetchRemoteSha256(
    manifestUrl: string,
    targetAssetFilename: string
  ): Promise<string | null> {
    try {
      const response = await InstallToolsCommand.fetchWithHardening(manifestUrl);
      if (!response.ok) return null;
      const text = await response.text();
      for (const line of text.split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const hash = parts[0]!;
          const filename = parts[parts.length - 1]!.replace(/^\.\//, '')
            .replace(/^\.\\/, '')
            .split(/[/\\]/)
            .pop()!;
          if (filename.toLowerCase() === targetAssetFilename.toLowerCase()) {
            if (/^[a-f0-9]{64}$/i.test(hash)) return hash.toLowerCase();
          }
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Executes hardened HTTP fetch adhering to strict timeout, max size, retry, and redirect policies.
   */
  public static async fetchWithHardening(urlStr: string): Promise<Response> {
    let currentUrl = urlStr;
    const redirectCountLimit = 5;

    for (let redirectHop = 0; redirectHop < redirectCountLimit; redirectHop++) {
      const parsedUrl = new URL(currentUrl);

      // Verify destination host against allowlist
      const isAllowedHost = Array.from(ALLOWED_REDIRECT_HOSTS).some(
        (h) => parsedUrl.hostname === h || parsedUrl.hostname.endsWith(`.${h}`)
      );
      if (!isAllowedHost) {
        throw new Error(
          `Security violation: Redirect to unauthorized host '${parsedUrl.hostname}' is blocked to prevent untrusted egress.`
        );
      }

      let attempt = 0;
      let lastError: Error | null = null;

      while (attempt < MAX_RETRIES) {
        attempt++;
        try {
          const response = await fetch(currentUrl, {
            redirect: 'manual',
            signal: AbortSignal.timeout(PER_REQUEST_TIMEOUT_MS),
            headers: {
              'User-Agent': 'SecureShip-CLI/1.0.0-beta.1',
            },
          });

          // Handle redirects explicitly
          if (
            [301, 302, 303, 307, 308].includes(response.status) &&
            response.headers.has('location')
          ) {
            const loc = response.headers.get('location')!;
            currentUrl = new URL(loc, currentUrl).toString();
            break; // Proceed to next redirect hop
          }

          if (response.status >= 500 && attempt < MAX_RETRIES) {
            // Server error retry
            const backoffMs = Math.min(1000 * Math.pow(2, attempt) + Math.random() * 200, 5000);
            await new Promise((res) => setTimeout(res, backoffMs));
            continue;
          }

          return response;
        } catch (err: unknown) {
          lastError = err instanceof Error ? err : new Error(String(err));
          if (attempt < MAX_RETRIES) {
            const backoffMs = Math.min(1000 * Math.pow(2, attempt) + Math.random() * 200, 5000);
            await new Promise((res) => setTimeout(res, backoffMs));
          }
        }
      }

      if (lastError) {
        throw lastError;
      }
    }

    throw new Error(`Exceeded maximum redirect limit (${redirectCountLimit}) fetching ${urlStr}`);
  }

  /**
   * Hardened download and installation pipeline:
   * 1. Pin Authoritative (Defect D1): Remote manifest is a cross-check; mismatch fails immediately.
   * 2. Network hygiene (Defect D3): timeouts, redirects, size cap, Content-Length check.
   * 3. In-process safe extraction (Defect D9): no shell out, traversal/symlink guards.
   * 4. Atomic write: unique temp file, verify, chmod, rename.
   */
  public static async downloadAndInstallAsset(
    asset: PlatformAsset | ToolLockAsset,
    destBinaryPath: string,
    targetDir: string,
    toolDef?: ToolDefinition,
    options?: Partial<InstallToolsOptions>
  ): Promise<void> {
    const tempFile = path.join(targetDir, `.tmp-dl-${crypto.randomBytes(8).toString('hex')}`);

    try {
      // 1. Cross-check remote manifest if available; bundled pin remains authoritative (Fix D1)
      if (toolDef?.sha256ManifestUrl) {
        const remoteHash = await InstallToolsCommand.fetchRemoteSha256(
          toolDef.sha256ManifestUrl,
          path.basename(asset.url)
        );
        if (remoteHash) {
          if (remoteHash.toLowerCase() !== asset.sha256.toLowerCase()) {
            throw new Error(
              `Security violation: Remote checksum manifest (${remoteHash}) does not match authoritative bundled pin (${asset.sha256}) for ${toolDef.name}! Aborting install to prevent trust downgrade.`
            );
          }
        } else if (!options?.json && options?.verbose) {
          console.warn(
            pc.yellow(
              '  ⚠ Upstream SHA256 manifest unavailable. Verified against bundled cryptographic pin.'
            )
          );
        }
      }

      // 2. Fetch asset with network hygiene (Fix D3)
      const response = await InstallToolsCommand.fetchWithHardening(asset.url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText} fetching ${asset.url}`);
      }

      // Check Content-Length header if present before reading body
      const clHeader = response.headers.get('content-length');
      let expectedBytes = 0;
      if (clHeader) {
        expectedBytes = parseInt(clHeader, 10);
        if (expectedBytes > MAX_DOWNLOAD_BYTES) {
          throw new Error(
            `Security violation: Download size ${expectedBytes} bytes exceeds maximum allowed limit of ${MAX_DOWNLOAD_BYTES} bytes.`
          );
        }
      }

      if (!response.body) {
        throw new Error(`Empty response body fetching ${asset.url}`);
      }

      // Stream download while calculating SHA-256 and measuring bytes
      const hash = crypto.createHash('sha256');
      const fileStream = fs.createWriteStream(tempFile);
      let totalBytesReceived = 0;

      const nodeReadable = Readable.fromWeb(
        response.body as import('node:stream/web').ReadableStream
      );

      nodeReadable.on('data', (chunk: Buffer) => {
        totalBytesReceived += chunk.length;
        if (totalBytesReceived > MAX_DOWNLOAD_BYTES) {
          fileStream.destroy(
            new Error(
              `Security violation: Download exceeded maximum limit of ${MAX_DOWNLOAD_BYTES} bytes.`
            )
          );
        }
        hash.update(chunk);
      });

      await stream.pipeline(nodeReadable, fileStream);

      // Verify Content-Length match if header was specified
      if (expectedBytes > 0 && totalBytesReceived !== expectedBytes) {
        throw new Error(
          `Asset download truncated: expected ${expectedBytes} bytes, received ${totalBytesReceived} bytes.`
        );
      }

      // Verify cryptographic SHA-256 hash against bundled pin
      const computedSha = hash.digest('hex').toLowerCase();
      if (computedSha !== asset.sha256.toLowerCase()) {
        throw new Error(
          `Cryptographic checksum mismatch! Expected SHA-256 ${asset.sha256}, got ${computedSha}. Aborting install.`
        );
      }

      // Ensure destination directory exists
      fs.mkdirSync(path.dirname(destBinaryPath), { recursive: true });

      // In-process safe extraction / installation (Fix D9)
      if (asset.archiveType === 'binary') {
        if (process.platform !== 'win32') {
          fs.chmodSync(tempFile, 0o755);
        }
        fs.renameSync(tempFile, destBinaryPath);
        if (process.platform !== 'win32') {
          fs.chmodSync(destBinaryPath, 0o755);
        }
      } else if (asset.archiveType === 'tar.gz') {
        await SafeArchiveExtractor.extractTarGzEntry(
          tempFile,
          asset.binarySubpath ?? path.basename(destBinaryPath),
          destBinaryPath
        );
      } else if (asset.archiveType === 'zip') {
        await SafeArchiveExtractor.extractZipEntry(
          tempFile,
          asset.binarySubpath ?? path.basename(destBinaryPath),
          destBinaryPath
        );
      }
    } finally {
      if (fs.existsSync(tempFile)) {
        try {
          fs.unlinkSync(tempFile);
        } catch {
          // Cleanup best effort
        }
      }
    }
  }

  public static printPathAdvice(targetDir: string): void {
    const currentPath = process.env.PATH ?? '';
    const delimiter = process.platform === 'win32' ? ';' : ':';
    const resolvedTarget = path.resolve(targetDir).toLowerCase();
    const inPath = currentPath
      .split(delimiter)
      .filter(Boolean)
      .some((p) => path.resolve(p).toLowerCase() === resolvedTarget);

    console.log(pc.bold('\nPath Verification:'));
    if (inPath) {
      console.log(`  ${pc.green('✔')} ${targetDir} is already present in your system PATH.`);
    } else {
      console.log(`  ${pc.yellow('⚠')} ${targetDir} is NOT in your current PATH.`);
      console.log(
        pc.gray('    To execute scanners globally, add it to your shell configuration:\n')
      );

      if (process.platform === 'win32') {
        console.log(`    PowerShell : ${pc.cyan(`$env:Path += ";${targetDir}"`)}`);
        console.log(
          `    Permanent  : ${pc.cyan(
            `[Environment]::SetEnvironmentVariable("Path", $env:Path + ";${targetDir}", "User")`
          )}`
        );
      } else {
        console.log(
          `    Bash / Zsh : ${pc.cyan(`export PATH="${targetDir}:$PATH"`)} (add to ~/.bashrc or ~/.zshrc)`
        );
      }
    }
    console.log();
  }
}
