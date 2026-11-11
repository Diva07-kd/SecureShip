import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { resolveDbDir, resolveToolDirs } from '../paths/index.js';
import {
  OfflineBundleManifest,
  OfflineBundleManifestSchema,
  OfflineComponent,
  OfflineGenerationManifest,
  OfflineGenerationManifestSchema,
} from './types.js';
import { canonicalJsonStringify, signEd25519, verifyEd25519 } from './canonical-json.js';
import { DeterministicTarWriter, SafeTarReader } from './tar-bundle.js';
import { DbLocator } from './db-locator.js';
import { SafeProcessRunner } from '../sandbox/safe-process-runner.js';

export interface CreateBundleOptions {
  outputPath?: string;
  bundleId?: string;
  platforms?: string[];
  ecosystems?: string[];
  includeJavaDb?: boolean;
  noTools?: boolean;
  signKeyPem?: string;
  keyId?: string;
  workDir?: string;
  force?: boolean;
  now?: () => Date;
  cliVersion?: string;
  toolPins?: Record<string, unknown>;
  skipDownload?: boolean;
  downloadTimeoutMs?: number;
}

export interface CreateBundleResult {
  outputPath: string;
  bundleId: string;
  totalSize: number;
  componentCount: number;
  signed: boolean;
  manifest: OfflineBundleManifest;
}

export interface ImportBundleOptions {
  bundlePath: string;
  trustKeyPems?: string[];
  allowUnsigned?: boolean;
  allowDowngrade?: boolean;
  dryRun?: boolean;
  verifyOnly?: boolean;
  dbDir?: string;
  toolsDir?: string;
  now?: () => Date;
  cliVersion?: string;
  toolPins?: Record<string, unknown>;
  verifyToolBinary?: (filePath: string, sha256: string) => boolean;
}

export interface ImportBundleResult {
  success: boolean;
  bundleId: string;
  generationId?: string;
  trust: 'VERIFIED' | 'UNSIGNED';
  dryRun: boolean;
  message: string;
  manifest: OfflineBundleManifest;
}

export class OfflineBundleService {
  /**
   * Creates a self-contained, signed, deterministic offline bundle tarball.
   */
  public static async createBundle(options: CreateBundleOptions = {}): Promise<CreateBundleResult> {
    const now = (options.now ?? (() => new Date()))();
    const dateStr = now.toISOString().replace(/[:.]/g, '-');
    const bundleId = options.bundleId ?? `bundle-${dateStr}`;
    const defaultName = `secureship-offline-bundle-${now.toISOString().slice(0, 10)}.tar.gz`;
    const outputPath = path.resolve(options.outputPath ?? defaultName);

    if (fs.existsSync(outputPath) && !options.force) {
      throw new Error(
        `Output bundle file '${outputPath}' already exists. Use --force to overwrite.`
      );
    }

    const outDir = path.dirname(outputPath);
    fs.mkdirSync(outDir, { recursive: true });

    const stagingBase = options.workDir ?? os.tmpdir();
    const stagingDir = fs.mkdtempSync(path.join(stagingBase, 'secureship-bundle-staging-'));

    try {
      const components: OfflineComponent[] = [];
      const platforms = options.platforms ?? [`${process.platform}-${process.arch}`];
      const toolsLock = options.toolPins ?? {};

      // 1. Acquire Trivy database
      const trivyStaging = path.join(stagingDir, 'trivy');
      const trivyDbDir = path.join(trivyStaging, 'db');
      fs.mkdirSync(trivyDbDir, { recursive: true });

      let trivyMetadata = {
        Version: 2,
        UpdatedAt: now.toISOString(),
        DownloadedAt: now.toISOString(),
      };

      // Try downloading via real trivy if available on system and not skipped
      if (!options.skipDownload) {
        try {
          const timeout = options.downloadTimeoutMs ?? 60_000;
          const trivyArgs = ['image', '--download-db-only', '--cache-dir', trivyStaging];
          await SafeProcessRunner.run('trivy', trivyArgs, { timeoutMs: timeout });
          if (options.includeJavaDb) {
            await SafeProcessRunner.run(
              'trivy',
              ['image', '--download-java-db-only', '--cache-dir', trivyStaging],
              { timeoutMs: timeout }
            );
          }
        } catch {
          // Fallback below
        }
      }
      if (!fs.existsSync(path.join(trivyDbDir, 'trivy.db'))) {
        // Check workDir first
        if (options.workDir) {
          const workTrivyDb = path.join(options.workDir, 'trivy', 'db');
          if (fs.existsSync(path.join(workTrivyDb, 'trivy.db'))) {
            fs.copyFileSync(path.join(workTrivyDb, 'trivy.db'), path.join(trivyDbDir, 'trivy.db'));
            if (fs.existsSync(path.join(workTrivyDb, 'metadata.json'))) {
              fs.copyFileSync(
                path.join(workTrivyDb, 'metadata.json'),
                path.join(trivyDbDir, 'metadata.json')
              );
            }
          }
        }
      }

      if (!fs.existsSync(path.join(trivyDbDir, 'trivy.db'))) {
        if (!options.skipDownload) {
          const localAppData =
            process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local');
          const defaultTrivyDb = path.join(localAppData, 'trivy', 'db');
          if (fs.existsSync(path.join(defaultTrivyDb, 'trivy.db'))) {
            fs.copyFileSync(
              path.join(defaultTrivyDb, 'trivy.db'),
              path.join(trivyDbDir, 'trivy.db')
            );
            if (fs.existsSync(path.join(defaultTrivyDb, 'metadata.json'))) {
              fs.copyFileSync(
                path.join(defaultTrivyDb, 'metadata.json'),
                path.join(trivyDbDir, 'metadata.json')
              );
            }
          }
        }
      }

      if (!fs.existsSync(path.join(trivyDbDir, 'trivy.db'))) {
        throw new Error(
          '[Bundle Error] Unable to acquire valid Trivy database. Real Trivy binary download failed and no local cache was found.'
        );
      }

      if (fs.existsSync(path.join(trivyDbDir, 'metadata.json'))) {
        try {
          trivyMetadata = JSON.parse(
            fs.readFileSync(path.join(trivyDbDir, 'metadata.json'), 'utf-8')
          );
        } catch {}
      }

      // Collect Trivy component files
      const trivyFiles: { path: string; size: number; sha256: string; mode: number }[] = [];
      let trivyTotalSize = 0;
      if (fs.existsSync(trivyDbDir)) {
        for (const file of fs.readdirSync(trivyDbDir).sort()) {
          const filePath = path.join(trivyDbDir, file);
          const stat = fs.statSync(filePath);
          const hash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
          trivyFiles.push({
            path: `trivy/db/${file}`,
            size: stat.size,
            sha256: hash,
            mode: 0o644,
          });
          trivyTotalSize += stat.size;
        }
      }

      components.push({
        id: 'trivy-db',
        kind: 'db',
        version: String(trivyMetadata.Version || '2'),
        upstreamUpdatedAt: trivyMetadata.UpdatedAt || now.toISOString(),
        upstreamMetadata: trivyMetadata as Record<string, unknown>,
        totalSizeBytes: trivyTotalSize,
        files: trivyFiles,
      });

      // 2. Acquire OSV-Scanner database
      const osvStaging = path.join(stagingDir, 'osv');
      fs.mkdirSync(osvStaging, { recursive: true });
      const osvMetadataFile = path.join(osvStaging, 'metadata.json');
      const osvMetadata = {
        version: '1.9.2',
        ecosystems: options.ecosystems ?? ['npm', 'PyPI', 'Go', 'Maven'],
        updatedAt: now.toISOString(),
      };
      fs.writeFileSync(osvMetadataFile, JSON.stringify(osvMetadata, null, 2));

      // Acquire ecosystem archives
      for (const eco of osvMetadata.ecosystems) {
        const ecoDir = path.join(osvStaging, eco);
        fs.mkdirSync(ecoDir, { recursive: true });
        const allZip = path.join(ecoDir, 'all.zip');

        // Check workDir first
        if (options.workDir) {
          const workEcoZip = path.join(options.workDir, 'osv', eco, 'all.zip');
          if (fs.existsSync(workEcoZip)) {
            fs.copyFileSync(workEcoZip, allZip);
          }
        }

        // Check local OSV cache next
        if (!fs.existsSync(allZip)) {
          const customCache =
            process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY ??
            process.env.OSV_SCANNER_CACHE_DIR ??
            path.join(os.homedir(), '.cache', 'osv-scanner');
          const cachedZip = path.join(customCache, eco, 'all.zip');
          if (fs.existsSync(cachedZip)) {
            fs.copyFileSync(cachedZip, allZip);
          }
        }

        // If not skipped, download from official OSV storage
        if (!fs.existsSync(allZip) && !options.skipDownload) {
          try {
            const timeout = options.downloadTimeoutMs ?? 60_000;
            const url = `https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip`;
            const res = await fetch(url, { signal: AbortSignal.timeout(timeout) });
            if (res.ok && res.body) {
              const fileStream = fs.createWriteStream(allZip);
              await new Promise<void>((resolve, reject) => {
                const reader = res.body!.getReader();
                function pump(): void {
                  reader
                    .read()
                    .then(({ done, value }) => {
                      if (done) {
                        fileStream.end();
                        resolve();
                        return;
                      }
                      fileStream.write(value, (err) => {
                        if (err) reject(err);
                        else pump();
                      });
                    })
                    .catch(reject);
                }
                pump();
              });
            }
          } catch {
            // Handled below
          }
        }

        if (!fs.existsSync(allZip)) {
          throw new Error(
            `[Bundle Error] Unable to acquire valid OSV database for ecosystem '${eco}'. Real download failed and no local cache was found.`
          );
        }
      }

      const osvFiles: { path: string; size: number; sha256: string; mode: number }[] = [];
      let osvTotalSize = 0;
      const walkDir = (currentDir: string, relPrefix: string) => {
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
          const fullPath = path.join(currentDir, entry.name);
          const relPath = `${relPrefix}/${entry.name}`;
          if (entry.isDirectory()) {
            walkDir(fullPath, relPath);
          } else {
            const stat = fs.statSync(fullPath);
            const hash = crypto
              .createHash('sha256')
              .update(fs.readFileSync(fullPath))
              .digest('hex');
            osvFiles.push({
              path: relPath,
              size: stat.size,
              sha256: hash,
              mode: 0o644,
            });
            osvTotalSize += stat.size;
          }
        }
      };
      walkDir(osvStaging, 'osv');

      components.push({
        id: 'osv-offline-db',
        kind: 'db',
        version: osvMetadata.version,
        upstreamUpdatedAt: osvMetadata.updatedAt,
        upstreamMetadata: osvMetadata as Record<string, unknown>,
        totalSizeBytes: osvTotalSize,
        files: osvFiles,
      });

      // 3. Collect tools & licenses if requested
      if (!options.noTools) {
        const toolDirs = resolveToolDirs();
        const candidateDir = toolDirs[0] ?? path.join(os.homedir(), '.secureship', 'bin');
        const toolFiles: { path: string; size: number; sha256: string; mode: number }[] = [];
        let toolTotalSize = 0;

        if (fs.existsSync(candidateDir)) {
          const entries = fs.readdirSync(candidateDir, { withFileTypes: true });
          entries.sort((a, b) => a.name.localeCompare(b.name));
          for (const dirent of entries) {
            if (!dirent.isDirectory()) {
              const fullPath = path.join(candidateDir, dirent.name);
              const stat = fs.statSync(fullPath);
              const hash = crypto
                .createHash('sha256')
                .update(fs.readFileSync(fullPath))
                .digest('hex');
              toolFiles.push({
                path: `tools/${dirent.name}`,
                size: stat.size,
                sha256: hash,
                mode: 0o755,
              });
              toolTotalSize += stat.size;
            }
          }
        }

        if (toolFiles.length > 0) {
          components.push({
            id: 'engine-binaries',
            kind: 'tool',
            version: '1.0.0',
            upstreamUpdatedAt: now.toISOString(),
            totalSizeBytes: toolTotalSize,
            files: toolFiles,
          });
        }
      }

      // Sort components and their files deterministically
      components.sort((a, b) => a.id.localeCompare(b.id));
      for (const comp of components) {
        comp.files.sort((a, b) => a.path.localeCompare(b.path));
      }

      // Calculate overall size
      const totalSizeBytes = components.reduce((acc, c) => acc + c.totalSizeBytes, 0);

      // Build manifest
      const rawManifest: OfflineBundleManifest = {
        schemaVersion: 1,
        createdAt: now.toISOString(),
        cliVersion: options.cliVersion ?? '1.0.0-beta.1',
        bundleId,
        platforms,
        toolPins: toolsLock as Record<string, unknown>,
        totalSize: totalSizeBytes,
        keyId: options.keyId,
        components,
      };

      if (options.signKeyPem) {
        const toSign = { ...rawManifest };
        delete toSign.signature;
        rawManifest.signature = signEd25519(canonicalJsonStringify(toSign), options.signKeyPem);
      }

      const validatedManifest = OfflineBundleManifestSchema.parse(rawManifest);

      // Write bundle deterministically to temp file in destination directory
      const tempOutputFile = path.join(
        outDir,
        `.tmp-bundle-${crypto.randomBytes(6).toString('hex')}.tar.gz`
      );
      const writer = new DeterministicTarWriter(tempOutputFile);

      // Manifest MUST be the first entry, encoded canonically
      const manifestBytes = Buffer.from(canonicalJsonStringify(validatedManifest), 'utf-8');
      writer.addBufferEntry('manifest.json', manifestBytes, 0o644);

      // Add all component files
      for (const comp of components) {
        for (const file of comp.files) {
          const sourcePath = path.join(stagingDir, file.path);
          if (fs.existsSync(sourcePath)) {
            await writer.addFileEntry(file.path, sourcePath, file.mode);
          }
        }
      }

      await writer.finalize();

      // Read-back verification pass
      const verifyDir = fs.mkdtempSync(path.join(stagingBase, 'secureship-bundle-verify-'));
      try {
        const extracted = await SafeTarReader.extractAll(tempOutputFile, verifyDir);
        const manifestEntry = extracted.find((e) => e.path === 'manifest.json');
        if (!manifestEntry) {
          throw new Error('Read-back verification failed: manifest.json is not present in bundle.');
        }
      } finally {
        fs.rmSync(verifyDir, { recursive: true, force: true });
      }

      // Atomic rename to final output path
      fs.renameSync(tempOutputFile, outputPath);

      return {
        outputPath,
        bundleId,
        totalSize: fs.statSync(outputPath).size,
        componentCount: components.length,
        signed: Boolean(options.signKeyPem),
        manifest: validatedManifest,
      };
    } finally {
      if (fs.existsSync(stagingDir)) {
        try {
          fs.rmSync(stagingDir, { recursive: true, force: true });
        } catch {}
      }
    }
  }

  /**
   * Imports and validates an offline bundle, atomically publishing a new database generation.
   */
  public static async importBundle(options: ImportBundleOptions): Promise<ImportBundleResult> {
    const bundlePath = path.resolve(options.bundlePath);
    if (!fs.existsSync(bundlePath)) {
      throw new Error(`Bundle file not found: '${bundlePath}'`);
    }

    const targetDbDir = options.dbDir ?? resolveDbDir();
    fs.mkdirSync(targetDbDir, { recursive: true });

    const stagingBase = path.join(targetDbDir, 'staging');
    fs.mkdirSync(stagingBase, { recursive: true, mode: 0o700 });

    const lockFilePath = path.join(stagingBase, 'import.lock');
    const STALE_LOCK_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

    // Check existing lock and handle stale recovery
    if (fs.existsSync(lockFilePath)) {
      try {
        const rawLock = fs.readFileSync(lockFilePath, 'utf-8');
        const lockInfo = JSON.parse(rawLock) as { pid: number; startedAt: number };
        let isAlive = false;
        try {
          process.kill(lockInfo.pid, 0);
          isAlive = true;
        } catch {
          isAlive = false;
        }

        const isExpired = Date.now() - lockInfo.startedAt > STALE_LOCK_TIMEOUT_MS;
        if (!isAlive || isExpired) {
          // Stale lock recovery
          fs.unlinkSync(lockFilePath);
        } else {
          throw new Error(
            `Concurrent import operation is in progress (PID: ${lockInfo.pid}, started: ${new Date(
              lockInfo.startedAt
            ).toISOString()}).`
          );
        }
      } catch (err: unknown) {
        if (err instanceof Error && err.message.includes('Concurrent import')) {
          throw err;
        }
        // If file was corrupt or unreadable, remove it
        try {
          fs.unlinkSync(lockFilePath);
        } catch {}
      }
    }

    // Acquire lock atomically
    try {
      fs.writeFileSync(lockFilePath, JSON.stringify({ pid: process.pid, startedAt: Date.now() }), {
        flag: 'wx',
      });
    } catch {
      throw new Error(
        `Failed to acquire import lockfile at '${lockFilePath}'. Another import process may have just started.`
      );
    }

    const stagingDir = fs.mkdtempSync(path.join(stagingBase, 'staging-'));

    try {
      // 1. Safe streaming extraction into isolated staging directory
      const extractedEntries = await SafeTarReader.extractAll(bundlePath, stagingDir);

      // 2. Validate manifest presence and structure
      const manifestPath = path.join(stagingDir, 'manifest.json');
      if (!fs.existsSync(manifestPath)) {
        throw new Error(
          `Invalid offline bundle: manifest.json missing from root of archive '${bundlePath}'.`
        );
      }

      const rawManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
      const manifest = OfflineBundleManifestSchema.parse(rawManifest);

      // 3. Cryptographic Signature & Trust Verification
      let trust: 'VERIFIED' | 'UNSIGNED' = 'UNSIGNED';
      if (options.trustKeyPems && options.trustKeyPems.length > 0) {
        if (!manifest.signature) {
          throw new Error(
            `[Security Violation] Bundle '${manifest.bundleId}' is unsigned, but trusted keys were specified. Rejecting import.`
          );
        }

        const toVerify = { ...manifest };
        delete toVerify.signature;
        const canonical = canonicalJsonStringify(toVerify);

        let verified = false;
        for (const keyPem of options.trustKeyPems) {
          if (verifyEd25519(canonical, manifest.signature, keyPem)) {
            verified = true;
            break;
          }
        }

        if (!verified) {
          throw new Error(
            `[Security Violation] Signature verification failed for bundle '${manifest.bundleId}' against all provided trusted public keys.`
          );
        }

        trust = 'VERIFIED';
      } else if (!manifest.signature) {
        if (!options.allowUnsigned) {
          throw new Error(
            `[Security Violation] Bundle '${manifest.bundleId}' is unsigned. Use --allow-unsigned to import unsigned bundles.`
          );
        }
        trust = 'UNSIGNED';
      } else {
        // Signed bundle, but no trust keys provided
        if (!options.allowUnsigned) {
          throw new Error(
            `[Security Violation] Bundle '${manifest.bundleId}' is signed (keyId: '${manifest.keyId ?? 'unspecified'}'), but no --trust-key was provided. Provide a trusted key or pass --allow-unsigned.`
          );
        }
        trust = 'UNSIGNED';
      }

      // 4. Anti-Rollback Protection
      const activeGen = DbLocator.getActiveGeneration(targetDbDir);
      if (activeGen) {
        const bundleCreated = new Date(manifest.createdAt).getTime();
        const activeCreated = new Date(activeGen.manifest.createdAt).getTime();
        if (bundleCreated < activeCreated && !options.allowDowngrade) {
          throw new Error(
            `[Security Violation] Anti-rollback rejected: Bundle timestamp (${manifest.createdAt}) is older than installed generation '${activeGen.id}' (${activeGen.manifest.createdAt}). Use --allow-downgrade to override.`
          );
        }
      }

      // 5. Verify file hashes against manifest components
      const fileMap = new Map(extractedEntries.map((e) => [e.path, e]));
      for (const comp of manifest.components) {
        for (const expectedFile of comp.files) {
          const actual = fileMap.get(expectedFile.path);
          if (!actual) {
            throw new Error(
              `Bundle corruption: Component '${comp.id}' missing expected file '${expectedFile.path}'.`
            );
          }
          if (actual.size !== expectedFile.size || actual.sha256 !== expectedFile.sha256) {
            throw new Error(
              `Integrity violation: Hash mismatch for file '${expectedFile.path}' (expected: ${expectedFile.sha256}, actual: ${actual.sha256}).`
            );
          }
        }
      }

      // 6. Verify engine binaries against CLI's authoritative tool pins
      for (const comp of manifest.components) {
        if (comp.kind === 'tool') {
          for (const file of comp.files) {
            let matchedPin = false;
            if (options.verifyToolBinary) {
              matchedPin = options.verifyToolBinary(file.path, file.sha256);
            } else if (options.toolPins) {
              const tools = options.toolPins as Record<
                string,
                { platforms?: Record<string, { sha256?: string }> }
              >;
              for (const [, toolDef] of Object.entries(tools)) {
                if (toolDef && typeof toolDef === 'object' && toolDef.platforms) {
                  for (const [, asset] of Object.entries(toolDef.platforms)) {
                    if (asset?.sha256 && asset.sha256.toLowerCase() === file.sha256.toLowerCase()) {
                      matchedPin = true;
                      break;
                    }
                  }
                }
                if (matchedPin) break;
              }
            } else {
              matchedPin = true;
            }

            if (!matchedPin) {
              throw new Error(
                `[Security Violation] Bundled binary '${file.path}' does not match any cryptographic pin in CLI tools.lock.json.`
              );
            }
          }
        }
      }

      // 7. Verify-only or Dry-run exits here leaving filesystem byte-identical
      if (options.verifyOnly || options.dryRun) {
        return {
          success: true,
          bundleId: manifest.bundleId,
          trust,
          dryRun: Boolean(options.dryRun || options.verifyOnly),
          message: options.verifyOnly
            ? `Bundle '${manifest.bundleId}' verified successfully (${trust}).`
            : `Dry-run: Bundle '${manifest.bundleId}' is valid and ready to import (${trust}).`,
          manifest,
        };
      }

      // 8. Publish new generation
      const now = (options.now ?? (() => new Date()))();
      const genId = `gen-${now.toISOString().slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
      const genDir = DbLocator.getGenerationDir(genId, targetDbDir);
      fs.mkdirSync(genDir, { recursive: true });

      // Move staging contents to generation directory
      for (const entry of fs.readdirSync(stagingDir).sort()) {
        if (entry !== 'manifest.json') {
          const src = path.join(stagingDir, entry);
          const dest = path.join(genDir, entry);
          fs.renameSync(src, dest);
        }
      }

      // Write generation manifest
      const genManifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: genId,
        createdAt: manifest.createdAt,
        importedAt: now.toISOString(),
        trust,
        keyId: manifest.keyId,
        bundleId: manifest.bundleId,
        cliVersion: manifest.cliVersion,
        components: manifest.components,
      };

      fs.writeFileSync(
        path.join(genDir, 'manifest.json'),
        JSON.stringify(OfflineGenerationManifestSchema.parse(genManifest), null, 2)
      );

      // Record PREVIOUS generation pointer for rollback support
      const currentId = DbLocator.getCurrentGenerationId(targetDbDir);
      if (currentId) {
        fs.writeFileSync(path.join(targetDbDir, 'PREVIOUS'), currentId);
      }

      // Atomic pointer swap to CURRENT
      const tempCurrent = path.join(targetDbDir, `.CURRENT.tmp-${process.pid}`);
      fs.writeFileSync(tempCurrent, genId);
      fs.renameSync(tempCurrent, path.join(targetDbDir, 'CURRENT'));

      // 9. Retention GC: Keep at least 2 generations, never delete CURRENT or PREVIOUS
      OfflineBundleService.runRetentionGc(targetDbDir, genId, currentId);

      return {
        success: true,
        bundleId: manifest.bundleId,
        generationId: genId,
        trust,
        dryRun: false,
        message: `Successfully imported offline bundle '${manifest.bundleId}' as generation '${genId}' (${trust}).`,
        manifest,
      };
    } finally {
      if (fs.existsSync(lockFilePath)) {
        try {
          fs.unlinkSync(lockFilePath);
        } catch {}
      }
      if (fs.existsSync(stagingDir)) {
        try {
          fs.rmSync(stagingDir, { recursive: true, force: true });
        } catch {}
      }
    }
  }

  /**
   * Restores the previous database generation using the PREVIOUS pointer file.
   */
  public static async rollback(
    dbDir?: string
  ): Promise<{ success: boolean; activeGeneration?: string; message: string }> {
    const targetDbDir = dbDir ?? resolveDbDir();
    const prevFile = path.join(targetDbDir, 'PREVIOUS');
    if (!fs.existsSync(prevFile)) {
      throw new Error('No previous generation found to rollback to.');
    }

    const prevGenId = fs.readFileSync(prevFile, 'utf-8').trim();
    if (!prevGenId) {
      throw new Error('Previous generation pointer is empty.');
    }

    const prevDir = DbLocator.getGenerationDir(prevGenId, targetDbDir);
    if (!fs.existsSync(prevDir) || !DbLocator.loadGenerationManifest(prevGenId, targetDbDir)) {
      throw new Error(`Previous generation directory '${prevGenId}' is missing or corrupted.`);
    }

    // Atomically swap CURRENT to point to PREVIOUS
    const currentId = DbLocator.getCurrentGenerationId(targetDbDir);
    const tempCurrent = path.join(targetDbDir, `.CURRENT.tmp-${process.pid}`);
    fs.writeFileSync(tempCurrent, prevGenId);
    fs.renameSync(tempCurrent, path.join(targetDbDir, 'CURRENT'));

    if (currentId) {
      fs.writeFileSync(prevFile, currentId);
    }

    return {
      success: true,
      activeGeneration: prevGenId,
      message: `Successfully rolled back active generation to '${prevGenId}'.`,
    };
  }

  /**
   * Retention GC: keeps the active and previous generations, deleting oldest excess generations.
   */
  private static runRetentionGc(
    targetDbDir: string,
    currentGenId: string,
    prevGenId: string | null,
    retainCount: number = 2
  ): void {
    try {
      const allGens = DbLocator.listGenerations(targetDbDir);
      if (allGens.length <= retainCount) return;

      const protectedIds = new Set<string>([currentGenId]);
      if (prevGenId) protectedIds.add(prevGenId);

      // Delete oldest generations not protected
      for (const gen of allGens) {
        if (!protectedIds.has(gen)) {
          const genDir = DbLocator.getGenerationDir(gen, targetDbDir);
          fs.rmSync(genDir, { recursive: true, force: true });
        }
      }
    } catch {
      // Best-effort GC
    }
  }
}
