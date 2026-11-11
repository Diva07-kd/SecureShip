import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { parseSnapshotBytes, FleetStorePersistError } from './fleet-snapshot.js';

export interface FsFacade {
  existsSync(p: string): boolean;
  readFileSync(p: string, encoding?: BufferEncoding): string | Buffer;
  writeFileSync(
    p: string,
    data: string | NodeJS.ArrayBufferView,
    options?: fs.WriteFileOptions
  ): void;
  mkdirSync(p: string, options?: fs.MakeDirectoryOptions): string | undefined;
  openSync(p: string, flags: string | number, mode?: number): number;
  writeSync(
    fd: number,
    buffer: NodeJS.ArrayBufferView,
    offset?: number,
    length?: number,
    position?: number | null
  ): number;
  fsyncSync(fd: number): void;
  closeSync(fd: number): void;
  statSync(p: string): fs.Stats;
  lstatSync(p: string): fs.Stats;
  renameSync(oldPath: string, newPath: string): void;
  copyFileSync(src: string, dest: string, mode?: number): void;
  unlinkSync(p: string): void;
  readdirSync(p: string, options?: { withFileTypes?: boolean }): string[] | fs.Dirent[];
  realpathSync(p: string): string;
  chmodSync?(p: string, mode: number): void;
}

export const defaultFsFacade: FsFacade = {
  existsSync: (p) => fs.existsSync(p),
  readFileSync: (p, enc) => (enc ? fs.readFileSync(p, enc) : fs.readFileSync(p)),
  writeFileSync: (p, data, opts) => fs.writeFileSync(p, data, opts),
  mkdirSync: (p, opts) => fs.mkdirSync(p, opts),
  openSync: (p, flags, mode) => fs.openSync(p, flags, mode),
  writeSync: (fd, buf, offset, len, pos) => fs.writeSync(fd, buf, offset, len, pos),
  fsyncSync: (fd) => fs.fsyncSync(fd),
  closeSync: (fd) => fs.closeSync(fd),
  statSync: (p) => fs.statSync(p),
  lstatSync: (p) => fs.lstatSync(p),
  renameSync: (oldP, newP) => fs.renameSync(oldP, newP),
  copyFileSync: (src, dest, mode) => fs.copyFileSync(src, dest, mode),
  unlinkSync: (p) => fs.unlinkSync(p),
  readdirSync: (p, opts) =>
    opts?.withFileTypes ? fs.readdirSync(p, { withFileTypes: true }) : fs.readdirSync(p),
  realpathSync: (p) => fs.realpathSync(p),
  chmodSync: (p, mode) => fs.chmodSync(p, mode),
};

export function defaultSleep(ms: number): void {
  if (ms <= 0) return;
  const sab = new SharedArrayBuffer(4);
  const ia = new Int32Array(sab);
  Atomics.wait(ia, 0, 0, ms);
}

export function defaultRandom(bytes: number = 4): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function formatUtcTimestamp(dateOrMs: number | Date = Date.now()): string {
  const d = typeof dateOrMs === 'number' ? new Date(dateOrMs) : dateOrMs;
  const pad = (n: number) => n.toString().padStart(2, '0');
  const yyyy = d.getUTCFullYear();
  const mm = pad(d.getUTCMonth() + 1);
  const dd = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const min = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  return `${yyyy}${mm}${dd}T${hh}${min}${ss}Z`;
}

/**
 * Startup probe: verifies directory writability by creating, fsyncing, and deleting a probe temp file.
 */
export function probeWritable(
  dir: string,
  fsFacade: FsFacade = defaultFsFacade,
  random: (bytes?: number) => string = defaultRandom,
  now: () => number = Date.now
): void {
  if (!fsFacade.existsSync(dir)) {
    fsFacade.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const probeFile = path.join(dir, `.probe.${process.pid}.${now()}.${random(4)}`);
  try {
    const fd = fsFacade.openSync(probeFile, 'wx', 0o600);
    const buf = Buffer.from([0]);
    fsFacade.writeSync(fd, buf, 0, 1);
    fsFacade.fsyncSync(fd);
    fsFacade.closeSync(fd);
    fsFacade.unlinkSync(probeFile);
  } catch (err) {
    try {
      if (fsFacade.existsSync(probeFile)) {
        fsFacade.unlinkSync(probeFile);
      }
    } catch (_cleanupErr: unknown) {
      void _cleanupErr;
      // Best-effort cleanup of probe file on probe failure
    }
    throw err;
  }
}

/**
 * Removes stale temporary and backup-temporary files older than maxAgeMs (default 10 minutes).
 * Deletes ONLY regular files matching ${base}.tmp.* or ${base}.bak.tmp.*. Symlinks are never removed.
 */
export function cleanStaleTemps(
  dir: string,
  baseName: string,
  maxAgeMs: number = 10 * 60 * 1000,
  fsFacade: FsFacade = defaultFsFacade,
  now: () => number = Date.now
): void {
  if (!fsFacade.existsSync(dir)) return;

  const tmpPrefix = `${baseName}.tmp.`;
  const bakTmpPrefix = `${baseName}.bak.tmp.`;

  try {
    const entries = fsFacade.readdirSync(dir, { withFileTypes: true });
    const currentTime = now();

    for (const entry of entries) {
      const name = typeof entry === 'string' ? entry : entry.name;
      if (name.startsWith(tmpPrefix) || name.startsWith(bakTmpPrefix)) {
        const fullPath = path.join(dir, name);
        try {
          const lstat = fsFacade.lstatSync(fullPath);
          // Never remove symlinks
          if (lstat.isSymbolicLink()) continue;
          if (lstat.isFile() && currentTime - lstat.mtimeMs > maxAgeMs) {
            fsFacade.unlinkSync(fullPath);
          }
        } catch (_entryErr: unknown) {
          void _entryErr;
          // File may have been removed concurrently by another process or cleanup
        }
      }
    }
  } catch (_dirErr: unknown) {
    void _dirErr;
    // Non-fatal if directory cannot be listed during stale temp cleanup
  }
}

/**
 * Quarantines an invalid or corrupt file by renaming (or copying if rename fails)
 * to ${target}.corrupt-<UTC yyyymmddThhmmssZ>-<4 hex> and retaining the newest `keep` entries.
 */
export function quarantine(
  filePath: string,
  keep: number = 5,
  fsFacade: FsFacade = defaultFsFacade,
  now: () => number = Date.now,
  random: (bytes?: number) => string = defaultRandom,
  platform: NodeJS.Platform = process.platform
): string {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  const quarantineName = `${base}.corrupt-${formatUtcTimestamp(now())}-${random(2)}`;
  const quarantinePath = path.join(dir, quarantineName);

  let renamed = false;
  try {
    fsFacade.renameSync(filePath, quarantinePath);
    renamed = true;
  } catch (_renameErr: unknown) {
    void _renameErr;
    try {
      fsFacade.copyFileSync(filePath, quarantinePath);
      renamed = true;
    } catch (_copyErr: unknown) {
      void _copyErr;
      // Best-effort copy fallback when rename fails across devices
    }
  }

  if (renamed && platform !== 'win32' && fsFacade.chmodSync) {
    try {
      fsFacade.chmodSync(quarantinePath, 0o600);
    } catch (_chmodErr: unknown) {
      void _chmodErr;
      // Chmod on quarantine file is best-effort on platforms that support it
    }
  }

  // Prune older quarantines exceeding keep
  try {
    const entries = fsFacade.readdirSync(dir, { withFileTypes: true });
    const prefix = `${base}.corrupt-`;
    const corruptEntries: Array<{ name: string; fullPath: string; mtimeMs: number }> = [];

    for (const entry of entries) {
      const name = typeof entry === 'string' ? entry : entry.name;
      if (name.startsWith(prefix)) {
        const fullPath = path.join(dir, name);
        try {
          const st = fsFacade.statSync(fullPath);
          if (st.isFile()) {
            corruptEntries.push({ name, fullPath, mtimeMs: st.mtimeMs });
          }
        } catch (_statErr: unknown) {
          void _statErr;
          // Ignore files that vanished during directory traversal
        }
      }
    }

    // Sort newest first
    corruptEntries.sort((a, b) => {
      if (b.name !== a.name) {
        return b.name.localeCompare(a.name);
      }
      return b.mtimeMs - a.mtimeMs;
    });

    if (corruptEntries.length > keep) {
      for (let i = keep; i < corruptEntries.length; i++) {
        const item = corruptEntries[i];
        if (item) {
          try {
            fsFacade.unlinkSync(item.fullPath);
          } catch (_unlinkErr: unknown) {
            void _unlinkErr;
            // Prune error on older quarantine file is non-fatal
          }
        }
      }
    }
  } catch (_pruneErr: unknown) {
    void _pruneErr;
    // Quarantine pruning directory traversal error is non-fatal
  }

  return quarantinePath;
}

export interface AtomicReplaceOptions {
  fs?: FsFacade;
  sleep?: (ms: number) => void;
  now?: () => number;
  random?: (bytes?: number) => string;
  platform?: NodeJS.Platform;
  primaryKnownGood?: boolean;
  lastWritten?: { size: number; mtimeMs: number; digest: string };
  expectedDigest: string;
  quarantineKeep?: number;
  logger?: { debug?(code: string, message: string): void };
  onExternalModification?: (type: 'valid' | 'invalid') => void;
  onQuarantine?: (corruptPath: string) => void;
  onFallback?: () => void;
}

export interface AtomicReplaceResult {
  mode: 'atomic' | 'non-atomic-fallback';
  rotatedBackup: boolean;
  externalModification?: 'valid' | 'invalid';
  quarantinedPath?: string;
  lastWritten: { size: number; mtimeMs: number; digest: string };
}

const WIN32_RETRY_DELAYS = [10, 20, 40, 80, 160, 320] as const;

function renameWithRetry(
  fsFacade: FsFacade,
  source: string,
  destination: string,
  platform: NodeJS.Platform,
  sleep: (ms: number) => void
): { success: boolean; error: (Error & { code?: string }) | null } {
  if (platform === 'win32') {
    let lastErr: (Error & { code?: string }) | null = null;
    for (let attempt = 0; attempt <= WIN32_RETRY_DELAYS.length; attempt++) {
      try {
        fsFacade.renameSync(source, destination);
        return { success: true, error: null };
      } catch (err: unknown) {
        lastErr = err as Error & { code?: string };
        if (
          attempt < WIN32_RETRY_DELAYS.length &&
          (lastErr.code === 'EPERM' || lastErr.code === 'EACCES' || lastErr.code === 'EBUSY')
        ) {
          const delay = WIN32_RETRY_DELAYS[attempt];
          if (delay !== undefined) {
            sleep(delay);
          }
          continue;
        }
        break;
      }
    }
    return { success: false, error: lastErr };
  } else {
    try {
      fsFacade.renameSync(source, destination);
      return { success: true, error: null };
    } catch (err: unknown) {
      return { success: false, error: err as Error & { code?: string } };
    }
  }
}

/**
 * Atomically replaces the target file with buffer content implementing crash consistency,
 * atomic backup rotation, read-back verification, and Docker single-file fallback.
 */
export function atomicReplace(
  target: string,
  buffer: Buffer,
  opts: AtomicReplaceOptions
): AtomicReplaceResult {
  const fsFacade = opts.fs ?? defaultFsFacade;
  const platform = opts.platform ?? process.platform;
  const sleep = opts.sleep ?? defaultSleep;
  const now = opts.now ?? Date.now;
  const random = opts.random ?? defaultRandom;
  let bakTmp: string | null = null;

  // 1. Resolve real target path to respect symlinks and mount points
  let realTarget = target;
  if (fsFacade.existsSync(target)) {
    try {
      realTarget = fsFacade.realpathSync(target);
    } catch (_err: unknown) {
      void _err;
      // Target realpath fallback when realpath fails
      realTarget = target;
    }
  } else {
    const parentDir = path.dirname(target);
    if (fsFacade.existsSync(parentDir)) {
      try {
        realTarget = path.join(fsFacade.realpathSync(parentDir), path.basename(target));
      } catch (_err: unknown) {
        void _err;
        // Parent realpath fallback
        realTarget = target;
      }
    } else {
      fsFacade.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
      try {
        realTarget = path.join(fsFacade.realpathSync(parentDir), path.basename(target));
      } catch (_err: unknown) {
        void _err;
        // Newly created parent realpath fallback
        realTarget = target;
      }
    }
  }

  const targetDir = path.dirname(realTarget);

  // 3. Create temp file in the SAME directory with exclusive 'wx' flag
  let tempFd: number | null = null;
  let tempPath = '';
  let openAttempts = 0;
  while (openAttempts < 3) {
    openAttempts++;
    tempPath = `${realTarget}.tmp.${process.pid}.${now()}.${random(4)}`;
    try {
      tempFd = fsFacade.openSync(tempPath, 'wx', 0o600);
      break;
    } catch (err: unknown) {
      const code = (err as { code?: string }).code;
      if (code === 'EEXIST' && openAttempts < 3) {
        continue;
      }
      throw err;
    }
  }

  if (tempFd === null) {
    throw new FleetStorePersistError(
      'Failed to allocate unique temp file',
      'FLEET_STORE_PERSIST_FAILED'
    );
  }

  try {
    // Write all bytes in loop handling short writes
    let written = 0;
    while (written < buffer.length) {
      const bytesWritten = fsFacade.writeSync(tempFd, buffer, written, buffer.length - written);
      written += bytesWritten;
    }
    fsFacade.fsyncSync(tempFd);
    fsFacade.closeSync(tempFd);
    tempFd = null;

    // 4. Read-back verification
    const readBack = fsFacade.readFileSync(tempPath);
    const readBackBuf = Buffer.isBuffer(readBack) ? readBack : Buffer.from(readBack);
    const verifyDigest = crypto.createHash('sha256').update(readBackBuf).digest('hex');
    if (verifyDigest !== opts.expectedDigest) {
      try {
        fsFacade.unlinkSync(tempPath);
      } catch (_unlinkErr: unknown) {
        void _unlinkErr;
        // Best-effort temp cleanup on verify mismatch
      }
      throw new FleetStorePersistError(
        'Temp file read-back verification failed',
        'PERSIST_VERIFY_FAILED'
      );
    }

    // 5. Backup rotation (only when primary exists)
    let rotatedBackup = false;
    let externalMod: 'valid' | 'invalid' | undefined;

    if (fsFacade.existsSync(realTarget)) {
      let primaryStat: fs.Stats;
      try {
        primaryStat = fsFacade.statSync(realTarget);
      } catch (err) {
        throw err;
      }

      let canRotate = false;
      if (
        opts.primaryKnownGood &&
        opts.lastWritten &&
        primaryStat.size === opts.lastWritten.size &&
        Math.abs(primaryStat.mtimeMs - opts.lastWritten.mtimeMs) < 2
      ) {
        canRotate = true;
      } else {
        // Primary stat changed or not known good: inspect validity
        try {
          const rawPrimary = fsFacade.readFileSync(realTarget);
          const rawBuf = Buffer.isBuffer(rawPrimary) ? rawPrimary : Buffer.from(rawPrimary);
          const parsed = parseSnapshotBytes(rawBuf);
          if (parsed.ok) {
            externalMod = 'valid';
            opts.onExternalModification?.('valid');
            canRotate = true;
          } else {
            externalMod = 'invalid';
            opts.onExternalModification?.('invalid');
            // Copy corrupt primary to quarantine, do not overwrite backup
            const corruptTarget = `${realTarget}.corrupt-${formatUtcTimestamp(now())}-${random(2)}`;
            try {
              fsFacade.copyFileSync(realTarget, corruptTarget);
              if (platform !== 'win32' && fsFacade.chmodSync) {
                try {
                  fsFacade.chmodSync(corruptTarget, 0o600);
                } catch (_chmodErr: unknown) {
                  void _chmodErr;
                }
              }
              opts.onQuarantine?.(corruptTarget);
              // Prune older quarantines
              try {
                const keep = opts.quarantineKeep ?? 5;
                const entries = fsFacade.readdirSync(targetDir, { withFileTypes: true });
                const prefix = `${path.basename(realTarget)}.corrupt-`;
                const corruptEntries: Array<{ fullPath: string; name: string; mtimeMs: number }> =
                  [];
                for (const entry of entries) {
                  const name = typeof entry === 'string' ? entry : entry.name;
                  if (name.startsWith(prefix)) {
                    const fullPath = path.join(targetDir, name);
                    try {
                      const st = fsFacade.statSync(fullPath);
                      if (st.isFile()) {
                        corruptEntries.push({ fullPath, name, mtimeMs: st.mtimeMs });
                      }
                    } catch (_stErr: unknown) {
                      void _stErr;
                    }
                  }
                }
                corruptEntries.sort(
                  (a, b) => b.name.localeCompare(a.name) || b.mtimeMs - a.mtimeMs
                );
                if (corruptEntries.length > keep) {
                  for (let i = keep; i < corruptEntries.length; i++) {
                    const item = corruptEntries[i];
                    if (item) {
                      try {
                        fsFacade.unlinkSync(item.fullPath);
                      } catch (_unErr: unknown) {
                        void _unErr;
                      }
                    }
                  }
                }
              } catch (_pruneErr: unknown) {
                void _pruneErr;
              }
            } catch (_qErr: unknown) {
              void _qErr;
            }
            canRotate = false;
          }
        } catch (_parseErr: unknown) {
          void _parseErr;
          externalMod = 'invalid';
          opts.onExternalModification?.('invalid');
          canRotate = false;
        }
      }

      if (canRotate) {
        // Atomic rotation: copyFileSync(primary -> `${target}.bak.tmp.<rand>`), fsync, rename to `${target}.bak`
        const currentBakTmp = `${realTarget}.bak.tmp.${random(4)}`;
        bakTmp = currentBakTmp;
        try {
          fsFacade.copyFileSync(realTarget, currentBakTmp);
          const bfd = fsFacade.openSync(currentBakTmp, 'r+', 0o600);
          fsFacade.fsyncSync(bfd);
          fsFacade.closeSync(bfd);
          if (platform !== 'win32' && fsFacade.chmodSync) {
            try {
              fsFacade.chmodSync(currentBakTmp, 0o600);
            } catch (_chmodErr: unknown) {
              void _chmodErr;
            }
          }
          const bakTarget = `${realTarget}.bak`;
          const bakRenameRes = renameWithRetry(fsFacade, currentBakTmp, bakTarget, platform, sleep);
          if (!bakRenameRes.success) {
            throw (
              bakRenameRes.error ??
              new FleetStorePersistError('Backup rename failed', 'FLEET_STORE_PERSIST_FAILED')
            );
          }
          bakTmp = null;
          rotatedBackup = true;
        } catch (err) {
          try {
            if (fsFacade.existsSync(currentBakTmp)) {
              fsFacade.unlinkSync(currentBakTmp);
            }
          } catch (_bakUnlinkErr: unknown) {
            void _bakUnlinkErr;
          }
          throw err;
        }
      }
    }

    // 6. Rename temp file to target
    const renameRes = renameWithRetry(fsFacade, tempPath, realTarget, platform, sleep);
    const renameSucceeded = renameRes.success;
    const renameError = renameRes.error;

    // 7. Fallback for Docker single-file bind mount (EBUSY / EXDEV)
    let mode: 'atomic' | 'non-atomic-fallback' = 'atomic';

    if (!renameSucceeded) {
      if (renameError && (renameError.code === 'EBUSY' || renameError.code === 'EXDEV')) {
        mode = 'non-atomic-fallback';
        opts.onFallback?.();

        // Direct write in place
        let wfd: number | null = null;
        try {
          wfd = fsFacade.openSync(realTarget, 'w', 0o600);
          let fbWritten = 0;
          while (fbWritten < buffer.length) {
            const n = fsFacade.writeSync(wfd, buffer, fbWritten, buffer.length - fbWritten);
            fbWritten += n;
          }
          fsFacade.fsyncSync(wfd);
        } finally {
          if (wfd !== null) {
            try {
              fsFacade.closeSync(wfd);
            } catch (_wcloseErr: unknown) {
              void _wcloseErr;
            }
          }
        }

        // Read-back verification for fallback
        const fbRead = fsFacade.readFileSync(realTarget);
        const fbBuf = Buffer.isBuffer(fbRead) ? fbRead : Buffer.from(fbRead);
        const fbDigest = crypto.createHash('sha256').update(fbBuf).digest('hex');

        if (fbDigest !== opts.expectedDigest) {
          // Restore backup in place if available
          const bakFile = `${realTarget}.bak`;
          if (fsFacade.existsSync(bakFile)) {
            let rfd: number | null = null;
            try {
              const bakContent = fsFacade.readFileSync(bakFile);
              rfd = fsFacade.openSync(realTarget, 'w', 0o600);
              const bBuf = Buffer.isBuffer(bakContent) ? bakContent : Buffer.from(bakContent);
              let bWritten = 0;
              while (bWritten < bBuf.length) {
                bWritten += fsFacade.writeSync(rfd, bBuf, bWritten, bBuf.length - bWritten);
              }
              fsFacade.fsyncSync(rfd);
            } catch (_restoreErr: unknown) {
              void _restoreErr;
            } finally {
              if (rfd !== null) {
                try {
                  fsFacade.closeSync(rfd);
                } catch (_rcloseErr: unknown) {
                  void _rcloseErr;
                }
              }
            }
          }
          throw new FleetStorePersistError(
            'Fallback write verification failed',
            'PERSIST_FALLBACK_VERIFY_FAILED'
          );
        }
      } else {
        throw (
          renameError ?? new FleetStorePersistError('Rename failed', 'FLEET_STORE_PERSIST_FAILED')
        );
      }
    }

    // 8. Directory fsync on POSIX
    if (platform !== 'win32') {
      try {
        const dfd = fsFacade.openSync(targetDir, 'r');
        fsFacade.fsyncSync(dfd);
        fsFacade.closeSync(dfd);
      } catch (_dfdErr: unknown) {
        void _dfdErr;
      }
    }

    // 9. Mode tightening on POSIX
    if (platform !== 'win32' && fsFacade.chmodSync) {
      try {
        fsFacade.chmodSync(realTarget, 0o600);
      } catch (_chmodErr: unknown) {
        void _chmodErr;
      }
    }

    const finalStat = fsFacade.statSync(realTarget);
    return {
      mode,
      rotatedBackup,
      externalModification: externalMod,
      lastWritten: {
        size: finalStat.size,
        mtimeMs: finalStat.mtimeMs,
        digest: opts.expectedDigest,
      },
    };
  } finally {
    if (tempFd !== null) {
      try {
        fsFacade.closeSync(tempFd);
      } catch (_closeErr: unknown) {
        void _closeErr;
      }
    }
    try {
      if (tempPath && fsFacade.existsSync(tempPath)) {
        fsFacade.unlinkSync(tempPath);
      }
    } catch (_unlinkErr: unknown) {
      void _unlinkErr;
      opts.logger?.debug?.('FLEET_STORE_CLEANUP_FAILED', `Failed to clean temp file ${tempPath}`);
    }
    if (bakTmp !== null) {
      try {
        if (fsFacade.existsSync(bakTmp)) {
          fsFacade.unlinkSync(bakTmp);
        }
      } catch (_bakErr: unknown) {
        void _bakErr;
        opts.logger?.debug?.(
          'FLEET_STORE_CLEANUP_FAILED',
          `Failed to clean backup temp file ${bakTmp}`
        );
      }
    }
  }
}
