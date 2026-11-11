import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import stores
const { FleetStore } = await import('../../dist/storage/fleet-store.js');
const { BaselineFleetStore } = await import('./baseline-fleet-store.ts');

const mode = process.argv[2];
const dataDir = process.argv[3];
const operation = process.argv[4]; // 'ingest' | 'updatePolicy' | 'clear' | 'first-write'
const targetK = parseInt(process.argv[5] || '0', 10);
const variant = process.argv[6] || 'before'; // 'before' | 'after-half-write'
const storeType = process.argv[7] || 'remediated'; // 'remediated' | 'baseline'

const dbPath = path.join(dataDir, 'fleet-db.json');
const resolvedDataDir = path.resolve(dataDir);

function touchesDataDir(p) {
  if (!p) return false;
  try {
    const resolved = path.resolve(String(p));
    return resolved.startsWith(resolvedDataDir);
  } catch {
    return false;
  }
}

function makePayload(repoName, canary = '') {
  return {
    fleetToken: 'corp-valid-test-token-at-least-24-chars',
    repoName: canary ? `${repoName}_${canary}` : repoName,
    branch: 'main',
    commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
    scannedAt: '2026-11-04T00:00:00.000Z',
    durationMs: 150,
    summary: {
      totalRaw: 10,
      totalReported: 2,
      totalSuppressed: 8,
      bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 1, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      reachabilitySuppressionPct: 80,
    },
    vulnerabilities: [
      {
        ruleId: 'VULN-001',
        severity: 'CRITICAL',
        category: 'SAST',
        reachability: 'REACHABLE_CALL_PATH',
      },
    ],
    sbom: {
      totalComponents: 2,
      compliantCount: 2,
      nonCompliantCount: 0,
      components: [
        { name: 'comp-1', version: '1.0.0', ecosystem: 'npm', compliant: true, license: 'MIT' },
      ],
    },
  };
}

// Interceptor state
let interceptActive = false;
let currentK = 0;
const recordedOps = [];
const openFds = new Map();

// Original fs functions
const origOpenSync = fs.openSync;
const origWriteSync = fs.writeSync;
const origWriteFileSync = fs.writeFileSync;
const origFsyncSync = fs.fsyncSync;
const origCloseSync = fs.closeSync;
const origRenameSync = fs.renameSync;
const origCopyFileSync = fs.copyFileSync;
const origUnlinkSync = fs.unlinkSync;
const origRmSync = fs.rmSync;
const origMkdirSync = fs.mkdirSync;
const origChmodSync = fs.chmodSync;
const origSymlinkSync = fs.symlinkSync;

function killSelf() {
  try {
    process.kill(process.pid, 'SIGKILL');
  } catch {
    process.exit(137);
  }
}

function onOp(opName, pathArg, isWriteOp, execWrite) {
  if (!interceptActive) {
    return execWrite ? execWrite() : undefined;
  }

  currentK++;
  recordedOps.push({ op: opName, path: pathArg, k: currentK, isWrite: isWriteOp });

  if (mode === 'kill-point' && currentK === targetK) {
    if (variant === 'before') {
      killSelf();
    } else if (variant === 'after-half-write' && isWriteOp && execWrite) {
      // Execute half write then kill
      execWrite(true);
      killSelf();
    }
  }

  if (execWrite) {
    return execWrite(false);
  }
}

// Monkey-patch fs mutating methods
fs.openSync = function (p, _flags, _mode) {
  const touches = touchesDataDir(p);
  const fd = origOpenSync.apply(fs, arguments);
  if (touches) {
    openFds.set(fd, p);
    onOp('openSync', p, false);
  }
  return fd;
};

fs.writeSync = function (fd, buffer, offset, length, position) {
  const p = openFds.get(fd);
  const touches = touchesDataDir(p);

  if (touches) {
    return onOp('writeSync', p, true, (isHalf) => {
      if (isHalf) {
        const fullLen =
          length !== undefined
            ? length
            : Buffer.isBuffer(buffer)
              ? buffer.length
              : Buffer.from(buffer).length;
        const halfLen = Math.max(1, Math.floor(fullLen / 2));
        return origWriteSync.call(fs, fd, buffer, offset, halfLen, position);
      }
      return origWriteSync.call(fs, fd, buffer, offset, length, position);
    });
  }
  return origWriteSync.apply(fs, arguments);
};

fs.writeFileSync = function (p, data, options) {
  const touches = touchesDataDir(p);
  if (touches) {
    return onOp('writeFileSync', p, true, (isHalf) => {
      if (isHalf) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
        const halfBuf = buf.subarray(0, Math.max(1, Math.floor(buf.length / 2)));
        return origWriteFileSync.call(fs, p, halfBuf, options);
      }
      return origWriteFileSync.call(fs, p, data, options);
    });
  }
  return origWriteFileSync.apply(fs, arguments);
};

fs.fsyncSync = function (fd) {
  const p = openFds.get(fd);
  const touches = touchesDataDir(p);
  if (touches) {
    onOp('fsyncSync', p, false);
  }
  return origFsyncSync.apply(fs, arguments);
};

fs.closeSync = function (fd) {
  const p = openFds.get(fd);
  const touches = touchesDataDir(p);
  if (touches) {
    onOp('closeSync', p, false);
    openFds.delete(fd);
  }
  return origCloseSync.apply(fs, arguments);
};

fs.renameSync = function (oldPath, newPath) {
  const touches = touchesDataDir(oldPath) || touchesDataDir(newPath);
  if (touches) {
    onOp('renameSync', `${oldPath} -> ${newPath}`, false);
  }
  return origRenameSync.apply(fs, arguments);
};

fs.copyFileSync = function (src, dest, _mode) {
  const touches = touchesDataDir(src) || touchesDataDir(dest);
  if (touches) {
    onOp('copyFileSync', `${src} -> ${dest}`, false);
  }
  return origCopyFileSync.apply(fs, arguments);
};

fs.unlinkSync = function (p) {
  const touches = touchesDataDir(p);
  if (touches) {
    onOp('unlinkSync', p, false);
  }
  return origUnlinkSync.apply(fs, arguments);
};

fs.rmSync = function (p, _options) {
  const touches = touchesDataDir(p);
  if (touches) {
    onOp('rmSync', p, false);
  }
  return origRmSync.apply(fs, arguments);
};

fs.mkdirSync = function (p, _options) {
  const touches = touchesDataDir(p);
  if (touches) {
    onOp('mkdirSync', p, false);
  }
  return origMkdirSync.apply(fs, arguments);
};

if (origChmodSync) {
  fs.chmodSync = function (p, _m) {
    const touches = touchesDataDir(p);
    if (touches) {
      onOp('chmodSync', p, false);
    }
    return origChmodSync.apply(fs, arguments);
  };
}

if (origSymlinkSync) {
  fs.symlinkSync = function (target, p, _type) {
    const touches = touchesDataDir(p);
    if (touches) {
      onOp('symlinkSync', p, false);
    }
    return origSymlinkSync.apply(fs, arguments);
  };
}

// -------------------------------------------------------------
// Execution flow
// -------------------------------------------------------------

async function run() {
  if (mode === 'random-loop') {
    // Ingest 5MB payloads continuously, printing ACK <n>
    const StoreClass = storeType === 'baseline' ? BaselineFleetStore : FleetStore;
    const store = new StoreClass({ storageFile: dbPath });

    // Generate large deterministic component list (~5MB)
    const largeComponents = Array.from({ length: 5000 }, (_, i) => ({
      name: `component-large-${i}`,
      version: `2.0.${i}`,
      ecosystem: 'npm',
      compliant: true,
      license: 'Apache-2.0',
    }));

    let ackCount = 0;
    while (true) {
      ackCount++;
      const payload = {
        ...makePayload(`repo-loop-${ackCount}`),
        sbom: {
          totalComponents: largeComponents.length,
          nonCompliantCount: 0,
          components: largeComponents,
        },
      };
      store.ingest(payload);
      process.stdout.write(`ACK ${ackCount}\n`);
    }
  }

  const StoreClass = storeType === 'baseline' ? BaselineFleetStore : FleetStore;

  // Step 1: Setup S1 if not 'first-write' or 'heal'
  if (operation === 'heal') {
    interceptActive = false;
    const setupStore = new StoreClass({ storageFile: dbPath });
    setupStore.ingest(makePayload('repo-A'));
    origCopyFileSync(dbPath, `${dbPath}.bak`);
    origWriteFileSync(dbPath, '{"repos": [{"repoName": "corrupted');
  } else if (operation !== 'first-write') {
    interceptActive = false;
    const setupStore = new StoreClass({ storageFile: dbPath });
    setupStore.ingest(makePayload('repo-A'));
    setupStore.ingest(makePayload('repo-B'));
  }

  // Step 2: Now arm interception for the target operation
  interceptActive = true;
  currentK = 0;

  if (operation === 'heal') {
    new StoreClass({ storageFile: dbPath });
  } else {
    const targetStore = new StoreClass({ storageFile: dbPath });

    if (operation === 'ingest' || operation === 'bak-rotation') {
      targetStore.ingest(makePayload('repo-C'));
    } else if (operation === 'updatePolicy') {
      targetStore.updatePolicy({ failOnSeverity: 'CRITICAL' });
    } else if (operation === 'clear') {
      targetStore.clear();
    } else if (operation === 'first-write') {
      targetStore.ingest(makePayload('repo-A'));
    }
  }

  // If dry-run, output the recorded ops as JSON
  if (mode === 'dry-run') {
    process.stdout.write(JSON.stringify(recordedOps) + '\n');
    process.exit(0);
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
