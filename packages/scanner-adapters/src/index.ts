export * from './binary-resolver.js';
export * from './sarif/sarif-parser.js';
export * from './adapters/opengrep.adapter.js';
export * from './adapters/gitleaks.adapter.js';
export * from './adapters/trivy.adapter.js';
export * from './adapters/osv-scanner.adapter.js';
export * from './adapters/checkov.adapter.js';
export * from './supported-versions.js';
export * from './semver-extractor.js';
export * from './paths.js';
export * from './tools-lock.js';
export * from './safe-archive.js';
export * from './standalone-exec.js';

import path from 'node:path';
import { getStandaloneExecDir } from './standalone-exec.js';
import { loadToolsLock } from './tools-lock.js';

const _execDir = getStandaloneExecDir();
if (_execDir) {
  try {
    loadToolsLock(undefined, [path.join(_execDir, 'tools.lock.json')]);
  } catch {
    // Graceful fallback if tools.lock.json is not present
  }
}
