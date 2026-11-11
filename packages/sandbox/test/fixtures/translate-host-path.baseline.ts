/**
 * Baseline translation function and container arg builder copied verbatim from
 * audit baseline commit 70c3087b863d06538a6b7116eaa4d22e25073e29 in
 * packages/sandbox/src/backends/container-backend.ts.
 *
 * Used exclusively as a RED ORACLE to prove that the baseline was defective,
 * and for regression differential testing.
 */

import type { SandboxConfig } from '@secureship/contracts';
import type { SandboxRunOptions } from '../../src/backends/sandbox-backend.interface.js';

/**
 * Verbatim baseline implementation of translateHostPath from 70c3087b.
 */
export function baselineTranslateHostPath(hostPath: string): string {
  const normalized = hostPath.replace(/\\/g, '/');
  if (/^[a-zA-Z]:\//.test(normalized)) {
    const drive = normalized[0]?.toLowerCase();
    const rest = normalized.substring(2);
    return `/${drive}${rest}`;
  }
  return normalized;
}

/**
 * Verbatim baseline implementation of buildContainerArgs from 70c3087b.
 */
export function baselineBuildContainerArgs(
  shadowDir: string,
  config: SandboxConfig,
  runId: string,
  command: string,
  args: string[],
  options: SandboxRunOptions = {}
): string[] {
  const limits = config.limits;
  const networkMode = options.network ? 'bridge' : 'none';
  const translatedShadow = baselineTranslateHostPath(shadowDir);

  const image =
    config.images.node ||
    config.images.python ||
    'node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6';

  const containerArgs: string[] = [
    'run',
    '--rm',
    `--network=${networkMode}`,
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    `--pids-limit=${limits.pids}`,
    `--memory=${limits.memory}`,
    `--memory-swap=${limits.memory}`,
    `--cpus=${limits.cpus}`,
    '--user=1000:1000',
    '--read-only',
    `--tmpfs=/tmp:rw,size=${limits.tmpfsMb}m`,
    '--workdir=/work',
    `-v=${translatedShadow}:/work:rw`,
    '--pull=never',
    `--label=secureship.run=${runId}`,
    '-e',
    'CI=1',
    '-e',
    'HOME=/tmp',
    '-e',
    'LANG=C.UTF-8',
  ];

  if (options.env) {
    for (const [k, v] of Object.entries(options.env)) {
      containerArgs.push('-e', `${k}=${v}`);
    }
  }

  containerArgs.push(image, command, ...args);
  return containerArgs;
}
