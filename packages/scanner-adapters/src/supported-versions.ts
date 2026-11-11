import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { platform } from 'node:os';

export interface SupportedVersionEntry {
  minVersion: string;
  recommended: string;
  testedVersion: string;
  installHints: {
    win32: string;
    darwin: string;
    linux: string;
  };
}

let cachedVersions: Record<string, SupportedVersionEntry> | null = null;

export function loadSupportedVersions(): Record<string, SupportedVersionEntry> {
  if (cachedVersions !== null) {
    return cachedVersions;
  }

  const candidates = [
    path.resolve('packages/scanner-adapters/src/supported-versions.json'),
    path.resolve('packages/scanner-adapters/dist/supported-versions.json'),
  ];

  for (const c of candidates) {
    if (existsSync(c)) {
      try {
        cachedVersions = JSON.parse(readFileSync(c, 'utf-8'));
        return cachedVersions!;
      } catch {
        // Continue
      }
    }
  }

  return {};
}

/**
 * Returns OS-specific installation hint for a scanner.
 * Appends a note about refreshing PATH for Windows winget installs.
 */
export function getInstallHint(scannerName: string, osPlatform: string = platform()): string {
  const all = loadSupportedVersions();
  const entry = all[scannerName.toLowerCase()];
  if (!entry || !entry.installHints) {
    return `Install ${scannerName} and ensure it is available on system PATH.`;
  }

  const osKey = (
    osPlatform === 'win32' ? 'win32' : osPlatform === 'darwin' ? 'darwin' : 'linux'
  ) as 'win32' | 'darwin' | 'linux';

  const baseHint = entry.installHints[osKey] || entry.installHints.linux;
  if (osKey === 'win32' && baseHint.includes('winget')) {
    return `${baseHint}. Note: winget installs may need a new terminal to refresh PATH.`;
  }

  return baseHint;
}

/**
 * Extracts and compares semantic version numbers (major.minor.patch).
 */
export function compareSemver(detected: string, min: string): number {
  const extractVersion = (v: string): number[] => {
    const match = v.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
    if (!match) return [0, 0, 0];
    return [
      parseInt(match[1]!, 10),
      parseInt(match[2]!, 10),
      match[3] ? parseInt(match[3]!, 10) : 0,
    ];
  };

  const [dMaj, dMin, dPatch] = extractVersion(detected);
  const [mMaj, mMin, mPatch] = extractVersion(min);

  if (dMaj !== mMaj) return dMaj! - mMaj!;
  if (dMin !== mMin) return dMin! - mMin!;
  return dPatch! - mPatch!;
}

export function isVersionSupported(detected: string, min: string): boolean {
  return compareSemver(detected, min) >= 0;
}
