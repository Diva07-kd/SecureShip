import fs from 'node:fs';
import path from 'node:path';
import { resolveSecureshipHome } from '../paths/index.js';

/**
 * Returns the default file path for the local SecureShip license token.
 * Respects SECURESHIP_LICENSE_PATH environment variable for air-gapped CI/testing.
 */
export function getDefaultLicensePath(): string {
  if (process.env.SECURESHIP_LICENSE_PATH) {
    return path.resolve(process.env.SECURESHIP_LICENSE_PATH);
  }
  return path.join(resolveSecureshipHome(), 'license.jwt');
}

/**
 * Reads the stored license JWT string from disk. Returns null if file does not exist.
 */
export function readLicenseFile(filePath: string = getDefaultLicensePath()): string | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const token = fs.readFileSync(filePath, 'utf-8').trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

/**
 * Writes the license JWT to disk with restrictive file permissions (0600 on POSIX).
 */
export function writeLicenseFile(
  jwtToken: string,
  filePath: string = getDefaultLicensePath()
): void {
  const targetDir = path.dirname(filePath);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
  }

  // Atomic write via temp file
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempPath, jwtToken.trim(), { encoding: 'utf-8', mode: 0o600 });
  fs.renameSync(tempPath, filePath);

  if (process.platform !== 'win32') {
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Best-effort permission tightening
    }
  }
}

/**
 * Deletes the local license token file, effectively reverting to the free tier.
 */
export function deleteLicenseFile(filePath: string = getDefaultLicensePath()): boolean {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
