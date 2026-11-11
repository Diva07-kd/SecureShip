/**
 * Safe Tar Handling & Extraction (Clean-Room, Zero-Dependency).
 * Implements strict security guards against:
 * - Zip-slip / path traversal (relative .., absolute paths, drive letters)
 * - Symlinks, hardlinks, character/block devices
 * - Tar-bombs (file count limit, file size limit, total uncompressed limit)
 * - SRI integrity verification (sha512 / sha1)
 */

import crypto from 'node:crypto';
import path from 'node:path';

export interface SafeTarOptions {
  maxFileSize?: number; // default 2 MiB
  maxTotalSize?: number; // default 100 MiB
  maxFileCount?: number; // default 20,000
}

export interface ExtractedFile {
  name: string;
  data: Uint8Array;
  size: number;
}

export interface SafeTarResult {
  ok: boolean;
  files: ExtractedFile[];
  diagnostics: string[];
  error?: string;
}

export class SafeTarExtractor {
  public static readonly DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MiB
  public static readonly DEFAULT_MAX_TOTAL_SIZE = 100 * 1024 * 1024; // 100 MiB
  public static readonly DEFAULT_MAX_FILE_COUNT = 20_000;

  /**
   * Verifies tarball integrity against SRI string (e.g. "sha512-..." or "sha1-...").
   */
  public static verifySri(tarBytes: Uint8Array, expectedSri: string): boolean {
    if (!expectedSri) return true;

    const parts = expectedSri.trim().split('-');
    if (parts.length !== 2) return false;

    const algo = parts[0]?.toLowerCase();
    const expectedBase64 = parts[1];

    if (!algo || !expectedBase64) return false;
    if (algo !== 'sha512' && algo !== 'sha1' && algo !== 'sha256' && algo !== 'sha384') {
      return false;
    }

    const hash = crypto.createHash(algo).update(tarBytes).digest('base64');
    return hash === expectedBase64;
  }

  /**
   * Parse and extract files from uncompressed tar bytes safely.
   */
  public static extract(tarBytes: Uint8Array, options: SafeTarOptions = {}): SafeTarResult {
    const maxFileSize = options.maxFileSize ?? this.DEFAULT_MAX_FILE_SIZE;
    const maxTotalSize = options.maxTotalSize ?? this.DEFAULT_MAX_TOTAL_SIZE;
    const maxFileCount = options.maxFileCount ?? this.DEFAULT_MAX_FILE_COUNT;

    const files: ExtractedFile[] = [];
    const diagnostics: string[] = [];

    let totalBytes = 0;
    let offset = 0;
    const len = tarBytes.length;

    while (offset + 512 <= len) {
      const header = tarBytes.subarray(offset, offset + 512);

      // Check for two consecutive empty 512-byte blocks indicating end of archive
      let isEmpty = true;
      for (let i = 0; i < 512; i++) {
        if (header[i] !== 0) {
          isEmpty = false;
          break;
        }
      }

      if (isEmpty) {
        break; // End of archive
      }

      // Read filename (bytes 0..100)
      let rawName = '';
      for (let i = 0; i < 100; i++) {
        if (header[i] === 0) break;
        rawName += String.fromCharCode(header[i]!);
      }

      // Read prefix (bytes 345..500) for ustar
      let prefix = '';
      for (let i = 345; i < 500; i++) {
        if (header[i] === 0) break;
        prefix += String.fromCharCode(header[i]!);
      }

      const fullRawName = prefix ? `${prefix}/${rawName}` : rawName;

      // Read file size (bytes 124..136, octal ASCII)
      let sizeStr = '';
      for (let i = 124; i < 136; i++) {
        const byte = header[i]!;
        if (byte === 0 || byte === 32) continue; // skip null and space
        sizeStr += String.fromCharCode(byte);
      }
      const fileSize = parseInt(sizeStr || '0', 8);

      // Type flag (byte 156)
      const typeFlag = String.fromCharCode(header[156] || 0);

      offset += 512;

      // Check for path traversal / slip and Windows reserved device names
      const normalizedPath = path.normalize(fullRawName).replace(/\\/g, '/');
      const WINDOWS_RESERVED_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;
      const hasReservedName = normalizedPath
        .split('/')
        .some((segment) => WINDOWS_RESERVED_NAMES.test(segment));

      const isPathTraversal =
        normalizedPath.startsWith('..') ||
        normalizedPath.includes('/../') ||
        normalizedPath.startsWith('/') ||
        /^[a-zA-Z]:/.test(fullRawName) ||
        hasReservedName;

      if (isPathTraversal) {
        diagnostics.push(`Rejected path traversal entry in tarball: ${fullRawName}`);
        // Advance offset past file data blocks
        const dataBlocks = Math.ceil(fileSize / 512);
        offset += dataBlocks * 512;
        continue;
      }

      // Check typeflag: '1' hardlink, '2' symlink, '3'/'4' device
      if (typeFlag === '1' || typeFlag === '2') {
        diagnostics.push(`Rejected symlink/hardlink in tarball: ${fullRawName}`);
        const dataBlocks = Math.ceil(fileSize / 512);
        offset += dataBlocks * 512;
        continue;
      }

      if (typeFlag === '3' || typeFlag === '4') {
        diagnostics.push(`Rejected device node in tarball: ${fullRawName}`);
        const dataBlocks = Math.ceil(fileSize / 512);
        offset += dataBlocks * 512;
        continue;
      }

      // '5' is directory
      if (typeFlag === '5' || fullRawName.endsWith('/')) {
        continue;
      }

      // Resource caps (Tar-bomb guards)
      if (fileSize > maxFileSize) {
        return {
          ok: false,
          files: [],
          diagnostics,
          error: `File size limit exceeded in tarball: ${fullRawName} (${fileSize} bytes > ${maxFileSize} limit)`,
        };
      }

      totalBytes += fileSize;
      if (totalBytes > maxTotalSize) {
        return {
          ok: false,
          files: [],
          diagnostics,
          error: `Total uncompressed size limit exceeded: ${totalBytes} bytes > ${maxTotalSize} limit`,
        };
      }

      if (files.length + 1 > maxFileCount) {
        return {
          ok: false,
          files: [],
          diagnostics,
          error: `File count limit exceeded: > ${maxFileCount} files in archive`,
        };
      }

      // Read file content
      if (offset + fileSize > len) {
        diagnostics.push(`Truncated file in tarball: ${fullRawName}`);
        break;
      }

      const fileData = tarBytes.subarray(offset, offset + fileSize);
      const dataBlocks = Math.ceil(fileSize / 512);
      offset += dataBlocks * 512;

      // Strip standard npm 'package/' prefix if present
      const cleanName = normalizedPath.startsWith('package/')
        ? normalizedPath.slice('package/'.length)
        : normalizedPath;

      files.push({
        name: cleanName,
        data: fileData,
        size: fileSize,
      });
    }

    return {
      ok: true,
      files,
      diagnostics,
    };
  }
}
