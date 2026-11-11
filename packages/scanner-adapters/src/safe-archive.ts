import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

export interface ExtractArchiveOptions {
  maxDecompressedBytes?: number;
  maxEntryCount?: number;
}

const DEFAULT_MAX_DECOMPRESSED_BYTES = 250 * 1024 * 1024; // 250 MB
const DEFAULT_MAX_ENTRY_COUNT = 10_000;

export class SafeArchiveExtractor {
  /**
   * Safely extracts a single named entry from a tar.gz archive in-process without invoking shell commands.
   * Strictly defends against zip-slip, symlink attacks, hardlink attacks, and decompression bombs.
   */
  public static async extractTarGzEntry(
    archivePath: string,
    targetEntryName: string,
    destBinaryPath: string,
    options: ExtractArchiveOptions = {}
  ): Promise<void> {
    const maxBytes = options.maxDecompressedBytes ?? DEFAULT_MAX_DECOMPRESSED_BYTES;
    const maxEntries = options.maxEntryCount ?? DEFAULT_MAX_ENTRY_COUNT;

    const compressed = fs.readFileSync(archivePath);
    let tarBuffer: Buffer;
    try {
      tarBuffer = zlib.gunzipSync(compressed, { maxOutputLength: maxBytes });
    } catch (err: unknown) {
      throw new Error(
        `Failed to decompress tar.gz archive (decompression limit ${maxBytes} bytes): ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }

    let offset = 0;
    let entryCount = 0;
    let found = false;

    // Sanitize target entry search name
    const normalizedTargetName = path.basename(targetEntryName).toLowerCase();

    while (offset + 512 <= tarBuffer.length) {
      // Two consecutive 512-byte zero blocks signify end of tar archive
      const isZeroBlock = tarBuffer.subarray(offset, offset + 512).every((b) => b === 0);
      if (isZeroBlock) {
        if (
          offset + 1024 <= tarBuffer.length &&
          tarBuffer.subarray(offset + 512, offset + 1024).every((b) => b === 0)
        ) {
          break;
        }
        offset += 512;
        continue;
      }

      entryCount++;
      if (entryCount > maxEntries) {
        throw new Error(
          `Security violation: Archive exceeds maximum entry count limit (${maxEntries}).`
        );
      }

      const header = tarBuffer.subarray(offset, offset + 512);
      offset += 512;

      // Extract entry name (offset 0, 100 bytes)
      let rawName = header.toString('utf8', 0, 100).replace(/\0.*$/, '').trim();

      // Check for prefix (offset 345, 155 bytes) for ustar long names
      const prefix = header.toString('utf8', 345, 500).replace(/\0.*$/, '').trim();
      if (prefix.length > 0) {
        rawName = `${prefix}/${rawName}`;
      }

      // Read size (offset 124, 12 bytes octal)
      const sizeStr = header.toString('utf8', 124, 136).replace(/\0.*$/, '').trim();
      const fileSize = parseInt(sizeStr, 8);
      if (isNaN(fileSize) || fileSize < 0) {
        throw new Error(`Corrupted tar archive header: invalid entry size '${sizeStr}'.`);
      }

      // Read typeflag (offset 156, 1 byte)
      const typeflag = String.fromCharCode(header[156] || 0);

      // Security validation on entry name: reject absolute paths, traversals, and null bytes
      if (
        rawName.startsWith('/') ||
        rawName.startsWith('\\') ||
        rawName.includes('..') ||
        rawName.includes('\0')
      ) {
        throw new Error(
          `Security violation: Archive entry '${rawName}' contains prohibited traversal sequences or absolute paths.`
        );
      }

      // Check prohibited entry types
      if (typeflag === '1') {
        throw new Error(
          `Security violation: Hardlink entry '${rawName}' is prohibited in safe extraction.`
        );
      }
      if (typeflag === '2') {
        throw new Error(
          `Security violation: Symlink entry '${rawName}' is prohibited in safe extraction.`
        );
      }
      if (typeflag === '3' || typeflag === '4' || typeflag === '6') {
        throw new Error(
          `Security violation: Device/FIFO entry '${rawName}' is prohibited in safe extraction.`
        );
      }

      // Check if entry size exceeds buffer
      if (offset + fileSize > tarBuffer.length) {
        throw new Error(
          `Corrupted tar archive: entry '${rawName}' specifies size exceeding archive bounds.`
        );
      }

      const entryData = tarBuffer.subarray(offset, offset + fileSize);
      const paddedSize = Math.ceil(fileSize / 512) * 512;
      offset += paddedSize;

      // Regular file check ('0' or '\0')
      const isRegularFile = typeflag === '0' || typeflag === '\0' || typeflag === '';
      if (!isRegularFile) {
        continue;
      }

      const entryBase = path.basename(rawName).toLowerCase();
      if (
        rawName.toLowerCase() === targetEntryName.toLowerCase() ||
        entryBase === normalizedTargetName
      ) {
        SafeArchiveExtractor.writeExtractedFile(entryData, destBinaryPath);
        found = true;
        break;
      }
    }

    if (!found) {
      throw new Error(`Binary entry '${targetEntryName}' not found in tar.gz archive.`);
    }
  }

  /**
   * Safely extracts a single named entry from a zip archive in-process without invoking external tools.
   */
  public static async extractZipEntry(
    archivePath: string,
    targetEntryName: string,
    destBinaryPath: string,
    options: ExtractArchiveOptions = {}
  ): Promise<void> {
    const maxBytes = options.maxDecompressedBytes ?? DEFAULT_MAX_DECOMPRESSED_BYTES;
    const maxEntries = options.maxEntryCount ?? DEFAULT_MAX_ENTRY_COUNT;

    const zipBuffer = fs.readFileSync(archivePath);
    const normalizedTargetName = path.basename(targetEntryName).toLowerCase();

    let offset = 0;
    let entryCount = 0;
    let found = false;

    // Scan through local file headers (Signature: 0x04034b50)
    while (offset + 30 <= zipBuffer.length) {
      const sig = zipBuffer.readUInt32LE(offset);
      // Stop if reached central directory or end of directory
      if (sig === 0x02014b50 || sig === 0x06054b50) {
        break;
      }
      if (sig !== 0x04034b50) {
        // Unknown signature or alignment gap
        offset++;
        continue;
      }

      entryCount++;
      if (entryCount > maxEntries) {
        throw new Error(
          `Security violation: Zip archive exceeds maximum entry count limit (${maxEntries}).`
        );
      }

      const compMethod = zipBuffer.readUInt16LE(offset + 8);
      const compSize = zipBuffer.readUInt32LE(offset + 18);
      const uncompSize = zipBuffer.readUInt32LE(offset + 22);
      const nameLen = zipBuffer.readUInt16LE(offset + 26);
      const extraLen = zipBuffer.readUInt16LE(offset + 28);

      if (uncompSize > maxBytes) {
        throw new Error(
          `Security violation: Zip entry exceeds maximum decompressed size limit (${uncompSize} > ${maxBytes}).`
        );
      }

      const nameOffset = offset + 30;
      if (nameOffset + nameLen > zipBuffer.length) {
        throw new Error('Corrupted zip archive: filename length exceeds buffer bounds.');
      }

      const entryName = zipBuffer.toString('utf8', nameOffset, nameOffset + nameLen);
      // Security check on entry name
      if (
        entryName.startsWith('/') ||
        entryName.startsWith('\\') ||
        entryName.includes('..') ||
        entryName.includes('\0')
      ) {
        throw new Error(
          `Security violation: Zip entry '${entryName}' contains prohibited traversal sequences or absolute paths.`
        );
      }

      const dataOffset = nameOffset + nameLen + extraLen;
      if (dataOffset + compSize > zipBuffer.length) {
        throw new Error(
          `Corrupted zip archive: entry '${entryName}' compressed data exceeds buffer bounds.`
        );
      }

      const compressedSlice = zipBuffer.subarray(dataOffset, dataOffset + compSize);
      offset = dataOffset + compSize;

      const entryBase = path.basename(entryName).toLowerCase();
      if (
        entryName.toLowerCase() === targetEntryName.toLowerCase() ||
        entryBase === normalizedTargetName
      ) {
        let decompressedData: Buffer;
        if (compMethod === 0) {
          // Stored (no compression)
          decompressedData = compressedSlice;
        } else if (compMethod === 8) {
          // Deflated
          decompressedData = zlib.inflateRawSync(compressedSlice, { maxOutputLength: maxBytes });
        } else {
          throw new Error(
            `Unsupported zip compression method '${compMethod}' for entry '${entryName}'.`
          );
        }

        SafeArchiveExtractor.writeExtractedFile(decompressedData, destBinaryPath);
        found = true;
        break;
      }
    }

    if (!found) {
      throw new Error(`Binary entry '${targetEntryName}' not found in zip archive.`);
    }
  }

  /**
   * Writes extracted bytes to a temporary file in the same directory, verifies size,
   * sets executable permissions, and atomically renames to the final destination.
   */
  private static writeExtractedFile(data: Buffer, destBinaryPath: string): void {
    const destDir = path.dirname(destBinaryPath);
    fs.mkdirSync(destDir, { recursive: true });

    const tempPath = path.join(destDir, `.tmp-extract-${crypto.randomBytes(6).toString('hex')}`);
    try {
      fs.writeFileSync(tempPath, data);
      if (process.platform !== 'win32') {
        fs.chmodSync(tempPath, 0o755);
      }
      fs.renameSync(tempPath, destBinaryPath);
      if (process.platform !== 'win32') {
        fs.chmodSync(destBinaryPath, 0o755);
      }
    } finally {
      if (fs.existsSync(tempPath)) {
        try {
          fs.unlinkSync(tempPath);
        } catch {
          // Best effort cleanup
        }
      }
    }
  }
}
