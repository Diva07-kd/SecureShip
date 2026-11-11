import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

export interface TarEntryMeta {
  path: string;
  size: number;
  sha256: string;
  mode: number;
}

const FIXED_MTIME_OCTAL = '00000000000 '; // Fixed deterministic timestamp
const DEFAULT_MAX_DECOMPRESSED_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB
const DEFAULT_MAX_ENTRY_COUNT = 50_000;

/**
 * Creates a standard 512-byte ustar header block.
 */
function createHeaderBlock(
  name: string,
  size: number,
  mode: number,
  typeflag: string = '0'
): Buffer {
  const header = Buffer.alloc(512);

  // Split name if > 100 bytes into prefix and name if possible, or truncate (PAX handles long names)
  const nameBuf = Buffer.from(name, 'utf8');
  if (nameBuf.length <= 100) {
    nameBuf.copy(header, 0);
  } else {
    nameBuf.subarray(nameBuf.length - 100).copy(header, 0);
  }

  // Mode (offset 100, 8 bytes)
  const modeStr = (mode & 0o7777).toString(8).padStart(7, '0') + '\0';
  header.write(modeStr, 100, 8, 'ascii');

  // UID & GID (offset 108 & 116, 8 bytes each)
  header.write('0000000\0', 108, 8, 'ascii');
  header.write('0000000\0', 116, 8, 'ascii');

  // Size (offset 124, 12 bytes octal)
  const sizeStr = size.toString(8).padStart(11, '0') + ' ';
  header.write(sizeStr, 124, 12, 'ascii');

  // MTime (offset 136, 12 bytes)
  header.write(FIXED_MTIME_OCTAL, 136, 12, 'ascii');

  // Typeflag (offset 156, 1 byte)
  header.write(typeflag, 156, 1, 'ascii');

  // Magic & Version (offset 257, 8 bytes)
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');

  // Uname & Gname (offset 265 & 297, 32 bytes each)
  header.write('secureship\0', 265, 32, 'ascii');
  header.write('secureship\0', 297, 32, 'ascii');

  // Calculate checksum (offset 148, 8 bytes)
  header.fill(32, 148, 156);
  let sum = 0;
  for (let i = 0; i < 512; i++) {
    sum += header[i]!;
  }
  const checksumStr = sum.toString(8).padStart(6, '0') + '\0 ';
  header.write(checksumStr, 148, 8, 'ascii');

  return header;
}

/**
 * Creates a PAX extended header block for entries with paths longer than 100 characters.
 */
function createPaxHeader(realPath: string): { paxHeader: Buffer; paxData: Buffer } {
  // PAX format: "<length> path=<path>\n"
  const payloadStr = `path=${realPath}\n`;
  let totalLen = payloadStr.length + 3; // Initial estimate
  let lenStr = String(totalLen);
  while (`${lenStr} ${payloadStr}`.length !== totalLen) {
    totalLen = `${lenStr} ${payloadStr}`.length;
    lenStr = String(totalLen);
  }
  const paxData = Buffer.from(`${totalLen} ${payloadStr}`, 'utf8');
  const paxHeader = createHeaderBlock('PaxHeader', paxData.length, 0o644, 'x');
  return { paxHeader, paxData };
}

/**
 * Deterministic, streaming ustar/pax tar.gz writer with zero external dependencies.
 */
export class DeterministicTarWriter {
  private readonly gzipStream: zlib.Gzip;
  private readonly outStream: fs.WriteStream;
  private isFinalized = false;

  constructor(outFilePath: string) {
    this.gzipStream = zlib.createGzip({ level: 6 });
    this.outStream = fs.createWriteStream(outFilePath);
    this.gzipStream.pipe(this.outStream);
  }

  /**
   * Adds an in-memory buffer entry to the tar archive.
   */
  public addBufferEntry(rawEntryPath: string, content: Buffer, mode: number = 0o644): TarEntryMeta {
    if (this.isFinalized) throw new Error('Cannot add entries to finalized archive.');

    // Normalize entry path to POSIX relative forward slashes
    const entryPath = rawEntryPath.replace(/\\/g, '/').replace(/^\/+/, '');
    const hash = crypto.createHash('sha256').update(content).digest('hex');

    // If path > 100 chars, write PAX header
    if (Buffer.byteLength(entryPath, 'utf8') > 100) {
      const { paxHeader, paxData } = createPaxHeader(entryPath);
      this.gzipStream.write(paxHeader);
      this.gzipStream.write(paxData);
      const paxPad = (512 - (paxData.length % 512)) % 512;
      if (paxPad > 0) this.gzipStream.write(Buffer.alloc(paxPad));
    }

    const header = createHeaderBlock(entryPath, content.length, mode, '0');
    this.gzipStream.write(header);
    this.gzipStream.write(content);

    const pad = (512 - (content.length % 512)) % 512;
    if (pad > 0) {
      this.gzipStream.write(Buffer.alloc(pad));
    }

    return {
      path: entryPath,
      size: content.length,
      sha256: hash,
      mode,
    };
  }

  /**
   * Streams a file from disk into the tar archive without loading the full file into memory.
   */
  public async addFileEntry(
    rawEntryPath: string,
    sourceFilePath: string,
    mode: number = 0o644
  ): Promise<TarEntryMeta> {
    if (this.isFinalized) throw new Error('Cannot add entries to finalized archive.');

    const stat = fs.statSync(sourceFilePath);
    const entryPath = rawEntryPath.replace(/\\/g, '/').replace(/^\/+/, '');
    const fileSize = stat.size;

    // Write PAX header if long path
    if (Buffer.byteLength(entryPath, 'utf8') > 100) {
      const { paxHeader, paxData } = createPaxHeader(entryPath);
      this.gzipStream.write(paxHeader);
      this.gzipStream.write(paxData);
      const paxPad = (512 - (paxData.length % 512)) % 512;
      if (paxPad > 0) this.gzipStream.write(Buffer.alloc(paxPad));
    }

    const header = createHeaderBlock(entryPath, fileSize, mode, '0');
    this.gzipStream.write(header);

    // Stream file while computing SHA-256
    const hash = crypto.createHash('sha256');
    await new Promise<void>((resolve, reject) => {
      const readStream = fs.createReadStream(sourceFilePath);
      readStream.on('data', (chunk: Buffer | string) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        hash.update(buf);
        this.gzipStream.write(buf);
      });
      readStream.on('error', reject);
      readStream.on('end', () => resolve());
    });

    const pad = (512 - (fileSize % 512)) % 512;
    if (pad > 0) {
      this.gzipStream.write(Buffer.alloc(pad));
    }

    return {
      path: entryPath,
      size: fileSize,
      sha256: hash.digest('hex'),
      mode,
    };
  }

  /**
   * Finalizes the tar archive by appending two 512-byte zero blocks and closing streams.
   */
  public async finalize(): Promise<void> {
    if (this.isFinalized) return;
    this.isFinalized = true;

    // Standard tar trailer: two 512-byte zero blocks
    this.gzipStream.write(Buffer.alloc(1024));
    this.gzipStream.end();

    await new Promise<void>((resolve, reject) => {
      this.outStream.on('finish', resolve);
      this.outStream.on('error', reject);
    });
  }
}

export interface SafeTarReadOptions {
  maxDecompressedBytes?: number;
  maxEntryCount?: number;
}

class StreamChunkReader {
  private iterator: AsyncIterator<Buffer>;
  private buffer: Buffer = Buffer.alloc(0);
  public reachedEof = false;

  constructor(stream: NodeJS.ReadableStream) {
    this.iterator = (stream as AsyncIterable<Buffer>)[Symbol.asyncIterator]();
  }

  public async readExact(n: number): Promise<Buffer | null> {
    while (this.buffer.length < n) {
      const next = await this.iterator.next();
      if (next.done) {
        this.reachedEof = true;
        if (this.buffer.length === 0) return null;
        const remaining = this.buffer;
        this.buffer = Buffer.alloc(0);
        return remaining;
      }
      this.buffer = Buffer.concat([this.buffer, next.value]);
    }
    const out = this.buffer.subarray(0, n);
    this.buffer = this.buffer.subarray(n);
    return out;
  }

  public async pipeToFile(
    targetFilePath: string,
    bytesToRead: number,
    hasher: crypto.Hash
  ): Promise<void> {
    const ws = fs.createWriteStream(targetFilePath);
    let streamErr: Error | null = null;
    ws.on('error', (err) => {
      streamErr = err;
    });
    let remaining = bytesToRead;
    try {
      while (remaining > 0) {
        if (streamErr) throw streamErr;
        if (this.buffer.length > 0) {
          const take = Math.min(this.buffer.length, remaining);
          const chunk = this.buffer.subarray(0, take);
          this.buffer = this.buffer.subarray(take);
          ws.write(chunk);
          hasher.update(chunk);
          remaining -= take;
          continue;
        }
        const next = await this.iterator.next();
        if (next.done) {
          throw new Error('Unexpected EOF in tar stream while reading entry content.');
        }
        const chunk = next.value;
        if (chunk.length <= remaining) {
          ws.write(chunk);
          hasher.update(chunk);
          remaining -= chunk.length;
        } else {
          const take = chunk.subarray(0, remaining);
          ws.write(take);
          hasher.update(take);
          this.buffer = chunk.subarray(remaining);
          remaining = 0;
        }
      }
    } finally {
      await new Promise<void>((resolve, reject) => {
        if (streamErr) {
          ws.destroy();
          return reject(streamErr);
        }
        ws.end((err?: Error | null) => (err || streamErr ? reject(err || streamErr) : resolve()));
      });
    }
  }

  public async skipBytes(n: number): Promise<void> {
    let remaining = n;
    while (remaining > 0) {
      if (this.buffer.length >= remaining) {
        this.buffer = this.buffer.subarray(remaining);
        remaining = 0;
      } else {
        remaining -= this.buffer.length;
        this.buffer = Buffer.alloc(0);
        const next = await this.iterator.next();
        if (next.done) {
          this.reachedEof = true;
          break;
        }
        this.buffer = next.value;
      }
    }
  }
}

/**
 * Pure in-process safe streaming tar.gz extractor with strict defenses against:
 * zip slips, directory traversals, symlink escapes, hardlinks, device files, case collisions,
 * Windows reserved names, and decompression bombs. Constant O(1) memory consumption.
 */
export class SafeTarReader {
  /**
   * Extracts all entries from a tar.gz archive into a destination directory while computing SHA-256 hashes.
   */
  public static async extractAll(
    tarGzPath: string,
    destDir: string,
    options: SafeTarReadOptions = {}
  ): Promise<TarEntryMeta[]> {
    const maxBytes = options.maxDecompressedBytes ?? DEFAULT_MAX_DECOMPRESSED_BYTES;
    const maxEntries = options.maxEntryCount ?? DEFAULT_MAX_ENTRY_COUNT;

    fs.mkdirSync(destDir, { recursive: true });

    let entryCount = 0;
    let totalDecompressedBytes = 0;
    let pendingPaxPath: string | null = null;
    const extractedEntries: TarEntryMeta[] = [];
    const seenPathsLower = new Set<string>();

    const readStream = fs.createReadStream(tarGzPath);
    const gunzip = zlib.createGunzip();
    readStream.pipe(gunzip);

    const chunkReader = new StreamChunkReader(gunzip);

    try {
      while (true) {
        const header = await chunkReader.readExact(512);
        if (!header || header.length < 512) {
          break;
        }

        totalDecompressedBytes += 512;
        if (totalDecompressedBytes > maxBytes) {
          throw new Error(
            `Security violation: Archive decompressed size exceeds maximum limit (${maxBytes} bytes).`
          );
        }

        const isZeroBlock = header.every((b) => b === 0);
        if (isZeroBlock) {
          const nextBlock = await chunkReader.readExact(512);
          if (!nextBlock || nextBlock.every((b) => b === 0)) {
            break; // Standard tar EOF: two consecutive zero blocks
          }
          // If second block was not zero, break as safe termination
          break;
        }

        entryCount++;
        if (entryCount > maxEntries) {
          throw new Error(
            `Security violation: Archive exceeds maximum entry count limit (${maxEntries}).`
          );
        }

        let entryName = header.toString('utf8', 0, 100).replace(/\0.*$/, '').trim();
        const prefix = header.toString('utf8', 345, 500).replace(/\0.*$/, '').trim();
        if (prefix.length > 0) {
          entryName = `${prefix}/${entryName}`;
        }

        const sizeStr = header.toString('utf8', 124, 136).replace(/\0.*$/, '').trim();
        const fileSize = parseInt(sizeStr, 8);
        if (isNaN(fileSize) || fileSize < 0) {
          throw new Error(`Corrupted tar header: invalid size '${sizeStr}'.`);
        }

        const modeStr = header.toString('utf8', 100, 108).replace(/\0.*$/, '').trim();
        const mode = parseInt(modeStr, 8) || 0o644;
        const typeflag = String.fromCharCode(header[156] || 0);

        // Handle PAX header
        if (typeflag === 'x') {
          totalDecompressedBytes += fileSize;
          if (totalDecompressedBytes > maxBytes) {
            throw new Error(
              `Security violation: Archive decompressed size exceeds limit (${maxBytes} bytes).`
            );
          }
          const paxData = await chunkReader.readExact(fileSize);
          if (!paxData || paxData.length < fileSize) {
            throw new Error('Corrupted tar archive: truncated PAX header.');
          }
          const paxStr = paxData.toString('utf8');
          const match = paxStr.match(/\d+ path=(.+)\n/);
          if (match && match[1]) {
            pendingPaxPath = match[1].trim();
          }
          const paddedPax = Math.ceil(fileSize / 512) * 512;
          await chunkReader.skipBytes(paddedPax - fileSize);
          continue;
        }

        if (pendingPaxPath) {
          entryName = pendingPaxPath;
          pendingPaxPath = null;
        }

        // Security validation on entry path: reject traversal, absolute, null bytes
        if (
          entryName.startsWith('/') ||
          entryName.startsWith('\\') ||
          entryName.includes('..') ||
          entryName.includes('\0') ||
          /^[a-zA-Z]:/.test(entryName)
        ) {
          throw new Error(
            `Security violation: Prohibited path traversal or absolute entry '${entryName}'.`
          );
        }

        // Prohibited characters on Windows filesystems
        if (process.platform === 'win32' && /[<>:"|?*\x00-\x1f]/.test(entryName)) {
          throw new Error(
            `Security violation: Prohibited character in archive entry '${entryName}'.`
          );
        }

        // Prohibited Windows reserved device names
        const segments = entryName.split(/[/\\]/);
        for (const seg of segments) {
          if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i.test(seg)) {
            throw new Error(
              `Security violation: Prohibited Windows reserved device name in entry '${entryName}'.`
            );
          }
        }

        // Case-collision & duplicate entry check
        const lowerName = entryName.toLowerCase();
        if (seenPathsLower.has(lowerName)) {
          throw new Error(
            `Security violation: Duplicate or case-collision entry '${entryName}' detected in archive.`
          );
        }
        seenPathsLower.add(lowerName);

        // Prohibited entry types (hardlinks, symlinks, device files)
        if (
          typeflag === '1' ||
          typeflag === '2' ||
          typeflag === '3' ||
          typeflag === '4' ||
          typeflag === '6'
        ) {
          throw new Error(
            `Security violation: Special/link entry '${entryName}' (typeflag '${typeflag}') is prohibited in offline bundles.`
          );
        }

        const paddedSize = Math.ceil(fileSize / 512) * 512;
        totalDecompressedBytes += fileSize;
        if (totalDecompressedBytes > maxBytes) {
          throw new Error(
            `Security violation: Archive decompressed size exceeds maximum limit (${maxBytes} bytes).`
          );
        }

        // Skip directory entries ('5')
        if (typeflag === '5') {
          await chunkReader.skipBytes(paddedSize);
          continue;
        }

        // Write file safely in streaming chunks
        const targetFilePath = path.join(destDir, entryName);
        const targetFileDir = path.dirname(targetFilePath);
        fs.mkdirSync(targetFileDir, { recursive: true });

        const hasher = crypto.createHash('sha256');
        await chunkReader.pipeToFile(targetFilePath, fileSize, hasher);
        await chunkReader.skipBytes(paddedSize - fileSize);

        if (process.platform !== 'win32' && (mode & 0o111) !== 0) {
          try {
            fs.chmodSync(targetFilePath, 0o755);
          } catch {}
        }

        extractedEntries.push({
          path: entryName.replace(/\\/g, '/'),
          size: fileSize,
          sha256: hasher.digest('hex'),
          mode,
        });
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.message.startsWith('Security violation')) {
        throw err;
      }
      throw new Error(
        `Failed to decompress tar.gz archive (decompression limit ${maxBytes} bytes): ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }

    return extractedEntries;
  }
}
