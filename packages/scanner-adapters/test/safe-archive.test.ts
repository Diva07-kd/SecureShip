import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import zlib from 'node:zlib';
import { SafeArchiveExtractor } from '../src/safe-archive.js';

function createTarGzArchive(
  entries: Array<{ name: string; content: string | Buffer; typeflag?: string }>
): Buffer {
  const blocks: Buffer[] = [];

  for (const entry of entries) {
    const header = Buffer.alloc(512);
    const content = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content);

    header.write(entry.name, 0);
    header.write('0000755\0', 100);
    header.write(content.length.toString(8).padStart(11, '0') + ' ', 124);
    header.write(entry.typeflag ?? '0', 156);
    header.write('ustar\0', 257);

    // Calculate checksum
    header.fill(32, 148, 156);
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += header[i]!;
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);

    blocks.push(header);
    blocks.push(content);
    const pad = (512 - (content.length % 512)) % 512;
    if (pad > 0) {
      blocks.push(Buffer.alloc(pad));
    }
  }

  // End of archive: two empty blocks
  blocks.push(Buffer.alloc(1024));
  const tar = Buffer.concat(blocks);
  return zlib.gzipSync(tar);
}

function createZipArchive(
  entries: Array<{ name: string; content: string | Buffer; method?: number }>
): Buffer {
  const parts: Buffer[] = [];

  for (const entry of entries) {
    const rawContent = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content);
    const method = entry.method ?? 0;
    let compressedData = rawContent;
    if (method === 8) {
      compressedData = zlib.deflateRawSync(rawContent);
    }

    const nameBuf = Buffer.from(entry.name, 'utf8');
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0); // Local header signature
    header.writeUInt16LE(20, 4); // Version needed
    header.writeUInt16LE(0, 6); // Flags
    header.writeUInt16LE(method, 8); // Compression method
    header.writeUInt16LE(0, 10); // Mod time
    header.writeUInt16LE(0, 12); // Mod date
    header.writeUInt32LE(0, 14); // CRC32 (dummy)
    header.writeUInt32LE(compressedData.length, 18); // Compressed size
    header.writeUInt32LE(rawContent.length, 22); // Uncompressed size
    header.writeUInt16LE(nameBuf.length, 26); // Name len
    header.writeUInt16LE(0, 28); // Extra len

    parts.push(header);
    parts.push(nameBuf);
    parts.push(compressedData);
  }

  return Buffer.concat(parts);
}

describe('SafeArchiveExtractor Suite (Phase C)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-archive-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Best effort
      }
    }
  });

  it('safely extracts regular binary entry from tar.gz archive', async () => {
    const tarGzBuf = createTarGzArchive([
      { name: 'trivy', content: 'mock-trivy-binary-bytes' },
      { name: 'README.md', content: 'documentation' },
    ]);
    const archivePath = path.join(tempDir, 'trivy.tar.gz');
    fs.writeFileSync(archivePath, tarGzBuf);

    const destBin = path.join(tempDir, 'trivy-bin');
    await SafeArchiveExtractor.extractTarGzEntry(archivePath, 'trivy', destBin);

    expect(fs.existsSync(destBin)).toBe(true);
    expect(fs.readFileSync(destBin, 'utf8')).toBe('mock-trivy-binary-bytes');
  });

  it('rejects tar entry containing directory traversal sequences', async () => {
    const tarGzBuf = createTarGzArchive([{ name: '../escape.exe', content: 'malicious' }]);
    const archivePath = path.join(tempDir, 'slip.tar.gz');
    fs.writeFileSync(archivePath, tarGzBuf);

    const destBin = path.join(tempDir, 'out.bin');
    await expect(
      SafeArchiveExtractor.extractTarGzEntry(archivePath, 'escape.exe', destBin)
    ).rejects.toThrow(/prohibited traversal sequences/);
  });

  it('rejects tar entry starting with absolute path', async () => {
    const tarGzBuf = createTarGzArchive([{ name: '/etc/passwd', content: 'root:x:0:0' }]);
    const archivePath = path.join(tempDir, 'abs.tar.gz');
    fs.writeFileSync(archivePath, tarGzBuf);

    const destBin = path.join(tempDir, 'out.bin');
    await expect(
      SafeArchiveExtractor.extractTarGzEntry(archivePath, 'passwd', destBin)
    ).rejects.toThrow(/prohibited traversal sequences/);
  });

  it('rejects symlink and hardlink entries in tar.gz', async () => {
    const symlinkTar = createTarGzArchive([
      { name: 'link-tool', content: 'target', typeflag: '2' },
    ]);
    const linkPath = path.join(tempDir, 'symlink.tar.gz');
    fs.writeFileSync(linkPath, symlinkTar);

    await expect(
      SafeArchiveExtractor.extractTarGzEntry(linkPath, 'link-tool', path.join(tempDir, 'out'))
    ).rejects.toThrow(/Symlink entry .* is prohibited/);

    const hardlinkTar = createTarGzArchive([
      { name: 'hard-tool', content: 'target', typeflag: '1' },
    ]);
    const hardPath = path.join(tempDir, 'hardlink.tar.gz');
    fs.writeFileSync(hardPath, hardlinkTar);

    await expect(
      SafeArchiveExtractor.extractTarGzEntry(hardPath, 'hard-tool', path.join(tempDir, 'out'))
    ).rejects.toThrow(/Hardlink entry .* is prohibited/);
  });

  it('rejects device and FIFO entries in tar.gz', async () => {
    const devTar = createTarGzArchive([{ name: 'dev-tool', content: '', typeflag: '3' }]);
    const devPath = path.join(tempDir, 'dev.tar.gz');
    fs.writeFileSync(devPath, devTar);

    await expect(
      SafeArchiveExtractor.extractTarGzEntry(devPath, 'dev-tool', path.join(tempDir, 'out'))
    ).rejects.toThrow(/Device\/FIFO entry .* is prohibited/);
  });

  it('handles ustar prefix for long paths and skips directory entries', async () => {
    const header = Buffer.alloc(512);
    header.write('tool.exe', 0);
    header.write('0000755\0', 100);
    header.write((10).toString(8).padStart(11, '0') + ' ', 124);
    header.write('0', 156);
    header.write('ustar\0', 257);
    header.write('sub/path/dir', 345);

    // Checksum
    header.fill(32, 148, 156);
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += header[i]!;
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);

    const content = Buffer.from('0123456789');
    const pad = Buffer.alloc(512 - 10);
    const end = Buffer.alloc(1024);
    const tarBuf = zlib.gzipSync(Buffer.concat([header, content, pad, end]));

    const archivePath = path.join(tempDir, 'prefix.tar.gz');
    fs.writeFileSync(archivePath, tarBuf);

    const dest = path.join(tempDir, 'prefix-out.exe');
    await SafeArchiveExtractor.extractTarGzEntry(archivePath, 'tool.exe', dest);
    expect(fs.existsSync(dest)).toBe(true);
    expect(fs.readFileSync(dest, 'utf8')).toBe('0123456789');
  });

  it('enforces maximum entry count in tar.gz', async () => {
    const tarGzBuf = createTarGzArchive([
      { name: 'file1', content: 'c1' },
      { name: 'file2', content: 'c2' },
      { name: 'file3', content: 'c3' },
    ]);
    const archivePath = path.join(tempDir, 'max-entries.tar.gz');
    fs.writeFileSync(archivePath, tarGzBuf);

    await expect(
      SafeArchiveExtractor.extractTarGzEntry(archivePath, 'file3', path.join(tempDir, 'out'), {
        maxEntryCount: 2,
      })
    ).rejects.toThrow(/Archive exceeds maximum entry count limit/);
  });

  it('throws error when gzip decompression fails', async () => {
    const invalidPath = path.join(tempDir, 'not-a-tar.gz');
    fs.writeFileSync(invalidPath, Buffer.from('random-non-gzip-bytes'));

    await expect(
      SafeArchiveExtractor.extractTarGzEntry(invalidPath, 'any', path.join(tempDir, 'out'))
    ).rejects.toThrow(/Failed to decompress tar.gz archive/);
  });

  it('throws error when requested entry is missing in tar.gz', async () => {
    const tarGzBuf = createTarGzArchive([{ name: 'other-file.txt', content: 'some-content' }]);
    const archivePath = path.join(tempDir, 'missing.tar.gz');
    fs.writeFileSync(archivePath, tarGzBuf);

    await expect(
      SafeArchiveExtractor.extractTarGzEntry(
        archivePath,
        'expected-binary',
        path.join(tempDir, 'out')
      )
    ).rejects.toThrow(/Binary entry 'expected-binary' not found in tar.gz archive/);
  });

  it('safely extracts deflated entry from zip archive', async () => {
    const zipBuf = createZipArchive([
      { name: 'gitleaks.exe', content: 'mock-gitleaks-content', method: 8 },
    ]);
    const zipPath = path.join(tempDir, 'gitleaks.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const destBin = path.join(tempDir, 'gitleaks.exe');
    await SafeArchiveExtractor.extractZipEntry(zipPath, 'gitleaks.exe', destBin);

    expect(fs.existsSync(destBin)).toBe(true);
    expect(fs.readFileSync(destBin, 'utf8')).toBe('mock-gitleaks-content');
  });

  it('safely extracts stored (uncompressed) entry from zip archive', async () => {
    const zipBuf = createZipArchive([
      { name: 'osv-scanner.exe', content: 'stored-uncompressed-bytes', method: 0 },
    ]);
    const zipPath = path.join(tempDir, 'osv.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const destBin = path.join(tempDir, 'osv-scanner.exe');
    await SafeArchiveExtractor.extractZipEntry(zipPath, 'osv-scanner.exe', destBin);

    expect(fs.existsSync(destBin)).toBe(true);
    expect(fs.readFileSync(destBin, 'utf8')).toBe('stored-uncompressed-bytes');
  });

  it('rejects zip entry exceeding maximum decompressed bytes', async () => {
    const zipBuf = createZipArchive([
      { name: 'bomb.exe', content: 'long-string-that-exceeds-small-limit', method: 0 },
    ]);
    const zipPath = path.join(tempDir, 'bomb.zip');
    fs.writeFileSync(zipPath, zipBuf);

    await expect(
      SafeArchiveExtractor.extractZipEntry(zipPath, 'bomb.exe', path.join(tempDir, 'out'), {
        maxDecompressedBytes: 10,
      })
    ).rejects.toThrow(/exceeds maximum decompressed size limit/);
  });

  it('enforces maximum entry count in zip', async () => {
    const zipBuf = createZipArchive([
      { name: 'e1.exe', content: 'c1' },
      { name: 'e2.exe', content: 'c2' },
      { name: 'e3.exe', content: 'c3' },
    ]);
    const zipPath = path.join(tempDir, 'entries.zip');
    fs.writeFileSync(zipPath, zipBuf);

    await expect(
      SafeArchiveExtractor.extractZipEntry(zipPath, 'e3.exe', path.join(tempDir, 'out'), {
        maxEntryCount: 2,
      })
    ).rejects.toThrow(/Zip archive exceeds maximum entry count limit/);
  });

  it('rejects unsupported zip compression methods', async () => {
    const zipBuf = createZipArchive([
      { name: 'bzip.exe', content: 'content', method: 12 }, // BZIP2 method
    ]);
    const zipPath = path.join(tempDir, 'unsupported.zip');
    fs.writeFileSync(zipPath, zipBuf);

    await expect(
      SafeArchiveExtractor.extractZipEntry(zipPath, 'bzip.exe', path.join(tempDir, 'out'))
    ).rejects.toThrow(/Unsupported zip compression method/);
  });

  it('throws when requested entry is missing in zip', async () => {
    const zipBuf = createZipArchive([{ name: 'other.exe', content: 'content' }]);
    const zipPath = path.join(tempDir, 'missing.zip');
    fs.writeFileSync(zipPath, zipBuf);

    await expect(
      SafeArchiveExtractor.extractZipEntry(zipPath, 'wanted.exe', path.join(tempDir, 'out'))
    ).rejects.toThrow(/Binary entry 'wanted.exe' not found in zip archive/);
  });

  it('rejects zip entry containing directory traversal sequences', async () => {
    const zipBuf = createZipArchive([{ name: '../../etc/cron', content: 'evil', method: 0 }]);
    const zipPath = path.join(tempDir, 'slip.zip');
    fs.writeFileSync(zipPath, zipBuf);

    await expect(
      SafeArchiveExtractor.extractZipEntry(zipPath, 'cron', path.join(tempDir, 'out'))
    ).rejects.toThrow(/prohibited traversal sequences/);
  });
});
