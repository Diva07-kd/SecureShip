import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import { DeterministicTarWriter, SafeTarReader } from '../src/offline/tar-bundle.js';

describe('TarBundle Suite (DeterministicTarWriter & SafeTarReader)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-tar-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  function makeHeader(opts: {
    name: string;
    size?: number;
    mode?: number;
    typeflag?: string;
    prefix?: string;
  }): Buffer {
    const h = Buffer.alloc(512);
    h.write(opts.name, 0, 100, 'utf8');
    const mode = opts.mode ?? 0o644;
    h.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'utf8');
    const size = opts.size ?? 0;
    h.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8');
    if (opts.typeflag) {
      h.write(opts.typeflag, 156, 1, 'utf8');
    }
    if (opts.prefix) {
      h.write(opts.prefix, 345, 155, 'utf8');
    }
    return h;
  }

  function createCustomTarGz(tarPath: string, blocks: (Buffer | string)[]): void {
    const bufs: Buffer[] = [];
    for (const b of blocks) {
      const payload = typeof b === 'string' ? Buffer.from(b, 'utf8') : b;
      bufs.push(payload);
      const remainder = payload.length % 512;
      if (remainder > 0) {
        bufs.push(Buffer.alloc(512 - remainder));
      }
    }
    // Tar trailer
    bufs.push(Buffer.alloc(1024));
    const rawTar = Buffer.concat(bufs);
    const gz = zlib.gzipSync(rawTar);
    fs.writeFileSync(tarPath, gz);
  }

  describe('DeterministicTarWriter & SafeTarReader roundtrip', () => {
    it('creates deterministic tar.gz and extracts with SafeTarReader', async () => {
      const tarPath = path.join(tempDir, 'sample.tar.gz');
      const writer = new DeterministicTarWriter(tarPath);

      writer.addBufferEntry('hello.txt', Buffer.from('hello world\n'), 0o644);
      writer.addBufferEntry('bin/run.sh', Buffer.from('#!/bin/sh\necho hi\n'), 0o755);

      // Long path that triggers PAX header
      const longPath = 'a'.repeat(60) + '/' + 'b'.repeat(60) + '/longfile.txt';
      writer.addBufferEntry(longPath, Buffer.from('long path content'));

      await writer.finalize();

      const extractDir = path.join(tempDir, 'extracted');
      const entries = await SafeTarReader.extractAll(tarPath, extractDir);

      expect(entries.length).toBe(3);
      expect(fs.readFileSync(path.join(extractDir, 'hello.txt'), 'utf8')).toBe('hello world\n');
      expect(fs.readFileSync(path.join(extractDir, 'bin/run.sh'), 'utf8')).toBe(
        '#!/bin/sh\necho hi\n'
      );
      expect(fs.readFileSync(path.join(extractDir, longPath), 'utf8')).toBe('long path content');
    });

    it('handles ustar prefix field correctly', async () => {
      const tarPath = path.join(tempDir, 'prefix.tar.gz');
      const content = Buffer.from('prefixed content');
      createCustomTarGz(tarPath, [
        makeHeader({ name: 'subfile.txt', size: content.length, prefix: 'my/prefix' }),
        content,
      ]);

      const extractDir = path.join(tempDir, 'extracted-prefix');
      const entries = await SafeTarReader.extractAll(tarPath, extractDir);

      expect(entries.length).toBe(1);
      expect(entries[0]!.path).toBe('my/prefix/subfile.txt');
      expect(fs.readFileSync(path.join(extractDir, 'my/prefix/subfile.txt'), 'utf8')).toBe(
        'prefixed content'
      );
    });

    it('skips directory typeflag 5 entries cleanly', async () => {
      const tarPath = path.join(tempDir, 'dir-entry.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: 'some-dir/', typeflag: '5' }),
        makeHeader({ name: 'some-dir/file.txt', size: 5 }),
        Buffer.from('hello'),
      ]);

      const extractDir = path.join(tempDir, 'extracted-dir');
      const entries = await SafeTarReader.extractAll(tarPath, extractDir);

      expect(entries.length).toBe(1);
      expect(entries[0]!.path).toBe('some-dir/file.txt');
    });
  });

  describe('Security defenses & error handling', () => {
    it('rejects relative directory traversal (..)', async () => {
      const tarPath = path.join(tempDir, 'slip.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: '../outside.txt', size: 5 }),
        Buffer.from('evil!'),
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
        /Security violation: Prohibited path traversal/
      );
    });

    it('rejects absolute unix path', async () => {
      const tarPath = path.join(tempDir, 'abs-unix.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: '/etc/shadow', size: 5 }),
        Buffer.from('evil!'),
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
        /Security violation: Prohibited path traversal or absolute entry/
      );
    });

    it('rejects absolute windows backslash and drive paths', async () => {
      const tarPath = path.join(tempDir, 'abs-win.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: '\\windows\\system32', size: 5 }),
        Buffer.from('evil!'),
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
        /Security violation: Prohibited path traversal or absolute entry/
      );

      const tarPath2 = path.join(tempDir, 'drive.tar.gz');
      createCustomTarGz(tarPath2, [
        makeHeader({ name: 'C:/boot.ini', size: 5 }),
        Buffer.from('evil!'),
      ]);
      await expect(SafeTarReader.extractAll(tarPath2, extractDir)).rejects.toThrow(
        /Security violation: Prohibited path traversal or absolute entry/
      );
    });

    it('rejects Windows reserved device names', async () => {
      const tarPath = path.join(tempDir, 'reserved.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: 'sub/con/test.txt', size: 5 }),
        Buffer.from('evil!'),
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
        /Security violation: Prohibited Windows reserved device name/
      );
    });

    it('rejects duplicate and case-colliding entries', async () => {
      const tarPath = path.join(tempDir, 'duplicate.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: 'file.txt', size: 5 }),
        Buffer.from('hello'),
        makeHeader({ name: 'FILE.TXT', size: 5 }),
        Buffer.from('world'),
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
        /Security violation: Duplicate or case-collision entry/
      );
    });

    it('rejects symlinks, hardlinks, and device files', async () => {
      const extractDir = path.join(tempDir, 'out');

      for (const flag of ['1', '2', '3', '4', '6']) {
        const tarPath = path.join(tempDir, `type-${flag}.tar.gz`);
        createCustomTarGz(tarPath, [makeHeader({ name: `entry-${flag}`, typeflag: flag })]);

        await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
          /Security violation: Special\/link entry .* is prohibited/
        );
      }
    });

    it('rejects decompression bomb exceeding byte limits', async () => {
      const tarPath = path.join(tempDir, 'bomb.tar.gz');
      const largeContent = Buffer.alloc(2000, 0x61);
      createCustomTarGz(tarPath, [
        makeHeader({ name: 'large.txt', size: largeContent.length }),
        largeContent,
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(
        SafeTarReader.extractAll(tarPath, extractDir, { maxDecompressedBytes: 1000 })
      ).rejects.toThrow(/Security violation: Archive decompressed size exceeds/);
    });

    it('rejects archive exceeding maxEntryCount limit', async () => {
      const tarPath = path.join(tempDir, 'many-entries.tar.gz');
      createCustomTarGz(tarPath, [
        makeHeader({ name: 'file1.txt', size: 1 }),
        Buffer.from('a'),
        makeHeader({ name: 'file2.txt', size: 1 }),
        Buffer.from('b'),
        makeHeader({ name: 'file3.txt', size: 1 }),
        Buffer.from('c'),
      ]);

      const extractDir = path.join(tempDir, 'out');
      await expect(
        SafeTarReader.extractAll(tarPath, extractDir, { maxEntryCount: 2 })
      ).rejects.toThrow(/Security violation: Archive exceeds maximum entry count/);
    });

    it('rejects corrupted tar header with invalid size', async () => {
      const tarPath = path.join(tempDir, 'bad-header.tar.gz');
      const h = Buffer.alloc(512);
      h.write('test.txt', 0, 100, 'utf8');
      h.write('not-an-octal', 124, 12, 'utf8');
      createCustomTarGz(tarPath, [h]);

      const extractDir = path.join(tempDir, 'out');
      await expect(SafeTarReader.extractAll(tarPath, extractDir)).rejects.toThrow(
        /Corrupted tar header: invalid size/
      );
    });
  });
});
