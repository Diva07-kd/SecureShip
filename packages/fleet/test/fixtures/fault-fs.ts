import fs from 'node:fs';
import type { FsFacade } from '../../src/storage/atomic-file.js';
import { defaultFsFacade } from '../../src/storage/atomic-file.js';

export interface FsCall {
  op: string;
  path?: string;
  args: unknown[];
  result?: unknown;
  error?: unknown;
}

export interface ScriptedFault {
  nth: number;
  err: Error;
  filter?: (...args: unknown[]) => boolean;
  matchedCount: number;
}

export function createFsError(
  code: string,
  message?: string,
  syscall?: string,
  p?: string
): Error & { code: string; syscall?: string; path?: string } {
  const err = new Error(
    message ?? `${code}: operation failed${p ? `, ${syscall ?? 'call'} '${p}'` : ''}`
  ) as Error & { code: string; syscall?: string; path?: string };
  err.code = code;
  if (syscall) err.syscall = syscall;
  if (p) err.path = p;
  return err;
}

export class FaultFs implements FsFacade {
  public callLog: FsCall[] = [];
  public sleepLog: number[] = [];
  public opCounts: Map<string, number> = new Map();
  public scriptedFaults: Map<string, ScriptedFault[]> = new Map();
  public shortWriteChunk: number | null = null;
  public alterReadBytesFn: ((buf: Buffer, filePath: string) => Buffer) | null = null;
  public currentTime: number = 1700000000000;
  public platform: NodeJS.Platform = 'linux';
  public randomCounter: number = 0;
  public fdPathMap: Map<number, string> = new Map();

  private realFs: FsFacade;

  constructor(options?: { realFs?: FsFacade; platform?: NodeJS.Platform; startTime?: number }) {
    this.realFs = options?.realFs ?? defaultFsFacade;
    this.platform = options?.platform ?? 'linux';
    this.currentTime = options?.startTime ?? 1700000000000;
  }

  public clearLogs(): void {
    this.callLog = [];
    this.sleepLog = [];
    this.opCounts.clear();
  }

  public failCall(
    op: string,
    nth: number,
    errOrCode: string | Error,
    filter?: (...args: unknown[]) => boolean
  ): void {
    const err = typeof errOrCode === 'string' ? createFsError(errOrCode, undefined, op) : errOrCode;
    const list = this.scriptedFaults.get(op) ?? [];
    list.push({ nth, err, filter, matchedCount: 0 });
    this.scriptedFaults.set(op, list);
  }

  public failAlways(
    op: string,
    errOrCode: string | Error,
    filter?: (...args: unknown[]) => boolean
  ): void {
    this.failCall(op, -1, errOrCode, filter);
  }

  public setShortWrite(chunk: number | null): void {
    this.shortWriteChunk = chunk;
  }

  public setAlteredBytesOnRead(fn: ((buf: Buffer, filePath: string) => Buffer) | null): void {
    this.alterReadBytesFn = fn;
  }

  public advanceClock(ms: number): void {
    this.currentTime += ms;
  }

  public now = (): number => {
    return this.currentTime;
  };

  public sleep = (ms: number): void => {
    this.sleepLog.push(ms);
  };

  public random = (bytes: number = 4): string => {
    this.randomCounter++;
    const hex = this.randomCounter.toString(16).padStart(bytes * 2, '0');
    return hex.slice(-bytes * 2);
  };

  private checkFault(op: string, p?: string, ...args: unknown[]): void {
    const count = (this.opCounts.get(op) ?? 0) + 1;
    this.opCounts.set(op, count);

    const faults = this.scriptedFaults.get(op);
    if (!faults) return;

    let faultToThrow: ScriptedFault | null = null;
    for (const f of faults) {
      if (!f.filter || f.filter(p, ...args)) {
        f.matchedCount++;
        if ((f.nth === -1 || f.matchedCount === f.nth) && !faultToThrow) {
          faultToThrow = f;
        }
      }
    }

    if (faultToThrow) {
      this.callLog.push({ op, path: p, args, error: faultToThrow.err });
      throw faultToThrow.err;
    }
  }

  public existsSync(p: string): boolean {
    this.checkFault('existsSync', p);
    const res = this.realFs.existsSync(p);
    this.callLog.push({ op: 'existsSync', path: p, args: [p], result: res });
    return res;
  }

  public readFileSync(p: string, encoding?: BufferEncoding): string | Buffer {
    this.checkFault('readFileSync', p, encoding);
    let res = this.realFs.readFileSync(p, encoding);
    if (this.alterReadBytesFn) {
      const buf = Buffer.isBuffer(res) ? res : Buffer.from(res as string);
      const altered = this.alterReadBytesFn(buf, p);
      res = encoding ? altered.toString(encoding) : altered;
    }
    this.callLog.push({ op: 'readFileSync', path: p, args: [p, encoding] });
    return res;
  }

  public writeFileSync(
    p: string,
    data: string | NodeJS.ArrayBufferView,
    options?: fs.WriteFileOptions
  ): void {
    this.checkFault('writeFileSync', p, data, options);
    this.realFs.writeFileSync(p, data, options);
    this.callLog.push({ op: 'writeFileSync', path: p, args: [p, data, options] });
  }

  public mkdirSync(p: string, options?: fs.MakeDirectoryOptions): string | undefined {
    this.checkFault('mkdirSync', p, options);
    const res = this.realFs.mkdirSync(p, options);
    this.callLog.push({ op: 'mkdirSync', path: p, args: [p, options], result: res });
    return res;
  }

  public openSync(p: string, flags: string | number, mode?: number): number {
    this.checkFault('openSync', p, flags, mode);
    const fd = this.realFs.openSync(p, flags, mode);
    this.fdPathMap.set(fd, p);
    this.callLog.push({ op: 'openSync', path: p, args: [p, flags, mode], result: fd });
    return fd;
  }

  public writeSync(
    fd: number,
    buffer: NodeJS.ArrayBufferView,
    offset?: number,
    length?: number,
    position?: number | null
  ): number {
    const p = this.fdPathMap.get(fd);
    this.checkFault('writeSync', p, fd, buffer, offset, length, position);

    if (this.shortWriteChunk !== null && this.shortWriteChunk > 0) {
      const actualLen = length ?? (buffer as Buffer).length;
      const toWrite = Math.min(this.shortWriteChunk, actualLen);
      const written = this.realFs.writeSync(fd, buffer, offset, toWrite, position);
      this.callLog.push({
        op: 'writeSync',
        path: p,
        args: [fd, buffer, offset, length, position],
        result: written,
      });
      return written;
    }

    const written = this.realFs.writeSync(fd, buffer, offset, length, position);
    this.callLog.push({
      op: 'writeSync',
      path: p,
      args: [fd, buffer, offset, length, position],
      result: written,
    });
    return written;
  }

  public fsyncSync(fd: number): void {
    const p = this.fdPathMap.get(fd);
    this.checkFault('fsyncSync', p, fd);
    try {
      this.realFs.fsyncSync(fd);
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code;
      if (
        this.platform !== 'win32' &&
        (code === 'EISDIR' || code === 'EINVAL' || code === 'EPERM')
      ) {
        // Ignored on simulated POSIX when underlying host OS is Windows
      } else {
        throw err;
      }
    }
    this.callLog.push({ op: 'fsyncSync', path: p, args: [fd] });
  }

  public closeSync(fd: number): void {
    const p = this.fdPathMap.get(fd);
    this.checkFault('closeSync', p, fd);
    this.realFs.closeSync(fd);
    this.fdPathMap.delete(fd);
    this.callLog.push({ op: 'closeSync', path: p, args: [fd] });
  }

  public statSync(p: string): fs.Stats {
    this.checkFault('statSync', p);
    const res = this.realFs.statSync(p);
    this.callLog.push({ op: 'statSync', path: p, args: [p], result: res });
    return res;
  }

  public lstatSync(p: string): fs.Stats {
    this.checkFault('lstatSync', p);
    const res = this.realFs.lstatSync(p);
    this.callLog.push({ op: 'lstatSync', path: p, args: [p], result: res });
    return res;
  }

  public renameSync(oldPath: string, newPath: string): void {
    this.checkFault('renameSync', oldPath, newPath);
    this.realFs.renameSync(oldPath, newPath);
    this.callLog.push({ op: 'renameSync', path: oldPath, args: [oldPath, newPath] });
  }

  public copyFileSync(src: string, dest: string, mode?: number): void {
    this.checkFault('copyFileSync', src, dest, mode);
    this.realFs.copyFileSync(src, dest, mode);
    this.callLog.push({ op: 'copyFileSync', path: src, args: [src, dest, mode] });
  }

  public unlinkSync(p: string): void {
    this.checkFault('unlinkSync', p);
    this.realFs.unlinkSync(p);
    this.callLog.push({ op: 'unlinkSync', path: p, args: [p] });
  }

  public readdirSync(p: string, options?: { withFileTypes?: boolean }): string[] | fs.Dirent[] {
    this.checkFault('readdirSync', p, options);
    const res = this.realFs.readdirSync(p, options);
    this.callLog.push({ op: 'readdirSync', path: p, args: [p, options] });
    return res;
  }

  public realpathSync(p: string): string {
    this.checkFault('realpathSync', p);
    const res = this.realFs.realpathSync(p);
    this.callLog.push({ op: 'realpathSync', path: p, args: [p], result: res });
    return res;
  }

  public chmodSync(p: string, mode: number): void {
    this.checkFault('chmodSync', p, mode);
    if (this.realFs.chmodSync) {
      this.realFs.chmodSync(p, mode);
    }
    this.callLog.push({ op: 'chmodSync', path: p, args: [p, mode] });
  }
}
