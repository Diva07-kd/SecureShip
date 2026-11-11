import crypto from 'node:crypto';
import net from 'node:net';
import { spawn } from 'node:child_process';
import fsSync from 'node:fs';
import path from 'node:path';
import type { FsFacade } from '../../src/security/fleet-token.js';

export function makeCanary(): string {
  return 'CNRY' + crypto.randomBytes(24).toString('base64url');
}

export function assertNoLeak(text: string, canary: string): void {
  if (text.includes(canary)) {
    throw new Error(`Canary leaked: full canary found in text.`);
  }
  for (let i = 0; i <= canary.length - 12; i++) {
    const window = canary.slice(i, i + 12);
    if (text.includes(window)) {
      throw new Error(`Canary leaked: 12-character window "${window}" found in text.`);
    }
  }
}

export interface RunEntryResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  url?: string;
  proc: ReturnType<typeof spawn>;
}

export async function runEntry(
  scriptPath: string,
  args: string[],
  customEnv: Record<string, string | undefined> = {},
  options: { timeoutMs?: number; waitForReady?: boolean } = {}
): Promise<RunEntryResult> {
  const timeoutMs = options.timeoutMs ?? 15000;
  const waitForReady = options.waitForReady ?? true;

  // Minimal env: keep essentials for Node to run, plus custom
  const cleanEnv: Record<string, string> = {
    PATH: process.env.PATH || '',
    SYSTEMROOT: process.env.SYSTEMROOT || '',
    COMSPEC: process.env.COMSPEC || '',
    NODE_ENV: 'test',
  };
  if (process.env.USERPROFILE) cleanEnv.USERPROFILE = process.env.USERPROFILE;
  if (process.env.HOME) cleanEnv.HOME = process.env.HOME;
  if (process.env.HOMEDRIVE) cleanEnv.HOMEDRIVE = process.env.HOMEDRIVE;
  if (process.env.HOMEPATH) cleanEnv.HOMEPATH = process.env.HOMEPATH;
  if (process.env.TEMP) cleanEnv.TEMP = process.env.TEMP;
  if (process.env.TMP) cleanEnv.TMP = process.env.TMP;

  for (const [k, v] of Object.entries(customEnv)) {
    if (v === undefined) {
      delete cleanEnv[k];
    } else {
      cleanEnv[k] = v;
    }
  }

  const child = spawn(process.execPath, [scriptPath, ...args], {
    env: cleanEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  let discoveredUrl: string | undefined;

  child.stdout.on('data', (d) => {
    stdout += d.toString();
    const clean = stdout.replace(/\u001b\[[0-9;]*m/g, '');
    const match = clean.match(/Web Dashboard\s*:\s*(http:\/\/[^\s]+)/);
    if (match && match[1]) {
      discoveredUrl = match[1];
    }
  });

  child.stderr.on('data', (d) => {
    stderr += d.toString();
  });

  if (!waitForReady) {
    const exitPromise = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve) => {
        child.on('exit', (code, signal) => resolve({ code, signal }));
      }
    );
    const result = await Promise.race([
      exitPromise,
      new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((_, reject) =>
        setTimeout(() => reject(new Error(`runEntry timeout after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
    return {
      code: result.code,
      signal: result.signal,
      stdout,
      stderr,
      proc: child,
    };
  }

  // Poll for readiness
  const startTime = Date.now();
  while (!discoveredUrl && Date.now() - startTime < timeoutMs) {
    if (child.exitCode !== null) {
      break;
    }
    await new Promise((r) => setTimeout(r, 50));
  }

  if (discoveredUrl) {
    // Poll GET / until 200
    const readyPollStart = Date.now();
    let isReady = false;
    while (!isReady && Date.now() - readyPollStart < 5000) {
      try {
        const res = await fetch(discoveredUrl, { redirect: 'error' });
        if (res.status === 200) {
          isReady = true;
          break;
        }
      } catch {
        // Retry
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  return {
    code: child.exitCode,
    signal: null,
    stdout,
    stderr,
    url: discoveredUrl,
    proc: child,
  };
}

export interface RawSocketHttpResponse {
  statusCode: number;
  statusLine: string;
  headers: Record<string, string>;
  body: string;
  raw: string;
}

export function rawHttp(
  port: number,
  requestBytes: string | Buffer
): Promise<RawSocketHttpResponse> {
  return new Promise((resolve, reject) => {
    let resolved = false;
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
      socket.write(requestBytes);
    });

    let raw = '';
    const finish = () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      socket.destroy();
      const headerEndIdx = raw.indexOf('\r\n\r\n');
      if (headerEndIdx === -1) {
        resolve({
          statusCode: 0,
          statusLine: '',
          headers: {},
          body: raw,
          raw,
        });
        return;
      }
      const headerPart = raw.slice(0, headerEndIdx);
      let bodyPart = raw.slice(headerEndIdx + 4);
      const lines = headerPart.split('\r\n');
      const statusLine = lines[0] || '';
      const match = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})/);
      const statusCode = match && match[1] ? parseInt(match[1], 10) : 0;
      const headers: Record<string, string> = {};
      for (let i = 1; i < lines.length; i++) {
        const l = lines[i];
        if (!l) continue;
        const colIdx = l.indexOf(':');
        if (colIdx !== -1) {
          headers[l.slice(0, colIdx).trim().toLowerCase()] = l.slice(colIdx + 1).trim();
        }
      }

      if (headers['transfer-encoding'] === 'chunked') {
        let decoded = '';
        let rem = bodyPart;
        while (rem.length > 0) {
          const crlf = rem.indexOf('\r\n');
          if (crlf === -1) break;
          const hexStr = rem.slice(0, crlf).trim().split(';')[0]!;
          const chunkSize = parseInt(hexStr, 16);
          if (isNaN(chunkSize) || chunkSize === 0) break;
          decoded += rem.slice(crlf + 2, crlf + 2 + chunkSize);
          rem = rem.slice(crlf + 2 + chunkSize + 2);
        }
        bodyPart = decoded;
      }

      resolve({
        statusCode,
        statusLine,
        headers,
        body: bodyPart,
        raw,
      });
    };

    socket.on('data', (chunk) => {
      raw += chunk.toString('latin1');
      const headerEndIdx = raw.indexOf('\r\n\r\n');
      if (headerEndIdx !== -1) {
        const headerPart = raw.slice(0, headerEndIdx);
        const clMatch = headerPart.match(/content-length:\s*(\d+)/i);
        if (clMatch && clMatch[1]) {
          const expectedLen = parseInt(clMatch[1], 10);
          const currentBodyLen = Buffer.byteLength(raw.slice(headerEndIdx + 4), 'latin1');
          if (currentBodyLen >= expectedLen) {
            finish();
          }
        } else if (/transfer-encoding:\s*chunked/i.test(headerPart)) {
          if (raw.endsWith('0\r\n\r\n')) {
            finish();
          }
        }
      }
    });

    socket.on('end', finish);
    socket.on('close', finish);
    socket.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        reject(err);
      }
    });
  });
}

export interface MemoryFsEntry {
  type: 'file' | 'dir' | 'symlink';
  content?: Buffer;
  mode: number;
  uid: number;
  target?: string;
}

export class FakeFsFacade implements FsFacade {
  public files = new Map<string, MemoryFsEntry>();
  public currentUid: number = 1000;
  public failNextChmod = false;
  public failNextOpen = false;

  constructor() {
    this.mkdirSync('/home/test/.secureship', 0o700);
  }

  private norm(p: string): string {
    return path.resolve(p).replace(/\\/g, '/');
  }

  public mkdirSync(p: string, mode = 0o700, uid = this.currentUid): void {
    const n = this.norm(p);
    this.files.set(n, { type: 'dir', mode, uid });
  }

  public writeFileSync(
    p: string,
    content: string | Buffer,
    mode = 0o600,
    uid = this.currentUid
  ): void {
    const n = this.norm(p);
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    this.files.set(n, { type: 'file', content: buf, mode, uid });
  }

  public symlinkSync(target: string, linkPath: string): void {
    const n = this.norm(linkPath);
    this.files.set(n, { type: 'symlink', target, mode: 0o777, uid: this.currentUid });
  }

  public getuid(): number {
    return this.currentUid;
  }

  public async lstat(p: string): Promise<fsSync.Stats> {
    const n = this.norm(p);
    const entry = this.files.get(n);
    if (!entry) {
      const err = new Error(
        `ENOENT: no such file or directory, lstat '${p}'`
      ) as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    }
    return {
      isFile: () => entry.type === 'file',
      isDirectory: () => entry.type === 'dir',
      isSymbolicLink: () => entry.type === 'symlink',
      mode: entry.mode,
      uid: entry.uid,
      size: entry.content ? entry.content.length : 0,
    } as unknown as fsSync.Stats;
  }

  public async stat(p: string): Promise<fsSync.Stats> {
    const real = await this.realpath(p);
    const entry = this.files.get(real);
    if (!entry) {
      const err = new Error(
        `ENOENT: no such file or directory, stat '${p}'`
      ) as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    }
    return {
      isFile: () => entry.type === 'file',
      isDirectory: () => entry.type === 'dir',
      isSymbolicLink: () => false,
      mode: entry.mode,
      uid: entry.uid,
      size: entry.content ? entry.content.length : 0,
    } as unknown as fsSync.Stats;
  }

  public async realpath(p: string): Promise<string> {
    let curr = this.norm(p);
    let hops = 0;
    while (hops++ < 20) {
      const entry = this.files.get(curr);
      if (!entry) return curr;
      if (entry.type === 'symlink' && entry.target) {
        curr = this.norm(entry.target);
      } else {
        return curr;
      }
    }
    return curr;
  }

  public async readFile(p: string): Promise<Buffer> {
    const real = await this.realpath(p);
    const entry = this.files.get(real);
    if (!entry || entry.type !== 'file' || !entry.content) {
      const err = new Error(
        `ENOENT: no such file or directory, readFile '${p}'`
      ) as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    }
    return entry.content;
  }

  public async open(
    p: string,
    flags: string | number,
    mode = 0o600
  ): Promise<{ write(buf: Uint8Array): Promise<unknown>; close(): Promise<void> }> {
    if (this.failNextOpen) {
      this.failNextOpen = false;
      const err = new Error('EACCES: permission denied') as NodeJS.ErrnoException;
      err.code = 'EACCES';
      throw err;
    }
    const n = this.norm(p);
    const existing = this.files.get(n);
    if (existing && flags === 'wx') {
      const err = new Error(`EEXIST: file already exists, open '${p}'`) as NodeJS.ErrnoException;
      err.code = 'EEXIST';
      throw err;
    }
    let writtenBuf = Buffer.alloc(0);
    return {
      write: async (buf: Uint8Array) => {
        writtenBuf = Buffer.concat([writtenBuf, Buffer.from(buf)]);
        this.files.set(n, {
          type: 'file',
          content: writtenBuf,
          mode,
          uid: this.currentUid,
        });
      },
      close: async () => {},
    };
  }

  public async mkdir(
    p: string,
    opts?: { recursive?: boolean; mode?: number }
  ): Promise<string | undefined> {
    const n = this.norm(p);
    this.files.set(n, {
      type: 'dir',
      mode: opts?.mode ?? 0o700,
      uid: this.currentUid,
    });
    return p;
  }

  public async chmod(p: string, mode: number): Promise<void> {
    if (this.failNextChmod) {
      this.failNextChmod = false;
      const err = new Error('EPERM: operation not permitted') as NodeJS.ErrnoException;
      err.code = 'EPERM';
      throw err;
    }
    const real = await this.realpath(p);
    const entry = this.files.get(real);
    if (entry) {
      entry.mode = mode;
    }
  }
}
