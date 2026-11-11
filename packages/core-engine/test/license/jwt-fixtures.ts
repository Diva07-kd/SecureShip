import crypto from 'node:crypto';
import path from 'node:path';
import { vi } from 'vitest';
import type { LicenseJwtPayload } from '@secureship/contracts';
import { writeLicenseFile } from '../../src/license/license-storage.js';

/**
 * Ephemeral SERVER and ATTACKER RSA-2048 keypairs.
 */
export const SERVER_KEYS = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export const ATTACKER_KEYS = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

/**
 * Generates an ephemeral RSA-2048 keypair for background refresh testing.
 */
export function generateTestKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  return {
    publicKeyPem: SERVER_KEYS.publicKey,
    privateKeyPem: SERVER_KEYS.privateKey,
  };
}

export function base64UrlEncode(data: string | Buffer | Uint8Array): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Signs arbitrary header and payload with given private key.
 * Allows forging alg ('none', 'HS256', etc.) for security testing.
 */
export function signWith(
  privateKeyPem: string,
  header: Record<string, unknown> | unknown,
  payload: Record<string, unknown> | unknown
): string {
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload =
    typeof payload === 'string' && (payload.startsWith('{') || payload.startsWith('['))
      ? base64UrlEncode(payload)
      : base64UrlEncode(JSON.stringify(payload));
  const messageToSign = `${encodedHeader}.${encodedPayload}`;

  const alg =
    typeof header === 'object' && header !== null && 'alg' in header
      ? String((header as Record<string, unknown>).alg)
      : 'RS256';

  if (alg === 'none') {
    return `${messageToSign}.`;
  }

  if (alg === 'HS256') {
    const hmac = crypto.createHmac('sha256', privateKeyPem);
    hmac.update(messageToSign);
    return `${messageToSign}.${hmac.digest('base64url')}`;
  }

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(messageToSign);
  signer.end();
  const sig = signer.sign(privateKeyPem);
  return `${messageToSign}.${base64UrlEncode(sig)}`;
}

/**
 * Creates a valid test LicenseJwtPayload conforming to LicenseJwtPayloadSchema.
 */
export function createTestPayload(overrides: Partial<LicenseJwtPayload> = {}): LicenseJwtPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: 'lead-dev@organization.com',
    tier: 'PRO_TEAM',
    seats: 5,
    orgId: 'org-enterprise',
    iat: now - 3600,
    exp: now + 30 * 86400,
    maxMonthlyAiFixes: 100,
    allowCallPathReachability: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: false,
    featureFlags: {},
    ...overrides,
  };
}

/**
 * Cryptographically signs a license payload with an RS256 private key.
 */
export function signTestLicenseJwt(
  payload: LicenseJwtPayload,
  privateKeyPem: string,
  keyId: string = 'secureship-2026-01'
): string {
  const header = {
    alg: 'RS256',
    kid: keyId,
    typ: 'JWT',
  };
  return signWith(privateKeyPem, header, payload);
}

/**
 * Helper that writes a license file and returns { path, jwt, payload }.
 */
export function setupLicenseFile(
  dir: string,
  payloadOverrides: Partial<LicenseJwtPayload> = {},
  privateKeyPem: string = SERVER_KEYS.privateKey,
  headerOverrides: Record<string, unknown> = {}
): { path: string; jwt: string; payload: LicenseJwtPayload } {
  const payload = createTestPayload(payloadOverrides);
  const header = {
    alg: 'RS256',
    kid: 'secureship-2026-01',
    typ: 'JWT',
    ...headerOverrides,
  };
  const jwt = signWith(privateKeyPem, header, payload);
  const licensePath = path.join(dir, 'license.jwt');
  writeLicenseFile(jwt, licensePath);
  return { path: licensePath, jwt, payload };
}

export interface Deferred<T = void> {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
}

export function createDeferred<T = void>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export interface FetchSpyCall {
  url: string;
  init?: RequestInit;
}

export interface FetchSpy {
  calls: FetchSpyCall[];
  mock: ReturnType<typeof vi.fn>;
  setHandler: (newHandler: (url: string, init?: RequestInit) => Promise<Response>) => void;
  setJsonResponse: (data: unknown, status?: number) => void;
  setError: (err: Error) => void;
}

export function createFetchSpy(
  defaultHandler?: (url: string, init?: RequestInit) => Promise<Response>
): FetchSpy {
  const calls: FetchSpyCall[] = [];
  let handler =
    defaultHandler ??
    (async () =>
      new Response(JSON.stringify({ valid: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }));

  const mock = vi
    .fn()
    .mockImplementation(async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      calls.push({ url: urlStr, init });
      return handler(urlStr, init);
    });

  vi.stubGlobal('fetch', mock);

  return {
    calls,
    mock,
    setHandler(newHandler: (url: string, init?: RequestInit) => Promise<Response>) {
      handler = newHandler;
    },
    setJsonResponse(data: unknown, status: number = 200) {
      handler = async () =>
        new Response(typeof data === 'string' ? data : JSON.stringify(data), {
          status,
          headers: { 'Content-Type': 'application/json' },
        });
    },
    setError(err: Error) {
      handler = async () => {
        throw err;
      };
    },
  };
}
