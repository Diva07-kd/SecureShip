/// <reference types="@cloudflare/workers-types" />
import {
  LicenseActivationRequestSchema,
  LicenseJwtPayloadSchema,
  type LicenseJwtPayload,
  type LicenseTier,
  TIER_CAPABILITY_DEFAULTS,
} from '@secureship/contracts';

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = unknown>(): Promise<T | null>;
  run(): Promise<{ success: boolean; meta?: { changes?: number } }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch?(
    statements: D1PreparedStatement[]
  ): Promise<Array<{ success: boolean; meta?: { changes?: number } }>>;
}

export interface Env {
  DB?: D1Database;
  JWT_PRIVATE_KEY?: string; // PEM private key for signing RS256 JWTs (secret)
  JWT_PUBLIC_KEY?: string; // SPKI PEM public key for verifying RS256 JWTs (public var)
  STRIPE_WEBHOOK_SECRET?: string;
}

export interface LicenseRecord {
  id: string;
  customer_id: string;
  activation_code: string;
  tier: LicenseTier;
  seats: number;
  org_id: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  expires_at: number;
  email?: string;
  stripe_subscription_id?: string | null;
  stripe_checkout_session_id?: string | null;
}

export interface ActivationRecord {
  id: string;
  license_id: string;
  machine_fingerprint: string;
  activated_at: number;
  last_validated_at: number;
}

export type ServerJwtPayload = LicenseJwtPayload & {
  lid?: string;
};

export type VerifyJwtResult =
  | { ok: true; payload: ServerJwtPayload }
  | {
      ok: false;
      reason:
        | 'MALFORMED'
        | 'BAD_ALGORITHM'
        | 'BAD_SIGNATURE'
        | 'BAD_KEY'
        | 'INVALID_CLAIMS'
        | 'EXPIRED';
    };

export const LICENSE_TERM_SECONDS = 365 * 86400; // 365 days
export const RENEWAL_GRACE_SECONDS = 3 * 86400; // 3 days

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Generates a high-entropy activation code conforming to Crockford Base32.
 * Format: SS-PRO-XXXX-XXXX-XXXX-XXXX or SS-ENT-XXXX-XXXX-XXXX-XXXX (80 bits entropy).
 */
export function generateActivationCode(
  tier: LicenseTier,
  getRandomValues: (array: Uint8Array) => Uint8Array = (arr) => crypto.getRandomValues(arr)
): string {
  const prefix = tier === 'ENTERPRISE' ? 'SS-ENT-' : 'SS-PRO-';
  const randomBytes = new Uint8Array(16);
  getRandomValues(randomBytes);

  const chars: string[] = [];
  for (let i = 0; i < 16; i++) {
    chars.push(CROCKFORD_ALPHABET[randomBytes[i]! & 31]!);
  }

  return (
    prefix +
    chars.slice(0, 4).join('') +
    '-' +
    chars.slice(4, 8).join('') +
    '-' +
    chars.slice(8, 12).join('') +
    '-' +
    chars.slice(12, 16).join('')
  );
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Cryptographically verifies a Stripe webhook signature using Web Crypto HMAC-SHA256.
 * Never throws.
 */
export async function verifyStripeSignatureWebCrypto(
  rawBody: string | Uint8Array,
  sigHeader: string,
  secret: string,
  toleranceSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000)
): Promise<boolean> {
  try {
    if (!secret || typeof sigHeader !== 'string' || !sigHeader) {
      return false;
    }

    let tStr: string | null = null;
    const v1List: string[] = [];
    const parts = sigHeader.split(',');

    for (const part of parts) {
      const eqIdx = part.indexOf('=');
      if (eqIdx === -1) continue;
      const key = part.slice(0, eqIdx).trim();
      const val = part.slice(eqIdx + 1).trim();

      if (key === 't') {
        if (tStr !== null) {
          // Require exactly one valid t
          return false;
        }
        if (!/^\d{1,12}$/.test(val)) {
          return false;
        }
        tStr = val;
      } else if (key === 'v1') {
        if (/^[0-9a-f]{64}$/i.test(val) && v1List.length < 10) {
          v1List.push(val);
        }
      }
    }

    if (!tStr || v1List.length === 0) {
      return false;
    }

    const t = parseInt(tStr, 10);
    if (Math.abs(nowSeconds - t) > toleranceSeconds) {
      return false;
    }

    const prefixBytes = new TextEncoder().encode(`${t}.`);
    const bodyBytes = typeof rawBody === 'string' ? new TextEncoder().encode(rawBody) : rawBody;
    const message = new Uint8Array(prefixBytes.length + bodyBytes.length);
    message.set(prefixBytes, 0);
    message.set(bodyBytes, prefixBytes.length);

    const keyBytes = new TextEncoder().encode(secret);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    for (const v1 of v1List) {
      const sigBytes = hexToBytes(v1);
      const valid = await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, message);
      if (valid) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

function isValidBase64Url(str: string): boolean {
  return str.length > 0 && str.length % 4 !== 1 && BASE64URL_REGEX.test(str);
}

export function base64UrlDecode(str: string): Uint8Array<ArrayBuffer> {
  if (!isValidBase64Url(str)) {
    throw new Error('Invalid base64url string');
  }
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlToString(str: string): string {
  const bytes = base64UrlDecode(str);
  return new TextDecoder().decode(bytes);
}

function base64UrlEncode(strOrBytes: string | Uint8Array): string {
  const bytes = typeof strOrBytes === 'string' ? new TextEncoder().encode(strOrBytes) : strOrBytes;
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Parses PEM private key into CryptoKey for Web Crypto RS256 signing.
 */
async function importRsaPrivateKey(pem: string): Promise<CryptoKey> {
  const cleanPem = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '');
  const binaryDer = atob(cleanPem);
  const bytes = new Uint8Array(binaryDer.length);
  for (let i = 0; i < binaryDer.length; i++) {
    bytes[i] = binaryDer.charCodeAt(i);
  }

  return crypto.subtle.importKey(
    'pkcs8',
    bytes.buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );
}

const publicKeyCache = new Map<string, CryptoKey>();

async function getOrImportRsaPublicKey(pem: string): Promise<CryptoKey | null> {
  const cached = publicKeyCache.get(pem);
  if (cached) return cached;

  try {
    const cleanPem = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, '')
      .replace(/-----END PUBLIC KEY-----/g, '')
      .replace(/\s+/g, '');
    const binaryDer = atob(cleanPem);
    const bytes = new Uint8Array(binaryDer.length);
    for (let i = 0; i < binaryDer.length; i++) {
      bytes[i] = binaryDer.charCodeAt(i);
    }

    const key = await crypto.subtle.importKey(
      'spki',
      bytes.buffer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['verify']
    );
    publicKeyCache.set(pem, key);
    return key;
  } catch {
    return null;
  }
}

/**
 * Signs a license payload using Web Crypto RSASSA-PKCS1-v1_5 (RS256).
 */
export async function signJwtWebCrypto(
  payload: LicenseJwtPayload | ServerJwtPayload,
  privateKeyPem: string
): Promise<string> {
  const header = {
    alg: 'RS256',
    kid: 'secureship-2026-01',
    typ: 'JWT',
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const messageToSign = `${encodedHeader}.${encodedPayload}`;

  const cryptoKey = await importRsaPrivateKey(privateKeyPem);
  const signatureBytes = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(messageToSign)
  );

  const encodedSignature = base64UrlEncode(new Uint8Array(signatureBytes));
  return `${messageToSign}.${encodedSignature}`;
}

export async function verifyJwtWebCrypto(
  token: string,
  publicKeyPem: string,
  options?: { now?: number; clockToleranceSeconds?: number }
): Promise<VerifyJwtResult> {
  if (typeof token !== 'string') {
    return { ok: false, reason: 'MALFORMED' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { ok: false, reason: 'MALFORMED' };
  }

  const [headerSegment, payloadSegment, signatureSegment] = parts;
  if (!headerSegment || !payloadSegment || !signatureSegment) {
    return { ok: false, reason: 'MALFORMED' };
  }

  let headerObj: Record<string, unknown>;
  try {
    const decodedHeader = base64UrlToString(headerSegment);
    headerObj = JSON.parse(decodedHeader) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: 'MALFORMED' };
  }

  if (!headerObj || typeof headerObj !== 'object' || Array.isArray(headerObj)) {
    return { ok: false, reason: 'MALFORMED' };
  }

  if (headerObj['alg'] !== 'RS256') {
    return { ok: false, reason: 'BAD_ALGORITHM' };
  }

  if (headerObj['typ'] !== undefined && headerObj['typ'] !== 'JWT') {
    return { ok: false, reason: 'MALFORMED' };
  }

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = base64UrlDecode(signatureSegment);
  } catch {
    return { ok: false, reason: 'MALFORMED' };
  }

  let cryptoKey: CryptoKey | null;
  try {
    cryptoKey = await getOrImportRsaPublicKey(publicKeyPem);
  } catch {
    return { ok: false, reason: 'BAD_KEY' };
  }

  if (!cryptoKey) {
    return { ok: false, reason: 'BAD_KEY' };
  }

  const signedContent = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      signatureBytes,
      signedContent
    );
  } catch {
    return { ok: false, reason: 'BAD_SIGNATURE' };
  }

  if (!verified) {
    return { ok: false, reason: 'BAD_SIGNATURE' };
  }

  let payloadObj: unknown;
  try {
    const decodedPayload = base64UrlToString(payloadSegment);
    payloadObj = JSON.parse(decodedPayload);
  } catch {
    return { ok: false, reason: 'MALFORMED' };
  }

  const parsed = LicenseJwtPayloadSchema.safeParse(payloadObj);
  if (!parsed.success) {
    return { ok: false, reason: 'INVALID_CLAIMS' };
  }

  const lid =
    typeof (payloadObj as Record<string, unknown>)['lid'] === 'string'
      ? ((payloadObj as Record<string, unknown>)['lid'] as string)
      : undefined;

  const fullPayload: ServerJwtPayload = {
    ...parsed.data,
    lid,
  };

  const now = options?.now ?? Math.floor(Date.now() / 1000);
  const tolerance = Math.max(0, options?.clockToleranceSeconds ?? 0);
  if (fullPayload.exp + tolerance <= now) {
    return { ok: false, reason: 'EXPIRED' };
  }

  return { ok: true, payload: fullPayload };
}

export interface LicenseStore {
  findByActivationCode(code: string): Promise<LicenseRecord | null>;
  findById(id: string): Promise<LicenseRecord | null>;
  claimSeat(
    licenseId: string,
    fingerprint: string,
    maxSeats: number,
    now: number
  ): Promise<{ success: boolean; isExisting?: boolean; error?: string }>;
  touchActivation(licenseId: string, now: number): Promise<void>;
  releaseActivation(licenseId: string, fingerprint: string): Promise<boolean>;

  // Stripe webhook extensions
  hasStripeEvent(id: string): Promise<boolean>;
  findLicenseByCheckoutSession(sessionId: string): Promise<LicenseRecord | null>;
  createLicenseFromCheckout(params: {
    eventId: string;
    eventType: string;
    email: string;
    stripeCustomerId?: string | null;
    licenseId: string;
    activationCode: string;
    tier: LicenseTier;
    seats: number;
    orgId: string;
    expiresAt: number;
    now: number;
    subscriptionId?: string | null;
    checkoutSessionId: string;
  }): Promise<{ success: boolean; licenseId: string }>;
  revokeSubscription(params: {
    eventId: string;
    eventType: string;
    subscriptionId: string;
    now: number;
  }): Promise<{ revoked: number }>;
  renewSubscription(params: {
    eventId: string;
    eventType: string;
    subscriptionId: string;
    periodEnd: number;
    now: number;
  }): Promise<{ renewed: number }>;
}

const mockActivationsStore = new WeakMap<Map<string, LicenseRecord>, ActivationRecord[]>();
const mockCustomersStore = new WeakMap<
  Map<string, LicenseRecord>,
  Map<string, { id: string; email: string; stripe_customer_id?: string | null; created_at: number }>
>();
const mockStripeEventsStore = new WeakMap<Map<string, LicenseRecord>, Set<string>>();

export function getMockActivations(mockDb: Map<string, LicenseRecord>): ActivationRecord[] {
  return [...(mockActivationsStore.get(mockDb) ?? [])];
}

export class MockStore implements LicenseStore {
  private readonly mockDb: Map<string, LicenseRecord>;

  constructor(mockDb: Map<string, LicenseRecord>) {
    this.mockDb = mockDb;
    if (!mockActivationsStore.has(mockDb)) {
      mockActivationsStore.set(mockDb, []);
    }
    if (!mockCustomersStore.has(mockDb)) {
      const custMap = new Map<
        string,
        { id: string; email: string; stripe_customer_id?: string | null; created_at: number }
      >();
      for (const lic of mockDb.values()) {
        if (lic.email && !custMap.has(lic.email.toLowerCase())) {
          custMap.set(lic.email.toLowerCase(), {
            id: lic.customer_id,
            email: lic.email.toLowerCase(),
            stripe_customer_id: null,
            created_at: Math.floor(Date.now() / 1000),
          });
        }
      }
      mockCustomersStore.set(mockDb, custMap);
    }
    if (!mockStripeEventsStore.has(mockDb)) {
      mockStripeEventsStore.set(mockDb, new Set<string>());
    }
  }

  async findByActivationCode(code: string): Promise<LicenseRecord | null> {
    const record = this.mockDb.get(code);
    return record ? { ...record } : null;
  }

  async findById(id: string): Promise<LicenseRecord | null> {
    for (const record of this.mockDb.values()) {
      if (record.id === id) {
        return { ...record };
      }
    }
    return null;
  }

  async claimSeat(
    licenseId: string,
    fingerprint: string,
    maxSeats: number,
    now: number
  ): Promise<{ success: boolean; isExisting?: boolean; error?: string }> {
    const activations = mockActivationsStore.get(this.mockDb)!;
    const existing = activations.find(
      (a) => a.license_id === licenseId && a.machine_fingerprint === fingerprint
    );

    if (existing) {
      existing.last_validated_at = now;
      return { success: true, isExisting: true };
    }

    const currentSeats = activations.filter((a) => a.license_id === licenseId).length;
    if (currentSeats >= maxSeats) {
      return { success: false, error: 'SEATS_EXCEEDED' };
    }

    const newActivation: ActivationRecord = {
      id: crypto.randomUUID(),
      license_id: licenseId,
      machine_fingerprint: fingerprint,
      activated_at: now,
      last_validated_at: now,
    };
    activations.push(newActivation);
    return { success: true, isExisting: false };
  }

  async touchActivation(licenseId: string, now: number): Promise<void> {
    const activations = mockActivationsStore.get(this.mockDb) ?? [];
    for (const a of activations) {
      if (a.license_id === licenseId) {
        a.last_validated_at = now;
      }
    }
  }

  async releaseActivation(licenseId: string, fingerprint: string): Promise<boolean> {
    const activations = mockActivationsStore.get(this.mockDb);
    if (!activations) return false;
    const idx = activations.findIndex(
      (a) => a.license_id === licenseId && a.machine_fingerprint === fingerprint
    );
    if (idx !== -1) {
      activations.splice(idx, 1);
      return true;
    }
    return false;
  }

  async hasStripeEvent(id: string): Promise<boolean> {
    const events = mockStripeEventsStore.get(this.mockDb);
    return Boolean(events?.has(id));
  }

  async findLicenseByCheckoutSession(sessionId: string): Promise<LicenseRecord | null> {
    for (const lic of this.mockDb.values()) {
      if (lic.stripe_checkout_session_id === sessionId) {
        return { ...lic };
      }
    }
    return null;
  }

  async createLicenseFromCheckout(params: {
    eventId: string;
    eventType: string;
    email: string;
    stripeCustomerId?: string | null;
    licenseId: string;
    activationCode: string;
    tier: LicenseTier;
    seats: number;
    orgId: string;
    expiresAt: number;
    now: number;
    subscriptionId?: string | null;
    checkoutSessionId: string;
  }): Promise<{ success: boolean; licenseId: string }> {
    const events = mockStripeEventsStore.get(this.mockDb)!;
    const customers = mockCustomersStore.get(this.mockDb)!;

    if (events.has(params.eventId)) {
      throw new Error('UNIQUE constraint failed: stripe_events.id');
    }
    for (const lic of this.mockDb.values()) {
      if (lic.stripe_checkout_session_id === params.checkoutSessionId) {
        throw new Error('UNIQUE constraint failed: licenses.stripe_checkout_session_id');
      }
    }
    if (this.mockDb.has(params.activationCode)) {
      throw new Error('UNIQUE constraint failed: licenses.activation_code');
    }

    events.add(params.eventId);

    const normEmail = params.email.toLowerCase();
    let cust = customers.get(normEmail);
    let customerId: string;
    if (cust) {
      customerId = cust.id;
      if (params.stripeCustomerId !== undefined && params.stripeCustomerId !== null) {
        cust.stripe_customer_id = params.stripeCustomerId;
      }
    } else {
      customerId = crypto.randomUUID();
      cust = {
        id: customerId,
        email: normEmail,
        stripe_customer_id: params.stripeCustomerId ?? null,
        created_at: params.now,
      };
      customers.set(normEmail, cust);
    }

    const lic: LicenseRecord = {
      id: params.licenseId,
      customer_id: customerId,
      activation_code: params.activationCode,
      tier: params.tier,
      seats: params.seats,
      org_id: params.orgId,
      status: 'ACTIVE',
      expires_at: params.expiresAt,
      email: params.email,
      stripe_subscription_id: params.subscriptionId ?? null,
      stripe_checkout_session_id: params.checkoutSessionId,
    };
    this.mockDb.set(params.activationCode, lic);

    return { success: true, licenseId: params.licenseId };
  }

  async revokeSubscription(params: {
    eventId: string;
    eventType: string;
    subscriptionId: string;
    now: number;
  }): Promise<{ revoked: number }> {
    const events = mockStripeEventsStore.get(this.mockDb)!;
    if (events.has(params.eventId)) {
      throw new Error('UNIQUE constraint failed: stripe_events.id');
    }
    events.add(params.eventId);

    let revoked = 0;
    for (const lic of this.mockDb.values()) {
      if (lic.stripe_subscription_id === params.subscriptionId && lic.status === 'ACTIVE') {
        lic.status = 'REVOKED';
        revoked++;
      }
    }
    return { revoked };
  }

  async renewSubscription(params: {
    eventId: string;
    eventType: string;
    subscriptionId: string;
    periodEnd: number;
    now: number;
  }): Promise<{ renewed: number }> {
    const events = mockStripeEventsStore.get(this.mockDb)!;
    if (events.has(params.eventId)) {
      throw new Error('UNIQUE constraint failed: stripe_events.id');
    }
    events.add(params.eventId);

    let renewed = 0;
    for (const lic of this.mockDb.values()) {
      if (lic.stripe_subscription_id === params.subscriptionId && lic.status === 'ACTIVE') {
        lic.expires_at = Math.max(lic.expires_at, params.periodEnd + RENEWAL_GRACE_SECONDS);
        renewed++;
      }
    }
    return { renewed };
  }
}

export class D1Store implements LicenseStore {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  async findByActivationCode(code: string): Promise<LicenseRecord | null> {
    return await this.db
      .prepare(
        `SELECT l.*, c.email 
         FROM licenses l
         JOIN customers c ON l.customer_id = c.id
         WHERE l.activation_code = ?`
      )
      .bind(code)
      .first<LicenseRecord>();
  }

  async findById(id: string): Promise<LicenseRecord | null> {
    return await this.db
      .prepare(
        `SELECT l.*, c.email 
         FROM licenses l
         JOIN customers c ON l.customer_id = c.id
         WHERE l.id = ?`
      )
      .bind(id)
      .first<LicenseRecord>();
  }

  async claimSeat(
    licenseId: string,
    fingerprint: string,
    maxSeats: number,
    now: number
  ): Promise<{ success: boolean; isExisting?: boolean; error?: string }> {
    const touchRes = await this.db
      .prepare(
        `UPDATE activations 
         SET last_validated_at = ? 
         WHERE license_id = ? AND machine_fingerprint = ?`
      )
      .bind(now, licenseId, fingerprint)
      .run();

    if (touchRes.meta?.changes && touchRes.meta.changes > 0) {
      return { success: true, isExisting: true };
    }

    const activationId = crypto.randomUUID();
    try {
      const insertRes = await this.db
        .prepare(
          `INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at)
           SELECT ?, ?, ?, ?, ?
           WHERE (SELECT COUNT(*) FROM activations WHERE license_id = ?) < ?`
        )
        .bind(activationId, licenseId, fingerprint, now, now, licenseId, maxSeats)
        .run();

      if (insertRes.meta?.changes && insertRes.meta.changes > 0) {
        return { success: true, isExisting: false };
      }

      return { success: false, isExisting: false, error: 'SEATS_EXCEEDED' };
    } catch (insertErr) {
      const errStr = String(insertErr).toLowerCase();
      if (errStr.includes('unique') || errStr.includes('constraint')) {
        await this.db
          .prepare(
            `UPDATE activations 
             SET last_validated_at = ? 
             WHERE license_id = ? AND machine_fingerprint = ?`
          )
          .bind(now, licenseId, fingerprint)
          .run();
        return { success: true, isExisting: true };
      }
      throw insertErr;
    }
  }

  async touchActivation(licenseId: string, now: number): Promise<void> {
    try {
      await this.db
        .prepare(
          `UPDATE activations 
           SET last_validated_at = ? 
           WHERE license_id = ?`
        )
        .bind(now, licenseId)
        .run();
    } catch {
      // Non-blocking best-effort
    }
  }

  async releaseActivation(licenseId: string, fingerprint: string): Promise<boolean> {
    const res = await this.db
      .prepare(
        `DELETE FROM activations 
         WHERE license_id = ? AND machine_fingerprint = ?`
      )
      .bind(licenseId, fingerprint)
      .run();
    return Boolean(res.meta?.changes && res.meta.changes > 0);
  }

  async hasStripeEvent(id: string): Promise<boolean> {
    const row = await this.db
      .prepare('SELECT id FROM stripe_events WHERE id = ?')
      .bind(id)
      .first<{ id: string }>();
    return Boolean(row);
  }

  async findLicenseByCheckoutSession(sessionId: string): Promise<LicenseRecord | null> {
    return await this.db
      .prepare('SELECT * FROM licenses WHERE stripe_checkout_session_id = ?')
      .bind(sessionId)
      .first<LicenseRecord>();
  }

  async createLicenseFromCheckout(params: {
    eventId: string;
    eventType: string;
    email: string;
    stripeCustomerId?: string | null;
    licenseId: string;
    activationCode: string;
    tier: LicenseTier;
    seats: number;
    orgId: string;
    expiresAt: number;
    now: number;
    subscriptionId?: string | null;
    checkoutSessionId: string;
  }): Promise<{ success: boolean; licenseId: string }> {
    const stmt1 = this.db
      .prepare('INSERT INTO stripe_events (id, type, received_at) VALUES (?, ?, ?)')
      .bind(params.eventId, params.eventType, params.now);

    const stmt2 = this.db
      .prepare(
        'INSERT INTO customers (id, email, stripe_customer_id, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO UPDATE SET stripe_customer_id = excluded.stripe_customer_id'
      )
      .bind(crypto.randomUUID(), params.email, params.stripeCustomerId ?? null, params.now);

    const stmt3 = this.db
      .prepare(
        `INSERT INTO licenses (
           id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at, stripe_subscription_id, stripe_checkout_session_id
         ) SELECT ?, c.id, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ? FROM customers c WHERE c.email = ? AND true`
      )
      .bind(
        params.licenseId,
        params.activationCode,
        params.tier,
        params.seats,
        params.orgId,
        params.expiresAt,
        params.now,
        params.now,
        params.subscriptionId ?? null,
        params.checkoutSessionId,
        params.email
      );

    if (typeof this.db.batch === 'function') {
      await this.db.batch([stmt1, stmt2, stmt3]);
    } else {
      await stmt1.run();
      await stmt2.run();
      await stmt3.run();
    }

    return { success: true, licenseId: params.licenseId };
  }

  async revokeSubscription(params: {
    eventId: string;
    eventType: string;
    subscriptionId: string;
    now: number;
  }): Promise<{ revoked: number }> {
    const stmt1 = this.db
      .prepare('INSERT INTO stripe_events (id, type, received_at) VALUES (?, ?, ?)')
      .bind(params.eventId, params.eventType, params.now);

    const stmt2 = this.db
      .prepare(
        "UPDATE licenses SET status = 'REVOKED', updated_at = ? WHERE stripe_subscription_id = ? AND status = 'ACTIVE'"
      )
      .bind(params.now, params.subscriptionId);

    let revoked = 0;
    if (typeof this.db.batch === 'function') {
      const results = await this.db.batch([stmt1, stmt2]);
      revoked = results[1]?.meta?.changes ?? 0;
    } else {
      await stmt1.run();
      const res = await stmt2.run();
      revoked = res.meta?.changes ?? 0;
    }

    return { revoked };
  }

  async renewSubscription(params: {
    eventId: string;
    eventType: string;
    subscriptionId: string;
    periodEnd: number;
    now: number;
  }): Promise<{ renewed: number }> {
    const stmt1 = this.db
      .prepare('INSERT INTO stripe_events (id, type, received_at) VALUES (?, ?, ?)')
      .bind(params.eventId, params.eventType, params.now);

    const stmt2 = this.db
      .prepare(
        "UPDATE licenses SET expires_at = MAX(expires_at, ? + ?), updated_at = ? WHERE stripe_subscription_id = ? AND status = 'ACTIVE'"
      )
      .bind(params.periodEnd, RENEWAL_GRACE_SECONDS, params.now, params.subscriptionId);

    let renewed = 0;
    if (typeof this.db.batch === 'function') {
      const results = await this.db.batch([stmt1, stmt2]);
      renewed = results[1]?.meta?.changes ?? 0;
    } else {
      await stmt1.run();
      const res = await stmt2.run();
      renewed = res.meta?.changes ?? 0;
    }

    return { renewed };
  }
}

function createStore(env: Env, mockDb?: Map<string, LicenseRecord>): LicenseStore | null {
  if (mockDb) {
    return new MockStore(mockDb);
  }
  if (env.DB) {
    return new D1Store(env.DB);
  }
  return null;
}

export class LicenseWorker {
  /**
   * Main fetch dispatcher for Cloudflare Workers.
   */
  public static async handleRequest(
    request: Request,
    env: Env,
    mockDb?: Map<string, LicenseRecord>
  ): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    };

    // 1. GET /v1/health
    if (url.pathname === '/v1/health' && method === 'GET') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'secureship-license-server',
          version: '1.0.0-beta.1',
          timestamp: new Date().toISOString(),
        }),
        { status: 200, headers }
      );
    }

    // 2. POST /v1/activate
    if (url.pathname === '/v1/activate' && method === 'POST') {
      try {
        const body = (await request.json().catch(() => ({}))) as unknown;
        const parsed = LicenseActivationRequestSchema.safeParse(body);
        if (!parsed.success) {
          return new Response(
            JSON.stringify({
              error: 'Invalid activation request',
              details: parsed.error.errors.map((e: { message: string }) => e.message),
            }),
            { status: 400, headers }
          );
        }

        const { activationCode, machineFingerprint } = parsed.data;

        const store = createStore(env, mockDb);
        if (!store) {
          return new Response(JSON.stringify({ error: 'License server storage not configured' }), {
            status: 500,
            headers,
          });
        }

        const record = await store.findByActivationCode(activationCode);
        if (!record) {
          return new Response(JSON.stringify({ error: 'Activation code not found or invalid' }), {
            status: 404,
            headers,
          });
        }

        if (record.status !== 'ACTIVE') {
          return new Response(
            JSON.stringify({
              error: `License is ${record.status.toLowerCase()} and cannot be activated`,
            }),
            { status: 403, headers }
          );
        }

        const now = Math.floor(Date.now() / 1000);
        if (record.expires_at <= now) {
          return new Response(
            JSON.stringify({ error: 'License has expired. Please renew your subscription.' }),
            { status: 410, headers }
          );
        }

        const trimmedFp = machineFingerprint ? machineFingerprint.trim() : '';
        if (!trimmedFp || trimmedFp.length < 1 || trimmedFp.length > 256) {
          return new Response(JSON.stringify({ error: 'MACHINE_FINGERPRINT_REQUIRED' }), {
            status: 400,
            headers,
          });
        }

        const privateKey = env.JWT_PRIVATE_KEY;
        if (!privateKey) {
          return new Response(
            JSON.stringify({ error: 'License server signing key not configured' }),
            { status: 500, headers }
          );
        }

        let claimResult;
        try {
          claimResult = await store.claimSeat(record.id, trimmedFp, record.seats, now);
        } catch {
          return new Response(JSON.stringify({ error: 'Failed to record activation' }), {
            status: 500,
            headers,
          });
        }
        if (!claimResult.success) {
          if (claimResult.error === 'SEATS_EXCEEDED') {
            return new Response(
              JSON.stringify({
                error: 'SEATS_EXCEEDED',
                message: 'License seat limit reached',
              }),
              { status: 403, headers }
            );
          }
          return new Response(JSON.stringify({ error: 'Failed to record activation' }), {
            status: 500,
            headers,
          });
        }

        const tierCaps = TIER_CAPABILITY_DEFAULTS[record.tier];
        const payload: ServerJwtPayload = {
          lid: record.id,
          sub: record.email ?? 'user@company.com',
          tier: record.tier,
          seats: record.seats,
          orgId: record.org_id,
          iat: now,
          exp: record.expires_at,
          maxMonthlyAiFixes: tierCaps.maxMonthlyAiFixes,
          allowCallPathReachability: tierCaps.allowCallPathReachability,
          allowCiCdGatekeeper: tierCaps.allowCiCdGatekeeper,
          allowSignedComplianceExport: tierCaps.allowSignedComplianceExport,
          allowAirGappedOnPrem: tierCaps.allowAirGappedOnPrem,
          featureFlags: {},
        };

        let jwt: string;
        try {
          jwt = await signJwtWebCrypto(payload, privateKey);
        } catch {
          if (!claimResult.isExisting) {
            try {
              await store.releaseActivation(record.id, trimmedFp);
            } catch {
              // Best-effort cleanup
            }
          }
          return new Response(
            JSON.stringify({
              error: 'Failed to sign activation token',
            }),
            { status: 500, headers }
          );
        }

        return new Response(
          JSON.stringify({
            success: true,
            jwt,
            tier: record.tier,
            expiresAt: new Date(record.expires_at * 1000).toISOString(),
            message: `License successfully activated for tier ${record.tier}.`,
          }),
          { status: 200, headers }
        );
      } catch (err) {
        return new Response(
          JSON.stringify({
            error: `Activation error: ${err instanceof Error ? err.message : String(err)}`,
          }),
          { status: 500, headers }
        );
      }
    }

    // 3. POST /v1/deactivate
    if (url.pathname === '/v1/deactivate' && method === 'POST') {
      try {
        const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
        const activationCode =
          typeof body?.['activationCode'] === 'string' ? body['activationCode'].trim() : '';
        const machineFingerprint =
          typeof body?.['machineFingerprint'] === 'string' ? body['machineFingerprint'].trim() : '';

        if (!activationCode || !machineFingerprint) {
          return new Response(
            JSON.stringify({ error: 'Activation code and machine fingerprint are required' }),
            { status: 400, headers }
          );
        }

        const store = createStore(env, mockDb);
        if (!store) {
          return new Response(JSON.stringify({ error: 'LICENSE_STORE_UNAVAILABLE' }), {
            status: 500,
            headers,
          });
        }

        let record: LicenseRecord | null = null;
        try {
          record = await store.findByActivationCode(activationCode);
        } catch {
          return new Response(JSON.stringify({ error: 'LICENSE_STORE_UNAVAILABLE' }), {
            status: 500,
            headers,
          });
        }

        if (!record) {
          return new Response(JSON.stringify({ error: 'Activation code not found or invalid' }), {
            status: 404,
            headers,
          });
        }

        let released = false;
        try {
          released = await store.releaseActivation(record.id, machineFingerprint);
        } catch {
          return new Response(JSON.stringify({ error: 'LICENSE_STORE_UNAVAILABLE' }), {
            status: 500,
            headers,
          });
        }

        return new Response(JSON.stringify({ success: true, released }), { status: 200, headers });
      } catch (err) {
        return new Response(
          JSON.stringify({
            error: `Deactivation error: ${err instanceof Error ? err.message : String(err)}`,
          }),
          { status: 500, headers }
        );
      }
    }

    // 4. GET /v1/validate (Background Refresh)
    if (url.pathname === '/v1/validate' && method === 'GET') {
      const authHeader = request.headers.get('Authorization') ?? '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim();

      if (!token) {
        return new Response(JSON.stringify({ valid: false, error: 'Missing Bearer token' }), {
          status: 401,
          headers,
        });
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        return new Response(JSON.stringify({ valid: false, error: 'Malformed token' }), {
          status: 400,
          headers,
        });
      }

      if (!env.JWT_PUBLIC_KEY) {
        return new Response(
          JSON.stringify({
            valid: false,
            error: 'License server verification key not configured',
          }),
          { status: 500, headers }
        );
      }

      const verifyResult = await verifyJwtWebCrypto(token, env.JWT_PUBLIC_KEY);
      if (!verifyResult.ok) {
        if (verifyResult.reason === 'EXPIRED') {
          return new Response(JSON.stringify({ valid: false, error: 'License token expired' }), {
            status: 410,
            headers,
          });
        }
        return new Response(JSON.stringify({ valid: false, error: 'Invalid token' }), {
          status: 401,
          headers,
        });
      }

      const payload = verifyResult.payload;

      if (!payload.lid) {
        return new Response(
          JSON.stringify({
            valid: false,
            error: 'Token does not reference a license; re-activate',
          }),
          { status: 401, headers }
        );
      }

      const store = createStore(env, mockDb);
      if (!store) {
        return new Response(JSON.stringify({ valid: false, error: 'LICENSE_STORE_UNAVAILABLE' }), {
          status: 500,
          headers,
        });
      }

      let record: LicenseRecord | null = null;
      try {
        record = await store.findById(payload.lid);
      } catch {
        return new Response(JSON.stringify({ valid: false, error: 'LICENSE_STORE_UNAVAILABLE' }), {
          status: 500,
          headers,
        });
      }

      if (!record) {
        return new Response(JSON.stringify({ valid: false, error: 'License not found' }), {
          status: 404,
          headers,
        });
      }

      const now = Math.floor(Date.now() / 1000);
      if (record.status !== 'ACTIVE') {
        const isRevoked = record.status === 'REVOKED';
        return new Response(
          JSON.stringify({
            valid: false,
            error: isRevoked ? 'License is revoked' : 'License is expired',
            code: isRevoked ? 'LICENSE_REVOKED' : 'LICENSE_EXPIRED',
          }),
          { status: 403, headers }
        );
      }

      if (record.expires_at <= now) {
        return new Response(JSON.stringify({ valid: false, error: 'License expired' }), {
          status: 410,
          headers,
        });
      }

      const secondsRemaining = payload.exp - now;
      let refreshedJwt: string | undefined;

      if (secondsRemaining < 7 * 86400 && env.JWT_PRIVATE_KEY) {
        const tierCaps = TIER_CAPABILITY_DEFAULTS[record.tier];
        const refreshedExp = Math.min(now + 30 * 86400, record.expires_at);
        const refreshedPayload: ServerJwtPayload = {
          lid: record.id,
          sub: record.email ?? 'user@company.com',
          tier: record.tier,
          seats: record.seats,
          orgId: record.org_id,
          iat: now,
          exp: refreshedExp,
          maxMonthlyAiFixes: tierCaps.maxMonthlyAiFixes,
          allowCallPathReachability: tierCaps.allowCallPathReachability,
          allowCiCdGatekeeper: tierCaps.allowCiCdGatekeeper,
          allowSignedComplianceExport: tierCaps.allowSignedComplianceExport,
          allowAirGappedOnPrem: tierCaps.allowAirGappedOnPrem,
          featureFlags: {},
        };

        try {
          refreshedJwt = await signJwtWebCrypto(refreshedPayload, env.JWT_PRIVATE_KEY);
        } catch {
          return new Response(
            JSON.stringify({ valid: false, error: 'Failed to sign refreshed token' }),
            { status: 500, headers }
          );
        }
      }

      void store.touchActivation(record.id, now);

      return new Response(
        JSON.stringify({
          valid: true,
          tier: record.tier,
          expiresAt: new Date(payload.exp * 1000).toISOString(),
          refreshedJwt,
        }),
        { status: 200, headers }
      );
    }

    // 5. POST /v1/webhook/stripe
    if (url.pathname === '/v1/webhook/stripe' && method === 'POST') {
      // 1. env.STRIPE_WEBHOOK_SECRET missing: 500 {error:'Stripe webhook secret not configured'}. Do not read body.
      if (!env.STRIPE_WEBHOOK_SECRET) {
        return new Response(JSON.stringify({ error: 'Stripe webhook secret not configured' }), {
          status: 500,
          headers,
        });
      }

      // 2. content-length over 1 MiB: 413 {error:'Payload too large'}.
      const clHeader = request.headers.get('content-length');
      if (clHeader) {
        const cl = parseInt(clHeader, 10);
        if (!isNaN(cl) && cl > 1024 * 1024) {
          return new Response(JSON.stringify({ error: 'Payload too large' }), {
            status: 413,
            headers,
          });
        }
      }

      // 3. Read body once with arrayBuffer(). Check actual size.
      const rawBuffer = await request.arrayBuffer();
      if (rawBuffer.byteLength > 1024 * 1024) {
        return new Response(JSON.stringify({ error: 'Payload too large' }), {
          status: 413,
          headers,
        });
      }
      const rawBody = new Uint8Array(rawBuffer);

      // Verify stripe-signature header. Missing or verification fails: 400 {error:'Invalid Stripe signature'}. No store access.
      const sigHeader = request.headers.get('stripe-signature');
      if (!sigHeader) {
        return new Response(JSON.stringify({ error: 'Invalid Stripe signature' }), {
          status: 400,
          headers,
        });
      }

      const isValidSig = await verifyStripeSignatureWebCrypto(
        rawBody,
        sigHeader,
        env.STRIPE_WEBHOOK_SECRET
      );
      if (!isValidSig) {
        return new Response(JSON.stringify({ error: 'Invalid Stripe signature' }), {
          status: 400,
          headers,
        });
      }

      // 4. Decode and JSON.parse. Failure, non-object, or missing string id/type: 400 {error:'Invalid event payload'}.
      let event: Record<string, unknown>;
      try {
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(rawBody);
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return new Response(JSON.stringify({ error: 'Invalid event payload' }), {
            status: 400,
            headers,
          });
        }
        if (
          typeof parsed.id !== 'string' ||
          !parsed.id ||
          typeof parsed.type !== 'string' ||
          !parsed.type
        ) {
          return new Response(JSON.stringify({ error: 'Invalid event payload' }), {
            status: 400,
            headers,
          });
        }
        event = parsed as Record<string, unknown>;
      } catch {
        return new Response(JSON.stringify({ error: 'Invalid event payload' }), {
          status: 400,
          headers,
        });
      }

      const store = createStore(env, mockDb);
      if (!store) {
        return new Response(JSON.stringify({ error: 'Webhook processing failed' }), {
          status: 500,
          headers,
        });
      }

      const eventId = event['id'] as string;
      const eventType = event['type'] as string;
      const dataObj = (event['data'] as Record<string, unknown> | undefined)?.['object'] as
        | Record<string, unknown>
        | undefined;

      const now = Math.floor(Date.now() / 1000);

      try {
        // Dispatch by event type
        if (
          eventType === 'checkout.session.completed' ||
          eventType === 'checkout.session.async_payment_succeeded'
        ) {
          if (!dataObj) {
            return new Response(
              JSON.stringify({ received: true, ignored: true, reason: 'PAYMENT_NOT_COMPLETED' }),
              { status: 200, headers }
            );
          }

          // Require data.object.payment_status === 'paid' (or 'no_payment_required')
          const paymentStatus = dataObj['payment_status'];
          if (paymentStatus !== 'paid' && paymentStatus !== 'no_payment_required') {
            return new Response(
              JSON.stringify({ received: true, ignored: true, reason: 'PAYMENT_NOT_COMPLETED' }),
              { status: 200, headers }
            );
          }

          // email = customer_details.email ?? customer_email, trimmed and lower-cased
          const custDetails = dataObj['customer_details'] as Record<string, unknown> | undefined;
          const rawEmail = (custDetails?.['email'] ?? dataObj['customer_email']) as
            | string
            | undefined;
          const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';
          if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return new Response(
              JSON.stringify({ received: true, ignored: true, reason: 'MISSING_EMAIL' }),
              { status: 200, headers }
            );
          }

          // Metadata validation
          const meta = (dataObj['metadata'] as Record<string, unknown> | undefined) ?? {};

          // tier: PRO_TEAM or ENTERPRISE (default PRO_TEAM; FREE_BYOK and unknown values rejected)
          let tier: LicenseTier = 'PRO_TEAM';
          if (meta['tier'] !== undefined && meta['tier'] !== '') {
            if (meta['tier'] === 'PRO_TEAM' || meta['tier'] === 'ENTERPRISE') {
              tier = meta['tier'];
            } else {
              return new Response(
                JSON.stringify({ received: true, ignored: true, reason: 'INVALID_METADATA' }),
                { status: 200, headers }
              );
            }
          }

          // seats: integer 1..10000 (default 5)
          let seats = 5;
          if (meta['seats'] !== undefined && meta['seats'] !== '') {
            const rawSeats = meta['seats'];
            const parsedSeats =
              typeof rawSeats === 'number'
                ? rawSeats
                : typeof rawSeats === 'string' && /^\d+$/.test(rawSeats)
                  ? parseInt(rawSeats, 10)
                  : NaN;
            if (Number.isInteger(parsedSeats) && parsedSeats >= 1 && parsedSeats <= 10000) {
              seats = parsedSeats;
            } else {
              return new Response(
                JSON.stringify({ received: true, ignored: true, reason: 'INVALID_METADATA' }),
                { status: 200, headers }
              );
            }
          }

          // org_id: match /^[A-Za-z0-9._-]{1,64}$/ (default 'individual')
          let orgId = 'individual';
          if (meta['org_id'] !== undefined && meta['org_id'] !== '') {
            const rawOrg = meta['org_id'];
            if (typeof rawOrg === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(rawOrg)) {
              orgId = rawOrg;
            } else {
              return new Response(
                JSON.stringify({ received: true, ignored: true, reason: 'INVALID_METADATA' }),
                { status: 200, headers }
              );
            }
          }

          const sessionId = dataObj['id'] as string;
          if (!sessionId) {
            return new Response(
              JSON.stringify({ received: true, ignored: true, reason: 'INVALID_PAYLOAD' }),
              { status: 200, headers }
            );
          }
          const subscriptionId = (dataObj['subscription'] as string | undefined) ?? null;
          const stripeCustomerId = (dataObj['customer'] as string | undefined) ?? null;

          // Duplicate handling (D2): before batch check stripe_events for event id and licenses for session id
          const existingEvent = await store.hasStripeEvent(eventId);
          const existingLic = await store.findLicenseByCheckoutSession(sessionId);
          if (existingEvent || existingLic) {
            return new Response(JSON.stringify({ received: true, duplicate: true }), {
              status: 200,
              headers,
            });
          }

          const expiresAt = now + LICENSE_TERM_SECONDS;
          let createdLicenseId: string | null = null;

          // Retry loop (up to 3 attempts) for activation code collisions
          for (let attempt = 0; attempt < 3; attempt++) {
            const activationCode = generateActivationCode(tier);
            const candidateLicId = crypto.randomUUID();

            try {
              const res = await store.createLicenseFromCheckout({
                eventId,
                eventType,
                email,
                stripeCustomerId,
                licenseId: candidateLicId,
                activationCode,
                tier,
                seats,
                orgId,
                expiresAt,
                now,
                subscriptionId,
                checkoutSessionId: sessionId,
              });
              createdLicenseId = res.licenseId;
              break;
            } catch {
              // Re-check duplicate conditions independent of error-message text
              const recheckEvent = await store.hasStripeEvent(eventId);
              const recheckLic = await store.findLicenseByCheckoutSession(sessionId);
              if (recheckEvent || recheckLic) {
                return new Response(JSON.stringify({ received: true, duplicate: true }), {
                  status: 200,
                  headers,
                });
              }
            }
          }

          if (!createdLicenseId) {
            return new Response(JSON.stringify({ error: 'Webhook processing failed' }), {
              status: 500,
              headers,
            });
          }

          return new Response(
            JSON.stringify({
              received: true,
              action: 'license_created',
              licenseId: createdLicenseId,
            }),
            { status: 200, headers }
          );
        }

        if (eventType === 'customer.subscription.deleted') {
          const subscriptionId = dataObj?.['id'] as string | undefined;
          if (!subscriptionId) {
            return new Response(JSON.stringify({ received: true, ignored: true }), {
              status: 200,
              headers,
            });
          }

          const isDuplicate = await store.hasStripeEvent(eventId);
          if (isDuplicate) {
            return new Response(JSON.stringify({ received: true, duplicate: true }), {
              status: 200,
              headers,
            });
          }

          let revoked = 0;
          try {
            const res = await store.revokeSubscription({
              eventId,
              eventType,
              subscriptionId,
              now,
            });
            revoked = res.revoked;
          } catch {
            const recheckEvent = await store.hasStripeEvent(eventId);
            if (recheckEvent) {
              return new Response(JSON.stringify({ received: true, duplicate: true }), {
                status: 200,
                headers,
              });
            }
            throw new Error('Failed to revoke subscription');
          }

          return new Response(
            JSON.stringify({ received: true, action: 'license_revoked', revoked }),
            { status: 200, headers }
          );
        }

        if (eventType === 'invoice.paid') {
          const subscriptionId = dataObj?.['subscription'] as string | undefined;
          const lines = (dataObj?.['lines'] as Record<string, unknown> | undefined)?.['data'] as
            | Array<Record<string, unknown>>
            | undefined;

          let periodEnd = 0;
          if (Array.isArray(lines) && lines.length > 0) {
            for (const line of lines) {
              const pEnd = (line['period'] as Record<string, unknown> | undefined)?.['end'];
              if (typeof pEnd === 'number' && Number.isInteger(pEnd)) {
                if (pEnd > periodEnd) periodEnd = pEnd;
              }
            }
          }

          if (!subscriptionId || periodEnd === 0) {
            return new Response(JSON.stringify({ received: true, ignored: true }), {
              status: 200,
              headers,
            });
          }

          const isDuplicate = await store.hasStripeEvent(eventId);
          if (isDuplicate) {
            return new Response(JSON.stringify({ received: true, duplicate: true }), {
              status: 200,
              headers,
            });
          }

          let renewed = 0;
          try {
            const res = await store.renewSubscription({
              eventId,
              eventType,
              subscriptionId,
              periodEnd,
              now,
            });
            renewed = res.renewed;
          } catch {
            const recheckEvent = await store.hasStripeEvent(eventId);
            if (recheckEvent) {
              return new Response(JSON.stringify({ received: true, duplicate: true }), {
                status: 200,
                headers,
              });
            }
            throw new Error('Failed to renew subscription');
          }

          return new Response(
            JSON.stringify({ received: true, action: 'license_renewed', renewed }),
            { status: 200, headers }
          );
        }

        // Any other event type: 200 {received:true, ignored:true}
        return new Response(JSON.stringify({ received: true, ignored: true }), {
          status: 200,
          headers,
        });
      } catch {
        return new Response(JSON.stringify({ error: 'Webhook processing failed' }), {
          status: 500,
          headers,
        });
      }
    }

    return new Response(JSON.stringify({ error: 'Endpoint not found' }), {
      status: 404,
      headers,
    });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return LicenseWorker.handleRequest(request, env);
  },
};
