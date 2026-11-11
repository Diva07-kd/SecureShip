import { describe, it, expect, vi, afterEach } from 'vitest';
import defaultWorker, { LicenseWorker, type Env } from '../src/worker.js';
import { SERVER_KEYS, createMockDb, activateHelper, signWith } from './fixtures.js';
import { verifyLicenseJwt } from '../../core-engine/src/license/license-validator.js';

describe('LAYER F: Regression and Compatibility Suite', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.SECURESHIP_PUBLIC_KEY;
  });

  const nowEpoch = Math.floor(Date.now() / 1000);
  const env: Env = {
    JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
    JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
    STRIPE_WEBHOOK_SECRET: 'whsec_layer_f_stripe_secret',
  };

  async function signStripe(body: string): Promise<string> {
    const timestamp = nowEpoch;
    const prefixBytes = new TextEncoder().encode(`${timestamp}.`);
    const bodyBytes = new TextEncoder().encode(body);
    const message = new Uint8Array(prefixBytes.length + bodyBytes.length);
    message.set(prefixBytes, 0);
    message.set(bodyBytes, prefixBytes.length);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET!),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const sigBuffer = await crypto.subtle.sign('HMAC', cryptoKey, message);
    const sigBytes = new Uint8Array(sigBuffer);
    let v1 = '';
    for (let i = 0; i < sigBytes.length; i++) {
      v1 += sigBytes[i]!.toString(16).padStart(2, '0');
    }
    return `t=${timestamp},v1=${v1}`;
  }

  // F1: Unchanged baseline tests still pass
  it('F1.1: baseline GET /v1/health serves 200 successfully', async () => {
    const mockDb = createMockDb(nowEpoch);
    const req = new Request('https://license.secureship.dev/v1/health', {
      method: 'GET',
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; service: string };
    expect(body.status).toBe('ok');
    expect(body.service).toBe('secureship-license-server');
  });

  it('F1.2: baseline POST /v1/activate returns 404 for unknown activation code', async () => {
    const mockDb = createMockDb(nowEpoch);
    const req = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-NONEXISTENT',
        machineFingerprint: 'machine-id-77',
      }),
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain('not found');
  });

  it('F1.3: baseline POST /v1/activate returns 410 for expired license code', async () => {
    const mockDb = createMockDb(nowEpoch);
    const req = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-EXPIRED-TIME',
        machineFingerprint: 'machine-id-77',
      }),
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(410);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain('expired');
  });

  it('F1.4: baseline POST /v1/webhook/stripe handles Stripe checkout events (byte-for-byte assertions)', async () => {
    const mockDb = createMockDb(nowEpoch);
    const raw = JSON.stringify({
      id: 'evt_f1_4',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_f1_4',
          payment_status: 'paid',
          customer_details: { email: 'newbuyer@enterprise.com' },
          metadata: { tier: 'PRO_TEAM', seats: 5, org_id: 'enterprise-inc' },
        },
      },
    });
    const sig = await signStripe(raw);
    const webhookReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: raw,
    });
    const res = await LicenseWorker.handleRequest(webhookReq, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { received: boolean; action: string };
    expect(body.received).toBe(true);
    expect(body.action).toBe('license_created');
  });

  // F2: CORS headers and OPTIONS preflight response are unchanged (golden assertion)
  it('F2: OPTIONS preflight response and CORS headers match golden baseline spec', async () => {
    const mockDb = createMockDb(nowEpoch);
    const optionsReq = new Request('https://license.secureship.dev/v1/activate', {
      method: 'OPTIONS',
    });
    const optionsRes = await LicenseWorker.handleRequest(optionsReq, env, mockDb);

    expect(optionsRes.status).toBe(204);
    expect(optionsRes.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(optionsRes.headers.get('Access-Control-Allow-Methods')).toBe('GET, POST, OPTIONS');
    expect(optionsRes.headers.get('Access-Control-Allow-Headers')).toBe(
      'Content-Type, Authorization'
    );

    // Also assert JSON responses include CORS header
    const healthReq = new Request('https://license.secureship.dev/v1/health', { method: 'GET' });
    const healthRes = await LicenseWorker.handleRequest(healthReq, env, mockDb);
    expect(healthRes.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(healthRes.headers.get('Content-Type')).toBe('application/json');
  });

  // F3: Client compatibility: verify server-issued token with REAL client verifier from core-engine
  it('F3: server-issued token (including lid) validates with real core-engine verifyLicenseJwt via key injection', async () => {
    const mockDb = createMockDb(nowEpoch);
    const { jwt } = await activateHelper(env, mockDb, 'SS-PRO-ACTIVE-0001', 'client-compat-fp');
    expect(typeof jwt).toBe('string');

    // 1. Injected test public key via environment variable injection point
    process.env.SECURESHIP_PUBLIC_KEY = SERVER_KEYS.publicKey;
    const clientValidationResult = verifyLicenseJwt(jwt!, undefined, nowEpoch);

    expect(clientValidationResult.valid).toBe(true);
    expect(clientValidationResult.payload).toBeDefined();
    expect(clientValidationResult.payload?.tier).toBe('PRO_TEAM');
    expect(clientValidationResult.payload?.seats).toBe(2);
    expect(clientValidationResult.payload?.sub).toBe('pro@acme.com');

    // 2. Negative test: verify that without the injection point, the hardcoded SECURESHIP_PUBLIC_KEY_PEM fails
    delete process.env.SECURESHIP_PUBLIC_KEY;
    const defaultValidationResult = verifyLicenseJwt(jwt!, undefined, nowEpoch);
    expect(defaultValidationResult.valid).toBe(false);
    expect(defaultValidationResult.error).toContain('Cryptographic signature mismatch');

    // 3. Direct parameter injection point
    const paramValidationResult = verifyLicenseJwt(jwt!, SERVER_KEYS.publicKey, nowEpoch);
    expect(paramValidationResult.valid).toBe(true);
    expect(paramValidationResult.payload?.tier).toBe('PRO_TEAM');
  });

  // F4: Default fetch export never uses mock storage
  it('F4: default fetch export with env.DB undefined returns 500 LICENSE_STORE_UNAVAILABLE and never reads Map', async () => {
    const defaultEnv: Env = {
      JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
      JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
    };

    // 1. GET /v1/validate with valid token
    const token = await activateHelper(
      env,
      createMockDb(nowEpoch),
      'SS-PRO-ACTIVE-0001',
      'temp-fp'
    ).then((r) => r.jwt!);

    const valReq = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    const valRes = await defaultWorker.fetch(valReq, defaultEnv);

    expect(valRes.status).toBe(500);
    const valBody = (await valRes.json()) as Record<string, unknown>;
    expect(valBody).toEqual({
      valid: false,
      error: 'LICENSE_STORE_UNAVAILABLE',
    });

    // 2. POST /v1/activate with valid payload
    const actReq = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-ACTIVE-0001',
        machineFingerprint: 'temp-fp',
      }),
    });
    const actRes = await defaultWorker.fetch(actReq, defaultEnv);

    expect(actRes.status).toBe(500);
    const actBody = (await actRes.json()) as Record<string, unknown>;
    expect(actBody['error']).toBe('License server storage not configured');
  });

  // F5: Full Stripe webhook handling coverage (cancellation, ignored events, errors)
  it('F5.1: POST /v1/webhook/stripe handles customer.subscription.deleted with license_revoked', async () => {
    const mockDb = createMockDb(nowEpoch);
    const raw = JSON.stringify({
      id: 'evt_f5_1',
      type: 'customer.subscription.deleted',
      data: { object: { id: 'sub_123' } },
    });
    const sig = await signStripe(raw);
    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: raw,
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ received: true, action: 'license_revoked', revoked: 0 });
  });

  it('F5.2: POST /v1/webhook/stripe ignores unhandled event types', async () => {
    const mockDb = createMockDb(nowEpoch);
    const raw = JSON.stringify({
      id: 'evt_f5_2',
      type: 'payment_intent.created',
    });
    const sig = await signStripe(raw);
    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: raw,
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ received: true, ignored: true });
  });

  it('F5.3: POST /v1/webhook/stripe gracefully handles unparseable JSON by returning 400', async () => {
    const mockDb = createMockDb(nowEpoch);
    const raw = '{invalid-json';
    const sig = await signStripe(raw);
    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: raw,
    });

    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body['error']).toBe('Invalid event payload');
  });

  // F6: Unknown route returns 404 Endpoint not found
  it('F6: returns 404 Endpoint not found for unrecognized endpoints', async () => {
    const mockDb = createMockDb(nowEpoch);
    const req = new Request('https://license.secureship.dev/v1/unknown-endpoint', {
      method: 'GET',
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(404);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ error: 'Endpoint not found' });
  });

  // F7: Refresh signing failure returns 500 Failed to sign refreshed token
  it('F7: GET /v1/validate returns 500 Failed to sign refreshed token if signing key throws during refresh', async () => {
    const mockDb = createMockDb(nowEpoch);
    const { jwt } = await activateHelper(env, mockDb, 'SS-ENT-REFRESH-3D', 'refresh-sign-fail-fp');
    expect(typeof jwt).toBe('string');

    // Provide broken private key that fails during signing
    const envBadPrivKey: Env = {
      JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
      JWT_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nBAD_KEY\n-----END PRIVATE KEY-----',
    };

    const valReq = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${jwt}` },
    });
    const valRes = await LicenseWorker.handleRequest(valReq, envBadPrivKey, mockDb);

    expect(valRes.status).toBe(500);
    const body = (await valRes.json()) as Record<string, unknown>;
    expect(body).toEqual({
      valid: false,
      error: 'Failed to sign refreshed token',
    });
  });

  // F8: GET /v1/validate without Bearer token returns 401 Missing Bearer token
  it('F8: GET /v1/validate without Bearer token returns 401 Missing Bearer token', async () => {
    const mockDb = createMockDb(nowEpoch);
    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(401);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ valid: false, error: 'Missing Bearer token' });
  });

  // F9: GET /v1/validate with expired token returns 410 License token expired
  it('F9: GET /v1/validate with expired token returns 410 License token expired', async () => {
    const mockDb = createMockDb(nowEpoch);
    const expiredPayload = {
      sub: 'user_123',
      tier: 'PRO_TEAM',
      seats: 1,
      orgId: 'org_123',
      maxMonthlyAiFixes: 100,
      iat: nowEpoch - 7200,
      exp: nowEpoch - 3600,
      lid: 'lic_active_001',
    };
    const expiredJwt = signWith(
      SERVER_KEYS.privateKey,
      { alg: 'RS256', typ: 'JWT' },
      expiredPayload
    );
    const req = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${expiredJwt}` },
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    expect(res.status).toBe(410);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ valid: false, error: 'License token expired' });
  });
});
