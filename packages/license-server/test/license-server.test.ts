import { describe, it, expect } from 'vitest';
import { LicenseWorker, type LicenseRecord, type Env } from '../src/worker.js';
import crypto from 'node:crypto';

describe('Cloudflare License Server Worker (Phase 5 Backend) — Baseline Suite', () => {
  // Generate test RSA keypair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const STRIPE_SECRET = 'whsec_test_stripe_webhook_secret_key_123';

  const env: Env = {
    JWT_PRIVATE_KEY: privateKey,
    JWT_PUBLIC_KEY: publicKey,
    STRIPE_WEBHOOK_SECRET: STRIPE_SECRET,
  };

  const mockDb = new Map<string, LicenseRecord>();
  const nowEpoch = Math.floor(Date.now() / 1000);

  // Seed mock database with an active PRO_TEAM license
  mockDb.set('SS-PRO-VALID-1234', {
    id: 'lic_123',
    customer_id: 'cust_456',
    activation_code: 'SS-PRO-VALID-1234',
    tier: 'PRO_TEAM',
    seats: 10,
    org_id: 'acme-corp',
    status: 'ACTIVE',
    expires_at: nowEpoch + 30 * 86400,
    email: 'billing@acme.com',
  });

  // Seed an expired license
  mockDb.set('SS-PRO-EXPIRED-9999', {
    id: 'lic_999',
    customer_id: 'cust_999',
    activation_code: 'SS-PRO-EXPIRED-9999',
    tier: 'PRO_TEAM',
    seats: 2,
    org_id: 'old-corp',
    status: 'ACTIVE',
    expires_at: nowEpoch - 1000, // Expired
    email: 'expired@old.com',
  });

  async function createStripeSignatureHeader(
    rawBody: string | Uint8Array,
    secret: string,
    timestamp: number = Math.floor(Date.now() / 1000)
  ): Promise<string> {
    const prefixBytes = new TextEncoder().encode(`${timestamp}.`);
    const bodyBytes = typeof rawBody === 'string' ? new TextEncoder().encode(rawBody) : rawBody;
    const message = new Uint8Array(prefixBytes.length + bodyBytes.length);
    message.set(prefixBytes, 0);
    message.set(bodyBytes, prefixBytes.length);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
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

  // Baseline Test 1
  it('serves GET /v1/health successfully', async () => {
    const req = new Request('https://license.secureship.dev/v1/health', {
      method: 'GET',
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; service: string };
    expect(body.status).toBe('ok');
    expect(body.service).toBe('secureship-license-server');
  });

  // Baseline Test 2 (Adjusted per DEV-7: machineFingerprint added)
  it('activates valid license code via POST /v1/activate and returns signed JWT', async () => {
    const req = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-VALID-1234',
        machineFingerprint: 'machine-id-77',
      }),
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; jwt: string; tier: string };
    expect(body.success).toBe(true);
    expect(body.tier).toBe('PRO_TEAM');
    expect(typeof body.jwt).toBe('string');
    expect(body.jwt.split('.').length).toBe(3);
  });

  // Baseline Test 3
  it('returns 404 for unknown activation code', async () => {
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

  // Baseline Test 4
  it('returns 410 for expired license code', async () => {
    const req = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-EXPIRED-9999',
        machineFingerprint: 'machine-id-77',
      }),
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);

    expect(res.status).toBe(410);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain('expired');
  });

  // Baseline Test 5 (Adjusted per DEV-7: machineFingerprint added)
  it('handles GET /v1/validate with Bearer token', async () => {
    // First activate to get a valid token
    const actReq = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-VALID-1234',
        machineFingerprint: 'machine-validate-1',
      }),
    });
    const actRes = await LicenseWorker.handleRequest(actReq, env, mockDb);
    const { jwt } = (await actRes.json()) as { jwt: string };

    const valReq = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${jwt}`,
      },
    });
    const valRes = await LicenseWorker.handleRequest(valReq, env, mockDb);

    expect(valRes.status).toBe(200);
    const valBody = (await valRes.json()) as { valid: boolean; tier: string };
    expect(valBody.valid).toBe(true);
    expect(valBody.tier).toBe('PRO_TEAM');
  });

  // Baseline Test 6 (Adjusted per DEV-9: signed Stripe webhook)
  it('handles Stripe webhook events on POST /v1/webhook/stripe', async () => {
    const rawPayload = JSON.stringify({
      id: 'evt_baseline_test_123',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_baseline_test_123',
          payment_status: 'paid',
          customer_details: { email: 'newbuyer@enterprise.com' },
          metadata: {
            tier: 'PRO_TEAM',
            seats: 5,
            org_id: 'enterprise-inc',
          },
        },
      },
    });

    const sigHeader = await createStripeSignatureHeader(rawPayload, STRIPE_SECRET);

    const webhookReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': sigHeader,
      },
      body: rawPayload,
    });
    const res = await LicenseWorker.handleRequest(webhookReq, env, mockDb);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { received: boolean; action: string };
    expect(body.received).toBe(true);
    expect(body.action).toBe('license_created');

    // Replay identical request: returns 200 { received: true, duplicate: true }
    const replayReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': sigHeader,
      },
      body: rawPayload,
    });
    const replayRes = await LicenseWorker.handleRequest(replayReq, env, mockDb);
    expect(replayRes.status).toBe(200);
    const replayBody = (await replayRes.json()) as { received: boolean; duplicate: boolean };
    expect(replayBody.received).toBe(true);
    expect(replayBody.duplicate).toBe(true);

    // Tamper one byte in the payload: signature mismatch returns 400
    const tamperedPayload = rawPayload.replace(
      'newbuyer@enterprise.com',
      'tampered@enterprise.com'
    );
    const tamperedReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': sigHeader,
      },
      body: tamperedPayload,
    });
    const tamperedRes = await LicenseWorker.handleRequest(tamperedReq, env, mockDb);
    expect(tamperedRes.status).toBe(400);
    const tamperedBody = (await tamperedRes.json()) as { error: string };
    expect(tamperedBody.error).toBe('Invalid Stripe signature');

    // Missing stripe-signature header returns 400
    const unsignedReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: rawPayload,
    });
    const unsignedRes = await LicenseWorker.handleRequest(unsignedReq, env, mockDb);
    expect(unsignedRes.status).toBe(400);
    const unsignedBody = (await unsignedRes.json()) as { error: string };
    expect(unsignedBody.error).toBe('Invalid Stripe signature');

    // Renewal event: invoice.paid
    const renewalPayload = JSON.stringify({
      id: 'evt_renewal_test_456',
      type: 'invoice.paid',
      data: {
        object: {
          id: 'in_test_123',
          subscription: 'sub_test_renewal',
          lines: {
            data: [{ period: { end: nowEpoch + 400 * 86400 } }],
          },
        },
      },
    });
    const renewalSig = await createStripeSignatureHeader(renewalPayload, STRIPE_SECRET);
    const renewalReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': renewalSig },
      body: renewalPayload,
    });
    const renewalRes = await LicenseWorker.handleRequest(renewalReq, env, mockDb);
    expect(renewalRes.status).toBe(200);
    const renewalBody = (await renewalRes.json()) as { received: boolean; action: string };
    expect(renewalBody.received).toBe(true);
    expect(renewalBody.action).toBe('license_renewed');

    // Replay invoice.paid returns 200 duplicate
    const replayRenewalReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': renewalSig },
      body: renewalPayload,
    });
    const replayRenewalRes = await LicenseWorker.handleRequest(replayRenewalReq, env, mockDb);
    expect(replayRenewalRes.status).toBe(200);
    const replayRenewalBody = (await replayRenewalRes.json()) as {
      received: boolean;
      duplicate: boolean;
    };
    expect(replayRenewalBody.duplicate).toBe(true);

    // Cancellation event: customer.subscription.deleted
    const cancelPayload = JSON.stringify({
      id: 'evt_cancel_test_789',
      type: 'customer.subscription.deleted',
      data: {
        object: {
          id: 'sub_test_renewal',
        },
      },
    });
    const cancelSig = await createStripeSignatureHeader(cancelPayload, STRIPE_SECRET);
    const cancelReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': cancelSig },
      body: cancelPayload,
    });
    const cancelRes = await LicenseWorker.handleRequest(cancelReq, env, mockDb);
    expect(cancelRes.status).toBe(200);
    const cancelBody = (await cancelRes.json()) as { received: boolean; action: string };
    expect(cancelBody.received).toBe(true);
    expect(cancelBody.action).toBe('license_revoked');

    // Replay customer.subscription.deleted returns 200 duplicate
    const replayCancelReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': cancelSig },
      body: cancelPayload,
    });
    const replayCancelRes = await LicenseWorker.handleRequest(replayCancelReq, env, mockDb);
    expect(replayCancelRes.status).toBe(200);
    const replayCancelBody = (await replayCancelRes.json()) as {
      received: boolean;
      duplicate: boolean;
    };
    expect(replayCancelBody.duplicate).toBe(true);
  });
});
