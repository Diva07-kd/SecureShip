import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { LicenseWorker, type Env, type LicenseRecord } from '../src/worker.js';
import { verifyLicenseJwt, refreshLicenseInBackground } from '../../core-engine/src/index.js';
import {
  createCheckoutSessionCompletedEvent,
  createInvoicePaidEvent,
  DEFAULT_STRIPE_SECRET,
  TEST_RSA_KEYS,
  computeIndependentStripeSignature,
} from './stripe-fixtures.js';

describe('LAYER H: Cross-Step End-to-End Chain Tests (DEV-3, DEV-5, F-LIC-001)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-chain-test-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  const secret = DEFAULT_STRIPE_SECRET;
  const fixedNow = 1770000000;

  // H1: Sign webhook, receive stored activation code, activate through worker, validate with core-engine client
  it('H1: complete purchase-to-activation flow verifies with core-engine verifyLicenseJwt', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const mockDb = new Map<string, LicenseRecord>();
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // 1. Deliver signed checkout.session.completed webhook
    const event = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_h1_purchase',
      email: 'pilot@defense.corp',
      tier: 'PRO_TEAM',
      seats: 8,
      orgId: 'defense-corp',
      now: fixedNow,
    });
    const rawBody = JSON.stringify(event);
    const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

    const whReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: rawBody,
    });
    const whRes = await LicenseWorker.handleRequest(whReq, env, mockDb);
    expect(whRes.status).toBe(200);

    // Retrieve stored activation code
    const storedLic = Array.from(mockDb.values())[0]!;
    expect(storedLic.tier).toBe('PRO_TEAM');
    expect(storedLic.seats).toBe(8);
    const activationCode = storedLic.activation_code;

    // 2. Activate through the worker
    const actReq = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode,
        machineFingerprint: 'machine-h1-fp',
      }),
    });
    const actRes = await LicenseWorker.handleRequest(actReq, env, mockDb);
    expect(actRes.status).toBe(200);
    const actJson = (await actRes.json()) as { success: boolean; jwt: string };
    expect(actJson.success).toBe(true);
    const issuedJwt = actJson.jwt;

    // 3. Verify issued JWT using real core-engine client verifier
    const verifyResult = verifyLicenseJwt(issuedJwt, TEST_RSA_KEYS.publicKey, fixedNow);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.isExpired).toBe(false);
    expect(verifyResult.payload?.tier).toBe('PRO_TEAM');
    expect(verifyResult.payload?.seats).toBe(8);
    expect(verifyResult.payload?.orgId).toBe('defense-corp');
    expect(verifyResult.payload?.sub).toBe('pilot@defense.corp');

    // 4. Validate through worker endpoint
    const valReq = new Request('https://license.secureship.dev/v1/validate', {
      method: 'GET',
      headers: { Authorization: `Bearer ${issuedJwt}` },
    });
    const valRes = await LicenseWorker.handleRequest(valReq, env, mockDb);
    expect(valRes.status).toBe(200);
    const valJson = (await valRes.json()) as { valid: boolean; tier: string };
    expect(valJson.valid).toBe(true);
    expect(valJson.tier).toBe('PRO_TEAM');

    vi.useRealTimers();
  });

  // H2: Renewal chain closes F-LIC-001:
  // activate a license, fast-forward fake Date to inside last 7 days, deliver signed invoice.paid,
  // run real client refreshLicenseInBackground against worker, local token exp increases and verifies.
  it('H2: background refresh extends token expiration after signed invoice.paid renewal (closes F-LIC-001)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const mockDb = new Map<string, LicenseRecord>();
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // 1. Provision initial license on subscription
    const event = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_h2_sess',
      subscriptionId: 'sub_h2_renew',
      email: 'f-lic-001@example.com',
      tier: 'ENTERPRISE',
      seats: 50,
      now: fixedNow,
    });
    const whSig = computeIndependentStripeSignature(JSON.stringify(event), secret, fixedNow).header;
    const whReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': whSig },
      body: JSON.stringify(event),
    });
    await LicenseWorker.handleRequest(whReq, env, mockDb);

    const lic = Array.from(mockDb.values())[0]!;
    const activationCode = lic.activation_code;

    // 2. Activate initial license
    const actReq = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode,
        machineFingerprint: 'machine-h2-node',
      }),
    });
    const actRes = await LicenseWorker.handleRequest(actReq, env, mockDb);
    const actJson = (await actRes.json()) as { jwt: string };
    const initialJwt = actJson.jwt;

    // Save initial JWT to disk for the client library
    const licenseFilePath = path.join(tempDir, 'license.jwt');
    fs.writeFileSync(licenseFilePath, initialJwt, 'utf-8');

    // Verify initial token
    const initialVerify = verifyLicenseJwt(initialJwt, TEST_RSA_KEYS.publicKey, fixedNow);
    expect(initialVerify.valid).toBe(true);
    const initialExp = initialVerify.payload!.exp;
    expect(initialExp).toBe(fixedNow + 365 * 86400); // Initial 1-year term

    // 3. Fast-forward fake Date to inside the last 7 days of the initial token (5 days remaining)
    const nearExpEpoch = fixedNow + 365 * 86400 - 5 * 86400;
    vi.setSystemTime(nearExpEpoch * 1000);

    // 4. Deliver signed invoice.paid with period.end = fixedNow + 730 days (year 2 renewal)
    const invoiceEvent = createInvoicePaidEvent([{ periodEnd: fixedNow + 730 * 86400 }], {
      id: 'evt_h2_inv_renew',
      subscriptionId: 'sub_h2_renew',
      now: nearExpEpoch,
    });
    const invSig = computeIndependentStripeSignature(
      JSON.stringify(invoiceEvent),
      secret,
      nearExpEpoch
    ).header;
    const invReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': invSig },
      body: JSON.stringify(invoiceEvent),
    });
    const invRes = await LicenseWorker.handleRequest(invReq, env, mockDb);
    expect(invRes.status).toBe(200);

    // 5. Intercept global fetch so refreshLicenseInBackground calls worker handleRequest
    const originalFetch = globalThis.fetch;
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr =
          typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        if (urlStr.includes('/v1/validate')) {
          const req = new Request(urlStr, init);
          return LicenseWorker.handleRequest(req, env, mockDb);
        }
        return originalFetch(input, init);
      }
    );

    // 6. Execute real client background refresh
    await refreshLicenseInBackground(
      licenseFilePath,
      initialJwt,
      'https://license.secureship.dev',
      {
        publicKeyPem: TEST_RSA_KEYS.publicKey,
        now: nearExpEpoch,
      }
    );

    // 7. Verify updated token on disk
    const refreshedJwt = fs.readFileSync(licenseFilePath, 'utf-8');
    expect(refreshedJwt).not.toBe(initialJwt);

    const refreshedVerify = verifyLicenseJwt(refreshedJwt, TEST_RSA_KEYS.publicKey, nearExpEpoch);
    expect(refreshedVerify.valid).toBe(true);
    expect(refreshedVerify.isExpired).toBe(false);
    expect(refreshedVerify.payload!.exp).toBeGreaterThan(nearExpEpoch + 5 * 86400); // Extended beyond old expiry!
    expect(refreshedVerify.payload!.exp).toBe(nearExpEpoch + 30 * 86400);

    vi.useRealTimers();
  });
});
