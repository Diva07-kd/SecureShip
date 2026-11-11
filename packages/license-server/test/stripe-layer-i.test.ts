import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LicenseWorker, type Env, type LicenseRecord } from '../src/worker.js';
import {
  createCheckoutSessionCompletedEvent,
  createCustomerSubscriptionDeletedEvent,
  createInvoicePaidEvent,
  DEFAULT_STRIPE_SECRET,
  TEST_RSA_KEYS,
  computeIndependentStripeSignature,
} from './stripe-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('LAYER I: Hygiene and Static Guards (license-server)', () => {
  const secret = DEFAULT_STRIPE_SECRET;
  const fixedNow = 1770000000;

  // I1: Spy on console.*: across ALL webhook operations no call contains secret, signature, email, or activation code
  it('I1: console calls never leak webhook secret, signature, email, or activation code', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const loggedMessages: string[] = [];
    const logSpy = (args: unknown[]) => {
      loggedMessages.push(
        args.map((a) => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ')
      );
    };

    vi.spyOn(console, 'log').mockImplementation((...args) => logSpy(args));
    vi.spyOn(console, 'warn').mockImplementation((...args) => logSpy(args));
    vi.spyOn(console, 'error').mockImplementation((...args) => logSpy(args));
    vi.spyOn(console, 'info').mockImplementation((...args) => logSpy(args));
    vi.spyOn(console, 'debug').mockImplementation((...args) => logSpy(args));

    const mockDb = new Map<string, LicenseRecord>();
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    const targetEmail = 'confidential-customer@privacy.org';
    const targetSessionId = 'cs_secret_session_999';

    // 1. Provision
    const event = createCheckoutSessionCompletedEvent({
      sessionId: targetSessionId,
      email: targetEmail,
      now: fixedNow,
    });
    const rawBody = JSON.stringify(event);
    const { header: sigHeader, v1 } = computeIndependentStripeSignature(rawBody, secret, fixedNow);

    const req1 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sigHeader },
      body: rawBody,
    });
    const res1 = await LicenseWorker.handleRequest(req1, env, mockDb);
    expect(res1.status).toBe(200);

    const lic = Array.from(mockDb.values())[0]!;
    const activationCode = lic.activation_code;

    // 2. Revoke
    const delEvent = createCustomerSubscriptionDeletedEvent({
      subscriptionId: lic.stripe_subscription_id!,
      now: fixedNow + 10,
    });
    const delSig = computeIndependentStripeSignature(
      JSON.stringify(delEvent),
      secret,
      fixedNow + 10
    ).header;
    const req2 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': delSig },
      body: JSON.stringify(delEvent),
    });
    await LicenseWorker.handleRequest(req2, env, mockDb);

    // 3. Renew
    const invEvent = createInvoicePaidEvent([{ periodEnd: fixedNow + 500 * 86400 }], {
      subscriptionId: lic.stripe_subscription_id!,
      now: fixedNow + 20,
    });
    const invSig = computeIndependentStripeSignature(
      JSON.stringify(invEvent),
      secret,
      fixedNow + 20
    ).header;
    const req3 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': invSig },
      body: JSON.stringify(invEvent),
    });
    await LicenseWorker.handleRequest(req3, env, mockDb);

    // Assert that none of the logged text contains secrets or sensitive data
    const allLogs = loggedMessages.join('\n');
    expect(allLogs).not.toContain(secret);
    expect(allLogs).not.toContain(v1);
    expect(allLogs).not.toContain(targetEmail);
    expect(allLogs).not.toContain(activationCode);

    vi.useRealTimers();
  });

  // I2: No node: imports in src; webhook response bodies never contain 'activation', '@', or token strings
  it('I2: src contains zero node: imports and webhook responses never leak activation codes, emails, or tokens', async () => {
    // 1. Static check: no node: imports in packages/license-server/src/
    const srcDir = path.resolve(__dirname, '../src');
    const srcFiles = fs.readdirSync(srcDir).filter((f) => f.endsWith('.ts'));
    expect(srcFiles.length).toBeGreaterThan(0);

    for (const file of srcFiles) {
      const content = fs.readFileSync(path.join(srcDir, file), 'utf-8');
      expect(content).not.toMatch(/from\s+['"]node:/);
      expect(content).not.toMatch(/require\(['"]node:/);
    }

    // 2. Webhook response bodies check across diverse webhook requests
    const mockDb = new Map<string, LicenseRecord>();
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    const event = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_i2_check',
      email: 'sensitive@corp.com',
      now: fixedNow,
    });
    const rawBody = JSON.stringify(event);
    const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: rawBody,
    });
    const res = await LicenseWorker.handleRequest(req, env, mockDb);
    const resText = await res.text();

    expect(resText).not.toContain('activation');
    expect(resText).not.toContain('@');
    expect(resText).not.toMatch(/ey[A-Za-z0-9_-]{10,}\./); // No JWT tokens
  });

  // I3: Existing tests (health, activate 404, activate 410, validate) pass
  it('I3: baseline routes (GET /v1/health, activate 404, activate 410) behave as expected', async () => {
    const mockDb = new Map<string, LicenseRecord>();
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // 1. Health check
    const healthReq = new Request('https://license.secureship.dev/v1/health');
    const healthRes = await LicenseWorker.handleRequest(healthReq, env, mockDb);
    expect(healthRes.status).toBe(200);
    const healthJson = (await healthRes.json()) as { status: string; service: string };
    expect(healthJson.status).toBe('ok');
    expect(healthJson.service).toBe('secureship-license-server');

    // 2. Activate 404 (non-existent code)
    const act404Req = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-NONEXISTENT-9999',
        machineFingerprint: 'machine-123',
      }),
    });
    const act404Res = await LicenseWorker.handleRequest(act404Req, env, mockDb);
    expect(act404Res.status).toBe(404);
    const act404Json = (await act404Res.json()) as { error: string };
    expect(act404Json.error).toContain('not found');

    // 3. Activate 410 (expired license)
    mockDb.set('SS-PRO-EXPIRED-CODE', {
      id: 'lic_expired_test',
      customer_id: 'cust_exp',
      activation_code: 'SS-PRO-EXPIRED-CODE',
      tier: 'PRO_TEAM',
      seats: 5,
      org_id: 'exp-corp',
      status: 'ACTIVE',
      expires_at: fixedNow - 1000, // Expired in past
    });

    const act410Req = new Request('https://license.secureship.dev/v1/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationCode: 'SS-PRO-EXPIRED-CODE',
        machineFingerprint: 'machine-123',
      }),
    });
    const act410Res = await LicenseWorker.handleRequest(act410Req, env, mockDb);
    expect(act410Res.status).toBe(410);
    const act410Json = (await act410Res.json()) as { error: string };
    expect(act410Json.error).toContain('expired');
  });

  // I4: License-server CORS headers and OPTIONS response are unchanged (golden assertion)
  it('I4: license-server CORS headers and OPTIONS preflights remain unchanged', async () => {
    const mockDb = new Map<string, LicenseRecord>();
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    const routes = [
      '/v1/activate',
      '/v1/validate',
      '/v1/deactivate',
      '/v1/webhook/stripe',
      '/v1/health',
    ];

    for (const route of routes) {
      // OPTIONS preflight request
      const optionsReq = new Request(`https://license.secureship.dev${route}`, {
        method: 'OPTIONS',
      });
      const optionsRes = await LicenseWorker.handleRequest(optionsReq, env, mockDb);
      expect(optionsRes.status).toBe(204);
      expect(optionsRes.headers.get('access-control-allow-origin')).toBe('*');
      expect(optionsRes.headers.get('access-control-allow-methods')).toBe('GET, POST, OPTIONS');
      expect(optionsRes.headers.get('access-control-allow-headers')).toBe(
        'Content-Type, Authorization'
      );

      // Regular request carries Access-Control-Allow-Origin: *
      const getReq = new Request(`https://license.secureship.dev${route}`, {
        method: 'GET',
      });
      const getRes = await LicenseWorker.handleRequest(getReq, env, mockDb);
      expect(getRes.headers.get('access-control-allow-origin')).toBe('*');
    }
  });
});
