import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyStripeSignatureWebCrypto } from '../src/worker.js';
import { computeIndependentStripeSignature, DEFAULT_STRIPE_SECRET } from './stripe-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('LAYER A: Stripe Signature Verifier Unit Tests (DEV-1)', () => {
  const secret = DEFAULT_STRIPE_SECRET;
  const samplePayload = JSON.stringify({ id: 'evt_test_123', type: 'charge.succeeded' });
  const fixedNow = 1770000000;

  // A1: Known-answer test
  it('A1: a signature produced by the independent signer verifies true', async () => {
    const { header } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(true);
  });

  // A2: Tampered cases and multi-byte UTF-8
  it('A2.1: wrong secret verifies false', async () => {
    const { header } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const wrongSecret = 'whsec_completely_wrong_secret_key_999';
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      wrongSecret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A2.2: body altered by one byte verifies false', async () => {
    const { header } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const alteredPayload = samplePayload.slice(0, -1) + 'X';
    const result = await verifyStripeSignatureWebCrypto(
      alteredPayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A2.3: re-serialized JSON body (spaces added) verifies false', async () => {
    const { header } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const reserializedWithSpaces = JSON.stringify(JSON.parse(samplePayload), null, 2);
    const result = await verifyStripeSignatureWebCrypto(
      reserializedWithSpaces,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A2.4: different timestamp t verifies false', async () => {
    const { header } = computeIndependentStripeSignature(samplePayload, secret, fixedNow - 10);
    // Header timestamp is fixedNow - 10, but verification message must match header
    // Here we tamper the header to have a different t than signed
    const tamperedHeader = header.replace(`t=${fixedNow - 10}`, `t=${fixedNow - 20}`);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      tamperedHeader,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A2.5: valid multi-byte UTF-8 payload verifies true, tampered multi-byte verifies false', async () => {
    const utf8Payload = JSON.stringify({
      id: 'evt_utf8_123',
      description: 'Acme Corp 🚀 — Über security café 🔒 日本語 test',
    });
    const { header } = computeIndependentStripeSignature(utf8Payload, secret, fixedNow);

    const validResult = await verifyStripeSignatureWebCrypto(
      utf8Payload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(validResult).toBe(true);

    const tamperedUtf8 = utf8Payload.replace('🔒', '🔓');
    const invalidResult = await verifyStripeSignatureWebCrypto(
      tamperedUtf8,
      header,
      secret,
      300,
      fixedNow
    );
    expect(invalidResult).toBe(false);
  });

  // A3: Header shapes with exact outcomes
  it('A3.1: missing header (empty string) returns false', async () => {
    const result = await verifyStripeSignatureWebCrypto(samplePayload, '', secret, 300, fixedNow);
    expect(result).toBe(false);
  });

  it('A3.2: no t returns false', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `v1=${v1}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.3: no v1 returns false', async () => {
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=${fixedNow}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.4: only v0 scheme returns false', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=${fixedNow},v0=${v1}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.5: two t values returns false', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const header = `t=${fixedNow},t=${fixedNow},v1=${v1}`;
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.6: non-numeric t returns false', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=not_a_number,v1=${v1}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.7: t with 13+ digits returns false', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=17700000000001,v1=${v1}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.8: v1 not hex returns false', async () => {
    const nonHexV1 = 'z'.repeat(64);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=${fixedNow},v1=${nonHexV1}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.9: v1 length 63 returns false', async () => {
    const v1_63 = 'a'.repeat(63);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=${fixedNow},v1=${v1_63}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.10: v1 length 65 returns false', async () => {
    const v1_65 = 'a'.repeat(65);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      `t=${fixedNow},v1=${v1_65}`,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A3.11: extra spaces around header items returns true for valid signature', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const headerWithSpaces = `   t = ${fixedNow}  ,   v1 = ${v1}   `;
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      headerWithSpaces,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(true);
  });

  it('A3.12: multiple v1 where only 2nd is valid returns true', async () => {
    const { v1 } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const bogusV1 = '0'.repeat(64);
    const header = `t=${fixedNow},v1=${bogusV1},v1=${v1}`;
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(true);
  });

  it('A3.13: multiple v1 where none is valid returns false', async () => {
    const bogusV1_a = '0'.repeat(64);
    const bogusV1_b = '1'.repeat(64);
    const header = `t=${fixedNow},v1=${bogusV1_a},v1=${bogusV1_b}`;
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  // A4: Tolerance checks
  it('A4.1: age exactly 300 s gives true', async () => {
    const pastTime = fixedNow - 300;
    const { header } = computeIndependentStripeSignature(samplePayload, secret, pastTime);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(true);
  });

  it('A4.2: age 301 s gives false', async () => {
    const pastTime = fixedNow - 301;
    const { header } = computeIndependentStripeSignature(samplePayload, secret, pastTime);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A4.3: future timestamp +300 s gives true', async () => {
    const futureTime = fixedNow + 300;
    const { header } = computeIndependentStripeSignature(samplePayload, secret, futureTime);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(true);
  });

  it('A4.4: future timestamp +301 s gives false', async () => {
    const futureTime = fixedNow + 301;
    const { header } = computeIndependentStripeSignature(samplePayload, secret, futureTime);
    const result = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      secret,
      300,
      fixedNow
    );
    expect(result).toBe(false);
  });

  it('A4.5: custom tolerance of 60 s is honoured (60s true, 61s false)', async () => {
    const time60 = fixedNow - 60;
    const { header: header60 } = computeIndependentStripeSignature(samplePayload, secret, time60);
    const result60 = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header60,
      secret,
      60,
      fixedNow
    );
    expect(result60).toBe(true);

    const time61 = fixedNow - 61;
    const { header: header61 } = computeIndependentStripeSignature(samplePayload, secret, time61);
    const result61 = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header61,
      secret,
      60,
      fixedNow
    );
    expect(result61).toBe(false);
  });

  // A5: Empty/garbage secret and 30+ hostile inputs never throw and return booleans
  it('A5.1: empty secret or garbage secret returns false', async () => {
    const { header } = computeIndependentStripeSignature(samplePayload, secret, fixedNow);
    const emptyResult = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      '',
      300,
      fixedNow
    );
    expect(emptyResult).toBe(false);

    const undefResult = await verifyStripeSignatureWebCrypto(
      samplePayload,
      header,
      undefined as unknown as string,
      300,
      fixedNow
    );
    expect(undefResult).toBe(false);
  });

  it('A5.2: 32 hostile inputs always return a boolean and never throw', async () => {
    const hostileInputs: Array<{ payload: unknown; header: unknown; secret: unknown }> = [
      { payload: '', header: '', secret: '' },
      { payload: null, header: null, secret: null },
      { payload: undefined, header: undefined, secret: undefined },
      { payload: 12345, header: true, secret: {} },
      { payload: {}, header: [], secret: () => {} },
      { payload: '{"a":1}', header: 't=NaN,v1=123', secret: 'sec' },
      { payload: '{"a":1}', header: 't=-100,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1.5,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1e10,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=0x123,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000\u0000,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,\u0000v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,v1=\u0000', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,v1=' + 'f'.repeat(10000), secret: 'sec' },
      { payload: '{"a":1}', header: 't='.repeat(100) + 'v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: ',,,,,,,', secret: 'sec' },
      { payload: '{"a":1}', header: '========', secret: 'sec' },
      {
        payload: '{"a":1}',
        header:
          't=1770000000,v1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,v1=invalid',
        secret: 'sec',
      },
      { payload: '{"a":1}', header: '__proto__=polluted,t=1770000000,v1=123', secret: 'sec' },
      { payload: '{"a":1}', header: 'constructor=evil,t=1770000000,v1=123', secret: 'sec' },
      {
        payload: '{"a":1}',
        header:
          't=1770000000,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz,v1=xyz',
        secret: 'sec',
      },
      { payload: new Uint8Array([0, 1, 2, 255]), header: 't=1770000000,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,v1=abc', secret: '\u0000\u0001\u0002' },
      { payload: '{"a":1}', header: 't=1770000000,v1=abc', secret: 'x'.repeat(100000) },
      { payload: '{"malformed json', header: 't=1770000000,v1=abc', secret: 'sec' },
      { payload: '{"a":' + '9'.repeat(500) + '}', header: 't=1770000000,v1=abc', secret: 'sec' },
      { payload: '🚀💥', header: 't=1770000000,v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,v1=abc,extra=param', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,v2=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000,v256=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000;v1=abc', secret: 'sec' },
      { payload: '{"a":1}', header: 't=1770000000&v1=abc', secret: 'sec' },
    ];

    expect(hostileInputs.length).toBeGreaterThanOrEqual(30);

    for (const item of hostileInputs) {
      const res = await verifyStripeSignatureWebCrypto(
        item.payload as string | Uint8Array,
        item.header as string,
        item.secret as string,
        300,
        fixedNow
      );
      expect(typeof res).toBe('boolean');
      expect(res).toBe(false);
    }
  });

  // A6: Static code guard
  it('A6: worker.ts contains no direct equality comparison of signatures and calls crypto.subtle.verify', () => {
    const workerPath = path.resolve(__dirname, '../src/worker.ts');
    const content = fs.readFileSync(workerPath, 'utf-8');

    // Extract the verifyStripeSignatureWebCrypto function body
    const fnStart = content.indexOf('export async function verifyStripeSignatureWebCrypto');
    expect(fnStart).toBeGreaterThan(-1);

    const fnSnippet = content.slice(fnStart, fnStart + 3500);

    // Verify it uses crypto.subtle.verify
    expect(fnSnippet).toContain('crypto.subtle.verify');

    // Verify no insecure signature equality check
    expect(fnSnippet).not.toMatch(/(?:sig|signature|v1|expectedSig)\s*[!=]==/i);
    expect(fnSnippet).not.toMatch(/[!=]==\s*(?:sig|signature|v1|expectedSig)/i);
  });
});
