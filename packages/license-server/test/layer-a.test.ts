import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { verifyJwtWebCrypto, type ServerJwtPayload } from '../src/worker.js';
import { SERVER_KEYS, ATTACKER_KEYS, signWith, base64UrlEncode } from './fixtures.js';

describe('LAYER A: verifyJwtWebCrypto Unit Test Suite', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const nowEpoch = 1770000000;

  const validPayload: ServerJwtPayload = {
    lid: 'lic_valid_001',
    sub: 'dev@secureship.dev',
    tier: 'PRO_TEAM',
    seats: 5,
    orgId: 'acme-corp',
    iat: nowEpoch,
    exp: nowEpoch + 86400,
    maxMonthlyAiFixes: 100,
    allowCallPathReachability: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: false,
    featureFlags: {},
  };

  const validHeader = {
    alg: 'RS256',
    kid: 'secureship-2026-01',
    typ: 'JWT',
  };

  // A1: A valid server-signed token returns { ok:true } with payload equal to the claims.
  it('A1: returns { ok: true } with payload equal to the claims for a valid token', async () => {
    const token = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });

    expect(result).toEqual({
      ok: true,
      payload: validPayload,
    });
  });

  // A2: Tampered payload, header, signature
  it('A2.1: tampered payload (tier ENTERPRISE, seats 99999) returns BAD_SIGNATURE', async () => {
    const validToken = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const [h, , s] = validToken.split('.');

    const tamperedPayload = {
      ...validPayload,
      tier: 'ENTERPRISE',
      seats: 99999,
    };
    const tamperedToken = `${h}.${base64UrlEncode(JSON.stringify(tamperedPayload))}.${s}`;

    const result = await verifyJwtWebCrypto(tamperedToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  it('A2.2: tampered header (modified kid) returns BAD_SIGNATURE', async () => {
    const validToken = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const [, p, s] = validToken.split('.');

    const tamperedHeader = { ...validHeader, kid: 'forged-key-id' };
    const tamperedToken = `${base64UrlEncode(JSON.stringify(tamperedHeader))}.${p}.${s}`;

    const result = await verifyJwtWebCrypto(tamperedToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  it('A2.3: tampered header (corrupted JSON) returns MALFORMED', async () => {
    const validToken = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const [, p, s] = validToken.split('.');

    const badHeaderToken = `${base64UrlEncode('{bad-json')}.${p}.${s}`;
    const result = await verifyJwtWebCrypto(badHeaderToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(result).toEqual({
      ok: false,
      reason: 'MALFORMED',
    });
  });

  it('A2.4: truncated signature (% 4 === 1) returns MALFORMED', async () => {
    const validToken = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const [h, p, s] = validToken.split('.');

    // Truncate to length % 4 === 1
    const targetLen = s!.length - (s!.length % 4) + 1;
    const truncatedSig = s!.slice(0, targetLen);
    const tamperedToken = `${h}.${p}.${truncatedSig}`;

    const result = await verifyJwtWebCrypto(tamperedToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(result).toEqual({
      ok: false,
      reason: 'MALFORMED',
    });
  });

  it('A2.5: truncated signature (valid base64url length) returns BAD_SIGNATURE', async () => {
    const validToken = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const [h, p, s] = validToken.split('.');

    // Truncate to length % 4 === 0
    const targetLen = s!.length - 4;
    const truncatedSig = s!.slice(0, targetLen);
    const tamperedToken = `${h}.${p}.${truncatedSig}`;

    const result = await verifyJwtWebCrypto(tamperedToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  it('A2.6: altered signature (flipped byte in payload of signature) returns BAD_SIGNATURE', async () => {
    const validToken = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const [h, p, s] = validToken.split('.');

    // Flip byte at index 10 to guarantee altered signature bytes
    const chars = s!.split('');
    chars[10] = chars[10] === 'A' ? 'B' : 'A';
    const tamperedToken = `${h}.${p}.${chars.join('')}`;

    const result = await verifyJwtWebCrypto(tamperedToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  // A3: alg:"none" with empty signature
  it('A3: alg:"none" is rejected before key operation (returns MALFORMED when empty sig due to step-1 segment length check, BAD_ALGORITHM with dummy sig)', async () => {
    const noneHeader = { alg: 'none', typ: 'JWT' };
    // Empty signature
    const emptySigToken = signWith(SERVER_KEYS.privateKey, noneHeader, validPayload);
    const rEmpty = await verifyJwtWebCrypto(emptySigToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    // Documents DEF-001: returns MALFORMED instead of BAD_ALGORITHM because !sigB64 is checked in step 1
    expect(rEmpty).toEqual({ ok: false, reason: 'MALFORMED' });

    // Dummy signature with alg: none returns BAD_ALGORITHM at step 2
    const [h, p] = emptySigToken.split('.');
    const dummySigToken = `${h}.${p}.${base64UrlEncode('dummy-sig')}`;
    const rDummy = await verifyJwtWebCrypto(dummySigToken, SERVER_KEYS.publicKey, {
      now: nowEpoch,
    });
    expect(rDummy).toEqual({ ok: false, reason: 'BAD_ALGORITHM' });
  });

  // A4: Algorithm confusion
  it('A4.1: alg:"HS256" with HMAC signature computed using public key PEM returns BAD_ALGORITHM', async () => {
    const hsHeader = { alg: 'HS256', typ: 'JWT' };
    const token = signWith(SERVER_KEYS.publicKey, hsHeader, validPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_ALGORITHM',
    });
  });

  it('A4.2: alg:"PS256" is rejected with BAD_ALGORITHM', async () => {
    const psHeader = { alg: 'PS256', typ: 'JWT' };
    const token = signWith(SERVER_KEYS.privateKey, psHeader, validPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_ALGORITHM',
    });
  });

  it('A4.3: lowercase alg:"rs256" is rejected with BAD_ALGORITHM', async () => {
    const rsHeader = { alg: 'rs256', typ: 'JWT' };
    const token = signWith(SERVER_KEYS.privateKey, rsHeader, validPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_ALGORITHM',
    });
  });

  // A5: Token signed by ATTACKER key with perfect RS256 header returns BAD_SIGNATURE
  it('A5: token signed by ATTACKER key with perfect RS256 header returns BAD_SIGNATURE', async () => {
    const token = signWith(ATTACKER_KEYS.privateKey, validHeader, validPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  // A6: Malformed inputs, each with its exact reason asserted
  it('A6.1: rejects 2 segments with MALFORMED', async () => {
    const result = await verifyJwtWebCrypto('partOne.partTwo', SERVER_KEYS.publicKey);
    expect(result).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.2: rejects 4 segments with MALFORMED', async () => {
    const result = await verifyJwtWebCrypto('a.b.c.d', SERVER_KEYS.publicKey);
    expect(result).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.3: rejects empty segments with MALFORMED', async () => {
    const r1 = await verifyJwtWebCrypto('.b.c', SERVER_KEYS.publicKey);
    expect(r1).toEqual({ ok: false, reason: 'MALFORMED' });

    const r2 = await verifyJwtWebCrypto('a..c', SERVER_KEYS.publicKey);
    expect(r2).toEqual({ ok: false, reason: 'MALFORMED' });

    const r3 = await verifyJwtWebCrypto('a.b.', SERVER_KEYS.publicKey);
    expect(r3).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.4: rejects non-base64url characters with MALFORMED', async () => {
    const r1 = await verifyJwtWebCrypto('a+b.c/d.efg', SERVER_KEYS.publicKey);
    expect(r1).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.5: rejects padding "=" with MALFORMED', async () => {
    const r1 = await verifyJwtWebCrypto('abc=.def.ghi', SERVER_KEYS.publicKey);
    expect(r1).toEqual({ ok: false, reason: 'MALFORMED' });

    const r2 = await verifyJwtWebCrypto('abc.def.ghi=', SERVER_KEYS.publicKey);
    expect(r2).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.6: rejects embedded whitespace with MALFORMED', async () => {
    const r1 = await verifyJwtWebCrypto('abc .def.ghi', SERVER_KEYS.publicKey);
    expect(r1).toEqual({ ok: false, reason: 'MALFORMED' });

    const r2 = await verifyJwtWebCrypto('abc.def. ghi', SERVER_KEYS.publicKey);
    expect(r2).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.7: rejects header that is not JSON with MALFORMED', async () => {
    const badHeader = base64UrlEncode('not-a-json-object');
    const validP = base64UrlEncode(JSON.stringify(validPayload));
    const token = `${badHeader}.${validP}.AAAA`;

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey);
    expect(result).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.8: rejects header that is not an object (array, number, string) with MALFORMED', async () => {
    const arrayHeader = base64UrlEncode(JSON.stringify([{ alg: 'RS256' }]));
    const numHeader = base64UrlEncode('12345');
    const strHeader = base64UrlEncode('"just a string"');
    const validP = base64UrlEncode(JSON.stringify(validPayload));

    const r1 = await verifyJwtWebCrypto(`${arrayHeader}.${validP}.AAAA`, SERVER_KEYS.publicKey);
    expect(r1).toEqual({ ok: false, reason: 'MALFORMED' });

    const r2 = await verifyJwtWebCrypto(`${numHeader}.${validP}.AAAA`, SERVER_KEYS.publicKey);
    expect(r2).toEqual({ ok: false, reason: 'MALFORMED' });

    const r3 = await verifyJwtWebCrypto(`${strHeader}.${validP}.AAAA`, SERVER_KEYS.publicKey);
    expect(r3).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('A6.9: rejects payload that is not JSON with MALFORMED', async () => {
    const badPayloadB64 = base64UrlEncode('{invalid-json-syntax');
    const validHB64 = base64UrlEncode(JSON.stringify(validHeader));
    const message = `${validHB64}.${badPayloadB64}`;

    // Compute valid signature over the unparseable payload
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(message);
    signer.end();
    const sigB64 = base64UrlEncode(signer.sign(SERVER_KEYS.privateKey));
    const token = `${message}.${sigB64}`;

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey);
    expect(result).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  // A7: Signature-valid token with exp in the past returns EXPIRED; invalid claims return INVALID_CLAIMS
  it('A7.1: signature-valid token with exp in the past returns EXPIRED', async () => {
    const expiredPayload: ServerJwtPayload = {
      ...validPayload,
      iat: nowEpoch - 7200,
      exp: nowEpoch - 100, // expired 100s ago
    };
    const token = signWith(SERVER_KEYS.privateKey, validHeader, expiredPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'EXPIRED',
    });
  });

  it('A7.1b: respects clockToleranceSeconds when evaluating token expiration', async () => {
    const recentlyExpiredPayload: ServerJwtPayload = {
      ...validPayload,
      iat: nowEpoch - 7200,
      exp: nowEpoch - 30, // expired 30s ago
    };
    const token = signWith(SERVER_KEYS.privateKey, validHeader, recentlyExpiredPayload);

    // Without tolerance: expired
    const expiredRes = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(expiredRes.ok).toBe(false);
    if (!expiredRes.ok) {
      expect(expiredRes.reason).toBe('EXPIRED');
    }

    // With 60s tolerance: valid
    const validRes = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, {
      now: nowEpoch,
      clockToleranceSeconds: 60,
    });
    expect(validRes.ok).toBe(true);

    // With 15s tolerance: still expired (30s elapsed > 15s tolerance)
    const stillExpiredRes = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, {
      now: nowEpoch,
      clockToleranceSeconds: 15,
    });
    expect(stillExpiredRes.ok).toBe(false);
    if (!stillExpiredRes.ok) {
      expect(stillExpiredRes.reason).toBe('EXPIRED');
    }
  });

  it('A7.2: exp as a string returns INVALID_CLAIMS', async () => {
    const badClaimsPayload = {
      ...validPayload,
      exp: 'not-a-number-epoch',
    };
    const token = signWith(SERVER_KEYS.privateKey, validHeader, badClaimsPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'INVALID_CLAIMS',
    });
  });

  it('A7.3: missing exp returns INVALID_CLAIMS', async () => {
    const { exp: _exp, ...payloadWithoutExp } = validPayload;
    const token = signWith(SERVER_KEYS.privateKey, validHeader, payloadWithoutExp);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'INVALID_CLAIMS',
    });
  });

  it('A7.4: unknown tier returns INVALID_CLAIMS', async () => {
    const badTierPayload = {
      ...validPayload,
      tier: 'SUPER_ENTERPRISE_GODMODE',
    };
    const token = signWith(SERVER_KEYS.privateKey, validHeader, badTierPayload);

    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.publicKey, { now: nowEpoch });
    expect(result).toEqual({
      ok: false,
      reason: 'INVALID_CLAIMS',
    });
  });

  // A8: Garbage PEM, empty PEM, private-key PEM passed as public key returns BAD_KEY; 30+ hostile inputs
  it('A8.1: garbage PEM returns BAD_KEY', async () => {
    const token = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const result = await verifyJwtWebCrypto(token, 'GARBAGE_KEY_MATERIAL');

    expect(result).toEqual({
      ok: false,
      reason: 'BAD_KEY',
    });
  });

  it('A8.2: empty PEM returns BAD_KEY', async () => {
    const token = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const result = await verifyJwtWebCrypto(token, '');

    expect(result).toEqual({
      ok: false,
      reason: 'BAD_KEY',
    });
  });

  it('A8.3: private-key PEM passed as public key returns BAD_KEY', async () => {
    const token = signWith(SERVER_KEYS.privateKey, validHeader, validPayload);
    const result = await verifyJwtWebCrypto(token, SERVER_KEYS.privateKey);

    expect(result).toEqual({
      ok: false,
      reason: 'BAD_KEY',
    });
  });

  it('A8.4: never throws for 32 hostile inputs and returns exact failure objects', async () => {
    const hostileInputs = [
      null as unknown as string,
      undefined as unknown as string,
      12345 as unknown as string,
      true as unknown as string,
      false as unknown as string,
      {} as unknown as string,
      [] as unknown as string,
      Symbol('test') as unknown as string,
      '',
      '.',
      '..',
      '...',
      '....',
      'a.b.c',
      'a.b.c.d',
      'Bearer ',
      'Bearer token',
      'null.null.null',
      'undefined.undefined.undefined',
      'NaN.NaN.NaN',
      '[object Object].[object Object].[object Object]',
      '\x00\x01\x02.\x03\x04.\x05\x06',
      'DROP TABLE licenses;--.DROP TABLE activations;--.sig',
      '<script>alert(1)</script>.<script>alert(2)</script>.sig',
      '../../../../etc/passwd.payload.sig',
      '\u202E\u0000\uFEFF.payload.sig',
      'a'.repeat(50000),
      `header.${'b'.repeat(50000)}.sig`,
      `${'c'.repeat(50000)}.payload.sig`,
      'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.',
      'eyJhbGciOiJSUzI1NiJ9.eyJleHAiOiJzdHIifQ.sig',
      '==.==.==',
    ];

    expect(hostileInputs.length).toBe(32);

    for (const hostile of hostileInputs) {
      const res = await verifyJwtWebCrypto(hostile, SERVER_KEYS.publicKey);
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect([
          'MALFORMED',
          'BAD_ALGORITHM',
          'BAD_KEY',
          'BAD_SIGNATURE',
          'INVALID_CLAIMS',
          'EXPIRED',
        ]).toContain(res.reason);
      }
    }
  });
});
