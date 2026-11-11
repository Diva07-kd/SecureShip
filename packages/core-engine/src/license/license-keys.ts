import crypto from 'node:crypto';
import type { LicenseJwtHeader, LicenseJwtPayload } from '@secureship/contracts';

/**
 * Key ID for current SecureShip RS256 license tokens.
 */
export const SECURESHIP_KEY_ID = 'secureship-2026-01';

/**
 * Embedded canonical SecureShip RSA-2048 Public Key (SPKI PEM format).
 * This public key is bundled in the CLI binary to perform 100% offline license validation.
 */
export const SECURESHIP_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt3H1H6+gFedY0ED9Uo39
RzuoO7kyTbjf/ggAgGeBZh/NF1kzKj5hjp+vNl6hZnqqI0PWLdUks5CTtYNvBDhx
J57QH17sp7Wruvza6tbo/MCbfoU3ceVkdydPaqNfMwdZRNZCqpHosuq7klA7ExHv
VGewQWIkuynNtSHy5cG1Qc1EWPZXXHBNonJ2HcBWMIvbXwuR5P9B7woRXYihAXCW
OqjfEHo3u6DC+KNFtCL/QfjdfxrUHjw08Iz1P6hPVZO3ojCCAS3a/vULRpSq8b7E
V0z1C9NswaieHr1siCyH2l8HnVdDNMTPKOXRqZgq63UAeNtay6pUdSiRJjYFita9
fQIDAQAB
-----END PUBLIC KEY-----`;

/**
 * Encodes an object or buffer as URL-safe base64 without padding.
 */
export function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a URL-safe base64 string to a UTF-8 string.
 */
export function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Cryptographically signs a license payload with an RSA-256 private key to produce a standard compact JWT.
 * Used by the license server and test suites.
 */
export function signLicenseJwt(
  payload: LicenseJwtPayload,
  privateKeyPem: string,
  keyId: string = SECURESHIP_KEY_ID
): string {
  const header: LicenseJwtHeader = {
    alg: 'RS256',
    kid: keyId,
    typ: 'JWT',
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const messageToSign = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(messageToSign);
  signer.end();

  const signature = signer.sign(privateKeyPem);
  const encodedSignature = base64UrlEncode(signature);

  return `${messageToSign}.${encodedSignature}`;
}

/**
 * Generates an ephemeral RSA-2048 keypair for testing or server setups.
 */
export function generateLicenseKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}
