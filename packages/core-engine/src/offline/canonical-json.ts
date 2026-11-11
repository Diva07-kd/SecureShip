import crypto from 'node:crypto';

/**
 * Serializes a value into canonical JSON with strictly sorted keys and no whitespace.
 * Conforms to RFC 8785 (JSON Canonicalization Scheme) subset for deterministic signing.
 */
export function canonicalJsonStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return (
      '[' +
      value.map((item) => (item === undefined ? 'null' : canonicalJsonStringify(item))).join(',') +
      ']'
    );
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((key) => obj[key] !== undefined)
    .sort();
  const entries = keys.map((key) => {
    return JSON.stringify(key) + ':' + canonicalJsonStringify(obj[key]);
  });

  return '{' + entries.join(',') + '}';
}

/**
 * Signs a canonical JSON string using an Ed25519 private key.
 * Returns base64-encoded signature.
 */
export function signEd25519(canonicalJson: string, privateKeyPem: string): string {
  const data = Buffer.from(canonicalJson, 'utf-8');
  const signature = crypto.sign(null, data, privateKeyPem);
  return signature.toString('base64');
}

/**
 * Verifies an Ed25519 signature against canonical JSON data using a public key.
 */
export function verifyEd25519(
  canonicalJson: string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    const data = Buffer.from(canonicalJson, 'utf-8');
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, data, publicKeyPem, signature);
  } catch {
    return false;
  }
}

/**
 * Generates an Ed25519 keypair formatted as PEM strings (SPKI public key, PKCS8 private key).
 */
export function generateEd25519KeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}
