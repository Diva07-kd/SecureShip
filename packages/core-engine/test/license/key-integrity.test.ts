import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { SECURESHIP_PUBLIC_KEY_PEM } from '../../src/license/license-keys.js';

describe('Embedded RSA Public Key Integrity', () => {
  it('embedded public key is a valid RSA-2048 SPKI PEM', () => {
    const { createPublicKey } = crypto;
    expect(() => createPublicKey(SECURESHIP_PUBLIC_KEY_PEM)).not.toThrow();
    const key = createPublicKey(SECURESHIP_PUBLIC_KEY_PEM);
    expect(key.asymmetricKeyType).toBe('rsa');
    const details = key.asymmetricKeyDetails;
    expect(details?.modulusLength).toBe(2048);
  });
});
