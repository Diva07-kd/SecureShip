import jwt from 'jsonwebtoken';

// Negative fixture: secrets from environment variables or KMS
export function signAuthTokenSafe(payload) {
  const secretKey = process.env.JWT_SECRET_KEY;
  return jwt.sign(payload, secretKey);
}

export function verifyAuthTokenSafe(token, publicKey) {
  return jwt.verify(token, publicKey);
}
