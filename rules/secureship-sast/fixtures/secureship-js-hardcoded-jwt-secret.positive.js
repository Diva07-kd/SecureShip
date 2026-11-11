import jwt from 'jsonwebtoken';

// Positive fixture: hardcoded secret string
export function signAuthToken(payload) {
  return jwt.sign(payload, "super_secret_jwt_key_12345");
}

export function verifyAuthToken(token) {
  return jwt.verify(token, "hardcoded_verification_secret");
}
