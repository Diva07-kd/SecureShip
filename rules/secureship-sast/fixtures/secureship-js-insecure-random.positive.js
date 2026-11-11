// Positive fixture: Math.random used for session token or nonce
function generateSessionToken() {
  const token = "tok_" + Math.random().toString(36).substring(2);
  return token;
}

function createPasswordResetNonce() {
  const nonce = Math.random().toString();
  return nonce;
}
