import crypto from 'node:crypto';

// Negative fixture: crypto.randomBytes for security tokens
function generateSessionTokenSafe() {
  return crypto.randomBytes(32).toString('hex');
}

// Math.random for UI layout or non-security purposes
function pickRandomColor(colors) {
  const index = Math.floor(Math.random() * colors.length);
  return colors[index];
}
