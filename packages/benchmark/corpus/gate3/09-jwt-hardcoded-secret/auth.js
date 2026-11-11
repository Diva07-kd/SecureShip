const jwt = require('jsonwebtoken');
export function verify(token) {
  return jwt.verify(token, 'super_hardcoded_jwt_secret_value_123');
}
