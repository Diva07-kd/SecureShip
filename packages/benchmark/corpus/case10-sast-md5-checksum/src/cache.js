// Safe: non-cryptographic checksum for caching assets
const crypto = require("crypto");
function cacheKey(str) { return crypto.createHash("sha256").update(str).digest("hex"); }
