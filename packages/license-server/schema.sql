-- SecureShip Cloudflare D1 Database Schema (Phase 5)
-- Production SQLite schema for zero-telemetry license management

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  stripe_customer_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  activation_code TEXT UNIQUE NOT NULL,
  tier TEXT NOT NULL CHECK(tier IN ('FREE_BYOK', 'PRO_TEAM', 'ENTERPRISE')),
  seats INTEGER NOT NULL DEFAULT 1,
  org_id TEXT NOT NULL DEFAULT 'individual',
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
  expires_at INTEGER NOT NULL, -- Unix epoch in seconds
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  stripe_subscription_id TEXT,
  stripe_checkout_session_id TEXT,
  FOREIGN KEY (customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS activations (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL,
  machine_fingerprint TEXT,
  activated_at INTEGER NOT NULL,
  last_validated_at INTEGER NOT NULL,
  FOREIGN KEY (license_id) REFERENCES licenses(id)
);

CREATE TABLE IF NOT EXISTS stripe_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  received_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_licenses_activation_code ON licenses(activation_code);
CREATE INDEX IF NOT EXISTS idx_licenses_customer_id ON licenses(customer_id);
CREATE INDEX IF NOT EXISTS idx_activations_license_id ON activations(license_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_activations_license_fp ON activations(license_id, machine_fingerprint);
CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_stripe_session ON licenses(stripe_checkout_session_id);
CREATE INDEX IF NOT EXISTS idx_licenses_stripe_subscription ON licenses(stripe_subscription_id);
