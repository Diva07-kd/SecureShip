-- Migration: 0003_stripe_webhook.sql
-- Add Stripe webhook idempotency table and subscription/session tracking columns to licenses.
-- Note: SQLite does not support IF NOT EXISTS on ALTER TABLE ADD COLUMN.
-- Cloudflare D1 / Wrangler applies migrations exactly once via the d1_migrations ledger table,
-- ensuring these ALTER TABLE statements execute only during initial migration application.

ALTER TABLE licenses ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE licenses ADD COLUMN stripe_checkout_session_id TEXT;

CREATE TABLE IF NOT EXISTS stripe_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  received_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_stripe_session ON licenses(stripe_checkout_session_id);
CREATE INDEX IF NOT EXISTS idx_licenses_stripe_subscription ON licenses(stripe_subscription_id);

