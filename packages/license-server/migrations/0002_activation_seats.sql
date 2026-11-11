-- Migration: 0002_activation_seats.sql
-- Enforce machine fingerprint seat limits, clean up untracked rows, and apply uniqueness constraints
-- Idempotent execution safe for repeated application on Cloudflare D1.

-- Destructive action: Delete legacy activation records that have NULL, empty, or 'unknown' machine fingerprints.
-- Rationale: Untracked or placeholder fingerprints cannot be attributed to a physical seat and allow unbounded evasion.
DELETE FROM activations
WHERE machine_fingerprint IS NULL
   OR TRIM(machine_fingerprint) = ''
   OR machine_fingerprint = 'unknown';

-- Destructive action: Deduplicate activations per (license_id, machine_fingerprint) keeping only the earliest row (MIN(rowid)).
-- Rationale: Ensure data conforms to the unique constraint idx_activations_license_fp prior to index creation.
DELETE FROM activations
WHERE rowid NOT IN (
  SELECT MIN(rowid)
  FROM activations
  GROUP BY license_id, machine_fingerprint
);

-- Index for high-performance seat counting per license in atomic INSERT ... WHERE queries
CREATE INDEX IF NOT EXISTS idx_activations_license_id ON activations(license_id);

-- Unique index guaranteeing at most one activation per machine fingerprint per license
CREATE UNIQUE INDEX IF NOT EXISTS idx_activations_license_fp ON activations(license_id, machine_fingerprint);

