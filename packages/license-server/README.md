# SecureShip License Server

Cloudflare Workers backend providing zero-telemetry license activation, cryptographic JWT verification, seat enforcement, and Stripe webhook handling.

## Cryptographic Key & Secret Configuration

The license server uses RS256 (RSASSA-PKCS1-v1_5 with SHA-256) asymmetric cryptography and HMAC-SHA256 Stripe webhook verification:

- **`JWT_PUBLIC_KEY`**: Public SPKI PEM string used by `GET /v1/validate` to verify client-presented JWTs. This is a public configuration value defined in `wrangler.toml` under `[vars]` (not a secret).
- **`JWT_PRIVATE_KEY`**: Private PKCS#8 PEM string used by `POST /v1/activate` and `GET /v1/validate` to mint and sign license JWTs. This is a highly confidential secret and must be provisioned via `wrangler secret put JWT_PRIVATE_KEY`.
- **`STRIPE_WEBHOOK_SECRET`**: Confidential signing secret for Stripe webhooks. This must be provisioned as a secret via `wrangler secret put STRIPE_WEBHOOK_SECRET` and MUST NEVER be committed to `wrangler.toml` or placed under `[vars]`.

## Stripe Webhook Integration

The endpoint `POST /v1/webhook/stripe` verifies the cryptographic `stripe-signature` header using WebCrypto HMAC-SHA256 before parsing JSON or executing any database operation.

Supported Stripe webhook events to configure in the Stripe dashboard:

1. **`checkout.session.completed`**: Provisions a new 365-day license upon completed checkout session (`payment_status === 'paid'`).
2. **`checkout.session.async_payment_succeeded`**: Handles asynchronous delayed payment checkout completion.
3. **`customer.subscription.deleted`**: Revokes the active license associated with the deleted subscription (`status = 'REVOKED'`).
4. **`invoice.paid`**: Renews the active license for the subscription, extending `expires_at` by the billing period end plus a 3-day renewal grace period.

## Seat Enforcement

- `POST /v1/activate` requires a non-empty `machineFingerprint` (1–256 characters).
- Seat counts are strictly enforced against Cloudflare D1 `activations` table.
- A license with $N$ seats can hold at most $N$ distinct machine fingerprints.
- Re-activation from an existing fingerprint updates `last_validated_at` without consuming additional seats.
- `POST /v1/deactivate` allows releasing an active machine fingerprint to free up a seat.
