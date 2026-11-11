# SecureShip-IDE Production-Readiness Audit

# 18. Items Not Verified, Gaps, and Open Questions

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Auditor:** Autonomous Verification Engine

---

## 1. Subsystems Not Fully Exercised Locally & Rationales

| Subsystem / Feature                     |    Verification Level    | Why Not Fully Exercised Offline                                                                        | Instructions for Next Investigator                                                                                      |
| :-------------------------------------- | :----------------------: | :----------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------- |
| **Cloudflare D1 Live Database**         |   Static Code Analysis   | Requires active Cloudflare Workers deployment and live D1 database binding (`env.DB`).                 | Run `pnpm --filter @secureship/license-server wrangler d1 execute` with local Wrangler emulator; verify SQL migrations. |
| **Live Stripe Payment Webhook**         |   Static Code Analysis   | Requires live Stripe webhook signing secret (`whsec_...`) and test credit card checkout.               | Run `stripe listen --forward-to localhost:8787/v1/webhook/stripe` and verify signature HMAC validation.                 |
| **Docker Container Sandbox on Windows** | Static & Logic Confirmed | Path translation logic `/c/...` causes Docker Desktop volume mount rejection on Windows (`F-SAN-001`). | Start Docker Desktop on Windows with WSL2 backend; verify fix for `C:/...` volume mount argument.                       |
| **VSCode Marketplace Packaging**        |   Static Code Analysis   | Requires `vsce package` with active VSCode extension marketplace publisher credentials.                | Run `pnpm --filter secureship-security run package` and test `.vsix` installation in fresh VSCode instance.             |

---

## 2. Open Strategic Questions for Engineering Leadership

1. **Monorepo Dependency Strategy:**

   - Should `@secureship/core-engine`, `@secureship/ai`, and other internal packages be officially published to npmjs.org under an `@secureship` enterprise organization, or should `@secureship/cli` remain a standalone bundled package with all dependencies internal?
   - _Auditor Recommendation:_ Clean `packages/cli/package.json` to keep them internal, avoiding dependency confusion vulnerabilities (`F-DIS-001`).

2. **Remediation Ladder Philosophy when Docker is Absent:**

   - When a developer runs `secureship fix verify` on a machine without Docker, should the engine fail closed (`VERIFICATION_UNAVAILABLE`), run tests directly on host if trusted, or degrade to `VERIFIED_STATIC`?
   - _Auditor Recommendation:_ Degrade to `VERIFIED_STATIC` and explicitly warn the user that dynamic runtime tests were skipped. Never fabricate exit code 0 (`FakeSandboxBackend`, `F-ENG-001`).

3. **Fleet Server Target Deployment:**
   - Is `packages/fleet` intended to be a lightweight developer dashboard or an enterprise-grade compliance platform?
   - _Auditor Recommendation:_ If enterprise-grade, migrate file-based `FleetStore` to PostgreSQL with RBAC, OIDC, and authentication before advertising fleet capabilities to customers.

---

## 3. Prioritized Leads for the Next Investigator

1. **Verify D1 Migration Scripts:** Inspect `packages/license-server/schema.sql` to verify whether table schemas match query columns in `packages/license-server/src/worker.ts`.
2. **Profile AI Egress Latency:** Measure total end-to-end latency on repositories with > 500 findings when AI triage max concurrency is increased from 2 to 10.
3. **Validate License Deactivation Protocol:** Once seat limits are enforced per `F-LIC-002`, design and verify cryptographic deactivation protocol when developer machines are decommissioned or re-imaged.
