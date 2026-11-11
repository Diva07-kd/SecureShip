import { describe, it, expect, vi, afterEach } from 'vitest';
import { RENEWAL_GRACE_SECONDS } from '../src/worker.js';
import {
  createCheckoutSessionCompletedEvent,
  createCustomerSubscriptionDeletedEvent,
  createInvoicePaidEvent,
  runDualStoreTest,
} from './stripe-fixtures.js';

describe('LAYER F: Subscription Renewal Tests (DEV-5)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const fixedNow = 1770000000;

  // F1: invoice.paid with period.end = now + 365 d extends expires_at to period_end + 3 d
  it('F1: invoice.paid extends license expiry to period.end + 3 days grace', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // Provision license
      const event = createCheckoutSessionCompletedEvent({
        id: 'evt_f1_prov',
        sessionId: 'cs_f1',
        subscriptionId: 'sub_f1_renew',
        email: 'f1@corp.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(event));

      const newPeriodEnd = fixedNow + 400 * 86400;
      const invoiceEvent = createInvoicePaidEvent([{ periodEnd: newPeriodEnd }], {
        id: 'evt_f1_inv',
        subscriptionId: 'sub_f1_renew',
        now: fixedNow + 3600,
      });

      const res = await ctx.dispatchWebhook(JSON.stringify(invoiceEvent));
      expect(res.status).toBe(200);
      const json = (await res.json()) as { received: boolean; action: string; renewed: number };
      expect(json).toEqual({
        received: true,
        action: 'license_renewed',
        renewed: 1,
      });

      const expectedExpiry = newPeriodEnd + RENEWAL_GRACE_SECONDS; // period.end + 3 days!
      expect(RENEWAL_GRACE_SECONDS).toBe(3 * 86400);

      if (storeName === 'MockStore') {
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.expires_at).toBe(expectedExpiry);
      } else {
        const lic = ctx
          .sqliteDb!.prepare('SELECT expires_at FROM licenses WHERE stripe_subscription_id = ?')
          .get('sub_f1_renew') as {
          expires_at: number;
        };
        expect(lic.expires_at).toBe(expectedExpiry);
      }
    });

    vi.useRealTimers();
  });

  // F2: Never shortens: a period.end earlier than the current expiry leaves expires_at unchanged
  it('F2: invoice.paid with earlier period.end never shortens current expiry', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // Provision: expires_at = fixedNow + 365 * 86400
      const event = createCheckoutSessionCompletedEvent({
        id: 'evt_f2_prov',
        sessionId: 'cs_f2',
        subscriptionId: 'sub_f2_noshort',
        email: 'f2@corp.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(event));

      const originalExpiry = fixedNow + 365 * 86400;

      // Deliver invoice with periodEnd far earlier (e.g. only 30 days into term)
      const earlierPeriodEnd = fixedNow + 30 * 86400;
      const invoiceEvent = createInvoicePaidEvent([{ periodEnd: earlierPeriodEnd }], {
        id: 'evt_f2_inv',
        subscriptionId: 'sub_f2_noshort',
        now: fixedNow + 100,
      });

      const res = await ctx.dispatchWebhook(JSON.stringify(invoiceEvent));
      expect(res.status).toBe(200);

      if (storeName === 'MockStore') {
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.expires_at).toBe(originalExpiry); // Expiry unchanged!
      } else {
        const lic = ctx
          .sqliteDb!.prepare('SELECT expires_at FROM licenses WHERE stripe_subscription_id = ?')
          .get('sub_f2_noshort') as {
          expires_at: number;
        };
        expect(lic.expires_at).toBe(originalExpiry); // Expiry unchanged!
      }
    });

    vi.useRealTimers();
  });

  // F3: REVOKED license not resurrected, unknown subscription gives 200 no-op, multiple lines uses max, missing/invalid period.end ignored
  it('F3: REVOKED license not resurrected, unknown sub no-op, max line periodEnd used, invalid periodEnd ignored', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // 1. Provision and revoke
      const event = createCheckoutSessionCompletedEvent({
        sessionId: 'cs_f3',
        subscriptionId: 'sub_f3_revoked',
        email: 'f3@corp.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(event));

      const delEvent = createCustomerSubscriptionDeletedEvent({
        subscriptionId: 'sub_f3_revoked',
        now: fixedNow + 10,
      });
      await ctx.dispatchWebhook(JSON.stringify(delEvent));

      // Attempt renewal of REVOKED license -> must NOT resurrect
      const invoiceRevoked = createInvoicePaidEvent([{ periodEnd: fixedNow + 500 * 86400 }], {
        id: 'evt_inv_on_revoked',
        subscriptionId: 'sub_f3_revoked',
        now: fixedNow + 20,
      });
      const resRevoked = await ctx.dispatchWebhook(JSON.stringify(invoiceRevoked));
      expect(resRevoked.status).toBe(200);
      const jsonRevoked = (await resRevoked.json()) as { action: string; renewed: number };
      expect(jsonRevoked.renewed).toBe(0); // 0 renewed!

      if (storeName === 'MockStore') {
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.status).toBe('REVOKED'); // Still REVOKED!
      } else {
        const lic = ctx
          .sqliteDb!.prepare('SELECT status FROM licenses WHERE stripe_subscription_id = ?')
          .get('sub_f3_revoked') as {
          status: string;
        };
        expect(lic.status).toBe('REVOKED'); // Still REVOKED!
      }

      // 2. Unknown subscription gives 200 { action: 'license_renewed', renewed: 0 }
      const invoiceUnknown = createInvoicePaidEvent([{ periodEnd: fixedNow + 500 * 86400 }], {
        id: 'evt_inv_unknown',
        subscriptionId: 'sub_ghost_sub',
        now: fixedNow + 30,
      });
      const resUnknown = await ctx.dispatchWebhook(JSON.stringify(invoiceUnknown));
      expect(resUnknown.status).toBe(200);
      const jsonUnknown = (await resUnknown.json()) as { action: string; renewed: number };
      expect(jsonUnknown.renewed).toBe(0);

      // 3. Multiple line items: uses maximum periodEnd
      const eventMulti = createCheckoutSessionCompletedEvent({
        sessionId: 'cs_f3_multi',
        subscriptionId: 'sub_f3_multi',
        email: 'f3_multi@corp.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(eventMulti));

      const lines = [
        { periodEnd: fixedNow + 100 * 86400 },
        { periodEnd: fixedNow + 450 * 86400 }, // MAX
        { periodEnd: fixedNow + 200 * 86400 },
      ];
      const invoiceMulti = createInvoicePaidEvent(lines, {
        id: 'evt_inv_multi_lines',
        subscriptionId: 'sub_f3_multi',
        now: fixedNow + 40,
      });
      const resMulti = await ctx.dispatchWebhook(JSON.stringify(invoiceMulti));
      expect(resMulti.status).toBe(200);

      const expectedMaxExpiry = fixedNow + 450 * 86400 + RENEWAL_GRACE_SECONDS;
      if (storeName === 'MockStore') {
        const lic = ctx.mockDb!.get(
          Array.from(ctx.mockDb!.values()).find((l) => l.stripe_subscription_id === 'sub_f3_multi')!
            .activation_code
        )!;
        expect(lic.expires_at).toBe(expectedMaxExpiry);
      } else {
        const lic = ctx
          .sqliteDb!.prepare('SELECT expires_at FROM licenses WHERE stripe_subscription_id = ?')
          .get('sub_f3_multi') as {
          expires_at: number;
        };
        expect(lic.expires_at).toBe(expectedMaxExpiry);
      }

      // 4. Missing or invalid period.end gives 200 ignored: true
      const invalidInvoice = {
        id: 'evt_inv_bad_period',
        type: 'invoice.paid',
        created: fixedNow,
        data: {
          object: {
            id: 'in_bad',
            subscription: 'sub_f3_multi',
            lines: { data: [] }, // Empty lines -> periodEnd 0
          },
        },
      };
      const resBad = await ctx.dispatchWebhook(JSON.stringify(invalidInvoice));
      expect(resBad.status).toBe(200);
      expect(await resBad.json()).toEqual({ received: true, ignored: true });
    });

    vi.useRealTimers();
  });

  // F4: Duplicate delivery gives 200 duplicate: true, expiry unchanged on 2nd
  it('F4: duplicate invoice.paid delivery returns 200 duplicate:true with expiry unchanged', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const event = createCheckoutSessionCompletedEvent({
        id: 'evt_f4_prov',
        sessionId: 'cs_f4',
        subscriptionId: 'sub_f4_dup',
        email: 'f4@corp.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(event));

      const newPeriodEnd = fixedNow + 420 * 86400;
      const invoiceEvent = createInvoicePaidEvent([{ periodEnd: newPeriodEnd }], {
        id: 'evt_f4_inv_dup',
        subscriptionId: 'sub_f4_dup',
        now: fixedNow + 3600,
      });
      const rawBody = JSON.stringify(invoiceEvent);

      // Delivery 1
      const res1 = await ctx.dispatchWebhook(rawBody);
      expect(res1.status).toBe(200);
      const json1 = (await res1.json()) as { action: string; renewed: number };
      expect(json1.renewed).toBe(1);

      const expectedExpiry = newPeriodEnd + RENEWAL_GRACE_SECONDS;

      // Delivery 2
      const res2 = await ctx.dispatchWebhook(rawBody);
      expect(res2.status).toBe(200);
      const json2 = (await res2.json()) as { received: boolean; duplicate: boolean };
      expect(json2).toEqual({ received: true, duplicate: true });

      // Expiry unchanged
      if (storeName === 'MockStore') {
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.expires_at).toBe(expectedExpiry);
      } else {
        const lic = ctx
          .sqliteDb!.prepare('SELECT expires_at FROM licenses WHERE stripe_subscription_id = ?')
          .get('sub_f4_dup') as {
          expires_at: number;
        };
        expect(lic.expires_at).toBe(expectedExpiry);
      }
    });

    vi.useRealTimers();
  });
});
