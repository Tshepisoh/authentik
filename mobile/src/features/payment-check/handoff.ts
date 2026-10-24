import type { PaymentExtraction } from '@authentik/shared';

/** Passes a page reading from the Sandbox viewer to the payment-check screen, in memory. */
let pending: PaymentExtraction | null = null;

export const paymentHandoff = {
  put(e: PaymentExtraction) {
    pending = e;
  },
  take(): PaymentExtraction | null {
    const e = pending;
    pending = null;
    return e;
  },
};
