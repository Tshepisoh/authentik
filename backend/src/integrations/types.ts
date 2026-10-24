import type { ObservedPayment } from '@authentik/shared';

/**
 * Extension point for future retailer, payment-provider and bank partnerships
 * (feature flow 10). Not used by the MVP.
 *
 * An integration turns an *authorised* order or payment reference into an
 * `ObservedPayment`; the existing PaymentIntegrityService then compares it
 * with what the user expected. Rules for implementers:
 *
 * - Use only official partner APIs, with the user's explicit consent recorded
 *   per integration. Never scrape, intercept or bypass another app's controls.
 * - Return only what the comparison needs (recipient, amount, currency,
 *   checkout host). Do not return card numbers, account numbers or credentials.
 * - Report `verified: false` rather than guessing when the source cannot be
 *   authenticated — the risk engine will mark the check incomplete.
 */
export interface PaymentContextProvider {
  /** e.g. `takealot`, `payfast`. Must match an entity id in the merchant registry. */
  readonly id: string;
  readonly kind: 'retailer' | 'payment_provider' | 'bank';

  /** True when the user has granted (and not revoked) consent for this provider. */
  hasConsent(uid: string): Promise<boolean>;

  fetchPaymentContext(input: {
    uid: string;
    /** Partner-issued order or transaction reference supplied by the user or a deep link. */
    reference: string;
  }): Promise<
    | { verified: true; observed: ObservedPayment; source: string; fetchedAt: string }
    | { verified: false; reason: string }
  >;
}
