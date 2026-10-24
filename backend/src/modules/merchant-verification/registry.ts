import { isSameOrSubdomain, registrableDomain } from '@authentik/shared';

export type EntityKind = 'merchant' | 'payment_provider' | 'bank';

export interface KnownEntity {
  id: string;
  name: string;
  kind: EntityKind;
  /** Registrable domains the entity officially operates. Subdomains are included implicitly. */
  domains: string[];
  /** Tokens that an impersonator would put in a hostname (lowercase, no punctuation). */
  brandTokens: string[];
  /** Names that legitimately appear as the payment recipient. */
  recipientNames?: string[];
  /** Merchants only: payment providers this merchant is known to use. */
  paymentProviders?: string[];
  /** Simulation-only entities used by the demo checkout. */
  demo?: boolean;
  /** Other ways the name appears in messages, lowercase (sent to phones for offline checks). */
  aliases?: string[];
}

/**
 * Seed registry. In production this belongs in a managed data source with
 * provenance for every domain — an incorrect "official domain" entry would
 * produce false reassurance, so additions need review.
 */
export const KNOWN_ENTITIES: KnownEntity[] = [
  // ── Merchants ──
  {
    id: 'takealot', name: 'Takealot', kind: 'merchant',
    domains: ['takealot.com'], brandTokens: ['takealot'],
    recipientNames: ['takealot', 'takealot online', 'takealot online (rf) (pty) ltd'],
    paymentProviders: ['payu', 'peach', 'ozow', 'paypal'],
  },
  {
    id: 'amazon', name: 'Amazon', kind: 'merchant',
    domains: ['amazon.com', 'amazon.co.za', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.ca', 'amazon.com.au', 'amazonpay.com', 'media-amazon.com'],
    brandTokens: ['amazon'],
    recipientNames: ['amazon', 'amazon.co.za', 'amazon retail south africa', 'amazon payments'],
  },
  { id: 'makro', name: 'Makro', kind: 'merchant', domains: ['makro.co.za'], brandTokens: ['makro'], recipientNames: ['makro', 'massmart'] },
  { id: 'checkers', name: 'Checkers', kind: 'merchant', domains: ['checkers.co.za', 'sixty60.co.za'], brandTokens: ['checkers', 'sixty60'], recipientNames: ['checkers', 'shoprite checkers'] },
  { id: 'woolworths', name: 'Woolworths', kind: 'merchant', domains: ['woolworths.co.za'], brandTokens: ['woolworths'], recipientNames: ['woolworths'] },
  { id: 'superbalist', name: 'Superbalist', kind: 'merchant', domains: ['superbalist.com'], brandTokens: ['superbalist'], recipientNames: ['superbalist'] },
  { id: 'mrprice', name: 'Mr Price', kind: 'merchant', domains: ['mrp.com', 'mrprice.co.za'], brandTokens: ['mrprice'], recipientNames: ['mr price', 'mr price group'] },
  { id: 'temu', name: 'Temu', kind: 'merchant', domains: ['temu.com'], brandTokens: ['temu'], recipientNames: ['temu', 'whaleco'] },
  { id: 'shein', name: 'SHEIN', kind: 'merchant', domains: ['shein.com', 'shein.co.za'], brandTokens: ['shein'], recipientNames: ['shein'] },

  // ── Payment providers ──
  { id: 'payfast', name: 'Payfast', kind: 'payment_provider', domains: ['payfast.co.za', 'payfast.io'], brandTokens: ['payfast'] },
  { id: 'payu', name: 'PayU', kind: 'payment_provider', domains: ['payu.co.za', 'payu.com', 'payu.in'], brandTokens: ['payu'] },
  { id: 'peach', name: 'Peach Payments', kind: 'payment_provider', domains: ['peachpayments.com', 'oppwa.com'], brandTokens: ['peachpayments'] },
  { id: 'ozow', name: 'Ozow', kind: 'payment_provider', domains: ['ozow.com'], brandTokens: ['ozow'] },
  { id: 'yoco', name: 'Yoco', kind: 'payment_provider', domains: ['yoco.com', 'yoco.co.za'], brandTokens: ['yoco'] },
  { id: 'paypal', name: 'PayPal', kind: 'payment_provider', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'], brandTokens: ['paypal'] },
  { id: 'stripe', name: 'Stripe', kind: 'payment_provider', domains: ['stripe.com', 'stripe.network'], brandTokens: ['stripe'] },
  { id: 'adyen', name: 'Adyen', kind: 'payment_provider', domains: ['adyen.com'], brandTokens: ['adyen'] },
  { id: 'snapscan', name: 'SnapScan', kind: 'payment_provider', domains: ['snapscan.co.za', 'snapscan.io'], brandTokens: ['snapscan'] },
  { id: 'zapper', name: 'Zapper', kind: 'payment_provider', domains: ['zapper.com'], brandTokens: ['zapper'] },

  // ── Banks (impersonation targets) ──
  { id: 'fnb', name: 'FNB', kind: 'bank', domains: ['fnb.co.za', 'firstrand.co.za'], brandTokens: ['fnb', 'firstnational'], aliases: ['first national bank'] },
  { id: 'absa', name: 'Absa', kind: 'bank', domains: ['absa.co.za', 'absa.africa'], brandTokens: ['absa'] },
  { id: 'standardbank', name: 'Standard Bank', kind: 'bank', domains: ['standardbank.co.za', 'standardbank.com'], brandTokens: ['standardbank'] },
  { id: 'nedbank', name: 'Nedbank', kind: 'bank', domains: ['nedbank.co.za'], brandTokens: ['nedbank'] },
  { id: 'capitec', name: 'Capitec', kind: 'bank', domains: ['capitecbank.co.za', 'capitec.co.za'], brandTokens: ['capitec', 'capitecbank'] },
  { id: 'discovery', name: 'Discovery Bank', kind: 'bank', domains: ['discovery.co.za'], brandTokens: ['discoverybank'] },
  { id: 'tymebank', name: 'TymeBank', kind: 'bank', domains: ['tymebank.co.za'], brandTokens: ['tymebank'], aliases: ['tyme bank'] },

  // ── Demo-only (simulated checkout; .test never resolves on the public internet) ──
  {
    id: 'demo-store', name: 'Authentik Demo Store', kind: 'merchant', demo: true,
    domains: ['authentik-demo.test'], brandTokens: ['authentikdemo'],
    recipientNames: ['authentik demo store', 'authentik demo store (pty) ltd'],
    paymentProviders: ['payfast', 'demo-pay'],
  },
  { id: 'demo-pay', name: 'DemoPay', kind: 'payment_provider', demo: true, domains: ['demopay.test'], brandTokens: ['demopay'] },
];

export class EntityRegistry {
  private readonly byId = new Map<string, KnownEntity>();
  constructor(readonly entities: KnownEntity[] = KNOWN_ENTITIES) {
    for (const e of entities) this.byId.set(e.id, e);
  }

  get(id: string): KnownEntity | undefined {
    return this.byId.get(id);
  }

  /** The entity that officially owns this hostname, if any. */
  ownerOf(hostname: string): KnownEntity | undefined {
    return this.entities.find((e) => e.domains.some((d) => isSameOrSubdomain(hostname, d)));
  }

  /** Resolves a user-typed merchant ("takealot", "Takealot.com", "amazon") to an entity. */
  findMerchant(input: string): KnownEntity | undefined {
    const key = normalizeName(input);
    const domain = registrableDomain(input.trim().toLowerCase());
    return this.entities.find(
      (e) =>
        e.kind === 'merchant' &&
        (normalizeName(e.id) === key ||
          normalizeName(e.name) === key ||
          e.brandTokens.includes(key) ||
          (domain !== null && e.domains.includes(domain))),
    );
  }

  /** Is this recipient name one the merchant legitimately uses? */
  recipientMatches(entity: KnownEntity, recipient: string): boolean {
    const r = normalizeName(recipient);
    return (entity.recipientNames ?? [entity.name]).some((n) => normalizeName(n) === r);
  }
}

export function normalizeName(s: string): string {
  return s
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/\.(com|co\.za|co\.uk)$/, '')
    // Company-form suffixes vary between invoices and checkout pages.
    .replace(/\b(pty|ltd|rf|inc|llc|limited|proprietary|plc|gmbh|sa)\b/g, '')
    .replace(/[^a-z0-9]/g, '');
}
