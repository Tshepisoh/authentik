import type { DemoScenario } from '@authentik/shared';

/**
 * Controlled checkout simulations for the MVP. Every host is under the
 * reserved `.test` TLD so nothing here can collide with a real site, and the
 * "observed" values stand in for what a supported integration would report.
 */
const expected = { merchant: 'demo-store', amountMinor: 129_900, currency: 'ZAR', allowedAdjustmentMinor: 9_900 };
const cart = 'https://shop.authentik-demo.test/cart/checkout';

export const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: 'legitimate',
    title: 'Normal checkout',
    description: 'R1,299 order paid through the merchant’s usual payment provider. Everything matches.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://pay.demopay.test/checkout/session',
        redirectChain: [cart, 'https://pay.demopay.test/checkout/session'],
        recipientName: 'Authentik Demo Store (Pty) Ltd',
        amountMinor: 129_900,
        currency: 'ZAR',
      },
    },
  },
  {
    id: 'shipping-fee',
    title: 'Checkout with delivery fee',
    description: 'R60 delivery is added — within the R99 adjustment you said you expected.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://pay.demopay.test/checkout/session',
        redirectChain: [cart, 'https://pay.demopay.test/checkout/session'],
        recipientName: 'Authentik Demo Store',
        amountMinor: 135_900,
        currency: 'ZAR',
      },
    },
  },
  {
    id: 'amount-tampered',
    title: 'Amount changed',
    description: 'The payment page asks for R1,899 instead of the R1,299 you agreed to.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://pay.demopay.test/checkout/session',
        redirectChain: [cart, 'https://pay.demopay.test/checkout/session'],
        recipientName: 'Authentik Demo Store (Pty) Ltd',
        amountMinor: 189_900,
        currency: 'ZAR',
      },
    },
  },
  {
    id: 'recipient-swapped',
    title: 'Different recipient',
    description: 'The amount is right, but the money would go to "QuickPay Holdings", not the store.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://pay.demopay.test/checkout/session',
        redirectChain: [cart, 'https://pay.demopay.test/checkout/session'],
        recipientName: 'QuickPay Holdings',
        amountMinor: 129_900,
        currency: 'ZAR',
      },
    },
  },
  {
    id: 'lookalike-redirect',
    title: 'Look-alike payment page',
    description: 'Checkout redirects to "demop4y" — a domain imitating the real payment provider.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://secure.demop4y.test/checkout',
        redirectChain: [cart, 'https://secure.demop4y.test/checkout'],
        recipientName: 'Authentik Demo Store (Pty) Ltd',
        amountMinor: 129_900,
        currency: 'ZAR',
      },
    },
  },
  {
    id: 'unknown-processor',
    title: 'Unrecognised payment page',
    description: 'Checkout moves to a payment site Authentik does not recognise. It might be fine — or not.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://checkout.fastgatewaypay.test/pay',
        redirectChain: [cart, 'https://checkout.fastgatewaypay.test/pay'],
        recipientName: 'Authentik Demo Store',
        amountMinor: 129_900,
        currency: 'ZAR',
      },
    },
  },
  {
    id: 'incomplete',
    title: 'Details not visible',
    description: 'The payment page does not show who is being paid or how much.',
    request: {
      expected,
      observed: {
        checkoutUrl: 'https://pay.demopay.test/checkout/session',
        redirectChain: [cart, 'https://pay.demopay.test/checkout/session'],
      },
    },
  },
];
