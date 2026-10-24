import { describe, expect, it } from 'vitest';
import { interpretPaymentEvidence, parseMoney, type RawPaymentEvidence } from './extract.js';

const raw = (over: Partial<RawPaymentEvidence>): RawPaymentEvidence => ({
  title: '', siteName: '', meta: {}, structured: [], labelled: [], buttons: [], loose: [], ...over,
});

describe('parseMoney', () => {
  it.each([
    ['R 1 299,00', 129_900, 'ZAR'],
    ['R1,299.00', 129_900, 'ZAR'],
    ['R1 299', 129_900, 'ZAR'],
    ['ZAR 49.9', 4_990, 'ZAR'],
    ['1 299,50 ZAR', 129_950, 'ZAR'],
    ['$19.99', 1_999, 'USD'],
    ['€ 1.299,00', 129_900, 'EUR'],
  ])('%s → %i %s', (text, amountMinor, currency) => {
    expect(parseMoney(text)).toEqual({ amountMinor, currency });
  });

  it('rejects text without a currency or amount', () => {
    expect(parseMoney('Order 12345')).toBeNull();
    expect(parseMoney('Rand')).toBeNull();
  });
});

describe('interpretPaymentEvidence', () => {
  it('reads a labelled total and recipient with high confidence when sources agree', () => {
    const r = interpretPaymentEvidence(raw({
      labelled: [{ label: 'Pay to', row: 'Pay to Takealot Online (RF) (Pty) Ltd' }, { label: 'Total due', row: 'Total due R 1 299,00' }],
      buttons: ['Pay R 1 299,00'],
      loose: ['R 1 299,00', 'R 999,00'],
    }));
    expect(r).toMatchObject({ amountMinor: 129_900, currency: 'ZAR', recipientName: 'Takealot Online (RF) (Pty) Ltd', confidence: 'high' });
  });

  it('refuses to guess between two differently-labelled totals', () => {
    const r = interpretPaymentEvidence(raw({
      labelled: [{ label: 'Total', row: 'Total R 499,00' }, { label: 'Amount due', row: 'Amount due R 899,00' }],
    }));
    expect(r.amountMinor).toBeNull();
    expect(r.amountCandidates.map((c) => c.amountMinor).sort()).toEqual([49_900, 89_900]);
    expect(r.notes.join(' ')).toMatch(/more than one possible total/);
  });

  it('is low confidence when the amount is only seen loosely on the page', () => {
    const r = interpretPaymentEvidence(raw({ loose: ['R 250,00'], siteName: 'Some Shop' }));
    expect(r).toMatchObject({ amountMinor: 25_000, confidence: 'low', recipientName: 'Some Shop' });
    expect(r.notes.join(' ')).toMatch(/taken from the site’s name/);
  });

  it('a product list of repeated prices is not corroboration', () => {
    const r = interpretPaymentEvidence(raw({ loose: Array(10).fill('R 99,00') }));
    expect(r.confidence).toBe('low');
  });

  it('uses structured data and its currency', () => {
    const r = interpretPaymentEvidence(raw({ structured: [{ kind: 'price', value: '1299.00' }, { kind: 'currency', value: 'ZAR' }, { kind: 'seller', value: 'Makro' }] }));
    expect(r).toMatchObject({ amountMinor: 129_900, currency: 'ZAR', recipientName: 'Makro' });
  });

  it('reports when nothing could be read', () => {
    const r = interpretPaymentEvidence(raw({}));
    expect(r).toMatchObject({ amountMinor: null, recipientName: null, confidence: 'low' });
    expect(r.notes.length).toBe(2);
  });
});
