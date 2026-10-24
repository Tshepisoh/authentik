import type { AmountCandidate } from '@authentik/shared';

/**
 * Reading payment details from a rendered checkout page.
 *
 * `collectPaymentEvidence` runs *inside* the untrusted page and only gathers
 * raw, size-capped strings. `interpretPaymentEvidence` runs in the worker and
 * decides what they mean, so a hostile page can influence what it displays but
 * not how Authentik interprets it. Either way the result is a claim made by the
 * page, and the user confirms it before any check runs.
 */

export interface RawPaymentEvidence {
  title: string;
  siteName: string;
  meta: Record<string, string>;
  /** Prices and merchant names from JSON-LD and microdata. */
  structured: { kind: 'price' | 'currency' | 'seller'; value: string }[];
  /** Text rows next to labels such as "Total" or "Pay to". */
  labelled: { label: string; row: string }[];
  /** Text of pay buttons, e.g. "Pay R 1 299,00". */
  buttons: string[];
  /** Currency amounts anywhere in the visible text (weak evidence). */
  loose: string[];
}

/**
 * Runs in the page, so it is plain JavaScript *text*, not a compiled function:
 * dev transpilers (tsx/esbuild) inject helpers such as `__name` into functions,
 * which don't exist in the page and break `page.evaluate(fn)`. Shipping source
 * text means no compiler can alter it. It evaluates to a RawPaymentEvidence.
 */
export const COLLECT_PAYMENT_EVIDENCE = String.raw`(() => {
  const clip = (s, n = 160) => (s == null ? '' : String(s)).replace(/\s+/g, ' ').trim().slice(0, n);
  const out = { title: clip(document.title, 150), siteName: '', meta: {}, structured: [], labelled: [], buttons: [], loose: [] };

  for (const m of Array.from(document.querySelectorAll('meta[property], meta[name]')).slice(0, 300)) {
    const key = (m.getAttribute('property') || m.getAttribute('name') || '').toLowerCase();
    if (/^(og:site_name|application-name|og:price:amount|og:price:currency|product:price:amount|product:price:currency)$/.test(key)) {
      out.meta[key] = clip(m.getAttribute('content'), 100);
    }
  }
  out.siteName = out.meta['og:site_name'] || out.meta['application-name'] || '';

  // JSON-LD: walk for prices, currencies and seller/merchant names.
  let budget = 400;
  const walk = (node, depth, parentKey) => {
    if (budget-- <= 0 || depth > 6 || node === null || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.slice(0, 30).forEach((n) => walk(n, depth + 1, parentKey)); return; }
    for (const [k, v] of Object.entries(node).slice(0, 60)) {
      const key = k.toLowerCase();
      if ((key === 'price' || key === 'totalprice' || key === 'lowprice') && (typeof v === 'string' || typeof v === 'number')) {
        out.structured.push({ kind: 'price', value: clip(String(v), 40) });
      } else if (key === 'pricecurrency' && typeof v === 'string') {
        out.structured.push({ kind: 'currency', value: clip(v, 10) });
      } else if (key === 'name' && typeof v === 'string' && /^(seller|merchant|provider|brand|organization)$/.test(parentKey)) {
        out.structured.push({ kind: 'seller', value: clip(v, 80) });
      }
      if (v && typeof v === 'object') walk(v, depth + 1, key);
    }
  };
  for (const s of Array.from(document.querySelectorAll('script[type="application/ld+json"]')).slice(0, 10)) {
    try { walk(JSON.parse(s.textContent || ''), 0, ''); } catch (e) { /* malformed JSON-LD is common */ }
  }
  for (const el of Array.from(document.querySelectorAll('[itemprop="price"], [itemprop="priceCurrency"]')).slice(0, 20)) {
    const value = clip(el.getAttribute('content') || el.textContent, 40);
    out.structured.push({ kind: el.getAttribute('itemprop') === 'price' ? 'price' : 'currency', value });
  }

  const visible = (el) => {
    const r = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
    if (!r || r.width === 0 || r.height === 0) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && cs.opacity !== '0';
  };

  const LABEL = /^(order\s+|grand\s+)?total(\s+(due|to pay|amount|payable))?:?$|^amount(\s+(due|payable|to pay))?:?$|^(you('|’)re|you are) paying:?$|^to pay:?$|^balance due:?$|^pay(ing)?\s+to:?$|^merchant(\s+name)?:?$|^payee:?$|^recipient:?$|^beneficiary:?$|^sold by:?$|^seller:?$|^paying:?$|^business:?$/i;
  const elements = Array.from(document.body ? document.body.querySelectorAll('*') : []).slice(0, 5000);
  for (const el of elements) {
    if (out.labelled.length >= 30) break;
    if (el.children.length > 2) continue;
    const own = clip(el.textContent, 50);
    if (!own || own.length > 40 || !LABEL.test(own) || !visible(el)) continue;
    // The label's row: the nearest ancestor with more text than the label itself.
    let row = el.parentElement;
    for (let i = 0; row && i < 3 && clip(row.innerText).length <= own.length + 1; i++) row = row.parentElement;
    if (row) out.labelled.push({ label: own.replace(/:$/, ''), row: clip(row.innerText, 160) });
  }

  for (const b of Array.from(document.querySelectorAll('button, a[role="button"], input[type="submit"]')).slice(0, 100)) {
    const text = clip(b.value || b.textContent, 60);
    if (/^(pay|confirm|complete)\b/i.test(text) && /\d/.test(text) && visible(b)) out.buttons.push(text);
  }

  const body = clip(document.body ? document.body.innerText : '', 20000);
  const re = /(?:\bR|ZAR|\$|USD|€|EUR|£|GBP)\s?\d[\d\s.,  ]{0,15}\d|\d[\d\s.,  ]{0,15}\d\s?(?:ZAR|USD|EUR|GBP)\b/g;
  out.loose = (body.match(re) || []).slice(0, 40).map((s) => clip(s, 40));
  return out;
})()`;

const CURRENCY: [RegExp, string][] = [
  [/\bZAR\b|(^|[^A-Za-z])R(?=\s?\d)/, 'ZAR'],
  [/\bUSD\b|\$/, 'USD'],
  [/\bEUR\b|€/, 'EUR'],
  [/\bGBP\b|£/, 'GBP'],
];

/** "R 1 299,00", "R1,299.00", "1299.5 ZAR" → { amountMinor: 129900, currency: 'ZAR' }. */
export function parseMoney(text: string, fallbackCurrency?: string): { amountMinor: number; currency: string } | null {
  const currency = CURRENCY.find(([re]) => re.test(text))?.[1] ?? fallbackCurrency;
  const num = /\d[\d\s.,  ]*\d|\d/.exec(text)?.[0];
  if (!num || !currency) return null;
  const compact = num.replace(/[\s  ]/g, '');
  const lastSep = Math.max(compact.lastIndexOf('.'), compact.lastIndexOf(','));
  const decimals = lastSep >= 0 && compact.length - lastSep - 1 <= 2 && compact.length - lastSep - 1 > 0;
  const whole = (decimals ? compact.slice(0, lastSep) : compact).replace(/[.,]/g, '');
  const frac = decimals ? compact.slice(lastSep + 1).padEnd(2, '0') : '00';
  const amountMinor = Number(whole) * 100 + Number(frac);
  if (!Number.isFinite(amountMinor) || amountMinor <= 0 || amountMinor > 10_000_000_00) return null;
  return { amountMinor, currency };
}

export interface InterpretedPayment {
  recipientName: string | null;
  amountMinor: number | null;
  currency: string | null;
  confidence: 'high' | 'medium' | 'low';
  amountCandidates: AmountCandidate[];
  recipientCandidates: string[];
  notes: string[];
}

const RECIPIENT_LABEL = /^(pay(ing)?\s+to|merchant(\s+name)?|payee|recipient|beneficiary|sold by|seller|paying|business)$/i;

export function interpretPaymentEvidence(raw: RawPaymentEvidence): InterpretedPayment {
  const notes: string[] = [];
  const structuredCurrency = raw.structured.find((s) => s.kind === 'currency')?.value.toUpperCase();
  const metaCurrency = (raw.meta['og:price:currency'] ?? raw.meta['product:price:currency'])?.toUpperCase();

  // ── Amounts: weight by how directly the page states "this is what you pay". ──
  // weight = strongest single source, + 0.5 per additional *kind* of source that agrees (max +1).
  // Kinds, not occurrences: a price repeated across a product list is not corroboration.
  const scored = new Map<string, AmountCandidate & { best: number; kinds: Set<number> }>();
  const add = (text: string, weight: number, label: string, currency?: string) => {
    const m = parseMoney(text, currency);
    if (!m) return;
    const key = `${m.currency}:${m.amountMinor}`;
    const prev = scored.get(key);
    if (!prev) {
      scored.set(key, { ...m, label, best: weight, kinds: new Set([weight]) });
      return;
    }
    prev.kinds.add(weight);
    if (weight > prev.best) {
      prev.best = weight;
      prev.label = label;
    }
  };
  const weightOf = (c: { best: number; kinds: Set<number> }) => c.best + Math.min(1, 0.5 * (c.kinds.size - 1));
  for (const s of raw.structured.filter((x) => x.kind === 'price')) add(s.value, 3, 'structured data', structuredCurrency ?? 'ZAR');
  for (const k of ['og:price:amount', 'product:price:amount']) if (raw.meta[k]) add(raw.meta[k], 2, 'page metadata', metaCurrency ?? 'ZAR');
  for (const l of raw.labelled.filter((x) => !RECIPIENT_LABEL.test(x.label))) add(l.row.replace(l.label, ''), 3, l.label);
  for (const b of raw.buttons) add(b, 3, 'pay button');
  for (const t of raw.loose) add(t, 1, 'shown on page');

  const amounts = [...scored.values()].map((c) => ({ ...c, weight: weightOf(c) })).sort((a, b) => b.weight - a.weight);
  const top = amounts[0];
  // Two strongly-labelled, different amounts (e.g. two "Total" rows) are contradictory: don't guess.
  const rivals = top ? amounts.filter((a) => a !== top && a.best >= 3 && a.weight >= top.weight - 0.5) : [];
  let amountMinor: number | null = null;
  let currency: string | null = null;
  let amountConfidence: 'high' | 'medium' | 'low' = 'low';
  if (!top) {
    notes.push('No amount was found on the page.');
  } else if (rivals.length > 0) {
    notes.push('The page shows more than one possible total. Choose the one you are being asked to pay.');
  } else {
    amountMinor = top.amountMinor;
    currency = top.currency;
    amountConfidence = top.weight >= 3.5 ? 'high' : top.weight >= 3 ? 'medium' : 'low';
    if (top.weight < 3) notes.push('The amount was not clearly labelled as the total, so check it carefully.');
  }

  // ── Recipient ──
  const recipients: { name: string; weight: number }[] = [];
  for (const l of raw.labelled.filter((x) => RECIPIENT_LABEL.test(x.label))) {
    const name = l.row.replace(new RegExp(`^.*?${escapeRe(l.label)}:?\\s*`, 'i'), '').replace(/\s+(R|ZAR)\s?\d.*$/, '').trim();
    if (name && name.length <= 80 && !/^\d/.test(name)) recipients.push({ name, weight: 3 });
  }
  for (const s of raw.structured.filter((x) => x.kind === 'seller')) recipients.push({ name: s.value, weight: 2.5 });
  if (raw.siteName) recipients.push({ name: raw.siteName, weight: 1 });
  recipients.sort((a, b) => b.weight - a.weight);
  const recipientCandidates = [...new Set(recipients.map((r) => r.name))].slice(0, 5);
  const best = recipients[0];
  const recipientName = best?.name ?? null;
  if (!best) notes.push('The page did not say who is being paid.');
  else if (best.weight < 2) notes.push('The recipient was taken from the site’s name; the page did not state who is being paid.');

  const confidence: InterpretedPayment['confidence'] =
    amountConfidence === 'high' && (best?.weight ?? 0) >= 2.5 ? 'high' : amountConfidence === 'low' || !best ? 'low' : 'medium';

  return {
    recipientName,
    amountMinor,
    currency,
    confidence,
    amountCandidates: amounts.slice(0, 5).map(({ amountMinor: a, currency: c, label }) => ({ amountMinor: a, currency: c, label })),
    recipientCandidates,
    notes,
  };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
