import { describe, expect, it } from 'vitest';
import { EntityRegistry } from '../merchant-verification/registry.js';
import { analyzeImpersonation, levenshtein, skeleton } from './lookalike.js';

const registry = new EntityRegistry();
const codes = (host: string) => analyzeImpersonation(host, registry).map((f) => f.code);

describe('skeleton', () => {
  it('folds homoglyphs, digits and separators', () => {
    expect(skeleton('tаkеаl0t')).toBe(skeleton('takealot')); // Cyrillic а/е
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('take-alot')).toBe(skeleton('takealot'));
    expect(skeleton('arnazon')).toBe(skeleton('amazon'));
  });
});

describe('levenshtein', () => {
  it('computes small distances and bails out early', () => {
    expect(levenshtein('takealot', 'takealott')).toBe(1);
    expect(levenshtein('takealot', 'takeal')).toBe(2);
    expect(levenshtein('a', 'abcdefgh', 2)).toBe(3);
  });
});

describe('analyzeImpersonation', () => {
  it('reassures on official domains and their subdomains', () => {
    expect(codes('www.takealot.com')).toEqual(['official_domain']);
    expect(codes('secure.payfast.co.za')).toEqual(['official_domain']);
    expect(codes('www.amazon.co.za')).toEqual(['official_domain']);
  });

  it.each([
    ['takea1ot.com', 'lookalike_domain'],
    ['xn--tkealot-2fg.com', 'lookalike_domain'], // tаkealot with Cyrillic а
    ['takealott.com', 'lookalike_domain'],
    ['takealot.shop', 'brand_on_unofficial_domain'],
    ['takealot-deals.co.za', 'brand_in_domain'],
    ['securecapitec.com', 'brand_in_domain'],
    ['takealot.com.order-verify.xyz', 'brand_in_subdomain'],
    ['fnb.secure-login.net', 'brand_in_subdomain'],
  ])('%s → %s', (host, code) => {
    expect(codes(host)).toContain(code);
  });

  it('does not flag unrelated names that merely contain a short brand', () => {
    expect(codes('absalom-tours.com')).toEqual([]);
    expect(codes('example.org')).toEqual([]);
    expect(codes('temuco-travel.cl')).toEqual([]);
  });

  it('flags unmatched IDN domains weakly', () => {
    const f = analyzeImpersonation('xn--mnchen-3ya.de', registry); // münchen
    expect(f.map((x) => x.code)).toEqual(['idn_domain']);
    expect(f[0]!.severity).toBe('low');
  });
});
