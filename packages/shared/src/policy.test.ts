import { describe, expect, it } from 'vitest';
import { checkStaticDestination, isPublicAddress } from './policy.js';
import { normalizeTargetUrl, redactUrl, registrableDomain } from './url.js';
import { resolveAndCheck } from './net.js';

describe('isPublicAddress', () => {
  it.each([
    '127.0.0.1', '10.0.0.5', '172.16.3.4', '192.168.1.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1',
    '::', 'not-an-ip',
  ])('refuses %s', (ip) => expect(isPublicAddress(ip)).toBe(false));

  it.each(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])('allows %s', (ip) =>
    expect(isPublicAddress(ip)).toBe(true));
});

describe('checkStaticDestination', () => {
  const check = (u: string) => {
    const r = normalizeTargetUrl(u);
    if (!r.ok) throw new Error(r.code);
    return checkStaticDestination(r.url);
  };
  it.each([
    ['http://localhost/', 'blocked_hostname'],
    ['http://api.internal/', 'blocked_hostname'],
    ['http://metadata.google.internal/', 'blocked_hostname'],
    ['http://intranet/', 'blocked_hostname'],
    ['http://printer/', 'single_label_hostname'],
    ['http://127.0.0.1/', 'non_public_address'],
    ['http://2130706433/', 'non_public_address'],
    ['http://0x7f.1/', 'non_public_address'],
    ['http://[::1]/', 'non_public_address'],
    ['http://169.254.169.254/latest/meta-data', 'non_public_address'],
    ['https://example.com:8443/', 'port_not_allowed'],
    ['example.com:22', 'port_not_allowed'],
  ])('%s → %s', (u, code) => expect(check(u)).toMatchObject({ allowed: false, code }));

  it('allows public hosts on standard ports', () => {
    expect(check('https://www.takealot.com/')).toEqual({ allowed: true });
    expect(check('http://8.8.8.8/')).toEqual({ allowed: true });
  });
});

describe('resolveAndCheck', () => {
  it('refuses when any resolved address is private (rebinding mix)', async () => {
    const r = await resolveAndCheck('evil.example', async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ]);
    expect(r).toMatchObject({ allowed: false, code: 'non_public_address' });
  });
  it('reports DNS failures without throwing', async () => {
    const r = await resolveAndCheck('nope.example', async () => { throw new Error('ENOTFOUND'); });
    expect(r).toMatchObject({ allowed: false, code: 'dns_failure' });
  });
  it('allows all-public answers', async () => {
    const r = await resolveAndCheck('ok.example', async () => [{ address: '93.184.216.34', family: 4 }]);
    expect(r.allowed).toBe(true);
  });
});

describe('normalizeTargetUrl', () => {
  it('assumes https for bare hosts', () => {
    const r = normalizeTargetUrl('  takealot.com/deals ');
    expect(r).toMatchObject({ ok: true, schemeAssumed: true });
    if (r.ok) expect(r.url.href).toBe('https://takealot.com/deals');
  });
  it('strips and reports embedded credentials', () => {
    const r = normalizeTargetUrl('https://takealot.com@evil.example/login');
    expect(r).toMatchObject({ ok: true, hadCredentials: true });
    if (r.ok) expect(r.url.hostname).toBe('evil.example');
  });
  it.each(['javascript:alert(1)', 'file:///etc/passwd', 'ftp://x.example/', 'data:text/html,hi'])(
    'rejects %s', (u) => expect(normalizeTargetUrl(u)).toMatchObject({ ok: false, code: 'unsupported_scheme' }));
  it('rejects empty and overlong input', () => {
    expect(normalizeTargetUrl('   ')).toMatchObject({ ok: false, code: 'empty' });
    expect(normalizeTargetUrl(`https://a.com/${'x'.repeat(3000)}`)).toMatchObject({ ok: false, code: 'too_long' });
  });
});

describe('redactUrl', () => {
  it('drops query values, fragments and token-like segments', () => {
    expect(redactUrl('https://bank.example/reset/9f8a7b6c5d4e3f2a1b0c9d8e7f6a/confirm?token=abc&email=a@b.c#x'))
      .toBe('https://bank.example/reset/[redacted]/confirm?token=[redacted]&email=[redacted]');
  });
});

describe('registrableDomain', () => {
  it('handles multi-part public suffixes', () => {
    expect(registrableDomain('secure.payfast.co.za')).toBe('payfast.co.za');
    expect(registrableDomain('www.amazon.co.uk')).toBe('amazon.co.uk');
  });
});
