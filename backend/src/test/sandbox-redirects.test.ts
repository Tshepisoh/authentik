import { describe, expect, it } from 'vitest';
import type { SandboxEvent } from '@authentik/shared';
import { findingsFromEvents } from '../sandbox-control/policies/index.js';
import { assess } from '../modules/risk-engine/engine.js';

const at = '2026-10-25T10:00:00.000Z';
const redirect = (target: string): SandboxEvent => ({ type: 'cross_domain_redirect', at, target, severity: 'warning' });
const tap = (target: string): SandboxEvent => ({ type: 'navigation', at, target, severity: 'info' });
const verdict = (events: SandboxEvent[], start: string) =>
  assess({ subject: 'sandbox', findings: findingsFromEvents(events, start), checks: [] }).verdict;

describe('Sandbox redirects', () => {
  it('ignores a busy shop bouncing through Google and back, however often', () => {
    const events = Array.from({ length: 106 }, (_, i) => redirect(i % 2 ? 'www.takealot.com' : 'accounts.google.com'));
    expect(findingsFromEvents(events, 'www.takealot.com')).toEqual([]);
    expect(verdict(events, 'www.takealot.com')).toBe('no_obvious_warnings');
  });

  it('ignores moves to known payment providers', () => {
    expect(findingsFromEvents([redirect('secure.payu.co.za')], 'www.takealot.com')).toEqual([]);
  });

  it('notes a brief pass through an unknown site without warning', () => {
    const events = [redirect('track.adnetwork.example'), redirect('www.takealot.com')];
    const [f] = findingsFromEvents(events, 'www.takealot.com');
    expect(f).toMatchObject({ code: 'sandbox_cross_domain_redirect', severity: 'low' });
    expect(verdict(events, 'www.takealot.com')).toBe('no_obvious_warnings');
  });

  it('warns when the page leaves you on an unknown site you did not choose', () => {
    const events = [redirect('bit-pay-verify.example'), redirect('login-secure.example')];
    const [f] = findingsFromEvents(events, 'shop.example.org');
    expect(f).toMatchObject({ code: 'sandbox_cross_domain_redirect', severity: 'medium' });
    expect(f!.reason).toContain('login-secure.example');
    expect(verdict(events, 'shop.example.org')).toBe('suspicious');
  });

  it('does not count sites the user tapped through to', () => {
    expect(findingsFromEvents([tap('news.example')], 'shop.example.org')).toEqual([]);
  });
});
