import { describe, expect, it } from 'vitest';
import type { CheckRun, Finding } from '@authentik/shared';
import { assess, decideVerdict, finding } from './engine.js';

const f = (over: Partial<Finding>): Finding =>
  finding({ code: 'x', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'low', quality: 'medium', title: 't', reason: 'r', ...over });
const ok: CheckRun = { check: 'reputation.x', status: 'completed', critical: true };
const down: CheckRun = { check: 'reputation.x', status: 'unavailable', critical: true, detail: 'down' };

describe('decideVerdict', () => {
  it('honours hard blocks above everything', () => {
    expect(decideVerdict([f({ kind: 'confirmed_threat', severity: 'critical' }), f({ kind: 'unknown', hardBlock: true })], [ok])).toBe('blocked');
  });
  it('treats a high-severity confirmed threat as high risk', () => {
    expect(decideVerdict([f({ kind: 'confirmed_threat', severity: 'high' })], [ok])).toBe('high_risk');
  });
  it('needs strong evidence for high risk from indicators', () => {
    expect(decideVerdict([f({ severity: 'high', quality: 'high' })], [ok])).toBe('high_risk');
    expect(decideVerdict([f({ severity: 'high', quality: 'medium' })], [ok])).toBe('suspicious');
    expect(decideVerdict([f({ severity: 'high' }), f({ severity: 'high' })], [ok])).toBe('high_risk');
  });
  it('one weak signal is not enough to be suspicious, two are', () => {
    expect(decideVerdict([f({ severity: 'low' })], [ok])).toBe('no_obvious_warnings');
    expect(decideVerdict([f({ severity: 'low' }), f({ severity: 'low' })], [ok])).toBe('suspicious');
  });
  it('never turns missing critical evidence into a safe verdict', () => {
    expect(decideVerdict([], [down])).toBe('inconclusive');
    expect(decideVerdict([f({ kind: 'reassurance', severity: 'info' })], [down])).toBe('inconclusive');
  });
  it('still reports concerns when evidence is missing', () => {
    expect(decideVerdict([f({ severity: 'medium' })], [down])).toBe('suspicious');
  });
  it('does not let reassurance cancel a threat', () => {
    expect(decideVerdict([f({ kind: 'reassurance', severity: 'info', quality: 'high' }), f({ kind: 'confirmed_threat', severity: 'critical' })], [ok])).toBe('high_risk');
  });
});

describe('assess', () => {
  it('marks partial completeness and caps confidence when checks are missing', () => {
    const a = assess({ subject: 'website', findings: [], checks: [ok, { check: 'page_evidence', status: 'failed', critical: false }] });
    expect(a.verdict).toBe('no_obvious_warnings');
    expect(a.completeness).toBe('partial');
    expect(a.confidence).toBe('low');
    expect(a.explanation.join(' ')).toMatch(/could not complete the page content check/);
  });
  it('never claims high confidence for "no obvious warnings"', () => {
    expect(assess({ subject: 'website', findings: [], checks: [ok] }).confidence).toBe('medium');
  });
  it('explains inconclusive results without implying safety', () => {
    const a = assess({ subject: 'website', findings: [], checks: [down] });
    expect(a.headline).toMatch(/could not check/i);
    expect(a.explanation.join(' ')).toMatch(/do not treat this result as verified safe/i);
  });
  it('sorts threats first and records the rules version', () => {
    const a = assess({ subject: 'website', findings: [f({ severity: 'low' }), f({ kind: 'confirmed_threat', severity: 'critical', code: 'reputation_match' })], checks: [ok] });
    expect(a.findings[0]!.code).toBe('reputation_match');
    expect(a.rulesVersion).toMatch(/^\d{4}\./);
    expect(a.recommendedActions.join(' ')).toMatch(/do not enter/i);
  });
});
