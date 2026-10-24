// The mobile app imports only *types* from @authentik/shared (erased at build time), so labels live here.
import type { ReportType, Verdict } from '@authentik/shared';

export type VerdictSubject = 'website' | 'payment' | 'notification';

export const VERDICT_LABEL: Record<VerdictSubject, Record<Verdict, string>> = {
  website: {
    high_risk: 'High risk',
    suspicious: 'Suspicious',
    no_obvious_warnings: 'No obvious warnings',
    inconclusive: 'Inconclusive',
    blocked: 'Scan blocked',
  },
  payment: {
    high_risk: 'High-risk payment',
    suspicious: 'Suspicious payment flow',
    no_obvious_warnings: 'No discrepancy detected',
    inconclusive: 'Verification incomplete',
    blocked: 'Check blocked',
  },
  notification: {
    high_risk: 'Likely scam',
    suspicious: 'Suspicious',
    no_obvious_warnings: 'No obvious warnings',
    inconclusive: 'Couldn’t fully check',
    blocked: 'Blocked',
  },
};

/** Plain names for the checks behind a verdict (`CheckRun.check`). */
const CHECK_LABEL: Record<string, string> = {
  'reputation.google_safe_browsing': 'Google Safe Browsing',
  'reputation.local_blocklist': 'Known scam lists',
  'reputation.threat_feeds': 'Threat feeds',
  'reputation.local_threat_list': 'Threat list on this phone',
  lookalike: 'Look-alike names',
  domain_registration: 'Domain age',
  page_evidence: 'Page contents',
  url_policy: 'Address safety rules',
  payment_observation: 'Payment details',
  notification_rules: 'Message rules',
  link_check: 'Link check',
};

export function checkLabel(check: string): string {
  const destination = check.endsWith('.destination');
  const base = destination ? check.slice(0, -'.destination'.length) : check;
  const label = CHECK_LABEL[base] ?? base.replace(/^reputation\./, '').replace(/[._]/g, ' ');
  return destination ? `${label} (where it redirects)` : label;
}

export type ProtectionState = 'unsupported' | 'not_in_build' | 'needs_access' | 'connecting' | 'needs_notifications' | 'paused' | 'active';

export type WebProtectionState = 'unsupported' | 'off' | 'starting' | 'on' | 'bypassed' | 'stopped';

export const WEB_PROTECTION_STATE_LABEL: Record<WebProtectionState, string> = {
  unsupported: 'Not available on this device',
  off: 'Off',
  starting: 'Starting',
  on: 'On',
  bypassed: 'On, but Private DNS bypasses it',
  stopped: 'Stopped',
};

export const PROTECTION_STATE_LABEL: Record<ProtectionState, string> = {
  unsupported: 'Not available on this device',
  not_in_build: 'Not in this version: paste a message to check it',
  needs_access: 'Off: needs notification access',
  connecting: 'Waiting for Android to start it',
  needs_notifications: 'On, but warnings are blocked',
  paused: 'Paused',
  active: 'On',
};

export const REPORT_TYPE_LABEL: Record<ReportType, string> = {
  website_scan: 'Website scan',
  payment_check: 'Payment check',
  sandbox_session: 'Sandbox session',
};

export const subjectOf = (t: ReportType) => (t === 'payment_check' ? 'payment' : 'website');

export function relativeTime(iso: string, now = Date.now()): string {
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 7 * 86_400) return `${Math.floor(s / 86_400)} d ago`;
  return new Date(iso).toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
}

export const dateTime = (iso: string) =>
  new Date(iso).toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

export function money(minor: number, currency: string) {
  try {
    return new Intl.NumberFormat('en-ZA', { style: 'currency', currency }).format(minor / 100);
  } catch {
    return `${(minor / 100).toFixed(2)} ${currency}`;
  }
}

/** "1 299,00" / "1299.50" / "R1,299" → 129900 minor units. */
export function parseAmount(input: string): number | null {
  const cleaned = input.replace(/[^\d.,]/g, '');
  if (!cleaned) return null;
  const lastSep = Math.max(cleaned.lastIndexOf('.'), cleaned.lastIndexOf(','));
  const hasDecimals = lastSep >= 0 && cleaned.length - lastSep - 1 <= 2;
  const whole = (hasDecimals ? cleaned.slice(0, lastSep) : cleaned).replace(/[.,]/g, '');
  const frac = hasDecimals ? cleaned.slice(lastSep + 1).padEnd(2, '0') : '00';
  const n = Number(whole || '0') * 100 + Number(frac);
  return Number.isFinite(n) ? n : null;
}
