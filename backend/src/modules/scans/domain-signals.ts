import { isIpLiteral, publicSuffix, type Finding } from '@authentik/shared';
import { finding } from '../risk-engine/engine.js';

/** TLDs with persistently high abuse rates in public phishing feeds. A weak signal on its own. */
const HIGH_ABUSE_TLDS = new Set([
  'zip', 'mov', 'top', 'icu', 'click', 'link', 'buzz', 'rest', 'cfd', 'sbs', 'monster',
  'gq', 'tk', 'ml', 'cf', 'ga', 'cyou', 'bond', 'quest', 'country', 'kim', 'work',
]);

/** Reserved for documentation and testing (RFC 2606 / 6761); they never resolve publicly. */
export const RESERVED_TLDS = new Set(['test', 'example', 'invalid', 'localhost']);

export interface UrlContext {
  url: URL;
  hadCredentials: boolean;
}

/** Signals readable from the URL alone. Each is weak; the risk engine combines them. */
export function domainSignals({ url, hadCredentials }: UrlContext): Finding[] {
  const out: Finding[] = [];
  const host = url.hostname;

  if (hadCredentials) {
    out.push(finding({
      code: 'embedded_credentials', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'high', quality: 'high',
      title: 'Link hides its real destination',
      reason: `The link contains text before an "@" sign, which browsers ignore. It actually goes to ${host}.`,
    }));
  }

  if (isIpLiteral(host)) {
    out.push(finding({
      code: 'ip_address_host', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'medium', quality: 'high',
      title: 'Uses a raw IP address',
      reason: 'Legitimate shops and banks use a website name, not a numeric IP address.',
    }));
    return out;
  }

  if (url.protocol === 'http:') {
    out.push(finding({
      code: 'no_https', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'low', quality: 'high',
      title: 'Connection is not encrypted',
      reason: 'The site uses http rather than https, so anything you type could be read in transit.',
    }));
  }

  const tld = (publicSuffix(host) ?? '').split('.').pop() ?? '';
  if (HIGH_ABUSE_TLDS.has(tld)) {
    out.push(finding({
      code: 'high_abuse_tld', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'low', quality: 'low',
      title: `Uses a ".${tld}" address`,
      reason: `".${tld}" addresses are frequently used in scams. Many are legitimate, so this is a weak signal on its own.`,
    }));
  }

  const labels = host.split('.');
  if (labels.length > 5) {
    out.push(finding({
      code: 'deep_subdomains', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
      title: 'Unusually long address',
      reason: `The address has ${labels.length} parts, which can push the real domain out of view on a phone screen.`,
    }));
  } else if (host.length > 60) {
    out.push(finding({
      code: 'long_hostname', source: 'domain_signals', kind: 'suspicious_indicator', severity: 'low', quality: 'low',
      title: 'Unusually long address',
      reason: 'Very long website names are harder to read and sometimes used to hide the real domain.',
    }));
  }

  return out;
}
