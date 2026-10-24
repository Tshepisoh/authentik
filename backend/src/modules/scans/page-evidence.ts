import { registrableDomain, type CheckRun, type Finding } from '@authentik/shared';
import { finding } from '../risk-engine/engine.js';
import type { SafeFetchResult } from '../../security/ssrf-protection/index.js';
import { normalizeName, type EntityRegistry } from '../merchant-verification/registry.js';

/**
 * Turns what we observed when fetching a page into findings. Only signals
 * that can be read from static HTML are used here; behaviour that needs a
 * browser (scripts, popups, downloads) is observed by the Sandbox.
 */
export function analyzePage(
  start: URL,
  result: SafeFetchResult,
  registry: EntityRegistry,
): { check: CheckRun; findings: Finding[] } {
  const findings: Finding[] = [];
  const startDomain = registrableDomain(start.hostname);

  if (result.blocked) {
    findings.push(finding({
      code: 'redirect_to_blocked_destination', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'high', quality: 'high',
      title: 'Redirects to a prohibited destination',
      reason: `While loading, the site redirected towards ${result.blocked.hostname}, which is not a public website. ${result.blocked.message}`,
      data: { code: result.blocked.code },
    }));
    return { check: { check: 'page_evidence', status: 'completed', critical: false, detail: 'stopped at a blocked redirect' }, findings };
  }

  if (result.error) {
    if (/certificate/i.test(result.error)) {
      findings.push(finding({
        code: 'invalid_certificate', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'medium', quality: 'high',
        title: 'Invalid security certificate',
        reason: 'The site’s https certificate could not be verified, so the connection may not be private or genuine.',
      }));
    }
    return { check: { check: 'page_evidence', status: 'failed', critical: false, detail: result.error.toLowerCase() }, findings };
  }

  // ── Redirects ──
  const final = result.finalUrl;
  const finalDomain = registrableDomain(final.hostname);
  if (finalDomain !== startDomain) {
    const owner = registry.ownerOf(final.hostname);
    findings.push(owner
      ? finding({
          code: 'redirect_to_known_entity', source: 'page_evidence', kind: 'reassurance', severity: 'info', quality: 'medium',
          title: `Redirects to ${owner.name}`,
          reason: `The link forwards to ${final.hostname}, an official ${owner.name} domain.`,
        })
      : finding({
          code: 'cross_domain_redirect', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
          title: 'Sends you to a different site',
          reason: `The link starts at ${start.hostname} but ends up at ${final.hostname}. Link shorteners do this legitimately; so do scams.`,
          data: { finalHost: final.hostname },
        }));
  }
  if (result.hops.length > 4) {
    findings.push(finding({
      code: 'long_redirect_chain', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'low', quality: 'high',
      title: 'Long chain of redirects',
      reason: `The link passed through ${result.hops.length - 1} redirects before reaching a page.`,
    }));
  }

  // ── Page content ──
  const html = result.body ?? '';
  if (html) {
    const title = (/<title[^>]*>([^<]{0,300})<\/title>/i.exec(html)?.[1] ?? '').trim();
    const finalOwner = registry.ownerOf(final.hostname);
    const claimed = finalOwner ? undefined : claimedEntity(title, registry);
    const hasPassword = /<input[^>]+type\s*=\s*["']?password/i.test(html);
    const hasCard = /autocomplete\s*=\s*["']?cc-(number|csc)|name\s*=\s*["']?(card.?number|cvv|cvc)/i.test(html);
    const offsiteActions = [...html.matchAll(/<form[^>]+action\s*=\s*["']([^"']+)["']/gi)]
      .map((mm) => safeUrl(mm[1]!, final))
      .filter((u): u is URL => !!u && registrableDomain(u.hostname) !== finalDomain);

    if (claimed) {
      findings.push(finding({
        code: 'page_claims_brand', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'high', quality: 'medium',
        title: `Page presents itself as ${claimed.name}`,
        reason: `The page title mentions ${claimed.name}, but ${final.hostname} is not an official ${claimed.name} domain.`,
        data: { entity: claimed.id },
      }));
    }
    if ((hasPassword || hasCard) && claimed) {
      findings.push(finding({
        code: 'credential_harvest', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'critical', quality: 'high',
        title: `Asks for ${hasCard ? 'card details' : 'a password'} while imitating ${claimed.name}`,
        reason: `The page requests sensitive details and claims to be ${claimed.name}, but is not hosted on ${claimed.name}'s domain.`,
      }));
    }
    if ((hasPassword || hasCard) && final.protocol === 'http:') {
      findings.push(finding({
        code: 'sensitive_form_over_http', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'high', quality: 'high',
        title: 'Asks for sensitive details without encryption',
        reason: 'The page has a password or card form but is not using https.',
      }));
    }
    if (hasPassword && offsiteActions.length > 0) {
      findings.push(finding({
        code: 'credential_form_offsite', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'high', quality: 'high',
        title: 'Sends your login to another site',
        reason: `The sign-in form submits to ${offsiteActions[0]!.hostname}, a different site from the one you are viewing.`,
      }));
    }
    const refresh = /<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]+url\s*=\s*([^"'>\s]+)/i.exec(html)?.[1];
    const refreshUrl = refresh ? safeUrl(refresh, final) : null;
    if (refreshUrl && registrableDomain(refreshUrl.hostname) !== finalDomain) {
      findings.push(finding({
        code: 'meta_refresh_offsite', source: 'page_evidence', kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
        title: 'Automatically forwards to another site',
        reason: `The page is set to forward visitors to ${refreshUrl.hostname}.`,
      }));
    }
  }

  return {
    check: {
      check: 'page_evidence',
      status: 'completed',
      critical: false,
      detail: result.body === null ? 'page content was not text, so only the connection was checked' : undefined,
    },
    findings,
  };
}

function claimedEntity(title: string, registry: EntityRegistry) {
  if (!title) return undefined;
  const words = title.toLowerCase();
  const compact = normalizeName(title);
  return registry.entities.find(
    (e) =>
      (e.brandTokens.some((t) => t.length >= 5 && compact.includes(t)) ||
        new RegExp(`\\b${escapeRe(e.name.toLowerCase())}\\b`).test(words)),
  );
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function safeUrl(href: string, base: URL): URL | null {
  try {
    return new URL(href, base);
  } catch {
    return null;
  }
}
