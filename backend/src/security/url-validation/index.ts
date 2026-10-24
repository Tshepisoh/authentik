import {
  checkStaticDestination,
  normalizeTargetUrl,
  redactUrl,
  registrableDomain,
  type DestinationBlockCode,
  type TargetSummary,
} from '@authentik/shared';
import { badRequest } from '../../lib/errors.js';

export type ValidatedTarget = {
  url: URL;
  summary: TargetSummary;
  hadCredentials: boolean;
  schemeAssumed: boolean;
} & (
  | { allowed: true }
  | { allowed: false; blockCode: DestinationBlockCode; blockMessage: string }
);

/**
 * Step one of every flow that takes a URL from a user.
 * - Malformed input → 400 (the user should fix it).
 * - Well-formed but outside policy → `allowed: false` (the scan is "blocked"
 *   and the user is told why — it is a result, not an input error).
 */
export function validateTargetUrl(input: string): ValidatedTarget {
  const normalized = normalizeTargetUrl(input);
  if (!normalized.ok) throw badRequest(`invalid_url.${normalized.code}`, normalized.message);

  const { url, hadCredentials, schemeAssumed } = normalized;
  const summary = summarizeTarget(url);
  const policy = checkStaticDestination(url);
  if (!policy.allowed) {
    return { url, summary, hadCredentials, schemeAssumed, allowed: false, blockCode: policy.code, blockMessage: policy.message };
  }
  return { url, summary, hadCredentials, schemeAssumed, allowed: true };
}

export function summarizeTarget(url: URL): TargetSummary {
  return {
    displayUrl: redactUrl(url),
    hostname: url.hostname,
    registrableDomain: registrableDomain(url.hostname),
  };
}
