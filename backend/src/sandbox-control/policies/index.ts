import { z } from 'zod';
import { SANDBOX_ALLOWED_KEYS, isSameOrSubdomain, registrableDomain, type Finding, type SandboxEvent, type SandboxEventType, type Verdict } from '@authentik/shared';
import { conflict, forbidden } from '../../lib/errors.js';
import { finding } from '../../modules/risk-engine/engine.js';
import { EntityRegistry } from '../../modules/merchant-verification/registry.js';

/** Decides whether a Sandbox may open a target, given its preliminary scan. */
export function preflight(verdict: Verdict, acknowledgeRisk: boolean | undefined): void {
  if (verdict === 'blocked') {
    throw forbidden('sandbox_target_blocked', 'This address is not permitted, so the Sandbox cannot open it.');
  }
  if (verdict === 'high_risk' && !acknowledgeRisk) {
    throw conflict(
      'risk_acknowledgement_required',
      'This site was rated high risk. Confirm you understand the risk to open it in the Sandbox.',
    );
  }
}

/** Every message a viewer can send. Anything else is dropped. */
export const clientMessageSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('tap'), x: z.number().min(0).max(4000), y: z.number().min(0).max(8000) }),
  z.object({ type: z.literal('scroll'), dx: z.number().min(-5000).max(5000), dy: z.number().min(-5000).max(5000) }),
  z.object({ type: z.literal('type'), text: z.string().max(500) }),
  z.object({ type: z.literal('key'), key: z.enum(SANDBOX_ALLOWED_KEYS) }),
  z.object({ type: z.literal('back') }),
  z.object({ type: z.literal('forward') }),
  z.object({ type: z.literal('reload') }),
  z.object({ type: z.literal('navigate'), url: z.string().max(2048) }),
]);

/** Messages the worker may send. Validated so a compromised worker can't inject arbitrary payloads to phones. */
export const workerMessageSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('frame'), data: z.string().max(3_000_000), width: z.number().int().positive(), height: z.number().int().positive() }),
  z.object({ type: z.literal('navigated'), url: z.string().max(2048), title: z.string().max(300) }),
  z.object({
    type: z.literal('event'),
    event: z.object({
      type: z.enum([
        'navigation', 'cross_domain_redirect', 'blocked_destination', 'download_blocked', 'permission_denied',
        'popup_blocked', 'dialog_dismissed', 'file_chooser_blocked', 'browser_crashed', 'session_expired', 'isolation_failure',
      ]),
      at: z.string().max(40),
      target: z.string().max(300).optional(),
      detail: z.string().max(300).optional(),
      severity: z.enum(['info', 'warning', 'critical']),
    }),
  }),
  z.object({ type: z.literal('closed'), reason: z.string().max(100) }),
]);

const EVENT_FINDINGS: Partial<Record<SandboxEventType, Pick<Finding, 'code' | 'severity' | 'quality' | 'title'> & { reason: (n: number, targets: string) => string }>> = {
  blocked_destination: {
    code: 'blocked_destination', severity: 'high', quality: 'high', title: 'Tried to reach a prohibited destination',
    reason: (n, t) => `The site attempted ${n} connection(s) to destinations Authentik does not allow${t}.`,
  },
  download_blocked: {
    code: 'download_blocked', severity: 'medium', quality: 'high', title: 'Tried to download a file',
    reason: (n) => `The site started ${n} download(s). Downloads are blocked in the Sandbox.`,
  },
  permission_denied: {
    code: 'permission_requested', severity: 'low', quality: 'high', title: 'Requested device permissions',
    reason: (n) => `The site asked ${n} time(s) for access such as camera, microphone, location or notifications. These are always denied in the Sandbox.`,
  },
  popup_blocked: {
    code: 'popup_blocked', severity: 'low', quality: 'medium', title: 'Opened pop-up windows',
    reason: (n) => `The site tried to open ${n} pop-up window(s).`,
  },
  file_chooser_blocked: {
    code: 'file_upload_requested', severity: 'low', quality: 'medium', title: 'Asked to upload a file',
    reason: () => 'The site asked to upload a file. File access is blocked in the Sandbox.',
  },
  dialog_dismissed: {
    code: 'dialog_dismissed', severity: 'low', quality: 'low', title: 'Showed pop-up dialogs',
    reason: (n) => `The site displayed ${n} alert or confirmation dialog(s), a common pressure tactic.`,
  },
};

const registry = new EntityRegistry();

/**
 * Platforms ordinary sites pass through for sign-in, consent, video or payment. Landing on one
 * isn't a sign of a scam by itself (their own checks, like Safe Browsing, cover abuse of them).
 */
const COMMON_PLATFORMS = [
  'google.com', 'google.co.za', 'youtube.com', 'gstatic.com', 'facebook.com', 'instagram.com', 'apple.com', 'icloud.com',
  'microsoft.com', 'microsoftonline.com', 'live.com', 'x.com', 'twitter.com', 'linkedin.com', 'tiktok.com', 'whatsapp.com',
];

const isTrusted = (host: string) =>
  !!registry.ownerOf(host) || COMMON_PLATFORMS.some((d) => isSameOrSubdomain(host, d));

/**
 * Judges unprompted moves between sites by where the page ended up, not by how often it hopped.
 * Busy shops bounce through sign-in, consent and analytics pages many times; what matters is being
 * left on an unknown site you didn't choose.
 */
function redirectFinding(events: SandboxEvent[], startHost: string | undefined): Finding | null {
  const startDomain = startHost ? registrableDomain(startHost) : null;
  const moves = events.filter((e) => (e.type === 'cross_domain_redirect' || e.type === 'navigation') && e.target);
  const away = moves.filter(
    (e) => e.type === 'cross_domain_redirect' && registrableDomain(e.target!) !== startDomain && !isTrusted(e.target!),
  );
  if (away.length === 0) return null;

  const domains = [...new Set(away.map((e) => registrableDomain(e.target!) ?? e.target!))];
  const finalHost = moves.at(-1)!.target!;
  const endedAway = away.at(-1) === moves.at(-1);
  const list = domains.slice(0, 3).join(', ');
  return finding({
    code: 'sandbox_cross_domain_redirect',
    source: 'sandbox',
    kind: 'suspicious_indicator',
    ...(endedAway
      ? {
          severity: 'medium', quality: 'medium', title: 'Sent you to another site',
          reason: `Without you tapping anything, the page moved you to ${domains.length === 1 ? 'another site' : `${domains.length} other sites`} and left you on ${finalHost}.`,
        }
      : {
          severity: 'low', quality: 'medium', title: 'Briefly passed through other sites',
          reason: `The page passed through ${list} on its own before moving on. Common on large sites, so this alone isn't a warning.`,
        }),
    observedAt: away[0]!.at,
    data: { count: away.length, sites: domains.length },
  });
}

/** Aggregates raw session events into findings for the Sandbox report. */
export function findingsFromEvents(events: SandboxEvent[], startHost?: string): Finding[] {
  const grouped = new Map<SandboxEventType, SandboxEvent[]>();
  for (const e of events) grouped.set(e.type, [...(grouped.get(e.type) ?? []), e]);

  const out: Finding[] = [];
  const redirect = redirectFinding(events, startHost);
  if (redirect) out.push(redirect);
  for (const [type, list] of grouped) {
    const spec = EVENT_FINDINGS[type];
    if (!spec) continue;
    const targets = [...new Set(list.map((e) => e.target).filter(Boolean))].slice(0, 3);
    const { reason, ...rest } = spec;
    out.push(finding({
      ...rest,
      source: 'sandbox',
      kind: 'suspicious_indicator',
      reason: reason(list.length, targets.length ? ` (${targets.join(', ')})` : ''),
      observedAt: list[0]!.at,
      data: { count: list.length },
    }));
  }
  return out;
}
