import { z } from 'zod';
import { SANDBOX_ALLOWED_KEYS, type Finding, type SandboxEvent, type SandboxEventType, type Verdict } from '@authentik/shared';
import { conflict, forbidden } from '../../lib/errors.js';
import { finding } from '../../modules/risk-engine/engine.js';

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
  cross_domain_redirect: {
    code: 'sandbox_cross_domain_redirect', severity: 'medium', quality: 'medium', title: 'Redirected to another site',
    reason: (n, t) => `The page moved you to a different site ${n} time(s)${t}.`,
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

/** Aggregates raw session events into findings for the Sandbox report. */
export function findingsFromEvents(events: SandboxEvent[]): Finding[] {
  const grouped = new Map<SandboxEventType, SandboxEvent[]>();
  for (const e of events) grouped.set(e.type, [...(grouped.get(e.type) ?? []), e]);

  const out: Finding[] = [];
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
