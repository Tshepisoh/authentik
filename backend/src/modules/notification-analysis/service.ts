import type {
  CheckRun,
  DomainAnalysis,
  EvidenceQuality,
  Finding,
  FindingKind,
  NotificationAnalysis,
  NotificationAnalyzeRequest,
  Severity,
} from '@authentik/shared';
import type { AuditLog } from '../../security/audit/index.js';
import { assess, finding } from '../risk-engine/engine.js';
import type { ScanService } from '../scans/service.js';

type Definition = { kind: FindingKind; severity: Severity; quality: EvidenceQuality; title: string; reason: string };

/**
 * Server-owned weights for the finding codes the Android rules emit
 * (mobile/modules/authentik-protection/.../rules/NotificationRules.kt). The phone
 * sends codes only, so it can't raise its own severity. Codes not listed here
 * are ignored, including the link codes (`lookalike_link`, `ip_link`,
 * `punycode_link`, `official_link`, `known_threat_link`): the server checks the
 * hosts itself, and counting both would double the same evidence.
 */
export const NOTIFICATION_FINDINGS: Record<string, Definition> = {
  payment_claim: {
    kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
    title: 'Claims a payment was made',
    reason: 'A notification can say anything. It doesn’t prove money reached your account.',
  },
  payment_claim_release: {
    kind: 'suspicious_indicator', severity: 'high', quality: 'high',
    title: 'Asks you to release goods because of a payment message',
    reason: 'A fake payment confirmation followed by pressure to hand over the item is a common marketplace scam.',
  },
  payment_claim_via_message: {
    kind: 'suspicious_indicator', severity: 'info', quality: 'medium',
    title: 'Arrived as a message, not from a banking app',
    reason: 'Anyone can send a message that looks like a bank alert.',
  },
  credential_request: {
    kind: 'suspicious_indicator', severity: 'high', quality: 'medium',
    title: 'Asks for your PIN, OTP, password or card details',
    reason: 'Your bank will never ask for these in a message.',
  },
  verify_via_link: {
    kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
    title: 'Asks you to verify or update details through a link',
    reason: 'Phishing messages send you to a fake sign-in page to collect your details.',
  },
  account_threat: {
    kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
    title: 'Says your account will be blocked',
    reason: 'Threats to close or block an account are used to rush people.',
  },
  urgency: {
    kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
    title: 'Pressures you to act quickly',
    reason: 'Scams push for speed so you don’t stop to check.',
  },
  delivery_fee_link: {
    kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
    title: 'Asks you to pay a delivery fee through a link',
    reason: 'Fake courier messages ask for small fees to collect card details.',
  },
  refund_link: {
    kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
    title: 'Offers a refund through a link',
    reason: 'Refund scams send you to a fake page that asks for your banking details.',
  },
  prize_link: {
    kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
    title: 'Offers a prize or reward through a link',
    reason: 'Unexpected prizes are a common way to get people onto scam pages.',
  },
  money_offer: {
    kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
    title: 'Offers money you weren’t expecting',
    reason: 'Unclaimed funds, inheritances and winnings offered by strangers are a classic advance-fee scam.',
  },
  money_offer_contact: {
    kind: 'suspicious_indicator', severity: 'high', quality: 'high',
    title: 'Promises money if you get in touch or pay first',
    reason: 'Scammers promise a payout, then ask for fees or personal details before you “receive” it. Nothing is ever paid out.',
  },
  shortened_link: {
    kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
    title: 'Uses a link shortener',
    reason: 'A shortened link hides where it really goes.',
  },
  // Needs the message text (a bank is named), which only the phone has.
  brand_link_mismatch: {
    kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
    title: 'Mentions a bank but links elsewhere',
    reason: 'The link doesn’t go to a website of the bank the message names.',
  },
};

/**
 * One assessment for a notification: the phone's findings plus a quick domain
 * check of each link. Nothing is stored, and no notification text is received.
 */
export class NotificationAnalysisService {
  constructor(private readonly deps: { scans: ScanService; audit: AuditLog }) {}

  async analyze(uid: string, req: NotificationAnalyzeRequest): Promise<NotificationAnalysis> {
    const findings: Finding[] = [];
    for (const code of new Set(req.findingCodes)) {
      const def = NOTIFICATION_FINDINGS[code];
      if (def) findings.push(finding({ code, source: 'notification', ...def }));
    }
    const checks: CheckRun[] = [
      { check: 'notification_rules', status: 'completed', critical: false, detail: req.localRulesVersion },
    ];

    const hosts = [...new Set(req.linkHosts.map((h) => h.toLowerCase()))];
    const results = await Promise.all(
      hosts.map(async (host) => {
        try {
          return { host, analysis: await this.deps.scans.analyzeDomain(uid, host, { depth: 'quick', source: 'notification' }) };
        } catch {
          return { host, analysis: null };
        }
      }),
    );

    const links: DomainAnalysis[] = [];
    for (const { host, analysis } of results) {
      if (!analysis) {
        // We were asked to check this link and couldn't: that's a gap, not a pass.
        checks.push({ check: 'link_check', status: 'failed', critical: true, detail: `${host} isn’t a valid address` });
        continue;
      }
      links.push(analysis);
      if (analysis.assessment.verdict === 'blocked') {
        // A policy block on one link shouldn't turn the whole notification into "blocked".
        findings.push(finding({
          code: 'link_not_public', source: 'notification', kind: 'suspicious_indicator', severity: 'medium', quality: 'high',
          title: 'Link points to a private or reserved address',
          reason: `${host} isn’t a public website address. Real companies don’t send links like this.`,
        }));
        continue;
      }
      findings.push(...analysis.assessment.findings);
      checks.push(...analysis.assessment.checks.map((c) => ({ ...c, detail: c.detail ? `${host}: ${c.detail}` : host })));
    }

    const assessment = assess({ subject: 'notification', findings, checks });
    this.deps.audit.record({ action: 'notification.analyzed', uid, outcome: assessment.verdict, detail: `${hosts.length} link(s)` });
    return { assessment, links };
  }
}
