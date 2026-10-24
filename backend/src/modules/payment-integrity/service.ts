import {
  normalizeTargetUrl,
  publicSuffix,
  redactUrl,
  registrableDomain,
  type CheckRun,
  type Finding,
  type ObservedSource,
  type PaymentCheckDetail,
  type PaymentCheckRequest,
  type RedirectHop,
} from '@authentik/shared';
import type { Config } from '../../config.js';
import type { ReportDoc } from '../../storage/models.js';
import type { AuditLog } from '../../security/audit/index.js';
import { validateTargetUrl } from '../../security/url-validation/index.js';
import { assess, finding } from '../risk-engine/engine.js';
import type { ReputationService } from '../reputation/index.js';
import type { EntityRegistry, KnownEntity } from '../merchant-verification/registry.js';
import { normalizeName } from '../merchant-verification/registry.js';
import type { ReportService } from '../reports/service.js';
import type { AlertService } from '../notifications/service.js';
import { analyzeImpersonation } from '../scans/lookalike.js';
import { RESERVED_TLDS } from '../scans/domain-signals.js';
import type { PageFetcher } from '../scans/service.js';
import { DEMO_SCENARIOS } from './scenarios.js';
import type { PaymentExtractionService } from './extraction.js';
import { badRequest } from '../../lib/errors.js';

const src = 'payment_integrity' as const;

/**
 * Compares what the user intended to pay with what the checkout actually
 * shows. A redirect to a payment processor is normal — the question is
 * whether each hop is consistent with this merchant's known flow.
 */
export class PaymentIntegrityService {
  constructor(
    private readonly deps: {
      config: Config;
      registry: EntityRegistry;
      reputation: ReputationService;
      fetcher: PageFetcher;
      reports: ReportService;
      alerts: AlertService;
      audit: AuditLog;
      extractions?: PaymentExtractionService;
    },
  ) {}

  scenarios() {
    return DEMO_SCENARIOS;
  }

  async check(uid: string, input: PaymentCheckRequest): Promise<ReportDoc> {
    const { registry } = this.deps;
    const { req, checkoutUrl, observedSource, contradictions } = this.resolveObserved(uid, input);
    const target = validateTargetUrl(checkoutUrl);
    const merchant = registry.findMerchant(req.expected.merchant);
    const simulated = isSimulated(target.url);

    const detail: PaymentCheckDetail = {
      expected: req.expected,
      observedRecipient: req.observed.recipientName ?? null,
      observedAmountMinor: req.observed.amountMinor ?? null,
      observedCurrency: req.observed.currency?.toUpperCase() ?? null,
      merchantId: merchant?.id ?? null,
      merchantName: merchant?.name ?? req.expected.merchant,
      paymentProvider: null,
      simulated,
      observedSource,
    };

    if (!target.allowed) {
      const assessment = assess({
        subject: 'payment',
        findings: [finding({
          code: 'check_blocked', source: 'url_policy', kind: 'unknown', severity: 'info', quality: 'high', hardBlock: true,
          title: 'Checkout address not permitted', reason: target.blockMessage,
        })],
        checks: [{ check: 'url_policy', status: 'completed', critical: true }],
      });
      return this.deps.reports.create(uid, { type: 'payment_check', target: target.summary, assessment, redirects: [], payment: detail });
    }

    const findings: Finding[] = [...contradictions];
    const checks: CheckRun[] = [];

    // 1. Merchant identity
    if (merchant) {
      checks.push({ check: 'merchant_identity', status: 'completed', critical: true });
    } else {
      checks.push({ check: 'merchant_identity', status: 'unavailable', critical: true, detail: 'merchant is not in the registry' });
      findings.push(finding({
        code: 'merchant_unknown', source: src, kind: 'unknown', severity: 'info', quality: 'medium',
        title: 'Merchant not recognised',
        reason: `"${req.expected.merchant}" is not in Authentik's merchant registry, so its official domains and payment arrangements cannot be confirmed.`,
      }));
    }

    // 2. Redirect chain
    const { hops, chainCheck } = await this.observeChain(req, target.url, simulated);
    checks.push(chainCheck);
    const hosts = [...new Set(hops.map((h) => h.hostname))];
    // Judge each organisation once: payfast.co.za → payfast.io is one provider, not two signals.
    const seenOwners = new Set<string>();
    for (const host of hosts) {
      const ownerKey = registry.ownerOf(host)?.id ?? registrableDomain(host) ?? host;
      if (seenOwners.has(ownerKey)) continue;
      seenOwners.add(ownerKey);
      const f = this.classifyHop(host, merchant);
      findings.push(...f.findings);
      if (f.provider) detail.paymentProvider = f.provider.name;
    }

    // 3. Reputation of every non-official hop. Useful but not what this check is about, so not critical here.
    const toCheck = hosts.filter((h) => !registry.ownerOf(h) && !isSimulatedHost(h));
    for (const host of toCheck) {
      const rep = await this.deps.reputation.check(new URL(`https://${host}/`));
      findings.push(...rep.findings);
      checks.push(...rep.checks.map((c) => ({ ...c, critical: false, check: `${c.check}.${host}` })));
    }

    // 4. Recipient and 5. amount
    findings.push(...this.compareRecipient(req, merchant, checks));
    findings.push(...this.compareAmount(req, checks));

    const assessment = assess({ subject: 'payment', findings, checks });
    const report = await this.deps.reports.create(uid, {
      type: 'payment_check',
      target: target.summary,
      assessment,
      redirects: hops,
      payment: detail,
    });
    this.deps.audit.record({ action: 'payment_check.created', uid, hostname: target.url.hostname, outcome: assessment.verdict });
    await this.deps.alerts.evaluate(report);
    return report;
  }

  /**
   * Merges what the user typed with what was read from the page. Values the
   * user left empty come from the page; where both exist and disagree, the
   * user's value is used and the disagreement becomes a finding, because
   * contradictory evidence is itself a warning sign.
   */
  private resolveObserved(uid: string, input: PaymentCheckRequest) {
    const o = input.observed;
    const ext = o.extractionId ? (this.deps.extractions?.get(uid, o.extractionId) ?? null) : null;
    if (o.extractionId && !ext) throw badRequest('extraction_expired', 'The page reading has expired. Read the page again.');
    const checkoutUrl = o.checkoutUrl ?? ext?.url;
    if (!checkoutUrl) throw badRequest('invalid_request', 'Enter the payment page address.');

    const contradictions: Finding[] = [];
    const disagree = (what: string, page: string, user: string) =>
      contradictions.push(finding({
        code: 'contradictory_payment_evidence', source: src, kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
        title: `The ${what} you entered differs from the page`,
        reason: `The payment page shows ${page}, but you entered ${user}. Check which one your bank will actually show before approving.`,
      }));

    let recipient: ObservedSource = null;
    let recipientName = o.recipientName;
    if (o.recipientName && ext?.recipientName) {
      if (normalizeName(o.recipientName) === normalizeName(ext.recipientName)) recipient = 'page_confirmed';
      else {
        recipient = 'user';
        disagree('recipient', `"${ext.recipientName}"`, `"${o.recipientName}"`);
      }
    } else if (o.recipientName) recipient = 'user';
    else if (ext?.recipientName) {
      recipientName = ext.recipientName;
      recipient = 'page';
    }

    let amount: ObservedSource = null;
    let amountMinor = o.amountMinor;
    let currency = o.currency ?? (o.amountMinor === undefined ? (ext?.currency ?? undefined) : undefined);
    if (o.amountMinor !== undefined && ext?.amountMinor != null) {
      const sameCurrency = !ext.currency || !o.currency || ext.currency === o.currency.toUpperCase();
      if (o.amountMinor === ext.amountMinor && sameCurrency) amount = 'page_confirmed';
      else {
        amount = 'user';
        disagree('amount', money(ext.amountMinor, ext.currency ?? input.expected.currency), money(o.amountMinor, o.currency ?? input.expected.currency));
      }
    } else if (o.amountMinor !== undefined) amount = 'user';
    else if (ext?.amountMinor != null) {
      amountMinor = ext.amountMinor;
      currency = ext.currency ?? undefined;
      amount = 'page';
    }

    const req: PaymentCheckRequest = {
      expected: input.expected,
      observed: { ...o, checkoutUrl, recipientName, amountMinor, currency },
    };
    return { req, checkoutUrl, observedSource: { recipient, amount }, contradictions };
  }

  private async observeChain(req: PaymentCheckRequest, checkout: URL, simulated: boolean) {
    const supplied = req.observed.redirectChain;
    if (supplied?.length || simulated) {
      const urls = (supplied?.length ? supplied : [checkout.href])
        .map((u) => normalizeTargetUrl(u))
        .filter((r) => r.ok)
        .map((r) => (r as { url: URL }).url);
      if (urls.at(-1)?.hostname !== checkout.hostname) urls.push(checkout);
      const start = registrableDomain(urls[0]!.hostname);
      const hops: RedirectHop[] = urls.map((u) => ({
        url: redactUrl(u), hostname: u.hostname, status: null, crossDomain: registrableDomain(u.hostname) !== start,
      }));
      return { hops, chainCheck: { check: 'payment_redirects', status: 'completed', critical: true, detail: simulated ? 'simulated checkout' : 'chain supplied by client' } satisfies CheckRun };
    }

    const res = await this.deps.fetcher.fetch(checkout, {
      timeoutMs: this.deps.config.SCAN_FETCH_TIMEOUT_MS,
      maxBytes: 100_000,
      maxRedirects: this.deps.config.SCAN_MAX_REDIRECTS,
    });
    if (res.blocked) {
      return {
        hops: res.hops,
        chainCheck: { check: 'payment_redirects', status: 'completed', critical: true, detail: `redirect blocked: ${res.blocked.code}` } satisfies CheckRun,
      };
    }
    if (res.error && res.hops.length === 0) {
      return {
        hops: [{ url: redactUrl(checkout), hostname: checkout.hostname, status: null, crossDomain: false }],
        chainCheck: { check: 'payment_redirects', status: 'failed', critical: true, detail: res.error.toLowerCase() } satisfies CheckRun,
      };
    }
    return { hops: res.hops, chainCheck: { check: 'payment_redirects', status: 'completed', critical: true } satisfies CheckRun };
  }

  private classifyHop(host: string, merchant: KnownEntity | undefined): { findings: Finding[]; provider?: KnownEntity } {
    const owner = this.deps.registry.ownerOf(host);
    if (owner && merchant && owner.id === merchant.id) return { findings: [] };
    if (owner?.kind === 'payment_provider') {
      const expectedProvider = !merchant?.paymentProviders || merchant.paymentProviders.includes(owner.id);
      return {
        provider: owner,
        findings: [expectedProvider
          ? finding({
              code: 'known_payment_provider', source: src, kind: 'reassurance', severity: 'info', quality: 'medium',
              title: `Payment handled by ${owner.name}`,
              reason: `${host} is an official ${owner.name} domain${merchant?.paymentProviders ? `, which ${merchant.name} is known to use` : ''}.`,
            })
          : finding({
              code: 'unexpected_payment_provider', source: src, kind: 'suspicious_indicator', severity: 'low', quality: 'medium',
              title: `Unusual payment provider for ${merchant!.name}`,
              reason: `${owner.name} is a legitimate provider, but not one ${merchant!.name} is known to use.`,
            })],
      };
    }
    if (owner?.kind === 'bank') return { findings: [] }; // e.g. a 3-D Secure step on the card issuer's domain
    if (owner) {
      return {
        findings: [finding({
          code: 'unrecognised_payment_redirect', source: src, kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
          title: `Checkout passes through ${owner.name}`,
          reason: `${host} belongs to ${owner.name}, which is not part of the expected payment flow${merchant ? ` for ${merchant.name}` : ''}.`,
        })],
      };
    }

    const impersonation = analyzeImpersonation(host, this.deps.registry).filter((f) => f.kind === 'suspicious_indicator');
    if (impersonation.some((f) => f.severity === 'high')) {
      return {
        findings: [
          ...impersonation,
          finding({
            code: 'unrecognised_payment_redirect', source: src, kind: 'suspicious_indicator', severity: 'high', quality: 'high',
            title: 'Checkout sends you to an imitation site',
            reason: `The payment step goes to ${host}, which imitates a known brand rather than using its official domain.`,
          }),
        ],
      };
    }
    return {
      findings: [
        ...impersonation,
        finding({
          code: 'unrecognised_payment_redirect', source: src, kind: 'suspicious_indicator', severity: 'medium', quality: 'medium',
          title: 'Unrecognised payment page',
          reason: `${host} is not a payment provider Authentik recognises. Smaller legitimate providers exist, so confirm with ${merchant?.name ?? 'the merchant'} before paying.`,
        }),
      ],
    };
  }

  private compareRecipient(req: PaymentCheckRequest, merchant: KnownEntity | undefined, checks: CheckRun[]): Finding[] {
    const recipient = req.observed.recipientName?.trim();
    if (!recipient) {
      checks.push({ check: 'payment_recipient', status: 'unavailable', critical: true, detail: 'recipient was not shown' });
      return [finding({
        code: 'recipient_not_observed', source: src, kind: 'unknown', severity: 'info', quality: 'high',
        title: 'Recipient not visible', reason: 'We could not see who this payment would go to.',
      })];
    }
    checks.push({ check: 'payment_recipient', status: 'completed', critical: true });
    const matches = merchant
      ? this.deps.registry.recipientMatches(merchant, recipient)
      : normalizeName(recipient) === normalizeName(req.expected.merchant);
    if (matches) {
      return [finding({
        code: 'recipient_matches', source: src, kind: 'reassurance', severity: 'info', quality: merchant ? 'high' : 'medium',
        title: 'Recipient matches', reason: `The payment goes to "${recipient}", which matches ${merchant?.name ?? req.expected.merchant}.`,
      })];
    }
    return [finding({
      code: 'payment_recipient_mismatch', source: src, kind: 'suspicious_indicator', severity: 'high',
      quality: merchant ? 'high' : 'medium',
      title: 'Payment goes to someone else',
      reason: `The payment would go to "${recipient}", not ${merchant?.name ?? req.expected.merchant}.`,
    })];
  }

  private compareAmount(req: PaymentCheckRequest, checks: CheckRun[]): Finding[] {
    const { amountMinor: observed, currency } = req.observed;
    const exp = req.expected;
    if (observed === undefined) {
      checks.push({ check: 'payment_amount', status: 'unavailable', critical: true, detail: 'amount was not shown' });
      return [finding({
        code: 'amount_not_observed', source: src, kind: 'unknown', severity: 'info', quality: 'high',
        title: 'Amount not visible', reason: 'We could not see how much this payment is for.',
      })];
    }
    checks.push({ check: 'payment_amount', status: 'completed', critical: true });
    const out: Finding[] = [];
    if (currency && currency.toUpperCase() !== exp.currency.toUpperCase()) {
      out.push(finding({
        code: 'payment_currency_mismatch', source: src, kind: 'suspicious_indicator', severity: 'high', quality: 'high',
        title: 'Different currency', reason: `The payment is in ${currency.toUpperCase()}, but you expected ${exp.currency.toUpperCase()}.`,
      }));
      return out;
    }
    const diff = observed - exp.amountMinor;
    const allowed = exp.allowedAdjustmentMinor ?? 0;
    const fmt = (v: number) => money(v, exp.currency);
    if (diff === 0) {
      out.push(finding({
        code: 'amount_matches', source: src, kind: 'reassurance', severity: 'info', quality: 'high',
        title: 'Amount matches', reason: `The payment is for ${fmt(observed)}, as expected.`,
      }));
    } else if (diff > 0 && diff <= allowed) {
      out.push(finding({
        code: 'amount_within_adjustment', source: src, kind: 'reassurance', severity: 'info', quality: 'high',
        title: 'Amount includes an expected adjustment',
        reason: `The payment is ${fmt(diff)} more than the item price, within the ${fmt(allowed)} you allowed for fees or delivery.`,
      }));
    } else if (diff > 0) {
      const big = diff - allowed > Math.max(allowed, exp.amountMinor * 0.05);
      out.push(finding({
        code: 'payment_amount_mismatch', source: src, kind: 'suspicious_indicator', severity: big ? 'high' : 'medium', quality: 'high',
        title: 'Amount is higher than expected',
        reason: `You expected to pay ${fmt(exp.amountMinor)}${allowed ? ` (plus up to ${fmt(allowed)})` : ''}, but the payment is for ${fmt(observed)}.`,
        data: { differenceMinor: diff },
      }));
    } else {
      out.push(finding({
        code: 'payment_amount_lower', source: src, kind: 'suspicious_indicator', severity: 'low', quality: 'high',
        title: 'Amount is lower than expected',
        reason: `The payment is for ${fmt(observed)}, less than the ${fmt(exp.amountMinor)} you expected. This may be a discount — confirm before paying.`,
      }));
    }
    return out;
  }
}

function isSimulatedHost(host: string) {
  return RESERVED_TLDS.has((publicSuffix(host) ?? '').split('.').pop() ?? '');
}
const isSimulated = (url: URL) => isSimulatedHost(url.hostname);

function money(minor: number, currency: string) {
  try {
    return new Intl.NumberFormat('en-ZA', { style: 'currency', currency }).format(minor / 100);
  } catch {
    return `${(minor / 100).toFixed(2)} ${currency}`;
  }
}
