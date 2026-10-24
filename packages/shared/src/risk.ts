/**
 * The shared vocabulary of the unified risk engine.
 *
 * Website scans, Sandbox observations and payment-flow checks all produce
 * `Finding`s. The risk engine turns findings plus the record of which checks
 * actually ran (`CheckRun`) into an `Assessment`. Keeping the two separate is
 * what lets Authentik say "nothing was found" and "we could not look" as
 * different things.
 */

/** Where a piece of evidence came from. */
export type FindingSource =
  | 'url_policy'
  | 'reputation'
  | 'lookalike'
  | 'domain_signals'
  | 'domain_registration'
  | 'page_evidence'
  | 'sandbox'
  | 'payment_integrity'
  /** On-device notification rules (Android). */
  | 'notification'
  /** On-device DNS / VPN observations (Android, planned). */
  | 'dns';

/**
 * What kind of claim a finding makes. Reports keep these apart so a user can
 * tell a confirmed threat from a concerning signal from a gap in evidence.
 */
export type FindingKind =
  /** A credible source says this is malicious (e.g. a reputation match). */
  | 'confirmed_threat'
  /** A signal that warrants attention but is not proof of malice. */
  | 'suspicious_indicator'
  /** Evidence we wanted but could not obtain. */
  | 'unknown'
  /** Evidence consistent with legitimacy. Never overrides a threat. */
  | 'reassurance';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** How much the evidence behind a finding can be trusted. */
export type EvidenceQuality = 'high' | 'medium' | 'low';

export interface Finding {
  /** Stable machine code, e.g. `reputation_match`, `lookalike_domain`. */
  code: string;
  source: FindingSource;
  kind: FindingKind;
  severity: Severity;
  /** Short user-facing title. */
  title: string;
  /** Plain-language reason grounded in the evidence. */
  reason: string;
  quality: EvidenceQuality;
  /** ISO-8601 timestamp of when the evidence was observed. */
  observedAt: string;
  /**
   * A hard security block (e.g. SSRF policy). The risk engine always honours
   * it; no explanation layer may soften it.
   */
  hardBlock?: boolean;
  /** Small, non-sensitive structured detail for the report. */
  data?: Record<string, string | number | boolean | null>;
}

export type CheckStatus = 'completed' | 'unavailable' | 'failed' | 'skipped';

/** A record that a check was attempted, and what happened. */
export interface CheckRun {
  /** e.g. `reputation.google_safe_browsing`, `page_evidence`. */
  check: string;
  status: CheckStatus;
  /**
   * Critical checks are ones whose absence means we cannot call a target
   * "no obvious warnings" — the verdict becomes `inconclusive` instead.
   */
  critical: boolean;
  detail?: string;
}

export type Verdict =
  | 'high_risk'
  | 'suspicious'
  | 'no_obvious_warnings'
  | 'inconclusive'
  | 'blocked';

export type Completeness = 'complete' | 'partial';

export interface Assessment {
  verdict: Verdict;
  confidence: EvidenceQuality;
  completeness: Completeness;
  headline: string;
  explanation: string[];
  recommendedActions: string[];
  findings: Finding[];
  checks: CheckRun[];
  assessedAt: string;
  /** Version of the deterministic rule set that produced this verdict. */
  rulesVersion: string;
}

/** User-facing labels for each verdict, per subject type. */
export const VERDICT_LABELS: Record<'website' | 'payment', Record<Verdict, string>> = {
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
};

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
