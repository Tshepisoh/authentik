import {
  SEVERITY_RANK,
  type Assessment,
  type CheckRun,
  type EvidenceQuality,
  type Finding,
  type Verdict,
} from '@authentik/shared';
import { explain, type Subject } from './explain.js';

/** Bump when rules change so stored reports say which rules produced them. */
export const RULES_VERSION = '2026.10.4';

export interface AssessInput {
  subject: Subject;
  findings: Finding[];
  checks: CheckRun[];
  now?: Date;
}

/**
 * The single place verdicts are decided. Rules are explicit and ordered so a
 * verdict can always be traced to the findings that caused it:
 *
 *  1. Any hard block                                   → blocked
 *  2. A confirmed threat of high/critical severity     → high_risk
 *  3. A critical indicator, a high-severity indicator
 *     backed by high-quality evidence, or two or more
 *     high-severity indicators                         → high_risk
 *  4. Any high/medium indicator, or 2+ low indicators  → suspicious
 *  5. A critical check didn't complete                 → inconclusive
 *  6. Otherwise                                        → no_obvious_warnings
 *
 * Missing evidence never becomes a safe verdict (rule 5), and reassurance
 * findings never cancel threats (they are not consulted above).
 */
export function assess(input: AssessInput): Assessment {
  const findings = [...input.findings].sort(bySeverity);
  const { checks } = input;
  const verdict = decideVerdict(findings, checks);
  // A policy block is a complete answer in itself, not a gap in evidence.
  const completeness =
    verdict === 'blocked' ||
    checks.every((c) => c.status === 'completed' || c.status === 'skipped') &&
    !findings.some((f) => f.kind === 'unknown')
      ? 'complete'
      : 'partial';
  const confidence = decideConfidence(verdict, findings, completeness);
  const text = explain(input.subject, verdict, findings, checks, completeness);

  return {
    verdict,
    confidence,
    completeness,
    ...text,
    findings,
    checks,
    assessedAt: (input.now ?? new Date()).toISOString(),
    rulesVersion: RULES_VERSION,
  };
}

export function decideVerdict(findings: Finding[], checks: CheckRun[]): Verdict {
  if (findings.some((f) => f.hardBlock)) return 'blocked';

  const threats = findings.filter((f) => f.kind === 'confirmed_threat');
  if (threats.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high)) return 'high_risk';

  const indicators = findings.filter((f) => f.kind === 'suspicious_indicator' || f.kind === 'confirmed_threat');
  const high = indicators.filter((f) => f.severity === 'high');
  const strong = indicators.filter(
    (f) => f.severity === 'critical' || (f.severity === 'high' && f.quality === 'high'),
  );
  if (strong.length > 0 || high.length >= 2) return 'high_risk';

  if (indicators.some((f) => f.severity === 'high' || f.severity === 'medium')) return 'suspicious';
  if (indicators.filter((f) => f.severity === 'low').length >= 2) return 'suspicious';

  if (checks.some((c) => c.critical && c.status !== 'completed')) return 'inconclusive';
  return 'no_obvious_warnings';
}

function decideConfidence(
  verdict: Verdict,
  findings: Finding[],
  completeness: Assessment['completeness'],
): EvidenceQuality {
  switch (verdict) {
    case 'blocked':
      return 'high';
    case 'high_risk': {
      const top = findings.find((f) => f.kind !== 'reassurance' && f.kind !== 'unknown');
      return top?.quality === 'high' ? 'high' : 'medium';
    }
    case 'suspicious':
      return completeness === 'complete' ? 'medium' : 'low';
    // Never "high": the absence of warnings is weaker evidence than their presence.
    case 'no_obvious_warnings':
      return completeness === 'complete' ? 'medium' : 'low';
    case 'inconclusive':
      return 'low';
  }
}

function bySeverity(a: Finding, b: Finding) {
  const kindOrder = { confirmed_threat: 0, suspicious_indicator: 1, unknown: 2, reassurance: 3 } as const;
  return kindOrder[a.kind] - kindOrder[b.kind] || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
}

/** Convenience constructor so modules build findings consistently. */
export function finding(f: Omit<Finding, 'observedAt'> & { observedAt?: string }): Finding {
  return { ...f, observedAt: f.observedAt ?? new Date().toISOString() };
}
