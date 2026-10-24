package app.authentik.protection.rules

/**
 * On-device copy of `decideVerdict` in backend/src/modules/risk-engine/engine.ts.
 * Notifications are judged offline, so the rules run here too. Keep the two in
 * step: same order, same thresholds. LocalVerdictTest mirrors the backend cases.
 *
 *  1. Any hard block                                   → blocked
 *  2. A confirmed threat of high/critical severity     → high_risk
 *  3. A critical indicator, a high-severity indicator
 *     backed by high-quality evidence, or two or more
 *     high-severity indicators                         → high_risk
 *  4. Any high/medium indicator, or 2+ low indicators  → suspicious
 *  5. A critical check didn't complete                 → inconclusive
 *  6. Otherwise                                        → no_obvious_warnings
 */
object LocalVerdict {
  fun decide(findings: List<Finding>, checks: List<CheckRun>): Verdict {
    if (findings.any { it.hardBlock }) return Verdict.BLOCKED

    val threats = findings.filter { it.kind == FindingKind.CONFIRMED_THREAT }
    if (threats.any { it.severity.rank >= Severity.HIGH.rank }) return Verdict.HIGH_RISK

    val indicators = findings.filter {
      it.kind == FindingKind.SUSPICIOUS_INDICATOR || it.kind == FindingKind.CONFIRMED_THREAT
    }
    val high = indicators.filter { it.severity == Severity.HIGH }
    val strong = indicators.filter {
      it.severity == Severity.CRITICAL || (it.severity == Severity.HIGH && it.quality == EvidenceQuality.HIGH)
    }
    if (strong.isNotEmpty() || high.size >= 2) return Verdict.HIGH_RISK

    if (indicators.any { it.severity == Severity.HIGH || it.severity == Severity.MEDIUM }) return Verdict.SUSPICIOUS
    if (indicators.count { it.severity == Severity.LOW } >= 2) return Verdict.SUSPICIOUS

    if (checks.any { it.critical && it.status != CheckStatus.COMPLETED }) return Verdict.INCONCLUSIVE
    return Verdict.NO_OBVIOUS_WARNINGS
  }

  private val kindOrder = mapOf(
    FindingKind.CONFIRMED_THREAT to 0,
    FindingKind.SUSPICIOUS_INDICATOR to 1,
    FindingKind.UNKNOWN to 2,
    FindingKind.REASSURANCE to 3,
  )

  /** Same ordering as the backend's `bySeverity`. */
  val bySeverity: Comparator<Finding> =
    compareBy<Finding> { kindOrder.getValue(it.kind) }.thenByDescending { it.severity.rank }
}
