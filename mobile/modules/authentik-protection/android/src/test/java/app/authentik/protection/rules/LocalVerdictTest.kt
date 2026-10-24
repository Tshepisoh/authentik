package app.authentik.protection.rules

import org.junit.Assert.assertEquals
import org.junit.Test

/** Mirrors the ordering in backend `decideVerdict`. Change both together. */
class LocalVerdictTest {
  private fun f(
    severity: Severity,
    kind: FindingKind = FindingKind.SUSPICIOUS_INDICATOR,
    quality: EvidenceQuality = EvidenceQuality.MEDIUM,
    hardBlock: Boolean = false,
  ) = Finding("x_${severity.wire}_${kind.wire}_${quality.wire}", kind, severity, quality, "t", "r", hardBlock)

  private val incomplete = listOf(CheckRun("reputation", CheckStatus.UNAVAILABLE, critical = true))
  private val complete = listOf(CheckRun("reputation", CheckStatus.COMPLETED, critical = true))

  @Test fun `hard block wins`() =
    assertEquals(Verdict.BLOCKED, LocalVerdict.decide(listOf(f(Severity.LOW, hardBlock = true)), complete))

  @Test fun `high confirmed threat is high risk`() =
    assertEquals(Verdict.HIGH_RISK, LocalVerdict.decide(listOf(f(Severity.HIGH, FindingKind.CONFIRMED_THREAT)), complete))

  @Test fun `critical indicator is high risk`() =
    assertEquals(Verdict.HIGH_RISK, LocalVerdict.decide(listOf(f(Severity.CRITICAL)), complete))

  @Test fun `high indicator with high quality is high risk`() =
    assertEquals(Verdict.HIGH_RISK, LocalVerdict.decide(listOf(f(Severity.HIGH, quality = EvidenceQuality.HIGH)), complete))

  @Test fun `one medium-quality high indicator is only suspicious`() =
    assertEquals(Verdict.SUSPICIOUS, LocalVerdict.decide(listOf(f(Severity.HIGH)), complete))

  @Test fun `two high indicators are high risk`() =
    assertEquals(
      Verdict.HIGH_RISK,
      LocalVerdict.decide(listOf(f(Severity.HIGH), f(Severity.HIGH, quality = EvidenceQuality.LOW)), complete),
    )

  @Test fun `two low indicators are suspicious`() =
    assertEquals(
      Verdict.SUSPICIOUS,
      LocalVerdict.decide(listOf(f(Severity.LOW), f(Severity.LOW, quality = EvidenceQuality.LOW)), complete),
    )

  @Test fun `one low indicator with a missing critical check is inconclusive`() =
    assertEquals(Verdict.INCONCLUSIVE, LocalVerdict.decide(listOf(f(Severity.LOW)), incomplete))

  @Test fun `reassurance never cancels a threat`() =
    assertEquals(
      Verdict.SUSPICIOUS,
      LocalVerdict.decide(listOf(f(Severity.MEDIUM), f(Severity.HIGH, FindingKind.REASSURANCE)), complete),
    )

  @Test fun `nothing found with every check complete`() =
    assertEquals(Verdict.NO_OBVIOUS_WARNINGS, LocalVerdict.decide(emptyList(), complete))
}
