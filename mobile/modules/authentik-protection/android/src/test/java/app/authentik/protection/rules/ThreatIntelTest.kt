package app.authentik.protection.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatIntelTest {
  private val sms = "com.google.android.apps.messaging"

  private fun intel(fresh: Boolean, blocked: Map<String, String> = mapOf("pay-release.top" to "KNOWN_FRAUD")) =
    ThreatIntel(blocked, KnownEntities.all, fresh, version = "0123456789abcdef")

  private fun analyze(text: String, intel: ThreatIntel) =
    NotificationRules.analyze(NotificationInput(sms, "", text), intel)

  @Test
  fun `a listed link is high risk`() {
    val a = analyze("Your payout is ready: https://pay-release.top/claim", intel(fresh = true))
    assertEquals(Verdict.HIGH_RISK, a.verdict)
    assertTrue(a.findings.any { it.code == "known_threat_link" && it.kind == FindingKind.CONFIRMED_THREAT })
    assertEquals("Don't open this link", a.headline)
  }

  @Test
  fun `listed domains cover their subdomains`() {
    val i = intel(fresh = true)
    assertEquals("KNOWN_FRAUD", i.threatFor("secure.pay-release.top"))
    assertNull(i.threatFor("release.top"))
    assertNull(i.threatFor("top"))
  }

  @Test
  fun `a fresh list lets an unlisted link complete the check`() {
    val a = analyze("Photos from Saturday: https://photos.example.com/album", intel(fresh = true))
    assertEquals(Verdict.NO_OBVIOUS_WARNINGS, a.verdict)
    assertTrue(a.checks.any { it.check == "reputation.local_threat_list" && it.status == CheckStatus.COMPLETED })
  }

  @Test
  fun `a stale list still flags what it knows but can't clear anything`() {
    val stale = intel(fresh = false)
    assertEquals(Verdict.HIGH_RISK, analyze("Go to pay-release.top now", stale).verdict)
    val clean = analyze("Photos from Saturday: https://photos.example.com/album", stale)
    assertEquals(Verdict.INCONCLUSIVE, clean.verdict)
    assertFalse(clean.shouldWarn)
  }

  @Test
  fun `downloaded brands replace the seed`() {
    val downloaded = ThreatIntel(
      emptyMap(),
      listOf(KnownEntity("Bank Zed", true, listOf("bankzed.co.za"), listOf("bankzed"), listOf("bank zed"))),
      fresh = true,
      version = "fedcba9876543210",
    )
    val a = analyze("Bank Zed: confirm your PIN at bankzed-secure.help", downloaded)
    assertTrue(a.findings.any { it.code == "lookalike_link" && it.title.contains("Bank Zed") })
    // The seed's brands are gone.
    assertNull(downloaded.imitatedBy("absa-login.help"))
  }
}
