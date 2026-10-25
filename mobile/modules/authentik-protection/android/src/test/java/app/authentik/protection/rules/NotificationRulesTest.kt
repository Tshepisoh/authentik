package app.authentik.protection.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic notifications only. None of these are real messages. */
class NotificationRulesTest {
  private val sms = "com.google.android.apps.messaging"

  private fun analyze(text: String, title: String = "", pkg: String = sms) =
    NotificationRules.analyze(NotificationInput(pkg, title, text))

  private fun Analysis.codes() = findings.map { it.code }.toSet()

  @Test
  fun `fake payment with release instruction is high risk`() {
    val a = analyze("You have received R4,500.00. Release the item now.", title = "Payment successful")
    assertEquals(Verdict.HIGH_RISK, a.verdict)
    assertTrue(a.codes().containsAll(setOf("payment_claim", "payment_claim_release", "payment_claim_via_message")))
    assertEquals("Don't release the item yet", a.headline)
    assertTrue(a.shouldWarn)
  }

  @Test
  fun `payment claim alone from a bank app does not warn`() {
    val a = analyze("Payment received: R250.00 from J Smith. Ref [number].", pkg = "com.example.bank")
    assertEquals(Verdict.NO_OBVIOUS_WARNINGS, a.verdict)
    assertFalse(a.shouldWarn)
  }

  @Test
  fun `merchant shipping notice is not a release instruction`() {
    val a = analyze("Payment received. We will ship your order within 2 days.", pkg = "com.example.shop")
    assertFalse("payment_claim_release" in a.codes())
    assertFalse(a.shouldWarn)
  }

  @Test
  fun `request to share an OTP is flagged`() {
    val a = analyze("FNB: we detected a problem. Please reply with your OTP to keep your account active.")
    assertTrue("credential_request" in a.codes())
    assertEquals("Don't share your PIN, OTP or password", a.headline)
    assertTrue(a.shouldWarn)
  }

  @Test
  fun `genuine OTP message is not flagged`() {
    val a = analyze("Your OTP is 482913. Never share this code with anyone, including bank staff.", pkg = "com.example.bank")
    assertFalse("credential_request" in a.codes())
    assertFalse(a.shouldWarn)
  }

  @Test
  fun `enter OTP to approve is not a credential request`() {
    val a = analyze("Enter OTP 552100 to approve your R899.00 purchase at Takealot.")
    assertFalse("credential_request" in a.codes())
  }

  @Test
  fun `lookalike bank link plus credential request is high risk`() {
    val a = analyze("Absa: your account will be suspended. Verify your details at https://absa-secure.help/login and confirm your PIN.")
    assertEquals(Verdict.HIGH_RISK, a.verdict)
    assertTrue(a.codes().containsAll(setOf("lookalike_link", "credential_request", "verify_via_link", "account_threat")))
    assertEquals(listOf("absa-secure.help"), a.linkHosts)
  }

  @Test
  fun `official bank link is reassurance but never cancels a threat`() {
    val a = analyze("Capitec: share your PIN with our agent. Details at www.capitecbank.co.za.")
    assertTrue("official_link" in a.codes())
    assertTrue(a.shouldWarn)
  }

  @Test
  fun `bank mentioned with an unrelated link is a mismatch`() {
    val a = analyze("Nedbank alert: unusual activity. Review it at secure-review.online now.")
    assertTrue("brand_link_mismatch" in a.codes())
    assertEquals("Don't open this link", a.headline)
  }

  @Test
  fun `delivery fee through a shortened link warns`() {
    val a = analyze("Your parcel is held at customs. Pay the R29.99 fee within 24 hours: bit.ly/3xYz")
    assertTrue(a.codes().containsAll(setOf("delivery_fee_link", "shortened_link", "urgency")))
    assertEquals(Verdict.SUSPICIOUS, a.verdict)
  }

  @Test
  fun `refund through a link warns`() {
    val a = analyze("SARS: you qualify for a refund of R3,120. Claim at http://sars-refunds.click/claim")
    assertTrue("refund_link" in a.codes())
    assertTrue(a.shouldWarn)
  }

  @Test
  fun `ip address link is flagged`() {
    val a = analyze("Account notice: log in at http://203.0.113.7/secure")
    assertTrue("ip_link" in a.codes())
  }

  @Test
  fun `an unchecked link alone is inconclusive, never a pass`() {
    val a = analyze("Here are the photos from Saturday: https://photos.example.com/album")
    assertEquals(Verdict.INCONCLUSIVE, a.verdict)
    assertFalse(a.shouldWarn)
    assertTrue(a.checks.any { it.critical && it.status == CheckStatus.UNAVAILABLE })
  }

  @Test
  fun `ordinary chat is no obvious warnings`() {
    val a = analyze("Are we still on for lunch tomorrow?", title = "Thandi")
    assertEquals(Verdict.NO_OBVIOUS_WARNINGS, a.verdict)
    assertTrue(a.linkHosts.isEmpty())
  }

  @Test
  fun `two weak signals together warn`() {
    val a = analyze("URGENT: your card has been blocked. Call us immediately.")
    assertEquals(Verdict.SUSPICIOUS, a.verdict)
  }

  @Test
  fun `findings never carry the notification text or secrets`() {
    val a = analyze("Reply with your PIN. Card 4111 1111 1111 1111. Your OTP is 123456.")
    val everything = a.findings.joinToString { it.title + it.reason } + a.headline + a.recommendedAction
    assertFalse(everything.contains("4111"))
    assertFalse(everything.contains("123456"))
  }

  @Test
  fun `card delivery PIN shown to the courier in person is not a credential request`() {
    val a = analyze(
      "Your new bank card is on its way. To confirm your identity, please share your delivery PIN 4821 with the courier when they arrive.",
    )
    assertFalse("credential_request" in a.codes())
    assertFalse(a.shouldWarn)
  }

  @Test
  fun `ride PIN for the driver is not a credential request`() {
    val a = analyze("Share your PIN 3390 with your driver to start the trip.", pkg = "com.example.rides")
    assertFalse(a.shouldWarn)
  }

  @Test
  fun `reading an OTP to a courier over the phone is still flagged`() {
    val a = analyze("Our courier will call you. Read out the OTP 552190 to the driver over the phone.")
    assertTrue("credential_request" in a.codes())
    assertTrue(a.shouldWarn)
  }

  @Test
  fun `giving the driver your card PIN is still flagged`() {
    val a = analyze("Give the driver your card PIN to confirm the delivery.")
    assertTrue("credential_request" in a.codes())
  }

  @Test
  fun `unclaimed funds offer asking you to email is high risk`() {
    val a = analyze(
      "Good day, I have access to your unclaimed funds of R350 000 held in a dormant account. Email them at claims.office@example.com for more info.",
    )
    assertEquals(Verdict.HIGH_RISK, a.verdict)
    assertTrue(a.codes().containsAll(setOf("money_offer", "money_offer_contact")))
    assertEquals("Don't reply to this money offer", a.headline)
  }

  @Test
  fun `inheritance with a release fee is high risk`() {
    val a = analyze("You have been named the beneficiary of an inheritance. Pay the release fee of R1 500 to receive it.")
    assertEquals(Verdict.HIGH_RISK, a.verdict)
    assertTrue("money_offer_contact" in a.codes())
  }

  @Test
  fun `a bank's new beneficiary alert is not a money offer`() {
    val a = analyze("New beneficiary added to your profile: J Smith.", pkg = "com.example.bank")
    assertFalse("money_offer" in a.codes())
    assertFalse(a.shouldWarn)
  }
}
