package app.authentik.protection.rules

/**
 * Strips secrets from notification text before any rule, log or store sees it.
 * Amounts survive (the rules need "R4,500.00"); OTPs, card numbers and account
 * numbers don't.
 */
object Redactor {
  // A code of 4–8 digits within a few words of an OTP-type keyword, on either side.
  private val otpAfter = Regex(
    """(?i)\b(otp|one[- ]?time (?:pin|password|code)|verification code|security code|auth(?:entication)? code|pin|code)\b([^\d\n]{0,24})\d{4,8}\b""",
  )
  private val otpBefore = Regex(
    """(?i)\b\d{4,8}\b(\s+(?:is|as)\s+(?:your|the)\s+(?:otp|one[- ]?time (?:pin|password|code)|verification code|security code|code|pin))\b""",
  )
  // 13–19 digits, optionally grouped by spaces or dashes: card numbers.
  private val card = Regex("""\b\d(?:[ -]?\d){12,18}\b""")
  // Any other run of 6+ digits: account, ID or reference numbers.
  private val longNumber = Regex("""\b\d{6,}\b""")

  fun redact(text: String): String =
    text
      .replace(otpAfter) { m -> "${m.groupValues[1]}${m.groupValues[2]}[code]" }
      .replace(otpBefore) { m -> "[code]${m.groupValues[1]}" }
      .replace(card, "[card]")
      .replace(longNumber, "[number]")
}
