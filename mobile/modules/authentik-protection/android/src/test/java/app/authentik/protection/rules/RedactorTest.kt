package app.authentik.protection.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class RedactorTest {
  @Test
  fun `removes OTPs after the keyword`() {
    assertEquals("Your OTP is [code].", Redactor.redact("Your OTP is 4821."))
    assertEquals("one-time pin: [code]", Redactor.redact("one-time pin: 99887766"))
  }

  @Test
  fun `removes OTPs before the keyword`() {
    assertEquals("[code] is your verification code", Redactor.redact("5521 is your verification code"))
  }

  @Test
  fun `removes card numbers with or without separators`() {
    assertEquals("Card [card] used", Redactor.redact("Card 4111 1111 1111 1111 used"))
    assertEquals("Card [card] used", Redactor.redact("Card 4111-1111-1111-1111 used"))
    assertEquals("[card]", Redactor.redact("4111111111111111"))
  }

  @Test
  fun `removes account and reference numbers`() {
    assertEquals("Acc [number] credited", Redactor.redact("Acc 62123456789 credited"))
  }

  @Test
  fun `keeps amounts`() {
    assertEquals("You have received R4,500.00", Redactor.redact("You have received R4,500.00"))
    assertEquals("Pay R29.99 now", Redactor.redact("Pay R29.99 now"))
  }

  @Test
  fun `keeps short numbers that aren't codes`() {
    assertEquals("See you at 1230 on the 14th", Redactor.redact("See you at 1230 on the 14th"))
  }

  @Test
  fun `nothing secret survives a mixed message`() {
    val out = Redactor.redact("PIN 7788, card 5500 0000 0000 0004, acc 1234567890")
    for (secret in listOf("7788", "5500", "1234567890")) assertFalse(out, out.contains(secret))
  }
}
