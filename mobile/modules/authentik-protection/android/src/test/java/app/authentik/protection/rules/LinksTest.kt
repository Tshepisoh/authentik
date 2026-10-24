package app.authentik.protection.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LinksTest {
  private fun hosts(text: String) = Links.extract(text).map { it.host }

  @Test
  fun `finds links with a scheme or www`() {
    assertEquals(listOf("pay.example.com"), hosts("Go to https://pay.example.com/x?y=1 now"))
    assertEquals(listOf("www.example.co.za"), hosts("Visit www.example.co.za/today"))
  }

  @Test
  fun `finds bare domains with common scam TLDs, even at the end of a sentence`() {
    assertEquals(listOf("fnb-verify.co.za"), hosts("Log in at fnb-verify.co.za."))
    assertEquals(listOf("bit.ly"), hosts("Tap bit.ly/abc"))
  }

  @Test
  fun `ignores amounts, abbreviations and missing spaces`() {
    assertTrue(hosts("You have received R4,500.00. Release the item.Thanks").isEmpty())
    assertTrue(hosts("e.g. tomorrow").isEmpty())
  }

  @Test
  fun `does not pick up email addresses as links`() {
    assertTrue(hosts("Email support@help.example.com for help").isEmpty())
  }

  @Test
  fun `normalises case, IDN and IP literals`() {
    assertEquals("example.com", Links.normalise("EXAMPLE.com.")!!.host)
    assertTrue(Links.normalise("fnб.co.za")!!.host.startsWith("xn--"))
    assertTrue(Links.normalise("203.0.113.7")!!.isIpLiteral)
    assertNull(Links.normalise("localhost"))
  }

  @Test
  fun `deduplicates hosts`() {
    assertEquals(listOf("a.example.com"), hosts("https://a.example.com/1 and https://a.example.com/2"))
  }

  @Test
  fun `brand tokens match whole labels only`() {
    assertEquals("Absa", ThreatIntel.SEED.imitatedBy("absa-login.help")?.name)
    assertNull(ThreatIntel.SEED.imitatedBy("absatz.de"))
    assertNull(ThreatIntel.SEED.imitatedBy("online.absa.co.za"))
  }
}
