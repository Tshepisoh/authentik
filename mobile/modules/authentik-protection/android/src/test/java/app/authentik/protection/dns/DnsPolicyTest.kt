package app.authentik.protection.dns

import app.authentik.protection.rules.KnownEntities
import app.authentik.protection.rules.ThreatIntel
import org.junit.Assert.assertEquals
import org.junit.Test

class DnsPolicyTest {
  private val intel = ThreatIntel(mapOf("pay-release.top" to "KNOWN_FRAUD"), KnownEntities.all, fresh = true, version = "v")

  @Test
  fun `blocks listed domains and their subdomains`() {
    assertEquals(DnsDecision.Block("KNOWN_FRAUD"), DnsPolicy.decide("pay-release.top", intel))
    assertEquals(DnsDecision.Block("KNOWN_FRAUD"), DnsPolicy.decide("WWW.Pay-Release.top.", intel))
  }

  @Test
  fun `warns on look-alikes in the registrable label, without blocking`() {
    assertEquals(DnsDecision.Warn("FNB"), DnsPolicy.decide("fnb-verify.co.za", intel))
    assertEquals(DnsDecision.Warn("Absa"), DnsPolicy.decide("login.absa-secure.help", intel))
  }

  @Test
  fun `leaves official domains and vendor tenant subdomains alone`() {
    assertEquals(DnsDecision.Allow, DnsPolicy.decide("online.fnb.co.za", intel))
    assertEquals(DnsDecision.Allow, DnsPolicy.decide("absa.okta.com", intel))
    assertEquals(DnsDecision.Allow, DnsPolicy.decide("capitec.service-now.com", intel))
  }

  @Test
  fun `ignores local and reverse lookups`() {
    for (n in listOf("printer", "router.lan", "1.0.168.192.in-addr.arpa", "nas.local", "fnb.home")) {
      assertEquals(n, DnsDecision.Allow, DnsPolicy.decide(n, intel))
    }
  }

  @Test
  fun `registrable label handles two-part suffixes`() {
    assertEquals("example", DnsPolicy.registrableLabel("a.b.example.co.za"))
    assertEquals("example", DnsPolicy.registrableLabel("example.com"))
    assertEquals("co", DnsPolicy.registrableLabel("co.za"))
  }
}
