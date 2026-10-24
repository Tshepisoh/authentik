package app.authentik.protection.dns

import app.authentik.protection.rules.ThreatIntel

sealed class DnsDecision {
  object Allow : DnsDecision()

  /** On the threat list: answered with NXDOMAIN. */
  data class Block(val threatType: String) : DnsDecision()

  /** Imitates a known brand: allowed, but the user is warned. Not proof, so never blocked. */
  data class Warn(val brand: String) : DnsDecision()
}

/**
 * What the VPN does with one lookup. Only confirmed entries on the threat list
 * are blocked; a look-alike is a warning, because blocking on a guess breaks
 * things people need.
 */
object DnsPolicy {
  private val localSuffixes = listOf("arpa", "local", "lan", "home", "internal", "localhost")
  private val secondLevel = setOf("co", "com", "org", "net", "gov", "ac", "edu", "gob", "nic")

  fun decide(rawName: String, intel: ThreatIntel): DnsDecision {
    val name = rawName.trimEnd('.').lowercase()
    if (!name.contains('.') || localSuffixes.any { name == it || name.endsWith(".$it") }) return DnsDecision.Allow

    intel.threatFor(name)?.let { return DnsDecision.Block(it) }

    // Only the registrable label counts: "fnb-verify.co.za" imitates FNB, but a vendor's
    // tenant subdomain like "absa.okta.com" belongs to the vendor, not to an impersonator.
    val label = registrableLabel(name) ?: return DnsDecision.Allow
    if (intel.officialFor(name) != null) return DnsDecision.Allow
    val tokens = label.split('-').toSet()
    val brand = intel.entities.firstOrNull { e -> e.brandTokens.any { it in tokens } }
    return if (brand != null) DnsDecision.Warn(brand.name) else DnsDecision.Allow
  }

  /**
   * The label a registrant chose, approximated without the Public Suffix List:
   * the one before the TLD, or before `co.za`-style two-part suffixes.
   */
  fun registrableLabel(host: String): String? {
    val labels = host.split('.')
    if (labels.size < 2) return null
    val twoPart = labels.size >= 3 && labels[labels.size - 1].length == 2 && labels[labels.size - 2] in secondLevel
    return labels[labels.size - if (twoPart) 3 else 2]
  }
}
