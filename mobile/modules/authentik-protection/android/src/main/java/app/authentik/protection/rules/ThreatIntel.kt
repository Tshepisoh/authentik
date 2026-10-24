package app.authentik.protection.rules

/**
 * What the rules know offline: known-bad domains and the brands to watch for
 * impersonation. Comes from `GET /v1/threats/updates`; until the first download
 * it is the built-in brand seed with no blocklist.
 */
data class ThreatIntel(
  /** Domain → threat type. A listed domain covers its subdomains. */
  val blocked: Map<String, String>,
  val entities: List<KnownEntity>,
  /** False when there's no list yet or it's older than the server's max age. */
  val fresh: Boolean,
  val version: String?,
) {
  fun threatFor(host: String): String? {
    val labels = host.split('.')
    for (i in 0 until labels.size - 1) {
      blocked[labels.subList(i, labels.size).joinToString(".")]?.let { return it }
    }
    return null
  }

  fun officialFor(host: String): KnownEntity? =
    entities.firstOrNull { e -> e.domains.any { Links.isSameOrSubdomain(host, it) } }

  /** An entity whose brand token appears as a whole label in a host it doesn't operate. */
  fun imitatedBy(host: String): KnownEntity? {
    if (officialFor(host) != null) return null
    val tokens = Links.tokens(host)
    return entities.firstOrNull { e -> e.brandTokens.any { it in tokens } }
  }

  fun mentionedIn(lowerText: String): List<KnownEntity> =
    entities.filter { e -> e.mentions.any { Regex("""\b${Regex.escape(it)}\b""").containsMatchIn(lowerText) } }

  companion object {
    val SEED = ThreatIntel(emptyMap(), KnownEntities.all, fresh = false, version = null)

    private val threatLabels = mapOf(
      "KNOWN_FRAUD" to "reported fraud",
      "FEED_LISTED" to "reported phishing or malware",
      "SOCIAL_ENGINEERING" to "phishing",
      "MALWARE" to "malware",
    )

    fun label(threatType: String) = threatLabels[threatType] ?: "scams"
  }
}
