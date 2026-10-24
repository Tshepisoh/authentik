package app.authentik.protection.rules

import java.net.IDN

/** A link found in notification text, reduced to what the rules need. */
data class LinkHost(
  /** Lowercase ASCII (punycode) hostname, no port, no trailing dot. */
  val host: String,
  val isIpLiteral: Boolean,
)

object Links {
  // Either an explicit scheme or www., or a bare name ending in a TLD that scam
  // texts commonly use. A bare `word.word` is too often just a missing space.
  private val withScheme = Regex("""(?i)\b(?:https?://|www\.)([^\s/?#:<>"']+)""")
  private val bareTlds =
    "za|com|net|org|info|xyz|top|online|site|shop|store|link|click|app|io|me|ly|gd|co|cc|live|vip|icu|buzz|support|help|pay|bank"
  private val bare = Regex("""(?i)(?<![\w@./-])((?:[a-z0-9-]+\.)+(?:$bareTlds))\b(?![\w@-]|\.\w)""")
  private val ipv4 = Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")

  /** Distinct hosts in order of appearance. Takes the *original* text: redaction can mangle URLs. */
  fun extract(text: String): List<LinkHost> {
    val raw = withScheme.findAll(text).map { m ->
      // `www.` is consumed by the pattern; put it back so the host is complete.
      if (m.value.startsWith("www.", ignoreCase = true)) "www." + m.groupValues[1] else m.groupValues[1]
    } + bare.findAll(text).map { it.groupValues[1] }
    return raw.mapNotNull(::normalise).distinctBy { it.host }.toList()
  }

  fun normalise(candidate: String): LinkHost? {
    val trimmed = candidate.substringAfterLast('@').trimEnd('.', ',', ')', ']').lowercase()
    if (trimmed.isEmpty() || !trimmed.contains('.')) return null
    if (ipv4.matches(trimmed)) return LinkHost(trimmed, isIpLiteral = true)
    val ascii = try {
      IDN.toASCII(trimmed, IDN.ALLOW_UNASSIGNED)
    } catch (_: IllegalArgumentException) {
      return null
    }
    return LinkHost(ascii, isIpLiteral = false)
  }

  /** Labels split on dots and hyphens, so `fnb-secure.co.za` yields `fnb`. */
  fun tokens(host: String): Set<String> = host.split('.', '-').filter { it.isNotEmpty() }.toSet()

  fun isSameOrSubdomain(host: String, domain: String) = host == domain || host.endsWith(".$domain")
}
