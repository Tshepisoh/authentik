package app.authentik.protection.rules

data class KnownEntity(
  val name: String,
  val isBank: Boolean,
  /** Registrable domains the entity operates. Subdomains count. */
  val domains: List<String>,
  /** Whole host labels that name the brand. */
  val brandTokens: List<String>,
  /** How the brand appears in message text (lowercase, whole words). */
  val mentions: List<String>,
)

/**
 * Brand seed for offline impersonation checks before the first threat-list
 * download (`ThreatIntel.SEED`). Copied from
 * backend/src/modules/merchant-verification/registry.ts; the downloaded list
 * replaces it.
 */
object KnownEntities {
  val all = listOf(
    KnownEntity("FNB", true, listOf("fnb.co.za", "firstrand.co.za"), listOf("fnb", "firstnational"), listOf("fnb", "first national bank")),
    KnownEntity("Absa", true, listOf("absa.co.za", "absa.africa"), listOf("absa"), listOf("absa")),
    KnownEntity("Standard Bank", true, listOf("standardbank.co.za", "standardbank.com"), listOf("standardbank"), listOf("standard bank")),
    KnownEntity("Nedbank", true, listOf("nedbank.co.za"), listOf("nedbank"), listOf("nedbank")),
    KnownEntity("Capitec", true, listOf("capitecbank.co.za", "capitec.co.za"), listOf("capitec", "capitecbank"), listOf("capitec")),
    KnownEntity("Discovery Bank", true, listOf("discovery.co.za"), listOf("discoverybank"), listOf("discovery bank")),
    KnownEntity("TymeBank", true, listOf("tymebank.co.za"), listOf("tymebank"), listOf("tymebank", "tyme bank")),
    KnownEntity("PayPal", false, listOf("paypal.com", "paypal.me"), listOf("paypal"), listOf("paypal")),
    KnownEntity("Payfast", false, listOf("payfast.co.za", "payfast.io"), listOf("payfast"), listOf("payfast")),
    KnownEntity("Ozow", false, listOf("ozow.com"), listOf("ozow"), listOf("ozow")),
    KnownEntity("Yoco", false, listOf("yoco.com", "yoco.co.za"), listOf("yoco"), listOf("yoco")),
    KnownEntity("SnapScan", false, listOf("snapscan.co.za", "snapscan.io"), listOf("snapscan"), listOf("snapscan")),
    KnownEntity("Takealot", false, listOf("takealot.com"), listOf("takealot"), listOf("takealot")),
  )

  /** Link shorteners hide the destination. */
  val shorteners = setOf(
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
    "tiny.cc", "s.id", "rebrand.ly", "t.ly", "buff.ly", "goo.su",
  )

  /** Messaging and SMS apps. A payment claim arriving here didn't come from a banking app. */
  val messagingPackages = setOf(
    "com.google.android.apps.messaging",
    "com.samsung.android.messaging",
    "com.android.mms",
    "com.whatsapp",
    "com.whatsapp.w4b",
    "org.telegram.messenger",
    "org.thoughtcrime.securesms",
    "com.facebook.orca",
  )
}
