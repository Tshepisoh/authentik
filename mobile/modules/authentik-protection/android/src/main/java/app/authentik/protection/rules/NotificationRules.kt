package app.authentik.protection.rules

import app.authentik.protection.rules.EvidenceQuality as Q
import app.authentik.protection.rules.FindingKind.CONFIRMED_THREAT
import app.authentik.protection.rules.FindingKind.REASSURANCE
import app.authentik.protection.rules.FindingKind.SUSPICIOUS_INDICATOR as SUSPICIOUS
import app.authentik.protection.rules.Severity.CRITICAL
import app.authentik.protection.rules.Severity.HIGH
import app.authentik.protection.rules.Severity.INFO
import app.authentik.protection.rules.Severity.LOW
import app.authentik.protection.rules.Severity.MEDIUM

/**
 * Deterministic rules for fraud in notification text. They emit findings and
 * check records only; `LocalVerdict` decides. Patterns are matched against
 * *redacted*, lowercased text. Links are pulled from the raw text first and
 * kept as hostnames.
 *
 * Bias: a genuine bank alert must not trip a warning on its own. Single weak
 * signals are `low` so that it takes two of them, or one strong one, to warn.
 */
object NotificationRules {
  /** Bump when rules change. Stored on every warning. */
  const val RULES_VERSION = "android-2026.10.2"

  private const val MAX_TEXT = 2000

  private val paymentClaim = listOf(
    Regex("""\bpayment (?:was |has been |is )?(?:successful|received|completed|confirmed|approved)\b"""),
    Regex("""\b(?:you have|you've|you) received (?:a payment|a deposit|funds|money|zar|r ?\d)"""),
    Regex("""\bfunds (?:have been|were|are) (?:paid|sent|transferred|deposited|released)\b"""),
    Regex("""\b(?:deposit|transfer|eft|payment) of (?:r|zar) ?[\d][\d., ]*(?:has been|was|is) (?:made|completed|successful|received|paid)\b"""),
    Regex("""\bproof of payment\b|\bpop\b"""),
    // Fake escrow: "the money is on hold until you release the item".
    Regex("""\b(?:money|payment|funds) (?:is|are|has been) (?:on hold|pending release|reserved)\b"""),
  )

  // An instruction to the reader, not a merchant's "we will ship your order".
  private val releaseGoods = Regex(
    """(?m)(?:please |kindly |you (?:can|may|should) (?:now )?|go ahead and |^|[.!]\s*)(?:release|ship|send|hand over|deliver|dispatch)(?: the)? (?:item|items|goods|product|parcel|car|vehicle|phone|stock|package)\b|\brelease (?:it|the item|now)\b""",
  )

  private val credentialObject = Regex(
    """\b(?:otp|one[- ]?time (?:pin|password|code)|pin|password|cvv|cvc|card (?:number|details)|banking details|login details|security code)\b""",
  )
  // No "enter" or "use": genuine OTP texts say "Enter OTP … to approve".
  private val credentialVerb = Regex("""\b(?:share|send|give|reply|forward|confirm|provide|tell|read out|verify|update)\b""")
  private val negation = Regex("""\b(?:never|do not|don't|dont|not|won't|will not|no one|nobody)\b""")

  private val verifyAccount = Regex(
    """\b(?:verify|update|confirm|validate|reactivate|unlock)\b.{0,30}\b(?:account|details|identity|card|profile|information|info)\b""",
  )
  private val accountThreat = Regex(
    """\b(?:account|card|profile|access)\b.{0,20}\b(?:will be|has been|is|was)\b.{0,10}\b(?:suspended|blocked|locked|closed|deactivated|frozen|restricted|terminated)\b""",
  )
  private val urgency = Regex(
    """\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?)\b|\burgent(?:ly)?\b|\bfinal (?:notice|warning|reminder)\b|\bimmediately\b|\bact now\b|\bexpires? today\b|\blast chance\b""",
  )
  private val delivery = Regex("""\b(?:parcel|package|delivery|courier|shipment|customs|redelivery|post office)\b""")
  private val fee = Regex("""\b(?:fee|pay|payment|duty|outstanding|unpaid|charge)\b|\br ?\d""")
  private val refund = Regex("""\brefund""")
  private val prize = Regex("""\b(?:you(?:'ve| have)? won|winner|prize|reward|free voucher|gift card|claim your)\b""")

  fun analyze(input: NotificationInput, intel: ThreatIntel = ThreatIntel.SEED): Analysis {
    val raw = "${input.title}\n${input.text}".take(MAX_TEXT)
    val links = Links.extract(raw)
    val text = Redactor.redact(raw).lowercase()
    val hasLink = links.isNotEmpty()
    val findings = mutableListOf<Finding>()

    if (paymentClaim.any { it.containsMatchIn(text) }) {
      findings += Finding(
        "payment_claim", SUSPICIOUS, LOW, Q.MEDIUM,
        "Claims a payment was made",
        "A notification can say anything. It doesn't prove money reached your account.",
      )
      if (releaseGoods.containsMatchIn(text)) {
        findings += Finding(
          "payment_claim_release", SUSPICIOUS, HIGH, Q.HIGH,
          "Asks you to release goods because of a payment message",
          "A fake payment confirmation followed by pressure to hand over the item is a common marketplace scam. Banks don't tell you to release goods.",
        )
      }
      if (input.packageName in KnownEntities.messagingPackages) {
        findings += Finding(
          "payment_claim_via_message", SUSPICIOUS, INFO, Q.MEDIUM,
          "Arrived as a message, not from a banking app",
          "Anyone can send a message that looks like a bank alert.",
        )
      }
    }

    if (asksForCredentials(text)) {
      findings += Finding(
        "credential_request", SUSPICIOUS, HIGH, Q.MEDIUM,
        "Asks for your PIN, OTP, password or card details",
        "Your bank will never ask for these in a message.",
      )
    }
    if (hasLink && verifyAccount.containsMatchIn(text)) {
      findings += Finding(
        "verify_via_link", SUSPICIOUS, MEDIUM, Q.MEDIUM,
        "Asks you to verify or update details through a link",
        "Phishing messages send you to a fake sign-in page to collect your details.",
      )
    }
    if (accountThreat.containsMatchIn(text)) {
      findings += Finding(
        "account_threat", SUSPICIOUS, LOW, Q.MEDIUM,
        "Says your account will be blocked",
        "Threats to close or block an account are used to rush people.",
      )
    }
    if (urgency.containsMatchIn(text)) {
      findings += Finding(
        "urgency", SUSPICIOUS, LOW, Q.MEDIUM,
        "Pressures you to act quickly",
        "Scams push for speed so you don't stop to check.",
      )
    }
    if (hasLink && delivery.containsMatchIn(text) && fee.containsMatchIn(text)) {
      findings += Finding(
        "delivery_fee_link", SUSPICIOUS, MEDIUM, Q.MEDIUM,
        "Asks you to pay a delivery fee through a link",
        "Fake courier messages ask for small fees to collect card details.",
      )
    }
    if (hasLink && refund.containsMatchIn(text)) {
      findings += Finding(
        "refund_link", SUSPICIOUS, MEDIUM, Q.MEDIUM,
        "Offers a refund through a link",
        "Refund scams send you to a fake page that asks for your banking details.",
      )
    }
    if (hasLink && prize.containsMatchIn(text)) {
      findings += Finding(
        "prize_link", SUSPICIOUS, MEDIUM, Q.MEDIUM,
        "Offers a prize or reward through a link",
        "Unexpected prizes are a common way to get people onto scam pages.",
      )
    }

    findings += linkFindings(links, text, intel)

    val checks = buildList {
      add(CheckRun("notification_rules", CheckStatus.COMPLETED, critical = false))
      if (hasLink) {
        // Without a current list a link can't be cleared, only flagged.
        add(
          if (intel.fresh) {
            CheckRun("reputation.local_threat_list", CheckStatus.COMPLETED, critical = true, intel.version)
          } else {
            CheckRun(
              "reputation.local_threat_list", CheckStatus.UNAVAILABLE, critical = true,
              "The threat list on this phone hasn't downloaded yet or is out of date.",
            )
          },
        )
      }
    }

    val sorted = findings.distinctBy { it.code }.sortedWith(LocalVerdict.bySeverity)
    val verdict = LocalVerdict.decide(sorted, checks)
    val (headline, action) = advice(sorted.map { it.code }.toSet())
    return Analysis(verdict, headline, action, sorted, checks, links.map { it.host }, RULES_VERSION)
  }

  private fun asksForCredentials(text: String): Boolean =
    text.split(Regex("""[.!?\n]+""")).any { sentence ->
      credentialObject.containsMatchIn(sentence) &&
        credentialVerb.containsMatchIn(sentence) &&
        !negation.containsMatchIn(sentence)
    }

  private fun linkFindings(links: List<LinkHost>, text: String, intel: ThreatIntel): List<Finding> {
    val out = mutableListOf<Finding>()
    val mentionedBanks = intel.mentionedIn(text).filter { it.isBank }
    for (link in links) {
      val host = link.host
      // A stale list still flags what it knows; it just can't clear anything.
      intel.threatFor(host)?.let { type ->
        out += Finding(
          "known_threat_link", CONFIRMED_THREAT, CRITICAL, Q.HIGH,
          "Link is on a known scam list",
          "$host is listed for ${ThreatIntel.label(type)}.",
        )
      }
      if (link.isIpLiteral) {
        out += Finding(
          "ip_link", SUSPICIOUS, MEDIUM, Q.HIGH,
          "Link points to a bare IP address",
          "Real companies link to their own named websites, not to numeric addresses.",
        )
        continue
      }
      if (host in KnownEntities.shorteners) {
        out += Finding(
          "shortened_link", SUSPICIOUS, LOW, Q.MEDIUM,
          "Uses a link shortener",
          "$host hides where the link really goes.",
        )
      }
      if (host.split('.').any { it.startsWith("xn--") }) {
        out += Finding(
          "punycode_link", SUSPICIOUS, LOW, Q.MEDIUM,
          "Link uses unusual characters",
          "International characters can make a fake address look like a familiar one.",
        )
      }
      val imitated = intel.imitatedBy(host)
      val official = intel.officialFor(host)
      when {
        imitated != null -> out += Finding(
          "lookalike_link", SUSPICIOUS, HIGH, Q.MEDIUM,
          "Link imitates ${imitated.name}",
          "$host uses the ${imitated.name} name but isn't one of its websites.",
        )
        official != null -> out += Finding(
          "official_link", REASSURANCE, INFO, Q.MEDIUM,
          "Links to an official ${official.name} website",
          "$host belongs to ${official.name}. That doesn't make the message genuine.",
        )
        mentionedBanks.isNotEmpty() && host !in KnownEntities.shorteners -> out += Finding(
          "brand_link_mismatch", SUSPICIOUS, MEDIUM, Q.MEDIUM,
          "Mentions ${mentionedBanks.first().name} but links elsewhere",
          "$host isn't a ${mentionedBanks.first().name} website.",
        )
      }
    }
    return out
  }

  private fun advice(codes: Set<String>): Pair<String, String> = when {
    "credential_request" in codes -> "Don't share your PIN, OTP or password" to
      "Your bank will never ask for these. If you're worried, call the number on the back of your card."
    "payment_claim_release" in codes -> "Don't release the item yet" to PAYMENT_ACTION
    codes.any { it in setOf("known_threat_link", "lookalike_link", "brand_link_mismatch", "ip_link") } -> "Don't open this link" to
      "Go to the official website or app yourself instead of using the link."
    "delivery_fee_link" in codes -> "Don't pay a fee through this link" to
      "Check the delivery in the courier's official app or website."
    "refund_link" in codes -> "Be careful with this refund message" to
      "Real refunds don't need you to sign in through a link. Contact the company directly."
    "prize_link" in codes -> "Be careful with this prize offer" to
      "Don't enter personal or banking details to claim it."
    "payment_claim" in codes -> "Check your banking app before you trust this" to PAYMENT_ACTION
    "verify_via_link" in codes -> "Don't verify your details through this link" to
      "Open the official app or website yourself."
    else -> "This notification looks suspicious" to
      "Check with the sender through a channel you already trust before you act on it."
  }

  private const val PAYMENT_ACTION =
    "A notification saying a payment arrived doesn't confirm the money reached your account. " +
      "Check the transaction in your own banking app before you hand over anything."
}
