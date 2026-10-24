package app.authentik.protection.rules

/*
 * On-device mirror of the shared risk vocabulary (packages/shared/src/risk.ts).
 * Wire names match the TypeScript string unions so results cross the JS bridge
 * unchanged. This package has no Android imports, so it runs in plain JVM tests.
 */

enum class FindingKind(val wire: String) {
  CONFIRMED_THREAT("confirmed_threat"),
  SUSPICIOUS_INDICATOR("suspicious_indicator"),
  UNKNOWN("unknown"),
  REASSURANCE("reassurance"),
}

enum class Severity(val wire: String, val rank: Int) {
  CRITICAL("critical", 4),
  HIGH("high", 3),
  MEDIUM("medium", 2),
  LOW("low", 1),
  INFO("info", 0),
}

enum class EvidenceQuality(val wire: String) { HIGH("high"), MEDIUM("medium"), LOW("low") }

enum class CheckStatus(val wire: String) {
  COMPLETED("completed"),
  UNAVAILABLE("unavailable"),
  FAILED("failed"),
  SKIPPED("skipped"),
}

enum class Verdict(val wire: String) {
  HIGH_RISK("high_risk"),
  SUSPICIOUS("suspicious"),
  NO_OBVIOUS_WARNINGS("no_obvious_warnings"),
  INCONCLUSIVE("inconclusive"),
  BLOCKED("blocked"),
}

data class Finding(
  val code: String,
  val kind: FindingKind,
  val severity: Severity,
  val quality: EvidenceQuality,
  val title: String,
  val reason: String,
  val hardBlock: Boolean = false,
)

data class CheckRun(
  val check: String,
  val status: CheckStatus,
  val critical: Boolean,
  val detail: String? = null,
)

/** What the listener hands to the rules: raw text, which `NotificationRules` redacts before matching and never returns. */
data class NotificationInput(
  val packageName: String,
  val title: String,
  val text: String,
)

data class Analysis(
  val verdict: Verdict,
  val headline: String,
  val recommendedAction: String,
  /** Most severe first. */
  val findings: List<Finding>,
  val checks: List<CheckRun>,
  /** Normalised hostnames of links in the notification; never full URLs. */
  val linkHosts: List<String>,
  val rulesVersion: String,
) {
  /** Only these verdicts raise a warning. `inconclusive` is not a pass, but it isn't worth an interruption either. */
  val shouldWarn: Boolean
    get() = verdict == Verdict.HIGH_RISK || verdict == Verdict.SUSPICIOUS || verdict == Verdict.BLOCKED

  /** The findings worth showing as reasons in a warning. */
  val reasons: List<Finding>
    get() = findings.filter { it.kind == FindingKind.CONFIRMED_THREAT || it.kind == FindingKind.SUSPICIOUS_INDICATOR }
}
