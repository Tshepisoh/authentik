package app.authentik.protection

import android.content.Context
import app.authentik.protection.rules.Analysis
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * A warning as kept on the phone. It holds the reasons and link hostnames, never
 * the notification text.
 */
data class StoredWarning(
  val id: String,
  val postedAt: Long,
  val appLabel: String,
  val packageName: String,
  val verdict: String,
  val headline: String,
  val recommendedAction: String,
  val reasons: List<Reason>,
  val linkHosts: List<String>,
  val rulesVersion: String,
) {
  data class Reason(val code: String, val title: String, val reason: String, val severity: String)

  fun toMap(): Map<String, Any?> = mapOf(
    "id" to id,
    "postedAt" to isoUtc(postedAt),
    "appLabel" to appLabel,
    "packageName" to packageName,
    "verdict" to verdict,
    "headline" to headline,
    "recommendedAction" to recommendedAction,
    "reasons" to reasons.map { mapOf("code" to it.code, "title" to it.title, "reason" to it.reason, "severity" to it.severity) },
    "linkHosts" to linkHosts,
    "rulesVersion" to rulesVersion,
  )

  fun toJson(): JSONObject = JSONObject()
    .put("id", id).put("postedAt", postedAt).put("appLabel", appLabel).put("packageName", packageName)
    .put("verdict", verdict).put("headline", headline).put("recommendedAction", recommendedAction)
    .put(
      "reasons",
      JSONArray(reasons.map { JSONObject().put("code", it.code).put("title", it.title).put("reason", it.reason).put("severity", it.severity) }),
    )
    .put("linkHosts", JSONArray(linkHosts))
    .put("rulesVersion", rulesVersion)

  companion object {
    // java.time needs API 26; minSdk is 24.
    private fun isoUtc(millis: Long): String =
      java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US)
        .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
        .format(java.util.Date(millis))

    fun from(analysis: Analysis, appLabel: String, packageName: String, postedAt: Long) = StoredWarning(
      id = UUID.randomUUID().toString(),
      postedAt = postedAt,
      appLabel = appLabel,
      packageName = packageName,
      verdict = analysis.verdict.wire,
      headline = analysis.headline,
      recommendedAction = analysis.recommendedAction,
      reasons = analysis.reasons.map { Reason(it.code, it.title, it.reason, it.severity.wire) },
      linkHosts = analysis.linkHosts,
      rulesVersion = analysis.rulesVersion,
    )

    fun fromJson(o: JSONObject): StoredWarning {
      val reasons = o.getJSONArray("reasons")
      val hosts = o.getJSONArray("linkHosts")
      return StoredWarning(
        id = o.getString("id"),
        postedAt = o.getLong("postedAt"),
        appLabel = o.getString("appLabel"),
        packageName = o.getString("packageName"),
        verdict = o.getString("verdict"),
        headline = o.getString("headline"),
        recommendedAction = o.getString("recommendedAction"),
        reasons = (0 until reasons.length()).map {
          val r = reasons.getJSONObject(it)
          Reason(r.getString("code"), r.getString("title"), r.getString("reason"), r.getString("severity"))
        },
        linkHosts = (0 until hosts.length()).map { hosts.getString(it) },
        rulesVersion = o.getString("rulesVersion"),
      )
    }
  }
}

/** Settings and recent warnings in private SharedPreferences. Shared by the service and the module. */
class ProtectionStore(context: Context) {
  private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  /** The user's switch. Notification access is granted separately in Android Settings. */
  var enabled: Boolean
    get() = prefs.getBoolean(KEY_ENABLED, true)
    set(value) = prefs.edit().putBoolean(KEY_ENABLED, value).apply()

  var listenerConnected: Boolean
    get() = prefs.getBoolean(KEY_CONNECTED, false)
    set(value) = prefs.edit().putBoolean(KEY_CONNECTED, value).apply()

  fun warnings(now: Long = System.currentTimeMillis()): List<StoredWarning> = synchronized(lock) {
    read().filter { now - it.postedAt < MAX_AGE_MS }
  }

  fun add(warning: StoredWarning) = synchronized(lock) {
    write((listOf(warning) + read()).take(MAX_WARNINGS))
  }

  fun remove(id: String) = synchronized(lock) { write(read().filterNot { it.id == id }) }

  fun clear() = synchronized(lock) { write(emptyList()) }

  private fun read(): List<StoredWarning> {
    val raw = prefs.getString(KEY_WARNINGS, null) ?: return emptyList()
    return try {
      val arr = JSONArray(raw)
      (0 until arr.length()).map { StoredWarning.fromJson(arr.getJSONObject(it)) }
    } catch (_: org.json.JSONException) {
      emptyList()
    }
  }

  private fun write(list: List<StoredWarning>) {
    prefs.edit().putString(KEY_WARNINGS, JSONArray(list.map { it.toJson() }).toString()).apply()
  }

  private companion object {
    val lock = Any()
    const val PREFS = "authentik_protection"
    const val KEY_ENABLED = "enabled"
    const val KEY_CONNECTED = "listener_connected"
    const val KEY_WARNINGS = "warnings"
    const val MAX_WARNINGS = 20
    const val MAX_AGE_MS = 30L * 24 * 60 * 60 * 1000
  }
}

/** Lets the service reach a live JS listener, if the app is open. */
object ProtectionEvents {
  @Volatile
  var onWarning: ((StoredWarning) -> Unit)? = null
}
