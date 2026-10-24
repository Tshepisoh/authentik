package app.authentik.protection

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/** A blocked lookup or a look-alike warning. Only these are kept; ordinary lookups never are. */
data class DnsEvent(val host: String, val at: Long, val kind: String, val detail: String) {
  fun toMap(): Map<String, Any?> = mapOf("host" to host, "at" to at.toDouble(), "kind" to kind, "detail" to detail)
}

/** The user's VPN choice and recent events, in private SharedPreferences. */
class VpnStore(context: Context) {
  private val prefs = context.applicationContext.getSharedPreferences("authentik_vpn", Context.MODE_PRIVATE)

  /** What the user asked for. The service restarts itself after being killed only while this is true. */
  var enabled: Boolean
    get() = prefs.getBoolean("enabled", false)
    set(value) = prefs.edit().putBoolean("enabled", value).apply()

  fun events(now: Long = System.currentTimeMillis()): List<DnsEvent> = synchronized(lock) {
    read().filter { now - it.at < MAX_AGE_MS }
  }

  fun add(e: DnsEvent) = synchronized(lock) { write((listOf(e) + read()).take(MAX_EVENTS)) }

  fun clear() = synchronized(lock) { write(emptyList()) }

  private fun read(): List<DnsEvent> = try {
    val arr = JSONArray(prefs.getString("events", "[]"))
    (0 until arr.length()).map {
      val o = arr.getJSONObject(it)
      DnsEvent(o.getString("host"), o.getLong("at"), o.getString("kind"), o.getString("detail"))
    }
  } catch (_: org.json.JSONException) {
    emptyList()
  }

  private fun write(list: List<DnsEvent>) {
    val arr = JSONArray(list.map { JSONObject().put("host", it.host).put("at", it.at).put("kind", it.kind).put("detail", it.detail) })
    prefs.edit().putString("events", arr.toString()).apply()
  }

  private companion object {
    val lock = Any()
    const val MAX_EVENTS = 50
    const val MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000
  }
}

/** Live state of the running service, read by the module. Process memory only. */
object VpnState {
  @Volatile var running = false
  @Volatile var startedAt = 0L
  val lookups = AtomicLong()
  val blocked = AtomicLong()
  val warned = AtomicLong()
  @Volatile var upstreamServers = 0
  /** Set when Private DNS is in strict ("hostname") mode: lookups then go straight to that provider. */
  @Volatile var privateDnsHost: String? = null
  @Volatile var lastError: String? = null

  @Volatile
  var onChange: (() -> Unit)? = null

  fun reset(running: Boolean) {
    this.running = running
    startedAt = System.currentTimeMillis()
    lookups.set(0)
    blocked.set(0)
    warned.set(0)
    lastError = null
  }

  fun changed() {
    onChange?.invoke()
  }

  fun toMap(enabled: Boolean, permitted: Boolean): Map<String, Any?> = mapOf(
    "enabled" to enabled,
    "permitted" to permitted,
    "running" to running,
    "startedAt" to if (running) startedAt.toDouble() else null,
    "lookups" to lookups.get().toDouble(),
    "blocked" to blocked.get().toDouble(),
    "warned" to warned.get().toDouble(),
    "upstreamServers" to upstreamServers,
    "privateDnsHost" to privateDnsHost,
    "lastError" to lastError,
  )
}
