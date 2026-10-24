package app.authentik.protection

import android.content.Context
import app.authentik.protection.rules.KnownEntity
import app.authentik.protection.rules.ThreatIntel
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * The downloaded threat list, kept in a private file so the listener can use it
 * without the JS runtime. The app fetches `GET /v1/threats/updates` and passes
 * the response to `apply`. It holds no user data.
 */
class ThreatListStore private constructor(context: Context) {
  private val file = File(context.applicationContext.filesDir, "authentik-threat-list.json")

  private class Loaded(
    val version: String,
    val fetchedAt: Long,
    val maxAgeSeconds: Long,
    val domains: Map<String, String>,
    val entities: List<KnownEntity>,
  )

  @Volatile
  private var loaded: Loaded? = null
  private var read = false

  /** The rules' view of the list. Freshness is judged now, not when it was saved. */
  fun intel(now: Long = System.currentTimeMillis()): ThreatIntel {
    val l = current() ?: return ThreatIntel.SEED
    val fresh = now - l.fetchedAt < l.maxAgeSeconds * 1000
    return ThreatIntel(l.domains, l.entities.ifEmpty { ThreatIntel.SEED.entities }, fresh, l.version)
  }

  fun info(now: Long = System.currentTimeMillis()): Map<String, Any?> {
    val l = current()
    return mapOf(
      "version" to l?.version,
      "fetchedAt" to l?.fetchedAt?.toDouble(),
      "entries" to (l?.domains?.size ?: 0),
      "fresh" to (l != null && now - l.fetchedAt < l.maxAgeSeconds * 1000),
    )
  }

  /**
   * Applies a `ThreatListUpdate`. A delta needs the version it was built
   * against; if that doesn't match, nothing changes and the caller should ask
   * for the full list.
   */
  @Synchronized
  fun apply(json: String, now: Long = System.currentTimeMillis()): Map<String, Any?> {
    val update = JSONObject(json)
    val full = update.getBoolean("full")
    val base = current()
    val domains = if (full) HashMap() else HashMap(base?.domains ?: throw DeltaMismatch())

    if (!full) {
      val removed = update.getJSONArray("removed")
      for (i in 0 until removed.length()) domains.remove(removed.getString(i))
    }
    val added = update.getJSONArray("added")
    for (i in 0 until added.length()) {
      val e = added.getJSONObject(i)
      domains[e.getString("domain").lowercase()] = e.getString("threatType")
    }

    val next = Loaded(
      version = update.getString("version"),
      fetchedAt = now,
      maxAgeSeconds = update.getLong("maxAgeSeconds"),
      domains = domains,
      entities = parseBrands(update.getJSONArray("brands")),
    )
    write(next)
    loaded = next
    return info(now)
  }

  class DeltaMismatch : IllegalStateException("The threat list on this phone doesn't match the update. Request the full list.")

  @Synchronized
  private fun current(): Loaded? {
    if (!read) {
      read = true
      loaded = try {
        if (file.exists()) parse(JSONObject(file.readText())) else null
      } catch (_: Exception) {
        // A corrupt file is treated as no list: links stay inconclusive until the next download.
        null
      }
    }
    return loaded
  }

  private fun write(l: Loaded) {
    val domains = JSONObject()
    l.domains.forEach { (d, t) -> domains.put(d, t) }
    val brands = JSONArray(
      l.entities.map {
        JSONObject()
          .put("name", it.name).put("isBank", it.isBank)
          .put("domains", JSONArray(it.domains)).put("brandTokens", JSONArray(it.brandTokens)).put("mentions", JSONArray(it.mentions))
      },
    )
    val tmp = File(file.parentFile, file.name + ".tmp")
    tmp.writeText(
      JSONObject()
        .put("version", l.version).put("fetchedAt", l.fetchedAt).put("maxAgeSeconds", l.maxAgeSeconds)
        .put("domains", domains).put("brands", brands)
        .toString(),
    )
    tmp.renameTo(file)
  }

  private fun parse(o: JSONObject): Loaded {
    val d = o.getJSONObject("domains")
    val domains = HashMap<String, String>(d.length())
    for (key in d.keys()) domains[key] = d.getString(key)
    return Loaded(o.getString("version"), o.getLong("fetchedAt"), o.getLong("maxAgeSeconds"), domains, parseBrands(o.getJSONArray("brands")))
  }

  private fun parseBrands(arr: JSONArray): List<KnownEntity> = (0 until arr.length()).map {
    val b = arr.getJSONObject(it)
    KnownEntity(
      name = b.getString("name"),
      isBank = b.getBoolean("isBank"),
      domains = b.getJSONArray("domains").strings(),
      brandTokens = b.getJSONArray("brandTokens").strings(),
      mentions = b.getJSONArray("mentions").strings(),
    )
  }

  private fun JSONArray.strings() = (0 until length()).map { getString(it).lowercase() }

  companion object {
    @Volatile
    private var instance: ThreatListStore? = null

    fun get(context: Context): ThreatListStore =
      instance ?: synchronized(this) { instance ?: ThreatListStore(context).also { instance = it } }
  }
}
