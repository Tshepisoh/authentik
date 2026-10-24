package app.authentik.protection

import android.app.Notification
import android.content.pm.PackageManager
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import app.authentik.protection.rules.NotificationInput
import app.authentik.protection.rules.NotificationRules
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Runs in the app process but outside React Native, so detection keeps working
 * while the JS runtime is suspended or the UI is closed. Notification text stays
 * in memory for the length of one analysis, and only the warning is stored.
 */
class ProtectionListenerService : NotificationListenerService() {
  private lateinit var store: ProtectionStore
  private lateinit var executor: ExecutorService

  // Apps re-post the same notification when they update it. Touched only on the executor.
  private val seen = object : LinkedHashMap<Int, Unit>(64, 0.75f, true) {
    override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, Unit>?) = size > 200
  }

  override fun onCreate() {
    super.onCreate()
    store = ProtectionStore(this)
    executor = Executors.newSingleThreadExecutor()
  }

  override fun onDestroy() {
    executor.shutdownNow()
    super.onDestroy()
  }

  override fun onListenerConnected() {
    store.listenerConnected = true
  }

  override fun onListenerDisconnected() {
    store.listenerConnected = false
  }

  override fun onNotificationPosted(sbn: StatusBarNotification?) {
    if (sbn == null || !store.enabled) return
    val input = extract(sbn) ?: return
    val postedAt = sbn.postTime
    executor.execute { handle(input, postedAt) }
  }

  private fun handle(input: NotificationInput, postedAt: Long) {
    val key = (input.packageName + '\u0000' + input.title + '\u0000' + input.text).hashCode()
    if (seen.put(key, Unit) != null) return

    val analysis = NotificationRules.analyze(input, ThreatListStore.get(this).intel())
    if (!analysis.shouldWarn) return

    val warning = StoredWarning.from(analysis, appLabel(input.packageName), input.packageName, postedAt)
    store.add(warning)
    WarningNotifier.post(this, warning)
    ProtectionEvents.onWarning?.invoke(warning)
  }

  /** Pulls the visible text, or returns null for notifications that aren't worth reading. */
  private fun extract(sbn: StatusBarNotification): NotificationInput? {
    if (sbn.packageName == packageName || sbn.isOngoing) return null
    val n = sbn.notification ?: return null
    if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return null
    if (n.category?.let { it in IGNORED_CATEGORIES } == true) return null

    val extras = n.extras ?: return null
    val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
    val body = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
      ?: extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
      ?: ""
    val lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.joinToString("\n").orEmpty()
    val text = listOf(body, lines).filter { it.isNotBlank() }.joinToString("\n")
    if ((title + text).trim().length < MIN_LENGTH) return null
    return NotificationInput(sbn.packageName, title, text)
  }

  private fun appLabel(pkg: String): String = try {
    packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
  } catch (_: PackageManager.NameNotFoundException) {
    // Android 11+ hides other packages unless declared in <queries>, so fall back to the package name.
    pkg
  }

  private companion object {
    const val MIN_LENGTH = 8
    val IGNORED_CATEGORIES = setOf(
      Notification.CATEGORY_CALL,
      Notification.CATEGORY_PROGRESS,
      Notification.CATEGORY_TRANSPORT,
      Notification.CATEGORY_SERVICE,
      Notification.CATEGORY_ALARM,
      Notification.CATEGORY_NAVIGATION,
      Notification.CATEGORY_STOPWATCH,
    )
  }
}
