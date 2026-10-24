package app.authentik.protection

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.service.notification.NotificationListenerService
import androidx.core.app.NotificationManagerCompat
import app.authentik.protection.rules.NotificationInput
import app.authentik.protection.rules.NotificationRules
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class AuthentikProtectionModule : Module() {
  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  private val store by lazy { ProtectionStore(context) }
  private val threatList by lazy { ThreatListStore.get(context) }

  private val vpnStore by lazy { VpnStore(context) }

  // Waiting for the user's answer to Android's VPN consent dialog.
  private var vpnPermission: Promise? = null

  // Text shared to Authentik while the app was already running, until JS reads it.
  @Volatile
  private var pendingShare: String? = null

  private val component: ComponentName
    get() = ComponentName(context, ProtectionListenerService::class.java)

  override fun definition() = ModuleDefinition {
    Name("AuthentikProtection")

    Events("onWarning", "onSharedText", "onVpnStatus")

    // Share sheet while the app is running: MainActivity receives the intent here.
    OnNewIntent { intent ->
      sharedText(intent)?.let {
        pendingShare = it
        sendEvent("onSharedText", mapOf<String, Any?>())
      }
    }

    OnActivityResult { _, payload ->
      if (payload.requestCode != REQUEST_VPN) return@OnActivityResult
      vpnPermission?.resolve(payload.resultCode == Activity.RESULT_OK)
      vpnPermission = null
    }

    OnStartObserving {
      ProtectionEvents.onWarning = { sendEvent("onWarning", it.toMap()) }
      VpnState.onChange = { sendEvent("onVpnStatus", vpnStatus()) }
    }

    OnStopObserving {
      ProtectionEvents.onWarning = null
      VpnState.onChange = null
    }

    Function("getStatus") {
      val access = NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)
      mapOf(
        "supported" to true,
        "notificationAccess" to access,
        "listenerConnected" to (access && store.listenerConnected),
        "enabled" to store.enabled,
        "warningsAllowed" to NotificationManagerCompat.from(context).areNotificationsEnabled(),
      )
    }

    Function("openNotificationAccessSettings") {
      val detail = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
          .putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, component.flattenToString())
      } else {
        null
      }
      val list = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
      // Some manufacturers don't ship the per-app detail screen.
      listOfNotNull(detail, list).any { intent ->
        try {
          context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
          true
        } catch (_: ActivityNotFoundException) {
          false
        }
      }
    }

    /** Asks Android to reconnect the listener when access is granted but it isn't bound. */
    Function("requestRebind") {
      NotificationListenerService.requestRebind(component)
    }

    Function("setEnabled") { enabled: Boolean ->
      store.enabled = enabled
    }

    Function("getWarnings") {
      store.warnings().map { it.toMap() }
    }

    Function("dismissWarning") { id: String ->
      store.remove(id)
    }

    Function("clearWarnings") {
      store.clear()
    }

    // ── Web protection (local DNS-only VPN) ──

    /**
     * Shows Android's VPN consent dialog if needed. Resolves true when Authentik
     * may run the VPN. Turning it on replaces any other VPN that's active.
     */
    AsyncFunction("requestVpnPermission") { promise: Promise ->
      val intent = VpnService.prepare(context)
      val activity = appContext.currentActivity
      when {
        intent == null -> promise.resolve(true)
        activity == null -> promise.resolve(false)
        else -> {
          vpnPermission?.resolve(false)
          vpnPermission = promise
          activity.startActivityForResult(intent, REQUEST_VPN)
        }
      }
    }

    Function("startVpn") {
      if (VpnService.prepare(context) != null) {
        throw CodedException("ERR_VPN_PERMISSION", "Authentik needs permission to run the VPN first.", null)
      }
      vpnStore.enabled = true
      VpnProtectionService.start(context)
    }

    Function("stopVpn") {
      vpnStore.enabled = false
      VpnProtectionService.stop(context)
    }

    Function("getVpnStatus") {
      vpnStatus()
    }

    Function("getDnsEvents") {
      vpnStore.events().map { it.toMap() }
    }

    Function("clearDnsEvents") {
      vpnStore.clear()
    }

    /** Android's VPN settings, where the user can make Authentik always-on (survives reboots). */
    Function("openVpnSettings") {
      try {
        context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
      } catch (_: ActivityNotFoundException) {
        false
      }
    }

    Function("getThreatListInfo") {
      threatList.info()
    }

    /** Takes a `ThreatListUpdate` as JSON. Throws `ERR_THREAT_DELTA` when a delta doesn't match the stored version. */
    Function("applyThreatUpdate") { json: String ->
      try {
        threatList.apply(json)
      } catch (e: ThreatListStore.DeltaMismatch) {
        throw CodedException("ERR_THREAT_DELTA", e.message, e)
      }
    }

    /**
     * Text shared to Authentik from another app (ACTION_SEND), or null. Returned
     * once: the launch intent is cleared so a later resume doesn't repeat it.
     */
    Function("consumeSharedText") {
      val pending = pendingShare
      if (pending != null) {
        pendingShare = null
        pending
      } else {
        val activity = appContext.currentActivity
        val text = sharedText(activity?.intent)
        if (text != null) activity?.intent = Intent(Intent.ACTION_MAIN)
        text
      }
    }

    /** Runs the rules on text the user typed. Nothing is stored or posted. */
    Function("analyzeSample") { title: String, text: String ->
      val a = NotificationRules.analyze(NotificationInput("sample", title, text), threatList.intel())
      mapOf(
        "verdict" to a.verdict.wire,
        "headline" to a.headline,
        "recommendedAction" to a.recommendedAction,
        "reasons" to a.reasons.map { mapOf("code" to it.code, "title" to it.title, "reason" to it.reason, "severity" to it.severity.wire) },
        "linkHosts" to a.linkHosts,
        "rulesVersion" to a.rulesVersion,
        "shouldWarn" to a.shouldWarn,
      )
    }
  }

  private fun vpnStatus() = VpnState.toMap(vpnStore.enabled, permitted = VpnService.prepare(context) == null)

  private fun sharedText(intent: Intent?): String? {
    if (intent?.action != Intent.ACTION_SEND || intent.type?.startsWith("text/") != true) return null
    val text = intent.getStringExtra(Intent.EXTRA_TEXT) ?: intent.getStringExtra(Intent.EXTRA_SUBJECT) ?: return null
    // Cap what crosses the bridge: a link, not a whole document.
    return text.take(4096)
  }

  private companion object {
    const val REQUEST_VPN = 0x4156
  }
}
