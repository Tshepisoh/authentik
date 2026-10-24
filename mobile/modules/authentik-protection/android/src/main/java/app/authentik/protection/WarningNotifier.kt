package app.authentik.protection

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object WarningNotifier {
  const val CHANNEL_ID = "fraud-warnings"

  // Must match "scheme" in app.json. Expo Router opens src/app/warning/[id].tsx.
  private const val WARNING_LINK = "authentik://warning/"
  private const val DNS_DEEP_LINK = "authentik://web-protection"

  private fun ensureChannel(context: Context) {
    NotificationManagerCompat.from(context).createNotificationChannel(
      NotificationChannelCompat.Builder(CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_HIGH)
        .setName("Fraud warnings")
        .setDescription("Warnings about suspicious notifications")
        .build(),
    )
  }

  fun post(context: Context, warning: StoredWarning) {
    val summary = warning.reasons.firstOrNull()?.let { "${warning.appLabel}: ${it.title}" }
      ?: "From ${warning.appLabel}"
    val details = buildString {
      append(summary)
      warning.reasons.drop(1).take(3).forEach { append("\n• ").append(it.title) }
      append("\n\n").append(warning.recommendedAction)
    }
    notify(context, warning.id.hashCode(), warning.headline, summary, details, "$WARNING_LINK${warning.id}", "Unlock to see why a notification was flagged.")
  }

  /** A lookup the VPN blocked, or a look-alike site something on the phone just looked up. */
  fun postDns(context: Context, event: DnsEvent) {
    val (title, summary) = if (event.kind == "blocked") {
      "Blocked a known scam site" to "${event.host} is listed for ${event.detail}. Authentik stopped it from loading."
    } else {
      "This site imitates ${event.detail}" to
        "${event.host} uses the ${event.detail} name but isn't one of its websites. Don't enter any details there."
    }
    notify(context, "dns:${event.host}".hashCode(), title, summary, summary, DNS_DEEP_LINK, "Unlock to see which site was flagged.")
  }

  @SuppressLint("MissingPermission") // Checked through areNotificationsEnabled().
  private fun notify(context: Context, id: Int, title: String, summary: String, details: String, deepLink: String, publicText: String) {
    val manager = NotificationManagerCompat.from(context)
    if (!manager.areNotificationsEnabled()) return
    ensureChannel(context)

    val open = PendingIntent.getActivity(
      context,
      deepLink.hashCode(),
      Intent(Intent.ACTION_VIEW, Uri.parse(deepLink))
        .setPackage(context.packageName)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    // The lock screen shows only this generic version.
    val public = NotificationCompat.Builder(context, CHANNEL_ID)
      .setSmallIcon(R.drawable.authentik_protection_shield)
      .setContentTitle("Authentik warning")
      .setContentText(publicText)
      .build()

    val notification = NotificationCompat.Builder(context, CHANNEL_ID)
      .setSmallIcon(R.drawable.authentik_protection_shield)
      .setContentTitle(title)
      .setContentText(summary)
      .setStyle(NotificationCompat.BigTextStyle().bigText(details))
      .setCategory(NotificationCompat.CATEGORY_STATUS)
      .setPriority(NotificationCompat.PRIORITY_HIGH)
      .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
      .setPublicVersion(public)
      .setContentIntent(open)
      .setAutoCancel(true)
      .build()

    manager.notify(id, notification)
  }
}
