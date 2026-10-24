// Adds an ACTION_SEND text/plain target to MainActivity so "Share → Authentik"
// works from browsers and messaging apps. The shared text is read by
// AuthentikProtection.consumeSharedText() and only pre-fills the scan screen.
const { withAndroidManifest, AndroidConfig } = require('expo/config-plugins');

const SEND_FILTER = {
  action: [{ $: { 'android:name': 'android.intent.action.SEND' } }],
  category: [{ $: { 'android:name': 'android.intent.category.DEFAULT' } }],
  data: [{ $: { 'android:mimeType': 'text/plain' } }],
};

function hasSendFilter(activity) {
  return (activity['intent-filter'] ?? []).some((f) =>
    (f.action ?? []).some((a) => a.$['android:name'] === 'android.intent.action.SEND'),
  );
}

module.exports = function withShareTarget(config) {
  return withAndroidManifest(config, (cfg) => {
    const activity = AndroidConfig.Manifest.getMainActivityOrThrow(cfg.modResults);
    if (!hasSendFilter(activity)) {
      activity['intent-filter'] = [...(activity['intent-filter'] ?? []), SEND_FILTER];
    }
    return cfg;
  });
};
