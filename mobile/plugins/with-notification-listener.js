// EXPO_PUBLIC_NOTIFICATION_LISTENER=off removes the notification listener service from the
// merged manifest. Play Protect blocks sideloaded APKs that declare it (enhanced fraud
// protection, South Africa and other markets), so the judge APK leaves it out and the app
// offers "Check a message yourself" instead. Google Play builds keep it.
const { withAndroidManifest } = require('expo/config-plugins');

const LISTENER = 'app.authentik.protection.ProtectionListenerService';

module.exports = function withNotificationListener(config) {
  if (process.env.EXPO_PUBLIC_NOTIFICATION_LISTENER !== 'off') return config;
  return withAndroidManifest(config, (cfg) => {
    const manifest = cfg.modResults.manifest;
    manifest.$['xmlns:tools'] = 'http://schemas.android.com/tools';
    const app = manifest.application[0];
    const services = (app.service ?? []).filter((s) => s.$['android:name'] !== LISTENER);
    app.service = [...services, { $: { 'android:name': LISTENER, 'tools:node': 'remove' } }];
    return cfg;
  });
};
