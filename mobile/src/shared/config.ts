/** Build-time configuration. EXPO_PUBLIC_* values are inlined into the bundle — never put secrets here. */
export const config = {
  apiUrl: (process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080').replace(/\/+$/, ''),
  authMode: (process.env.EXPO_PUBLIC_AUTH_MODE === 'dev' ? 'dev' : 'firebase') as 'dev' | 'firebase',
  /** `off` in the sideloaded judge APK: plugins/with-notification-listener.js removes the service. */
  notificationListener: process.env.EXPO_PUBLIC_NOTIFICATION_LISTENER !== 'off',
  firebase: {
    apiKey: process.env.EXPO_PUBLIC_FIREBASE_API_KEY ?? '',
    authDomain: process.env.EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN ?? '',
    projectId: process.env.EXPO_PUBLIC_FIREBASE_PROJECT_ID ?? '',
    appId: process.env.EXPO_PUBLIC_FIREBASE_APP_ID ?? '',
  },
};

export const wsUrl = (path: string) => `${config.apiUrl.replace(/^http/, 'ws')}${path}`;
