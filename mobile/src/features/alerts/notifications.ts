import { useEffect } from 'react';
import { Platform } from 'react-native';
import { isRunningInExpoGo } from 'expo';
import Constants, { ExecutionEnvironment } from 'expo-constants';
import * as Device from 'expo-device';
import { useRouter } from 'expo-router';
import type * as NotificationsModule from 'expo-notifications';
import { api } from '@/shared/api/client';

/**
 * Expo Go (SDK 53+) ships without the push-notification native modules, and
 * expo-notifications throws as soon as it is *imported* there. So the module
 * is loaded lazily, only in development or store builds, and never at import
 * time: a static import would crash every screen that touches this file.
 */
// isRunningInExpoGo() checks for Expo Go's own native module, the authoritative signal;
// executionEnvironment alone reported false in Expo Go on SDK 58.
const inExpoGo = isRunningInExpoGo() || Constants.executionEnvironment === ExecutionEnvironment.StoreClient;

let loaded: Promise<typeof NotificationsModule | null> | null = null;

function loadNotifications(): Promise<typeof NotificationsModule | null> {
  loaded ??= inExpoGo
    ? Promise.resolve(null)
    : import('expo-notifications').then(
        (N) => {
          N.setNotificationHandler({
            handleNotification: async () => ({
              shouldShowBanner: true,
              shouldShowList: true,
              shouldPlaySound: false,
              shouldSetBadge: true,
            }),
          });
          return N;
        },
        () => null,
      );
  return loaded;
}

/** Opens the Alerts tab when the user taps a security notification. No-op in Expo Go. */
export function useNotificationRouting(enabled: boolean) {
  const router = useRouter();
  useEffect(() => {
    if (!enabled) return;
    let sub: { remove(): void } | null = null;
    let cancelled = false;
    void loadNotifications().then((N) => {
      if (!N || cancelled) return;
      sub = N.addNotificationResponseReceivedListener(() => router.push('/alerts'));
    });
    return () => {
      cancelled = true;
      sub?.remove();
    };
  }, [enabled, router]);
}

/**
 * Asks only for permission to show notifications, without registering for push.
 * On-device fraud warnings need this on Android 13+. False in Expo Go.
 */
export async function allowLocalNotifications(): Promise<boolean> {
  const N = await loadNotifications();
  if (!N) return false;
  const current = await N.getPermissionsAsync();
  return current.granted || (await N.requestPermissionsAsync()).granted;
}

export class PushUnavailableError extends Error {}

/**
 * Registers this device for security-alert pushes. The backend sends via
 * Firebase Cloud Messaging, which takes the native FCM token on Android.
 * iOS needs the FCM iOS SDK (or a relay) to map APNs tokens — not in this build.
 */
export async function enablePush(): Promise<void> {
  if (inExpoGo) {
    throw new PushUnavailableError('Push alerts need the installed Authentik app — they don’t work in Expo Go. Alerts still appear in the app.');
  }
  if (Platform.OS !== 'android') {
    throw new PushUnavailableError('Push alerts are not available on iOS yet. Alerts will still appear in the app.');
  }
  if (!Device.isDevice) throw new PushUnavailableError('Push alerts need a physical device.');
  const N = await loadNotifications();
  if (!N) throw new PushUnavailableError('Push alerts are not available in this build.');

  await N.setNotificationChannelAsync('security-alerts', {
    name: 'Security alerts',
    importance: N.AndroidImportance.HIGH,
    // Lock-screen safe: content is hidden until unlocked.
    lockscreenVisibility: N.AndroidNotificationVisibility.PRIVATE,
  });
  const current = await N.getPermissionsAsync();
  const status = current.granted ? current : await N.requestPermissionsAsync();
  if (!status.granted) throw new PushUnavailableError('Notifications are turned off for Authentik in your phone’s settings.');

  const token = await N.getDevicePushTokenAsync();
  await api.registerDevice({ token: String(token.data), platform: 'android' });
}
