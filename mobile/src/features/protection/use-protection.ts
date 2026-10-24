import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';
import { useFocusEffect } from 'expo-router';
import {
  AuthentikProtection,
  getProtectionStatus,
  type ProtectionStatus,
  type ProtectionWarning,
  type ThreatListInfo,
} from '@modules/authentik-protection';
import { config } from '@/shared/config';
import type { ProtectionState } from '@/shared/lib/format';
import { syncThreatList } from './threat-sync';

export function protectionState(s: ProtectionStatus): ProtectionState {
  if (!s.supported) return 'unsupported';
  if (!config.notificationListener) return 'not_in_build';
  if (!s.notificationAccess) return 'needs_access';
  if (!s.enabled) return 'paused';
  if (!s.listenerConnected) return 'connecting';
  if (!s.warningsAllowed) return 'needs_notifications';
  return 'active';
}

/**
 * Status and recent warnings from the native listener. Re-reads when the screen
 * gains focus, when the app returns from Android Settings, and when a warning
 * arrives while the app is open.
 */
export function useProtection() {
  const [status, setStatus] = useState<ProtectionStatus>(getProtectionStatus);
  const [warnings, setWarnings] = useState<ProtectionWarning[]>(() => AuthentikProtection?.getWarnings() ?? []);
  const [threatList, setThreatList] = useState<ThreatListInfo | null>(() => AuthentikProtection?.getThreatListInfo() ?? null);
  // When the status was read, so render code never calls Date.now().
  const [checkedAt, setCheckedAt] = useState(() => Date.now());

  const refresh = useCallback(() => {
    const s = getProtectionStatus();
    setCheckedAt(Date.now());
    // Access is granted but Android hasn't bound the listener (common right after granting).
    if (s.notificationAccess && !s.listenerConnected) AuthentikProtection?.requestRebind();
    setStatus(s);
    setWarnings(AuthentikProtection?.getWarnings() ?? []);
    setThreatList(AuthentikProtection?.getThreatListInfo() ?? null);
    // Offline? The listener keeps using the stored list; the status line shows its age.
    syncThreatList().then((info) => info && setThreatList(info), () => undefined);
  }, []);

  useFocusEffect(refresh);

  useEffect(() => {
    const app = AppState.addEventListener('change', (next) => {
      if (next === 'active') refresh();
    });
    const warning = AuthentikProtection?.addListener('onWarning', refresh);
    return () => {
      app.remove();
      warning?.remove();
    };
  }, [refresh]);

  return { status, state: protectionState(status), warnings, threatList, checkedAt, refresh };
}
