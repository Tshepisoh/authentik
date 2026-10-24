import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';
import { useFocusEffect } from 'expo-router';
import { AuthentikProtection, type DnsEvent, type VpnStatus } from '@modules/authentik-protection';
import type { WebProtectionState } from '@/shared/lib/format';

export function webProtectionState(s: VpnStatus | null): WebProtectionState {
  if (!s) return 'unsupported';
  if (s.running) return s.privateDnsHost ? 'bypassed' : 'on';
  // Revoked by another VPN, or failed to start.
  if (s.lastError) return 'stopped';
  if (s.enabled) return 'starting';
  return 'off';
}

/** Status of the local VPN. Polls while mounted, since lookup counts change without events. */
export function useWebProtection({ poll = false } = {}) {
  const [status, setStatus] = useState<VpnStatus | null>(() => AuthentikProtection?.getVpnStatus() ?? null);
  const [events, setEvents] = useState<DnsEvent[]>(() => AuthentikProtection?.getDnsEvents() ?? []);
  // When the status was read, so render code never calls Date.now().
  const [checkedAt, setCheckedAt] = useState(() => Date.now());

  const refresh = useCallback(() => {
    setCheckedAt(Date.now());
    setStatus(AuthentikProtection?.getVpnStatus() ?? null);
    setEvents(AuthentikProtection?.getDnsEvents() ?? []);
  }, []);

  useFocusEffect(refresh);

  useEffect(() => {
    const app = AppState.addEventListener('change', (next) => {
      if (next === 'active') refresh();
    });
    const sub = AuthentikProtection?.addListener('onVpnStatus', refresh);
    const timer = poll ? setInterval(refresh, 5000) : null;
    return () => {
      app.remove();
      sub?.remove();
      if (timer) clearInterval(timer);
    };
  }, [refresh, poll]);

  return { status, state: webProtectionState(status), events, checkedAt, refresh };
}
