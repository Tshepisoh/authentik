import { useEffect } from 'react';
import { AppState } from 'react-native';
import { useRouter } from 'expo-router';
import { AuthentikProtection } from '@modules/authentik-protection';

/** The first link in shared text: a URL with a scheme, else a bare `www.`/domain-looking token. */
export function firstLink(text: string): string | null {
  const m = text.match(/https?:\/\/[^\s<>"']+/i) ?? text.match(/\b(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}(?:\/[^\s<>"']*)?/i);
  return m ? m[0].replace(/[).,!?]+$/, '').slice(0, 2048) : null;
}

/**
 * Handles "Share → Authentik" from other apps (Android). A link pre-fills the
 * website check; text without a link pre-fills the message checker. Nothing is
 * checked until the user asks.
 */
export function useSharedLinks(enabled: boolean) {
  const router = useRouter();
  useEffect(() => {
    const native = AuthentikProtection;
    if (!enabled || !native) return;
    const handle = () => {
      const text = native.consumeSharedText();
      if (!text) return;
      const url = firstLink(text);
      if (url) router.push({ pathname: '/scan', params: { url } });
      else router.push({ pathname: '/protection', params: { sample: text.slice(0, 2000) } });
    };
    handle();
    const app = AppState.addEventListener('change', (next) => {
      if (next === 'active') handle();
    });
    const shared = native.addListener('onSharedText', handle);
    return () => {
      app.remove();
      shared.remove();
    };
  }, [enabled, router]);
}
