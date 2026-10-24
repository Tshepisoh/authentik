import { useState } from 'react';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { api, ApiError } from '@/shared/api/client';
import { Button, Card, Notice, Screen, Text, TextField } from '@/shared/ui';
import { sandboxHandoff } from './handoff';

export function SandboxStartScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{ url?: string }>();
  const [url, setUrl] = useState(typeof params.url === 'string' ? params.url : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsAck, setNeedsAck] = useState<string | null>(null);

  const start = async (acknowledgeRisk = false) => {
    if (!url.trim()) return setError('Enter a website address.');
    setBusy(true);
    setError(null);
    try {
      const session = await api.startSandbox({ url: url.trim(), acknowledgeRisk });
      sandboxHandoff.put(session);
      router.replace({ pathname: '/sandbox/[id]', params: { id: session.sessionId } });
    } catch (e) {
      if (e instanceof ApiError && e.code === 'risk_acknowledgement_required') setNeedsAck(e.message);
      else setError(e instanceof ApiError ? e.message : 'The Sandbox could not start. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen>
      <Text muted>The site opens in a disposable browser on Authentik’s servers. You see a live picture of it; its code never runs on your phone.</Text>
      <Card>
        <Text variant="subheading">Before you start</Text>
        <Text variant="small">• Don’t enter real passwords, card numbers or one-time PINs — the Sandbox protects your phone, not what you type.</Text>
        <Text variant="small">• Downloads, camera, microphone, location and notifications are blocked.</Text>
        <Text variant="small">• Sessions end automatically after 10 minutes, and everything is deleted.</Text>
      </Card>
      <TextField label="Website address" value={url} onChangeText={(v) => { setUrl(v); setNeedsAck(null); }} autoCapitalize="none" autoCorrect={false} keyboardType="url" error={error} />
      {needsAck ? (
        <>
          <Notice tone="danger" title="High-risk site">{needsAck}</Notice>
          <Button kind="danger" title="I understand — open it anyway" onPress={() => start(true)} loading={busy} />
          <Button kind="ghost" title="Cancel" onPress={() => router.back()} />
        </>
      ) : (
        <Button title="Open in Sandbox" onPress={() => start(false)} loading={busy} accessibilityHint="Scans the site first, then opens it in an isolated remote browser" />
      )}
    </Screen>
  );
}
