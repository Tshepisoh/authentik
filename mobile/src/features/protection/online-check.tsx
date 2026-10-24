import { useState } from 'react';
import { View } from 'react-native';
import type { NotificationAnalysis, NotificationAnalyzeRequest } from '@authentik/shared';
import { api, ApiError } from '@/shared/api/client';
import { Button, Notice, Text, VerdictBadge } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';

/**
 * Asks the server to check a notification's links and combine them with the
 * phone's findings. Only on request, and without the notification text.
 */
export function OnlineCheck({ request }: { request: NotificationAnalyzeRequest }) {
  const t = useTheme();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<NotificationAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.analyzeNotification(request));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Couldn’t check the link. Try again.');
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <View style={{ gap: t.space.sm }} accessibilityLiveRegion="polite">
        <VerdictBadge verdict={result.assessment.verdict} subject="notification" size="sm" />
        <Text variant="bodyMedium">{result.assessment.headline}</Text>
        {result.assessment.explanation.slice(0, 3).map((line) => (
          <Text key={line} variant="bodySmall" muted>{line}</Text>
        ))}
      </View>
    );
  }
  return (
    <View style={{ gap: t.space.sm }}>
      {error ? <Notice tone="warning">{error}</Notice> : null}
      <Button kind="tonal" title={busy ? 'Checking…' : 'Check link online'} loading={busy} onPress={() => void run()} />
      <Text variant="bodySmall" muted>Sends the site name and the warning types to Authentik. Never the message.</Text>
    </View>
  );
}
