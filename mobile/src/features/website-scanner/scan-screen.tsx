import { useState } from 'react';
import { View } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { useLocalSearchParams, useRouter } from 'expo-router';
import type { Report } from '@authentik/shared';
import { api, ApiError } from '@/shared/api/client';
import { Button, IconButton, Notice, Screen, Text, TextField } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { AssessmentView } from '@/features/reports/assessment-view';

/**
 * Paste or receive a link (deep link or share sheet). A link that arrives from
 * outside is only pre-filled: the user still chooses to check it. The result
 * shows here; it's also saved to Activity.
 */
export function ScanScreen() {
  const t = useTheme();
  const router = useRouter();
  const params = useLocalSearchParams<{ url?: string }>();
  const [url, setUrl] = useState(typeof params.url === 'string' ? params.url.slice(0, 2048) : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  const paste = async () => {
    const text = (await Clipboard.getStringAsync()).trim();
    if (text) setUrl(text.slice(0, 2048));
  };

  const edit = (value: string) => {
    setUrl(value);
    setError(null);
  };

  const scan = async () => {
    if (!url.trim()) return setError('Enter or paste a website address.');
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      setReport(await api.scan(url.trim()));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The check couldn’t be completed. Try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen>
      <View style={{ gap: t.space.md }}>
        <TextField
          label="Website or link"
          placeholder="takealot.com, or a link from a message"
          value={url}
          onChangeText={edit}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          returnKeyType="go"
          onSubmitEditing={scan}
          error={error}
          hint="Paste a link, or share one to Authentik from any app."
          trailing={
            url ? (
              <IconButton name="close" label="Clear" onPress={() => { setUrl(''); setReport(null); setError(null); }} />
            ) : (
              <IconButton name="content-paste" label="Paste" onPress={() => void paste()} />
            )
          }
        />
        <Button title={busy ? 'Checking…' : 'Check'} onPress={scan} loading={busy} />
      </View>

      {busy ? (
        <Text variant="bodyMedium" muted accessibilityLiveRegion="polite" style={{ textAlign: 'center', paddingVertical: t.space.lg }}>
          Checking scam lists, look-alike names and the domain. This usually takes a few seconds.
        </Text>
      ) : null}

      {report ? (
        <>
          <AssessmentView assessment={report.assessment} subject="website" target={report.target.hostname} />
          <View style={{ gap: t.space.sm }}>
            {report.verdict !== 'blocked' ? (
              <Button
                kind="secondary"
                title="Look at it safely in the Sandbox"
                onPress={() => router.push({ pathname: '/sandbox', params: { url: `https://${report.target.hostname}/` } })}
              />
            ) : null}
            <Button kind="ghost" title="Done" onPress={() => router.back()} />
          </View>
        </>
      ) : !busy ? (
        <Notice title="Not sure about a link?">Don’t open it first. Copy it from the message and paste it here.</Notice>
      ) : null}
    </Screen>
  );
}
