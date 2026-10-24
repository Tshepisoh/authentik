import { useState } from 'react';
import { View } from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import {
  AuthentikProtection,
  type ProtectionWarning,
  type SampleAnalysis,
  type ThreatListInfo,
} from '@modules/authentik-protection';
import { allowLocalNotifications } from '@/features/alerts/notifications';
import { PROTECTION_STATE_LABEL, relativeTime } from '@/shared/lib/format';
import { Button, Card, EmptyState, FactRow, Icon, ListItem, Notice, Screen, Section, Switch, Text, TextField, VerdictBadge } from '@/shared/ui';
import { useTheme, verdictColors } from '@/shared/ui/theme';
import { useProtection } from './use-protection';
import { OnlineCheck } from './online-check';


/** Explains notification access before sending the user to Android Settings. */
export function AccessExplainer({ onOpen }: { onOpen: () => void }) {
  const t = useTheme();
  return (
    <Card variant="filled" style={{ borderRadius: t.radius.xl, padding: 20, gap: t.space.lg }}>
      <Text variant="headlineSmall">Turn on notification protection</Text>
      <FactRow icon="manage-search" title="What it checks" body="New notifications, for fake payment alerts, bank impersonation, delivery-fee and refund scams, and requests for your PIN or OTP." />
      <FactRow icon="smartphone" title="Checked on this phone" body="Notification text isn’t sent to Authentik or saved. Only the warning is kept." />
      <FactRow icon="visibility-off" title="Only what apps show" body="It sees notifications, not your chats or other apps’ screens." />
      <Button title="Open Android settings" onPress={onOpen} accessibilityHint="Opens notification access settings. Allow Authentik fraud protection." />
      <Text variant="bodySmall" muted>Find “Authentik fraud protection” and switch it on. Android shows a warning there. That’s expected.</Text>
    </Card>
  );
}

export function ProtectionScreen() {
  const t = useTheme();
  const { status, state, warnings, threatList, refresh } = useProtection();
  const params = useLocalSearchParams<{ sample?: string }>();
  const [notice, setNotice] = useState<string | null>(null);

  const openSettings = () => {
    setNotice(null);
    if (!AuthentikProtection?.openNotificationAccessSettings()) {
      setNotice('Couldn’t open Android settings. Go to Settings › Notifications › Notification access (Device & app notifications on some phones) and allow Authentik.');
    }
  };

  const allowWarnings = async () => {
    if (!(await allowLocalNotifications())) {
      setNotice('Notifications are turned off for Authentik. Turn them on in Android Settings › Apps › Authentik › Notifications.');
    }
    refresh();
  };

  const setEnabled = (on: boolean) => {
    AuthentikProtection?.setEnabled(on);
    refresh();
  };

  const clear = () => {
    AuthentikProtection?.clearWarnings();
    refresh();
  };

  if (state === 'unsupported') {
    return (
      <Screen>
        <Notice tone="neutral" title="Not available here">
          <Text variant="small">Automatic notification protection needs the installed Authentik app on Android. It isn’t available on iOS, on the web or in Expo Go.</Text>
        </Notice>
      </Screen>
    );
  }

  if (state === 'not_in_build') {
    return (
      <Screen>
        <Notice tone="neutral" title="Automatic checking isn’t in this version">
          <Text variant="small">Android blocks apps installed outside Google Play from reading notifications, so this version leaves that part out. Paste a message below: it runs the same checks on this phone that automatic protection uses.</Text>
        </Notice>
        <SampleChecker initialText={typeof params.sample === 'string' ? params.sample : ''} />
        <ThreatListLine info={threatList} />
      </Screen>
    );
  }

  return (
    <Screen>
      {notice ? <Notice tone="warning">{notice}</Notice> : null}

      {state === 'needs_access' ? (
        <AccessExplainer onOpen={openSettings} />
      ) : (
        <Card>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.md }}>
            <View style={{ flex: 1 }}>
              <Text variant="subheading">Check new notifications</Text>
              <Text variant="small" muted>{PROTECTION_STATE_LABEL[state]}</Text>
            </View>
            <Switch value={status.enabled} onValueChange={setEnabled} label="Check new notifications" />
          </View>
          {state === 'connecting' ? (
            <Notice tone="warning" title="Android hasn’t started protection yet">
              <Text variant="small">This usually sorts itself out within a few seconds. If it doesn’t, turn notification access off and on again.</Text>
              <View style={{ flexDirection: 'row', gap: t.space.sm, marginTop: t.space.sm }}>
                <Button kind="secondary" title="Check again" onPress={refresh} />
                <Button kind="ghost" title="Open settings" onPress={openSettings} />
              </View>
            </Notice>
          ) : null}
          {state === 'needs_notifications' ? (
            <Notice tone="warning" title="Warnings can’t be shown">
              <Text variant="small">Authentik is checking notifications but isn’t allowed to post its own, so you won’t see warnings until you open the app.</Text>
              <Button kind="secondary" title="Allow warnings" onPress={() => void allowWarnings()} style={{ marginTop: t.space.sm }} />
            </Notice>
          ) : null}
          {state === 'active' ? (
            <Text variant="small" muted>Notification text is checked on this phone and isn’t sent anywhere.</Text>
          ) : null}
          <ThreatListLine info={threatList} />
        </Card>
      )}

      <Section title="Recent warnings">
        {warnings.length === 0 ? (
          <EmptyState title="No warnings" body="When a notification looks like a scam, the warning appears here and in your notification shade." />
        ) : (
          <>
            <View style={{ borderWidth: 1, borderColor: t.colors.outlineVariant, borderRadius: t.radius.lg, overflow: 'hidden' }}>
              {warnings.map((w, i) => <WarningRow key={w.id} warning={w} divider={i < warnings.length - 1} />)}
            </View>
            <Button kind="ghost" title="Clear all warnings" onPress={clear} />
          </>
        )}
      </Section>

      <SampleChecker initialText={typeof params.sample === 'string' ? params.sample : ''} />

      <Section title="What it can’t see">
        <Card>
          <Text variant="small">• Messages inside apps that aren’t shown in a notification.</Text>
          <Text variant="small">• Whether money actually arrived. A “payment received” notification is only a claim. Always check your own banking app.</Text>
          <Text variant="small">• New scam sites that aren’t on the threat list yet. A link that isn’t listed isn’t proven safe.</Text>
        </Card>
      </Section>
    </Screen>
  );
}

function WarningRow({ warning: w, divider }: { warning: ProtectionWarning; divider: boolean }) {
  const t = useTheme();
  const router = useRouter();
  return (
    <ListItem
      icon={w.verdict === 'high_risk' ? 'warning-amber' : 'error-outline'}
      iconColor={verdictColors(t.colors, w.verdict).solid}
      headline={w.headline}
      supporting={`${w.appLabel} · ${relativeTime(w.postedAt)}`}
      trailing={<Icon name="chevron-right" />}
      onPress={() => router.push({ pathname: '/warning/[id]', params: { id: w.id } })}
      divider={divider}
    />
  );
}

function ThreatListLine({ info }: { info: ThreatListInfo | null }) {
  const t = useTheme();
  if (!info) return null;
  const text = !info.fetchedAt
    ? 'Threat list not downloaded yet. Links can’t be checked offline until it is.'
    : info.fresh
      ? `Threat list updated ${relativeTime(new Date(info.fetchedAt).toISOString())} · ${info.entries.toLocaleString()} known scam sites`
      : `Threat list is out of date (updated ${relativeTime(new Date(info.fetchedAt).toISOString())}). Links can be flagged but not cleared until it updates.`;
  return <Text variant="caption" color={info.fresh ? t.colors.textMuted : t.colors.warning}>{text}</Text>;
}

/** Runs the same rules on pasted text. Nothing is stored or posted. */
function SampleChecker({ initialText }: { initialText: string }) {
  const [title, setTitle] = useState('');
  const [text, setText] = useState(initialText);
  const [result, setResult] = useState<SampleAnalysis | null>(null);

  return (
    <Section title="Check a message yourself">
      <Card>
        <TextField label="Title (optional)" value={title} onChangeText={setTitle} />
        <TextField label="Message" value={text} onChangeText={setText} placeholder="Paste the message here" multiline style={{ minHeight: 88, textAlignVertical: 'top' }} />
        <Button
          kind="secondary"
          title="Check this text"
          disabled={!text.trim()}
          onPress={() => setResult(AuthentikProtection?.analyzeSample(title, text) ?? null)}
        />
        <Text variant="caption" muted>Checked on this phone only. Nothing is saved.</Text>
      </Card>
      {result ? (
        <Card>
          <VerdictBadge verdict={result.verdict} subject="notification" />
          {result.shouldWarn ? (
            <>
              <Text variant="subheading">{result.headline}</Text>
              {result.reasons.map((r) => <Text key={r.code} variant="small">• {r.title}: {r.reason}</Text>)}
              <Text variant="small" muted>{result.recommendedAction}</Text>
            </>
          ) : (
            <Text variant="small" muted>
              {result.verdict === 'inconclusive'
                ? 'Nothing stood out, but the link in it couldn’t be checked against a current threat list.'
                : 'Nothing in the text matched a known scam pattern. That doesn’t prove it’s genuine.'}
            </Text>
          )}
          {result.linkHosts.length > 0 ? (
            <OnlineCheck
              key={result.linkHosts.join(',') + result.reasons.map((r) => r.code).join(',')}
              request={{
                packageName: 'app.authentik.pasted',
                findingCodes: result.reasons.map((r) => r.code),
                linkHosts: result.linkHosts.slice(0, 5),
                localRulesVersion: result.rulesVersion,
              }}
            />
          ) : null}
        </Card>
      ) : null}
    </Section>
  );
}
