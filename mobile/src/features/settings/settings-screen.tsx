import { useState } from 'react';
import { Alert as RNAlert, Switch, View } from 'react-native';
import { useRouter } from 'expo-router';
import { api, ApiError } from '@/shared/api/client';
import { useAsync } from '@/shared/lib/use-async';
import { Button, Card, Loading, Notice, Row, Screen, Section, Text, TextField } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { config } from '@/shared/config';
import { useAuth } from '@/features/auth/auth-context';
import { authErrorMessage, identity } from '@/features/auth/identity';
import { enablePush, PushUnavailableError } from '@/features/alerts/notifications';

const RETENTION_OPTIONS = [7, 30, 90];

export function SettingsScreen() {
  const t = useTheme();
  const router = useRouter();
  const { user, signOut } = useAuth();
  const settings = useAsync(() => api.settings());
  const [notice, setNotice] = useState<{ tone: 'ok' | 'warning' | 'danger'; text: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const update = async (patch: Parameters<typeof api.updateSettings>[0]) => {
    try {
      settings.setData(await api.updateSettings(patch));
    } catch (e) {
      setNotice({ tone: 'danger', text: (e as Error).message });
    }
  };

  const togglePush = async (on: boolean) => {
    setNotice(null);
    if (on) {
      try {
        await enablePush();
      } catch (e) {
        setNotice({ tone: 'warning', text: e instanceof PushUnavailableError ? e.message : 'Could not turn on push alerts.' });
        return;
      }
    }
    await update({ pushNotifications: on });
  };

  const signOutEverywhere = () =>
    RNAlert.alert('Sign out everywhere?', 'This signs you out on every device, including this one.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Sign out everywhere', style: 'destructive', onPress: async () => { await api.revokeSessions().catch(() => undefined); await signOut(); } },
    ]);

  const deleteAccount = async () => {
    setBusy(true);
    setNotice(null);
    try {
      // The API requires a recent sign-in for deletion, so confirm the password first.
      await identity.reauthenticate(password);
      await api.deleteAccount();
      await signOut();
    } catch (e) {
      setNotice({ tone: 'danger', text: e instanceof ApiError ? e.message : authErrorMessage(e) });
    } finally {
      setBusy(false);
    }
  };

  if (settings.loading && !settings.data) return <Loading label="Loading settings" />;
  const s = settings.data;

  return (
    <Screen>
      {notice ? <Notice tone={notice.tone}>{notice.text}</Notice> : null}

      <Section title="Protection">
        <Card style={{ paddingVertical: t.space.xs }}>
          <Row label="Notification protection" onPress={() => router.push('/protection')} />
          <Row label="Web protection" onPress={() => router.push('/web-protection')} />
        </Card>
      </Section>

      <Section title="Alerts">
        <Card>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.md }}>
            <View style={{ flex: 1 }}>
              <Text variant="subheading">Push notifications</Text>
              <Text variant="small" muted>Only for serious findings. Notifications never include the full link or payment details.</Text>
            </View>
            <Switch value={!!s?.pushNotifications} onValueChange={togglePush} accessibilityLabel="Push notifications" />
          </View>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.md }}>
            <View style={{ flex: 1 }}>
              <Text variant="subheading">Show website name</Text>
              <Text variant="small" muted>Include the site’s name in notifications. Off keeps them generic on your lock screen.</Text>
            </View>
            <Switch value={!!s?.showDomainInNotifications} onValueChange={(v) => update({ showDomainInNotifications: v })} disabled={!s?.pushNotifications} accessibilityLabel="Show website name in notifications" />
          </View>
        </Card>
      </Section>

      <Section title="Report history">
        <Card>
          <Text variant="small" muted>Keep reports for</Text>
          <View style={{ flexDirection: 'row', gap: t.space.sm }}>
            {RETENTION_OPTIONS.map((d) => (
              <Button key={d} kind={s?.reportRetentionDays === d ? 'primary' : 'secondary'} title={`${d} days`} onPress={() => update({ reportRetentionDays: d })} style={{ flex: 1 }} />
            ))}
          </View>
          <Text variant="caption" muted>Applies to new reports. Existing reports keep their original expiry.</Text>
        </Card>
      </Section>

      <Section title="Account">
        <Card style={{ paddingVertical: t.space.xs }}>
          <Row label="Signed in as" value={user?.email ?? ''} />
          <Row label="Privacy & data" onPress={() => router.push('/privacy')} />
          <Row label="Sign out" onPress={() => void signOut()} />
          <Row label="Sign out on all devices" onPress={signOutEverywhere} />
          <Row label="Delete account" destructive onPress={() => setDeleting(true)} />
        </Card>
      </Section>

      {deleting ? (
        <Card>
          <Text variant="subheading" color={t.colors.danger}>Delete your account</Text>
          <Text variant="small">
            This permanently deletes your profile, settings, devices, reports, alerts and Sandbox records, ends any open Sandbox session, and deletes your sign-in. It can’t be undone. Pseudonymous security logs are kept for up to 90 days.
          </Text>
          {config.authMode !== 'dev' ? (
            <TextField label="Confirm your password" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password" />
          ) : null}
          <Button kind="danger" title="Delete permanently" onPress={deleteAccount} loading={busy} disabled={config.authMode !== 'dev' && !password} />
          <Button kind="ghost" title="Cancel" onPress={() => { setDeleting(false); setPassword(''); }} />
        </Card>
      ) : null}
    </Screen>
  );
}

export function PrivacyScreen() {
  const { data, error, loading } = useAsync(() => api.privacy());
  if (loading) return <Loading label="Loading" />;
  if (error || !data) return <Screen><Notice tone="warning">{error ?? 'Unavailable.'}</Notice></Screen>;
  return (
    <Screen>
      <Section title="What we keep">
        <Card>{data.collected.map((c) => <Text key={c} variant="small">• {c}</Text>)}</Card>
      </Section>
      <Section title="What we never collect">
        <Card>{data.notCollected.map((c) => <Text key={c} variant="small">• {c}</Text>)}</Card>
      </Section>
      <Section title="Retention">
        <Card>
          <Text variant="small">Reports are kept for {data.reportRetentionDays.default} days by default (you can choose {data.reportRetentionDays.min}–{data.reportRetentionDays.max}) and then deleted automatically.</Text>
        </Card>
      </Section>
      <Section title="Deleting data">
        <Card>
          <Text variant="small">{data.deletion.reportDeletion}</Text>
          <Text variant="small">{data.deletion.accountDeletion}</Text>
          <Text variant="small">{data.deletion.auditLogs}</Text>
        </Card>
      </Section>
    </Screen>
  );
}
