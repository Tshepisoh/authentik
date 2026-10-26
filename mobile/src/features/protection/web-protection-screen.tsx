import { useState } from 'react';
import { View } from 'react-native';
import { AuthentikProtection, type DnsEvent } from '@modules/authentik-protection';
import { relativeTime } from '@/shared/lib/format';
import { Button, Card, Checkbox, EmptyState, FactRow, Icon, ListItem, Notice, Screen, Section, Text } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { useWebProtection } from './use-web-protection';
import { useProtection } from './use-protection';

const NO_LOOKUPS_AFTER_MS = 2 * 60 * 1000;

/**
 * Google Play requires a disclosure for VpnService that stands on its own, says
 * what the VPN accesses and how it's used, and needs an affirmative action.
 * Keep it separate from the notification-access explanation.
 */
function VpnDisclosure({ onAccept, busy }: { onAccept: () => void; busy: boolean }) {
  const t = useTheme();
  const [agreed, setAgreed] = useState(false);
  const divider = { height: 1, backgroundColor: t.colors.surfaceContainerHighest };
  return (
    <>
      <View style={{ gap: t.space.sm, paddingHorizontal: 4 }}>
        <Text variant="headlineMedium">Block scam sites in every app</Text>
        <Text variant="bodyLarge" muted>Web protection uses Android’s VPN feature, entirely on this phone. Here’s exactly what that means.</Text>
      </View>

      <Card variant="filled" style={{ backgroundColor: t.colors.surfaceContainerLow, borderRadius: t.radius.xl, paddingVertical: t.space.sm, gap: 0 }}>
        <View style={{ paddingVertical: t.space.md }}>
          <FactRow icon="visibility" title="What it sees" body="The names of sites that apps look up, like example.com. Not the pages, not what you type, and no other traffic." />
        </View>
        <View style={divider} />
        <View style={{ paddingVertical: t.space.md }}>
          <FactRow icon="block" title="What it does" body="Stops known scam sites from loading, and warns you about sites pretending to be a bank or payment service." />
        </View>
        <View style={divider} />
        <View style={{ paddingVertical: t.space.md }}>
          <FactRow icon="lock-outline" title="What’s kept" body="Only the sites it blocked or warned about, on this phone, for 7 days. Nothing else is recorded or sent to Authentik." />
        </View>
        <View style={divider} />
        <View style={{ paddingVertical: t.space.md }}>
          <FactRow icon="public" title="Where lookups go" body="On to your network’s usual DNS server, as they would without Authentik. If there isn’t one, or it doesn’t answer, to Cloudflare (1.1.1.1) or Google (8.8.8.8)." />
        </View>
        <View style={divider} />
        <View style={{ paddingVertical: t.space.md }}>
          <FactRow icon="info-outline" title="Good to know" body="It doesn’t hide your location or encrypt your traffic. Android allows one VPN at a time, so this replaces any other VPN you use." />
        </View>
      </Card>

      <Checkbox checked={agreed} onChange={setAgreed} label="I understand what web protection sees and agree to turn it on." />

      <View style={{ gap: t.space.sm }}>
        <Button title="Turn on" disabled={!agreed} loading={busy} onPress={onAccept} accessibilityHint="Android will ask you to allow the VPN connection." />
        <Text variant="bodySmall" muted style={{ textAlign: 'center' }}>Android will ask you to allow the connection next.</Text>
      </View>
    </>
  );
}

export function WebProtectionScreen() {
  const t = useTheme();
  const c = t.colors;
  const { status, state, events, checkedAt, refresh } = useWebProtection({ poll: true });
  const { threatList } = useProtection();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const turnOn = async () => {
    const native = AuthentikProtection;
    if (!native) return;
    setBusy(true);
    setNotice(null);
    try {
      if (!(await native.requestVpnPermission())) {
        setNotice('Android didn’t allow the VPN connection, so web protection is still off.');
        return;
      }
      native.startVpn();
    } catch (e) {
      setNotice((e as Error).message);
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const turnOff = () => {
    AuthentikProtection?.stopVpn();
    setTimeout(refresh, 500);
  };

  if (state === 'unsupported' || !status) {
    return (
      <Screen>
        <Notice tone="neutral" title="Not available here">
          <Text variant="bodyMedium">Web protection needs the installed Authentik app on Android. It isn’t available on iOS, on the web or in Expo Go.</Text>
        </Notice>
      </Screen>
    );
  }

  const running = status.running;
  const quiet = running && status.lookups === 0 && status.startedAt !== null && checkedAt - status.startedAt > NO_LOOKUPS_AFTER_MS;
  const since = status.startedAt ? new Date(status.startedAt).toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit' }) : null;

  return (
    <Screen>
      {notice ? <Notice tone="warning">{notice}</Notice> : null}

      {state === 'off' ? <VpnDisclosure onAccept={() => void turnOn()} busy={busy} /> : null}

      {state === 'stopped' ? (
        <Notice tone="warning" title="Web protection stopped">
          <Text variant="bodyMedium" color={c.onWarningContainer}>{status.lastError}</Text>
          <View style={{ flexDirection: 'row', gap: t.space.sm, marginTop: t.space.sm, flexWrap: 'wrap' }}>
            <Button kind="primary" title="Turn on again" loading={busy} onPress={() => void turnOn()} />
            <Button kind="ghost" title="Leave off" onPress={turnOff} />
          </View>
        </Notice>
      ) : null}

      {state === 'starting' ? <Notice title="Starting web protection…" /> : null}

      {running ? (
        <>
          <View accessibilityRole="summary" style={{ backgroundColor: c.okContainer, borderRadius: t.radius.xxl, padding: 20, gap: t.space.md }}>
            <View style={{ flexDirection: 'row', gap: t.space.lg, alignItems: 'center' }}>
              <View style={{ width: 56, height: 56, borderRadius: 28, backgroundColor: c.ok, alignItems: 'center', justifyContent: 'center' }}>
                <Icon name="verified-user" size={28} color={t.scheme === 'dark' ? c.surface : '#FFFFFF'} />
              </View>
              <View style={{ flex: 1, gap: 2 }}>
                <Text variant="headlineSmall" color={c.onOkContainer}>{state === 'bypassed' ? 'On, but bypassed' : 'Web protection is on'}</Text>
                {since ? <Text variant="bodyMedium" color={c.onOkContainerMuted}>On since {since}</Text> : null}
              </View>
            </View>
            <Text variant="bodyMedium" color={c.onOkContainerMuted}>
              {status.lookups.toLocaleString()} lookups checked. {status.blocked.toLocaleString()} blocked, {status.warned.toLocaleString()} {status.warned === 1 ? 'warning' : 'warnings'}.
            </Text>
          </View>

          {status.privateDnsHost ? (
            <Notice tone="warning" title="Private DNS bypasses web protection">
              <Text variant="bodyMedium" color={c.onWarningContainer}>
                Your phone sends lookups straight to {status.privateDnsHost}, so Authentik can’t check them. Set Private DNS to “Automatic” or “Off” in Settings › Network &amp; internet › Private DNS.
              </Text>
            </Notice>
          ) : null}
          {quiet && !status.privateDnsHost ? (
            <Notice tone="warning" title="No lookups seen yet">
              <Text variant="bodyMedium" color={c.onWarningContainer}>Some browsers and apps use their own secure DNS, which Authentik can’t see. Check your browser’s “secure DNS” setting.</Text>
            </Notice>
          ) : null}
          {threatList && !threatList.fresh ? (
            <Notice tone="warning" title={threatList.fetchedAt ? 'Threat list is out of date' : 'Threat list not downloaded yet'}>
              <Text variant="bodyMedium" color={c.onWarningContainer}>
                {threatList.fetchedAt ? 'Open Authentik while online to update it. Sites already on it are still blocked.' : 'Nothing can be blocked until it downloads. Open Authentik while online.'}
              </Text>
            </Notice>
          ) : null}
        </>
      ) : null}

      {state !== 'off' ? (
        <Section title="Blocked and flagged">
          {events.length === 0 ? (
            <EmptyState title="Nothing yet" body="Sites web protection blocks or warns about appear here for 7 days." />
          ) : (
            <>
              <View style={{ marginHorizontal: -t.space.lg }}>
                {events.map((e) => <EventRow key={`${e.kind}:${e.host}:${e.at}`} event={e} now={checkedAt} />)}
              </View>
              <Button kind="ghost" title="Clear this list" onPress={() => { AuthentikProtection?.clearDnsEvents(); refresh(); }} />
            </>
          )}
        </Section>
      ) : null}

      {running ? (
        <>
          <View style={{ borderWidth: 1, borderColor: c.outlineVariant, borderRadius: t.radius.lg, overflow: 'hidden' }}>
            <ListItem
              icon="autorenew"
              headline="Keep it on after a restart"
              supporting="In Android’s VPN settings, choose Authentik and turn on Always-on VPN"
              trailing={<Icon name="chevron-right" />}
              onPress={() => AuthentikProtection?.openVpnSettings()}
            />
          </View>

          <Section title="What it can’t see">
            <View style={{ gap: t.space.sm, paddingHorizontal: 4 }}>
              <Text variant="bodyMedium">Full addresses or pages, only site names. Share a link to Authentik to check the whole address.</Text>
              <Text variant="bodyMedium">Apps or browsers that use their own secure DNS, or Private DNS set to a provider.</Text>
              <Text variant="bodyMedium">Sites an app already looked up before protection started, or connects to by IP address.</Text>
              <Text variant="bodyMedium">New scam sites that aren’t on the list yet. A site that isn’t blocked isn’t proven safe.</Text>
            </View>
          </Section>

          <Button kind="secondary" title="Turn off" onPress={turnOff} />
        </>
      ) : null}
    </Screen>
  );
}

function EventRow({ event: e, now }: { event: DnsEvent; now: number }) {
  const t = useTheme();
  const c = t.colors;
  const blocked = e.kind === 'blocked';
  return (
    <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.lg, paddingHorizontal: t.space.lg, paddingVertical: t.space.md, minHeight: 72 }}>
      <View style={{ width: 40, height: 40, borderRadius: 20, backgroundColor: blocked ? c.dangerContainer : c.warningContainer, alignItems: 'center', justifyContent: 'center' }}>
        <Icon name={blocked ? 'block' : 'warning-amber'} size={20} color={blocked ? c.danger : c.warning} />
      </View>
      <View style={{ flex: 1, minWidth: 0 }}>
        <Text variant="bodyLarge" numberOfLines={1}>{e.host}</Text>
        <Text variant="bodyMedium" muted>
          {blocked ? `Blocked · ${e.detail}` : `Allowed with a warning · Imitates ${e.detail}`} · {relativeTime(new Date(e.at).toISOString(), now)}
        </Text>
      </View>
    </View>
  );
}
