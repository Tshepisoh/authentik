import { useCallback } from 'react';
import { Pressable, RefreshControl, ScrollView, View } from 'react-native';
import { useFocusEffect, useRouter } from 'expo-router';
import { AuthentikProtection } from '@modules/authentik-protection';
import { api } from '@/shared/api/client';
import { useAsync } from '@/shared/lib/use-async';
import { Button, ExtendedFab, Icon, ListItem, Notice, Section, Switch, Text, type IconName } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { ReportRow } from '@/features/reports/report-row';
import { useProtection } from '@/features/protection/use-protection';
import { useWebProtection } from '@/features/protection/use-web-protection';
import { PROTECTION_STATE_LABEL, relativeTime, VERDICT_LABEL, WEB_PROTECTION_STATE_LABEL } from '@/shared/lib/format';

const RECENT_WARNING_MS = 24 * 60 * 60 * 1000;

export default function Home() {
  const t = useTheme();
  const c = t.colors;
  const router = useRouter();
  const recent = useAsync(async () => (await api.reports()).slice(0, 3));
  const protection = useProtection();
  const web = useWebProtection();
  useFocusEffect(useCallback(() => { void recent.refresh(); }, [])); // eslint-disable-line react-hooks/exhaustive-deps

  const supported = protection.state !== 'unsupported';
  // The sideloaded judge APK has no notification listener, so only web protection can be on.
  const hasListener = protection.state !== 'not_in_build';
  const notifOn = ['active', 'connecting', 'needs_notifications'].includes(protection.state);
  const webOn = ['on', 'bypassed', 'starting'].includes(web.state);
  const onCount = Number(notifOn) + Number(webOn);
  const total = hasListener ? 2 : 1;
  const latest = protection.warnings[0];
  const showLatest = latest && protection.checkedAt - Date.parse(latest.postedAt) < RECENT_WARNING_MS;

  const toggleNotifications = (on: boolean) => {
    if (on && protection.state === 'needs_access') return router.push('/protection');
    AuthentikProtection?.setEnabled(on);
    protection.refresh();
  };
  const toggleWeb = (on: boolean) => {
    // Turning on always goes through the disclosure and Android's consent.
    if (on) return router.push('/web-protection');
    AuthentikProtection?.stopVpn();
    setTimeout(web.refresh, 500);
  };

  const hero = !supported
    ? { bg: c.surfaceContainerHigh, fg: c.onSurface, muted: c.onSurfaceVariant, iconBg: c.neutral, icon: 'shield' as IconName, title: 'Manual checks on this device', body: 'Automatic protection needs the Authentik app on Android. You can still check websites and payments yourself.' }
    : onCount === total
      ? { bg: c.primaryContainer, fg: c.onPrimaryContainer, muted: c.onPrimaryContainerMuted, iconBg: c.primary, icon: 'verified-user' as IconName, title: 'Protection is on', body: hasListener ? 'Checking new notifications and blocking known scam sites.' : 'Blocking known scam sites. Paste a message below to check it.' }
      : onCount === 1
        ? { bg: c.warningContainer, fg: c.onWarningContainer, muted: c.onWarningContainer, iconBg: c.warning, icon: 'gpp-maybe' as IconName, title: 'Protection is partly on', body: notifOn ? 'Notifications are checked, but scam sites aren’t blocked.' : 'Scam sites are blocked, but notifications aren’t checked.' }
        : { bg: c.surfaceContainerHigh, fg: c.onSurface, muted: c.onSurfaceVariant, iconBg: c.outline, icon: 'shield' as IconName, title: 'Protection is off', body: hasListener ? 'Turn it on so Authentik can warn you about scams automatically.' : 'Turn on web protection so Authentik can block known scam sites.' };

  const listUpdated = protection.threatList?.fetchedAt ? `Threat list updated ${relativeTime(new Date(protection.threatList.fetchedAt).toISOString(), protection.checkedAt)}.` : null;

  return (
    <View style={{ flex: 1, backgroundColor: c.surface }}>
      <ScrollView
        contentContainerStyle={{ paddingHorizontal: t.space.lg, paddingTop: t.space.xs, paddingBottom: 112, gap: t.space.xl }}
        refreshControl={<RefreshControl refreshing={recent.refreshing} onRefresh={() => { void recent.refresh(); protection.refresh(); web.refresh(); }} />}
      >
        <View accessibilityRole="summary" style={{ backgroundColor: hero.bg, borderRadius: t.radius.xxl, padding: 20, paddingBottom: t.space.lg, gap: t.space.lg }}>
          <View style={{ flexDirection: 'row', gap: t.space.lg, alignItems: 'center' }}>
            <View style={{ width: 56, height: 56, borderRadius: 28, backgroundColor: hero.iconBg, alignItems: 'center', justifyContent: 'center' }}>
              <Icon name={hero.icon} size={28} color={t.scheme === 'dark' ? c.surface : '#FFFFFF'} />
            </View>
            <View style={{ flex: 1, gap: 2 }}>
              <Text variant="headlineSmall" color={hero.fg}>{hero.title}</Text>
              {supported ? <Text variant="bodyMedium" color={hero.muted}>{onCount} of {total} protections on</Text> : null}
            </View>
          </View>
          <Text variant="bodyMedium" color={hero.muted}>{[hero.body, supported ? listUpdated : null].filter(Boolean).join(' ')}</Text>
          {supported && onCount < total ? (
            hasListener ? (
              <Button kind="primary" title={onCount === 0 ? 'Set up protection' : notifOn ? 'Turn on web protection' : 'Turn on notification protection'} onPress={() => router.push(notifOn ? '/web-protection' : '/protection')} style={{ alignSelf: 'flex-start' }} />
            ) : (
              <Button kind="primary" title="Turn on web protection" onPress={() => router.push('/web-protection')} style={{ alignSelf: 'flex-start' }} />
            )
          ) : null}
        </View>

        {showLatest ? (
          <Pressable
            onPress={() => router.push({ pathname: '/warning/[id]', params: { id: latest.id } })}
            accessibilityRole="button"
            accessibilityLabel={`Warning: ${latest.headline}. ${VERDICT_LABEL.notification[latest.verdict]}, from ${latest.appLabel}`}
            android_ripple={{ color: 'rgba(0,0,0,0.08)' }}
            style={({ pressed }) => ({ backgroundColor: c.dangerContainer, borderRadius: t.radius.lg, padding: t.space.lg, flexDirection: 'row', gap: t.space.lg, alignItems: 'center', opacity: pressed ? 0.9 : 1 })}
          >
            <Icon name="warning-amber" color={c.danger} />
            <View style={{ flex: 1, gap: 2 }}>
              <Text variant="titleMedium" color={c.onDangerContainer}>{latest.headline}</Text>
              <Text variant="bodyMedium" color={c.onDangerContainerMuted}>
                {VERDICT_LABEL.notification[latest.verdict]} · {latest.appLabel} · {relativeTime(latest.postedAt, protection.checkedAt)}
              </Text>
            </View>
            <Icon name="chevron-right" color={c.onDangerContainer} />
          </Pressable>
        ) : null}

        {supported ? (
          <Section title="Protections">
            <View style={{ borderWidth: 1, borderColor: c.outlineVariant, borderRadius: t.radius.lg, overflow: 'hidden' }}>
              <ListItem
                icon="notifications-none"
                headline="Notification protection"
                supporting={protection.state === 'active' ? 'Checks new notifications for scams' : PROTECTION_STATE_LABEL[protection.state]}
                onPress={() => router.push('/protection')}
                trailing={hasListener ? <Switch value={notifOn} onValueChange={toggleNotifications} label="Notification protection" /> : <Icon name="chevron-right" />}
                divider
              />
              <ListItem
                icon="language"
                headline="Web protection"
                supporting={web.state === 'on' ? 'Blocks known scam sites in every app' : WEB_PROTECTION_STATE_LABEL[web.state]}
                onPress={() => router.push('/web-protection')}
                trailing={<Switch value={webOn} onValueChange={toggleWeb} label="Web protection" />}
              />
            </View>
          </Section>
        ) : null}

        <Section title="Check something yourself">
          <View style={{ flexDirection: 'row', gap: t.space.sm }}>
            {supported ? (
              <QuickCheck icon="chat-bubble-outline" title="A message" body="Paste what you received" onPress={() => router.push('/protection')} />
            ) : null}
            <QuickCheck icon="credit-card" title="A payment" body="Who you’re paying, and how much" onPress={() => router.push('/payment-check')} />
          </View>
        </Section>

        <Section
          title="Recent"
          action={<Button kind="ghost" title="See all" onPress={() => router.push('/history')} style={{ paddingHorizontal: 12 }} />}
        >
          {recent.error ? <Notice tone="warning">{recent.error}</Notice> : null}
          {recent.data?.length === 0 ? <Text variant="bodyMedium" muted style={{ paddingHorizontal: 4 }}>Your checks will appear here.</Text> : null}
          <View style={{ marginHorizontal: -t.space.lg }}>
            {recent.data?.map((r) => <ReportRow key={r.id} report={r} />)}
          </View>
        </Section>
      </ScrollView>

      <ExtendedFab icon="add-link" label="Check a link" onPress={() => router.push('/scan')} style={{ position: 'absolute', right: t.space.lg, bottom: t.space.lg }} />
    </View>
  );
}

function QuickCheck({ icon, title, body, onPress }: { icon: IconName; title: string; body: string; onPress: () => void }) {
  const t = useTheme();
  return (
    <Pressable
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={`Check ${title.toLowerCase()}`}
      android_ripple={{ color: 'rgba(0,0,0,0.08)' }}
      style={({ pressed }) => ({ flex: 1, backgroundColor: t.colors.surfaceContainer, borderRadius: t.radius.lg, padding: t.space.lg, gap: t.space.md, minHeight: 112, opacity: pressed ? 0.9 : 1 })}
    >
      <Icon name={icon} color={t.colors.primary} />
      <View style={{ gap: 2 }}>
        <Text variant="titleMedium">{title}</Text>
        <Text variant="bodyMedium" muted>{body}</Text>
      </View>
    </Pressable>
  );
}
