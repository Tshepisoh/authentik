import { useState } from 'react';
import { View } from 'react-native';
import { AuthentikProtection } from '@modules/authentik-protection';
import { useAuth } from '@/features/auth/auth-context';
import { identity } from '@/features/auth/identity';
import { useProtection } from '@/features/protection/use-protection';
import { Button, FactRow, Icon, Notice, Screen, StepProgress, Text, type IconName } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';

type Step = 'intro' | 'notifications' | 'honesty';

export default function Onboarding() {
  const t = useTheme();
  const { user, completeOnboarding, refreshProfile } = useAuth();
  const protection = useProtection();
  // The notification step only appears where Android lets it work.
  const steps: Step[] = protection.state === 'unsupported' || protection.state === 'not_in_build' ?['intro', 'honesty'] : ['intro', 'notifications', 'honesty'];
  const [index, setIndex] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const step = steps[Math.min(index, steps.length - 1)]!;
  const last = index >= steps.length - 1;

  const next = async () => {
    if (!last) return setIndex(index + 1);
    setBusy(true);
    setError(null);
    try {
      await completeOnboarding();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen edges={['top', 'bottom']}>
      <View style={{ paddingTop: t.space.md }}>
        <StepProgress step={index + 1} total={steps.length} />
      </View>

      {step === 'intro' ? <Intro /> : null}
      {step === 'notifications' ? <NotificationStep granted={protection.state !== 'needs_access'} /> : null}
      {step === 'honesty' ? <Honesty /> : null}

      {last && user && !user.emailVerified ? (
        <Notice tone="warning" title="Verify your email">
          <Text variant="bodyMedium">We sent a verification link to {user.email}. Verifying lets you recover your account.</Text>
          <View style={{ flexDirection: 'row', gap: t.space.sm, marginTop: t.space.sm, flexWrap: 'wrap' }}>
            <Button kind="tonal" title="Resend" onPress={() => void identity.resendVerification()} />
            <Button kind="ghost" title="I’ve verified" onPress={async () => { await identity.reload(); await refreshProfile(); }} />
          </View>
        </Notice>
      ) : null}
      {error ? <Notice tone="danger">{error}</Notice> : null}

      <View style={{ gap: t.space.sm }}>
        {step === 'notifications' && protection.state === 'needs_access' ? (
          <>
            <Button title="Turn on in Android settings" onPress={() => AuthentikProtection?.openNotificationAccessSettings()} />
            <Button kind="ghost" title="Not now" onPress={() => void next()} />
            <Text variant="bodySmall" muted style={{ textAlign: 'center' }}>
              Find “Authentik fraud protection” and switch it on. Android shows a warning there. That’s expected.
            </Text>
          </>
        ) : (
          <View style={{ flexDirection: 'row', gap: t.space.sm }}>
            {index > 0 ? <Button kind="secondary" title="Back" onPress={() => setIndex(index - 1)} style={{ flex: 1 }} /> : null}
            <Button title={last ? 'Get started' : 'Next'} loading={busy} onPress={() => void next()} style={{ flex: 2 }} />
          </View>
        )}
      </View>
    </Screen>
  );
}

function Heading({ title, body }: { title: string; body: string }) {
  const t = useTheme();
  return (
    <View style={{ gap: t.space.sm }}>
      <Text variant="headlineMedium">{title}</Text>
      <Text variant="bodyLarge" muted>{body}</Text>
    </View>
  );
}

function Intro() {
  const t = useTheme();
  return (
    <>
      <Heading title="Stop scams before you trust them" body="Authentik checks the messages, links and payments scammers use, and tells you plainly what it found." />
      <View style={{ gap: t.space.xl }}>
        <FactRow icon="notifications-none" title="Fake notifications" body="On Android, new notifications are checked for fake payment alerts, bank impersonation and other scams." />
        <FactRow icon="language" title="Scam websites" body="Check any link yourself, and block known scam sites in every app." />
        <FactRow icon="credit-card" title="Payment claims" body="A “payment received” message is only a claim. Authentik helps you spot fakes before you hand anything over." />
      </View>
    </>
  );
}

function NotificationStep({ granted }: { granted: boolean }) {
  const t = useTheme();
  const c = t.colors;
  return (
    <>
      <Heading title="Let Authentik check your notifications" body="Scammers send fake bank alerts and payment messages. Authentik reads new notifications and warns you before you act on a fake one." />

      <View accessible accessibilityLabel="Example: a fake Payment successful message, and Authentik's warning beneath it saying Don't release the item yet" style={{ backgroundColor: c.surfaceContainer, borderRadius: t.radius.xl, padding: t.space.lg, gap: t.space.sm }}>
        <Text variant="labelMedium" muted>Example</Text>
        <ExampleNotification icon="chat-bubble-outline" iconBg={c.surfaceContainerHighest} iconColor={c.onSurfaceVariant} app="Messages" title="Payment successful" body="You have received R4,500.00. Release the item now." />
        <ExampleNotification icon="shield" iconBg={c.danger} iconColor={t.scheme === 'dark' ? c.surface : '#FFFFFF'} app="Authentik" title="Don’t release the item yet" body="A payment message isn’t proof. Check your own banking app first." />
      </View>

      {granted ? (
        <Notice tone="ok" title="Notification protection is on">You can turn it off any time in Authentik or in Android settings.</Notice>
      ) : (
        <View style={{ gap: t.space.lg }}>
          <FactRow icon="smartphone" title="Checked on this phone" body="Notification text never leaves your phone, and only the warning is kept." />
          <FactRow icon="visibility-off" title="Only what apps show" body="Authentik sees the notification, not your chats or other apps’ screens." />
          <FactRow icon="toggle-on" title="You’re in control" body="Turn it off any time, in Authentik or in Android settings." />
        </View>
      )}
    </>
  );
}

function ExampleNotification({ icon, iconBg, iconColor, app, title, body }: { icon: IconName; iconBg: string; iconColor: string; app: string; title: string; body: string }) {
  const t = useTheme();
  return (
    <View style={{ backgroundColor: t.colors.surface, borderRadius: t.radius.lg, padding: t.space.md, flexDirection: 'row', gap: t.space.md, alignItems: 'flex-start', elevation: 1, shadowColor: '#000', shadowOpacity: 0.1, shadowRadius: 2, shadowOffset: { width: 0, height: 1 } }}>
      <View style={{ width: 32, height: 32, borderRadius: 16, backgroundColor: iconBg, alignItems: 'center', justifyContent: 'center' }}>
        <Icon name={icon} size={18} color={iconColor} />
      </View>
      <View style={{ flex: 1, gap: 2 }}>
        <Text variant="bodySmall" muted>{app} · now</Text>
        <Text variant="titleSmall">{title}</Text>
        <Text variant="bodyMedium" muted>{body}</Text>
      </View>
    </View>
  );
}

function Honesty() {
  const t = useTheme();
  return (
    <>
      <Heading title="Straight answers, and your privacy" body="Authentik tells you what it checked and what it couldn’t. It never pretends to know more than it does." />
      <View style={{ gap: t.space.xl }}>
        <FactRow icon="info-outline" title="“No obvious warnings” isn’t “safe”" body="It means nothing known turned up. New scams appear every day, and a padlock doesn’t prove a site is genuine." />
        <FactRow icon="remove-circle-outline" title="We say when we couldn’t check" body="If a check can’t run, the result is “Inconclusive”, never a silent pass." />
        <FactRow icon="lock-outline" title="We keep the minimum" body="Your email, and reports with the site name and findings. Never your passwords, card numbers or bank logins." />
      </View>
    </>
  );
}
