import { useState } from 'react';
import { View } from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { AuthentikProtection, type ProtectionReason, type ProtectionWarning } from '@modules/authentik-protection';
import { Button, Icon, Notice, Screen, Section, Text, VerdictBadge, type IconName } from '@/shared/ui';
import { useTheme, type Colors } from '@/shared/ui/theme';
import { dateTime } from '@/shared/lib/format';
import { OnlineCheck } from './online-check';

const PAYMENT = new Set(['payment_claim', 'payment_claim_release', 'payment_claim_via_message']);
const LINK = new Set([
  'known_threat_link', 'lookalike_link', 'brand_link_mismatch', 'ip_link', 'shortened_link', 'punycode_link',
  'delivery_fee_link', 'refund_link', 'prize_link', 'verify_via_link',
]);

/** The concrete next steps, chosen by what the phone flagged. */
function stepsFor(codes: Set<string>): string[] {
  if (codes.has('credential_request')) {
    return [
      'Don’t reply, and don’t share your PIN, OTP or password with anyone.',
      'Worried about your account? Call your bank on the number on the back of your card.',
      'Never use a number or link from the message.',
    ];
  }
  if ([...codes].some((c) => PAYMENT.has(c))) {
    return [
      'Open your own banking app yourself. Don’t use a link or number from the message.',
      'Check the money shows in your available balance, not just as pending.',
      'Only then hand over the item.',
    ];
  }
  if ([...codes].some((c) => LINK.has(c))) {
    return [
      'Don’t open the link in the message.',
      'Go to the official app or website yourself.',
      'Already entered details? Call your bank on the number on your card now.',
    ];
  }
  return ['Don’t act on the message yet.', 'Contact the sender through a number or app you already trust.'];
}

function reasonIcon(r: ProtectionReason, c: Colors): { name: IconName; color: string } {
  if (r.severity === 'critical' || r.severity === 'high') return { name: 'warning-amber', color: c.danger };
  if (r.severity === 'medium') return { name: 'error-outline', color: c.warning };
  return { name: 'info-outline', color: c.neutral };
}

/** Opened from a warning notification (authentik://warning/<id>) or from a list. */
export function WarningScreen() {
  const t = useTheme();
  const c = t.colors;
  const router = useRouter();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [warning] = useState<ProtectionWarning | null>(() => AuthentikProtection?.getWarnings().find((w) => w.id === id) ?? null);

  const done = () => (router.canGoBack() ? router.back() : router.replace('/'));

  if (!warning) {
    return (
      <Screen>
        <Notice tone="neutral" title="This warning isn’t on this phone any more">
          <Text variant="bodyMedium">Warnings are kept for 30 days, or until you clear them.</Text>
        </Notice>
        <Button title="Back to home" onPress={() => router.replace('/')} />
      </Screen>
    );
  }

  const codes = new Set(warning.reasons.map((r) => r.code));
  const steps = stepsFor(codes);

  return (
    <Screen>
      <View style={{ gap: t.space.md, paddingHorizontal: 4 }}>
        <VerdictBadge verdict={warning.verdict} subject="notification" strong />
        <Text variant="headlineMedium" style={{ fontSize: 32, lineHeight: 40 }}>{warning.headline}</Text>
        <Text variant="bodyLarge" muted>{warning.recommendedAction}</Text>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.sm }}>
          <Icon name="chat-bubble-outline" size={20} />
          <Text variant="bodyMedium" muted>From {warning.appLabel} · {dateTime(warning.postedAt)}</Text>
        </View>
      </View>

      <View style={{ backgroundColor: c.dangerSurface, borderRadius: t.radius.xl, padding: 20, gap: t.space.lg }}>
        <Text variant="titleMedium" color={c.onDangerContainer} accessibilityRole="header">What to do</Text>
        {steps.map((step, i) => (
          <View key={step} style={{ flexDirection: 'row', gap: 14, alignItems: 'flex-start' }}>
            <View style={{ width: 28, height: 28, borderRadius: 14, backgroundColor: c.danger, alignItems: 'center', justifyContent: 'center' }}>
              <Text variant="labelLarge" color={t.scheme === 'dark' ? '#690005' : '#FFFFFF'}>{i + 1}</Text>
            </View>
            <Text variant="bodyLarge" color={c.onDangerContainer} style={{ flex: 1 }}>{step}</Text>
          </View>
        ))}
      </View>

      {warning.reasons.length ? (
        <Section title="What we noticed">
          <View style={{ gap: t.space.lg, paddingHorizontal: 4 }}>
            {warning.reasons.map((r) => {
              const ic = reasonIcon(r, c);
              return (
                <View key={r.code} style={{ flexDirection: 'row', gap: t.space.lg, alignItems: 'flex-start' }}>
                  <View style={{ paddingTop: 2 }}><Icon name={ic.name} color={ic.color} /></View>
                  <View style={{ flex: 1, gap: 2 }}>
                    <Text variant="titleMedium">{r.title}</Text>
                    <Text variant="bodyMedium" muted>{r.reason}</Text>
                  </View>
                </View>
              );
            })}
          </View>
        </Section>
      ) : null}

      {warning.linkHosts.length ? (
        <View style={{ borderWidth: 1, borderColor: c.outlineVariant, borderRadius: t.radius.lg, padding: t.space.lg, gap: t.space.md }}>
          <View style={{ flexDirection: 'row', gap: t.space.lg, alignItems: 'center' }}>
            <Icon name="link" />
            <View style={{ flex: 1, minWidth: 0 }}>
              <Text variant="bodyMedium" muted>{warning.linkHosts.length === 1 ? 'Link in the message' : 'Links in the message'}</Text>
              <Text variant="bodyLarge" numberOfLines={2}>{warning.linkHosts.join(', ')}</Text>
            </View>
          </View>
          <OnlineCheck
            request={{
              packageName: warning.packageName,
              findingCodes: warning.reasons.map((r) => r.code),
              linkHosts: warning.linkHosts.slice(0, 5),
              localRulesVersion: warning.rulesVersion,
            }}
          />
        </View>
      ) : null}

      <View style={{ flexDirection: 'row', gap: t.space.md, alignItems: 'flex-start', paddingHorizontal: 4 }}>
        <Icon name="lock-outline" size={20} />
        <Text variant="bodyMedium" muted style={{ flex: 1 }}>Checked on this phone. Authentik doesn’t keep the message text.</Text>
      </View>

      <View style={{ gap: t.space.sm }}>
        <Button title="Got it" onPress={done} />
        <Button
          kind="ghost"
          title="Remove this warning"
          onPress={() => {
            AuthentikProtection?.dismissWarning(warning.id);
            done();
          }}
        />
      </View>
    </Screen>
  );
}
