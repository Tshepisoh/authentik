import type { ReactNode } from 'react';
import { Modal, View } from 'react-native';
import { IconButton, Screen, Text } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';

/**
 * Terms of Service and Privacy Policy, readable before sign-in. Drafts written from what the
 * app and backend actually do (docs/data-retention.md, SettingsService.privacyStatement());
 * update them together, and have them reviewed against POPIA and the CPA before a public launch.
 */
export const LEGAL_UPDATED = '25 October 2026';
/** Replace before publishing: the address users write to about their data or these terms. */
export const LEGAL_CONTACT = '[contact email]';

export type LegalDoc = 'terms' | 'privacy';

/**
 * Shows a legal document full screen over sign-in or register. A modal rather than a route:
 * signed-out routes are guarded, and an always-available route would become the start screen.
 */
export function LegalSheet({ doc, onClose }: { doc: LegalDoc | null; onClose: () => void }) {
  const t = useTheme();
  return (
    <Modal visible={doc !== null} animationType="slide" onRequestClose={onClose} statusBarTranslucent>
      <View style={{ flex: 1, backgroundColor: t.colors.surface }}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.xs, paddingTop: 40, paddingHorizontal: t.space.xs }}>
          <IconButton name="close" label="Close" onPress={onClose} />
          <Text variant="titleLarge" accessibilityRole="header">{doc === 'privacy' ? 'Privacy Policy' : 'Terms of Service'}</Text>
        </View>
        {doc === 'privacy' ? <PrivacyPolicyScreen /> : doc === 'terms' ? <TermsScreen /> : null}
      </View>
    </Modal>
  );
}

function Doc({ children }: { children: ReactNode }) {
  return (
    <Screen>
      <Text variant="bodySmall" muted>Last updated {LEGAL_UPDATED}</Text>
      {children}
    </Screen>
  );
}

function Part({ title, children }: { title: string; children: ReactNode }) {
  const t = useTheme();
  return (
    <View style={{ gap: t.space.sm }}>
      <Text variant="titleMedium" accessibilityRole="header">{title}</Text>
      {children}
    </View>
  );
}

function P({ children }: { children: ReactNode }) {
  return <Text variant="bodyMedium">{children}</Text>;
}

function Bullets({ items }: { items: string[] }) {
  const t = useTheme();
  return (
    <View style={{ gap: t.space.xs }}>
      {items.map((item) => (
        <View key={item} style={{ flexDirection: 'row', gap: t.space.sm }}>
          <Text variant="bodyMedium">•</Text>
          <Text variant="bodyMedium" style={{ flex: 1 }}>{item}</Text>
        </View>
      ))}
    </View>
  );
}

export function TermsScreen() {
  return (
    <Doc>
      <Part title="1. What Authentik is">
        <P>Authentik helps you spot scams. It checks websites, links, payment pages and messages, and on Android it can check new notifications and block known scam sites. By creating an account or using the app you agree to these terms.</P>
      </Part>
      <Part title="2. No guarantee">
        <P>Authentik gives warnings, not guarantees. “No obvious warnings” means our checks found nothing, not that a site, message or person is safe. New scams may not be known yet, and some checks can fail; when they do we say the result is inconclusive. Always use your own judgement before you pay, share details or hand over goods.</P>
      </Part>
      <Part title="3. Payment notifications are claims, not proof">
        <P>A notification or message saying you were paid is only a claim. Confirm every payment in your own banking app before you release goods or money.</P>
      </Part>
      <Part title="4. Your account">
        <P>Keep your sign-in details private and tell us if you think someone else is using your account. You are responsible for activity on your account. You must be 18 or older, or use Authentik with a parent or guardian’s consent.</P>
      </Part>
      <Part title="5. Acceptable use">
        <P>Don’t use Authentik to:</P>
        <Bullets items={[
          'attack, probe or overload websites, including through the safe browsing Sandbox;',
          'scan sites automatically or in bulk, or resell the results;',
          'get around rate limits, security controls or other users’ privacy;',
          'break the law or help someone commit fraud.',
        ]} />
        <P>We may limit or close accounts that break these rules.</P>
      </Part>
      <Part title="6. Permissions you choose to give">
        <P>Notification protection and web protection are optional. Each asks for its own Android permission after explaining what it sees. You can turn either off at any time in the app or in Android settings.</P>
      </Part>
      <Part title="7. Other services we rely on">
        <P>Authentik uses Google Firebase for sign-in and storage, and Google Safe Browsing and public registry data for website checks. Website warnings from Safe Browsing are advisories provided by Google, which can’t guarantee they are complete or correct.</P>
      </Part>
      <Part title="8. Wrong warnings">
        <P>If Authentik flags a legitimate site or message, tell us at {LEGAL_CONTACT} and we will review it.</P>
      </Part>
      <Part title="9. Availability and changes">
        <P>Authentik is an early version and is provided free of charge. Features may change, pause or stop. We will update these terms when things change and show the new date at the top.</P>
      </Part>
      <Part title="10. Liability">
        <P>To the extent the law allows, including the Consumer Protection Act, Authentik is not liable for losses from scams it did not detect, from decisions you make using its warnings, or from services it relies on being unavailable. Nothing in these terms limits rights you have under South African law.</P>
      </Part>
      <Part title="11. Ending your account">
        <P>You can delete your account at any time in Settings. This removes your data as described in the Privacy Policy.</P>
      </Part>
      <Part title="12. Law and contact">
        <P>These terms are governed by the laws of South Africa. Questions: {LEGAL_CONTACT}.</P>
      </Part>
    </Doc>
  );
}

export function PrivacyPolicyScreen() {
  return (
    <Doc>
      <Part title="Who we are">
        <P>Authentik is responsible for the personal information described here, under the Protection of Personal Information Act (POPIA). Contact us at {LEGAL_CONTACT}.</P>
      </Part>
      <Part title="What we collect">
        <Bullets items={[
          'Your email address and sign-in identifier. Sign-in is handled by Firebase Authentication; Authentik never sees your password.',
          'Reports from checks you run: the domain, a shortened address with private parts removed, what we found and the verdict.',
          'Alerts raised from those reports, your settings, and a notification token for each device if you turn alerts on.',
          'Security logs with a scrambled ID that can’t be read back to your account, used to prevent abuse.',
          'When you ask to check a notification’s links online: the app that posted it, the link hostnames and the warning codes. Never the notification text, and nothing is saved.',
        ]} />
      </Part>
      <Part title="What stays on your phone">
        <Bullets items={[
          'Notification text. Notification checks run on your phone and the text is never stored or sent.',
          'The websites you visit. Web protection checks site names on your phone and keeps only blocked or look-alike sites, on the phone, for up to 7 days.',
          'Fraud warnings, kept on the phone for up to 30 days. You can clear them.',
        ]} />
      </Part>
      <Part title="What we never collect">
        <Bullets items={[
          'Passwords, PINs, OTPs, banking credentials or card numbers.',
          'Full web addresses with private parts, page content or screenshots.',
          'Anything you type or view in the Sandbox; it is destroyed when the session ends.',
          'Your contacts, location or browsing history.',
        ]} />
      </Part>
      <Part title="Why we use it">
        <P>To run the checks you ask for, show your history and alerts, keep the service secure, and prevent abuse. We don’t sell your information or use it for advertising.</P>
      </Part>
      <Part title="Who we share it with">
        <Bullets items={[
          'Google Firebase, for sign-in, storage and notifications. Your stored data is kept in South Africa (Johannesburg region); sign-in may be processed outside South Africa.',
          'Google Safe Browsing receives the address being checked, without private parts, to look up known threats.',
          'Domain registries receive the domain name, to look up how old a site is.',
          'The website you check receives one visit from our server, with no cookies or details about you.',
        ]} />
      </Part>
      <Part title="How long we keep it">
        <P>Reports and alerts are deleted automatically after 30 days by default; you can choose between 1 and 90 days. Sandbox session records are kept for up to 90 days and security logs for up to 90 days. Your account details are kept until you delete your account.</P>
      </Part>
      <Part title="Your rights">
        <P>You can see, correct or delete your information. Delete reports one by one or delete your whole account in Settings; account deletion removes your profile, settings, devices, reports, alerts and Sandbox records. You can also object to processing or ask questions at {LEGAL_CONTACT}, and complain to the Information Regulator (inforegulator.org.za).</P>
      </Part>
      <Part title="Security">
        <P>Data is encrypted in transit, only our server can read stored data, and each account can only see its own reports. Suspicious links open in an isolated remote browser, never on your phone.</P>
      </Part>
      <Part title="Children">
        <P>Authentik is meant for adults. Anyone under 18 should use it only with a parent or guardian’s consent.</P>
      </Part>
      <Part title="Changes">
        <P>We will update this policy when what we collect changes, and show the new date at the top.</P>
      </Part>
    </Doc>
  );
}
