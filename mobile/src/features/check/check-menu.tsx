import { useState } from 'react';
import { Image, Modal, Pressable, View } from 'react-native';
import { useRouter, type Href } from 'expo-router';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Button, ListItem, Text, type IconName } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { useProtection } from '@/features/protection/use-protection';

const BRAND_MARK = require('../../../assets/brand-mark.png');

/**
 * The raised centre tab: the app's main job ("check before you trust") one tap away on every
 * tab. It isn't a destination; it opens a short menu of the three manual checks.
 */
export function CheckTabButton() {
  const t = useTheme();
  const c = t.colors;
  const [open, setOpen] = useState(false);
  return (
    <View style={{ flex: 1, alignItems: 'center' }}>
      <Pressable
        onPress={() => setOpen(true)}
        accessibilityRole="button"
        accessibilityLabel="Check something"
        accessibilityHint="Choose a link, a message or a payment to check"
        style={({ pressed }) => ({
          marginTop: -26,
          width: 60,
          height: 60,
          borderRadius: 30,
          borderWidth: 4,
          borderColor: c.surface,
          backgroundColor: c.primary,
          alignItems: 'center',
          justifyContent: 'center',
          elevation: 4,
          shadowColor: '#0B1220',
          shadowOpacity: 0.22,
          shadowRadius: 6,
          shadowOffset: { width: 0, height: 3 },
          opacity: pressed ? 0.9 : 1,
        })}
      >
        <Image source={BRAND_MARK} style={{ width: 28, height: 28, tintColor: c.onPrimary }} />
      </Pressable>
      <Text variant="labelMedium" color={c.onSurfaceVariant} style={{ marginTop: 0 }}>Check</Text>
      <CheckMenu open={open} onClose={() => setOpen(false)} />
    </View>
  );
}

function CheckMenu({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useTheme();
  const c = t.colors;
  const router = useRouter();
  const insets = useSafeAreaInsets();
  // The message checker runs the on-phone rules, so it needs the installed Android app.
  const canCheckMessages = useProtection().state !== 'unsupported';

  const go = (href: Href) => {
    onClose();
    router.push(href);
  };

  const options: { icon: IconName; title: string; body: string; href: Href }[] = [
    { icon: 'link', title: 'A link or website', body: 'Paste or type it to see if it’s known or looks fake', href: '/scan' },
    ...(canCheckMessages
      ? [{ icon: 'chat-bubble-outline' as IconName, title: 'A message', body: 'Paste an SMS or WhatsApp message', href: '/protection' as Href }]
      : []),
    { icon: 'credit-card', title: 'A payment', body: 'Who you’re paying and how much, before you pay', href: '/payment-check' },
  ];

  return (
    <Modal visible={open} transparent animationType="fade" onRequestClose={onClose} statusBarTranslucent>
      <Pressable style={{ flex: 1, backgroundColor: c.scrim }} onPress={onClose} accessibilityLabel="Close" />
      <View
        style={{
          backgroundColor: c.surfaceContainerLow,
          borderTopLeftRadius: t.radius.xxl,
          borderTopRightRadius: t.radius.xxl,
          paddingTop: t.space.sm,
          paddingBottom: insets.bottom + t.space.lg,
          gap: t.space.sm,
        }}
      >
        <View style={{ alignSelf: 'center', width: 32, height: 4, borderRadius: 2, backgroundColor: c.outline, opacity: 0.6 }} />
        <Text variant="titleLarge" accessibilityRole="header" style={{ paddingHorizontal: t.space.xl, paddingTop: t.space.md }}>
          What do you want to check?
        </Text>
        <View>
          {options.map((o, i) => (
            <ListItem key={o.title} icon={o.icon} iconColor={c.primary} headline={o.title} supporting={o.body} onPress={() => go(o.href)} divider={i < options.length - 1} />
          ))}
        </View>
        <Button kind="ghost" title="Cancel" onPress={onClose} style={{ alignSelf: 'center' }} />
      </View>
    </Modal>
  );
}
