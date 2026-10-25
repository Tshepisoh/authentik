import { Tabs } from 'expo-router';
import type { ColorValue } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Icon, type IconName } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { useUnreviewedAlertCount } from '@/features/alerts/use-alert-count';
import { CheckTabButton } from '@/features/check/check-menu';

function tabIcon(name: IconName) {
  return function TabIcon({ color }: { color: ColorValue }) {
    return <Icon name={name} color={color as string} />;
  };
}

export default function TabsLayout() {
  const t = useTheme();
  const insets = useSafeAreaInsets();
  const unreviewed = useUnreviewedAlertCount();
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: t.colors.surface },
        headerTintColor: t.colors.onSurface,
        headerTitleStyle: { ...t.type.titleLarge },
        headerShadowVisible: false,
        tabBarActiveTintColor: t.colors.primary,
        tabBarInactiveTintColor: t.colors.onSurfaceVariant,
        tabBarLabelStyle: { ...t.type.labelMedium },
        tabBarStyle: {
          backgroundColor: t.colors.surface,
          borderTopWidth: 1,
          borderTopColor: t.colors.outlineVariant,
          elevation: 0,
          height: 80 + insets.bottom,
          paddingTop: 8,
          paddingBottom: insets.bottom + 12,
        },
        tabBarBadgeStyle: { backgroundColor: t.colors.danger, color: t.scheme === 'dark' ? '#690005' : '#FFFFFF', fontSize: 11 },
        sceneStyle: { backgroundColor: t.colors.surface },
      }}
    >
      <Tabs.Screen name="index" options={{ title: 'Home', headerTitle: 'Authentik', tabBarIcon: tabIcon('home') }} />
      <Tabs.Screen name="history" options={{ title: 'Activity', tabBarIcon: tabIcon('history') }} />
      {/* Not a destination: the raised centre button opens the check menu. */}
      <Tabs.Screen name="check" options={{ title: 'Check', tabBarButton: () => <CheckTabButton /> }} />
      <Tabs.Screen
        name="alerts"
        options={{ title: 'Alerts', tabBarIcon: tabIcon('notifications-none'), tabBarBadge: unreviewed > 0 ? unreviewed : undefined }}
      />
      <Tabs.Screen name="settings" options={{ title: 'Settings', tabBarIcon: tabIcon('tune') }} />
    </Tabs>
  );
}
