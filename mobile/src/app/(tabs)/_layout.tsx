import { Tabs } from 'expo-router';
import { View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Icon, type IconName } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { useUnreviewedAlertCount } from '@/features/alerts/use-alert-count';

/** M3 navigation bar icon: the active destination sits in a 64×32 indicator pill. */
function tabIcon(name: IconName) {
  return function TabIcon({ focused }: { focused: boolean }) {
    const t = useTheme();
    return (
      <View style={{ width: 64, height: 32, borderRadius: 16, alignItems: 'center', justifyContent: 'center', backgroundColor: focused ? t.colors.secondaryContainer : 'transparent' }}>
        <Icon name={name} color={focused ? t.colors.onSecondaryContainer : t.colors.onSurfaceVariant} />
      </View>
    );
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
        tabBarActiveTintColor: t.colors.onSurface,
        tabBarInactiveTintColor: t.colors.onSurfaceVariant,
        tabBarLabelStyle: { ...t.type.labelMedium, marginTop: 4 },
        tabBarIconStyle: { height: 32 },
        tabBarItemStyle: { paddingVertical: 4 },
        tabBarStyle: {
          backgroundColor: t.colors.surfaceContainer,
          borderTopWidth: 0,
          elevation: 0,
          height: 80 + insets.bottom,
          paddingTop: 8,
          paddingBottom: insets.bottom + 8,
        },
        tabBarBadgeStyle: { backgroundColor: t.colors.danger, color: t.scheme === 'dark' ? '#690005' : '#FFFFFF', fontSize: 11 },
        sceneStyle: { backgroundColor: t.colors.surface },
      }}
    >
      <Tabs.Screen name="index" options={{ title: 'Home', headerTitle: 'Authentik', tabBarIcon: tabIcon('home') }} />
      <Tabs.Screen name="history" options={{ title: 'Activity', tabBarIcon: tabIcon('history') }} />
      <Tabs.Screen
        name="alerts"
        options={{ title: 'Alerts', tabBarIcon: tabIcon('notifications-none'), tabBarBadge: unreviewed > 0 ? unreviewed : undefined }}
      />
      <Tabs.Screen name="settings" options={{ title: 'Settings', tabBarIcon: tabIcon('tune') }} />
    </Tabs>
  );
}
