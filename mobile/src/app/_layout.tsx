import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { View } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { AuthProvider, useAuth } from '@/features/auth/auth-context';
import { useNotificationRouting } from '@/features/alerts/notifications';
import { useSharedLinks } from '@/features/protection/use-shared-links';
import { Loading, Notice, Button, Screen } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <AuthProvider>
        <Navigator />
      </AuthProvider>
    </SafeAreaProvider>
  );
}

function Navigator() {
  const { initializing, user, profile, profileError, refreshProfile } = useAuth();
  const t = useTheme();
  useNotificationRouting(!!user);
  useSharedLinks(!!user && !!profile?.onboardingCompletedAt);

  // Signed in but the profile hasn't arrived yet (e.g. just after sign-in): no route is valid in
  // that moment, so wait rather than render a navigator with every screen guarded off.
  if (initializing || (user && !profile && !profileError)) {
    return (
      <View style={{ flex: 1, justifyContent: 'center', backgroundColor: t.colors.bg }}>
        <Loading label="Starting Authentik" />
      </View>
    );
  }
  if (user && !profile && profileError) {
    return (
      <Screen edges={['top', 'bottom']}>
        <Notice tone="warning" title="Can’t reach Authentik">{profileError}</Notice>
        <Button title="Try again" onPress={() => void refreshProfile()} />
      </Screen>
    );
  }

  const signedIn = !!user && !!profile;
  const onboarded = !!profile?.onboardingCompletedAt;

  return (
    <>
      <StatusBar style={t.scheme === 'dark' ? 'light' : 'dark'} />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: t.colors.surface },
          headerTintColor: t.colors.onSurface,
          headerTitleStyle: { ...t.type.titleLarge },
          headerShadowVisible: false,
          contentStyle: { backgroundColor: t.colors.surface },
        }}
      >
        <Stack.Protected guard={!user}>
          <Stack.Screen name="sign-in" options={{ headerShown: false }} />
          <Stack.Screen name="register" options={{ title: '' }} />
          <Stack.Screen name="forgot-password" options={{ title: 'Reset password' }} />
        </Stack.Protected>

        <Stack.Protected guard={signedIn && !onboarded}>
          <Stack.Screen name="onboarding" options={{ headerShown: false }} />
        </Stack.Protected>

        <Stack.Protected guard={signedIn && onboarded}>
          <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
          <Stack.Screen name="scan" options={{ title: 'Check a website' }} />
          <Stack.Screen name="report/[id]" options={{ title: 'Report' }} />
          <Stack.Screen name="sandbox/index" options={{ title: 'Open in Sandbox' }} />
          <Stack.Screen name="sandbox/[id]" options={{ headerShown: false, gestureEnabled: false }} />
          <Stack.Screen name="payment-check" options={{ title: 'Check a payment' }} />
          <Stack.Screen name="privacy" options={{ title: 'Privacy & data' }} />
          <Stack.Screen name="protection" options={{ title: 'Notification protection' }} />
          <Stack.Screen name="web-protection" options={{ title: 'Web protection' }} />
          <Stack.Screen name="warning/[id]" options={{ title: 'Warning' }} />
        </Stack.Protected>
      </Stack>
    </>
  );
}
