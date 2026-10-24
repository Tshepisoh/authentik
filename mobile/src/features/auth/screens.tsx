import { useRef, useState, type ComponentRef } from 'react';
import { TextInput, View } from 'react-native';
import { useRouter } from 'expo-router';
import { Button, Icon, IconButton, Notice, Screen, Text, TextField } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { config } from '@/shared/config';
import { authErrorMessage, identity } from './identity';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function SignInScreen() {
  const t = useTheme();
  const c = t.colors;
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  // Field problems sit under the field; sign-in failures (wrong password, offline) above the button.
  const [fieldError, setFieldError] = useState<{ email?: string; password?: string }>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<ComponentRef<typeof TextInput>>(null);

  const submit = async () => {
    const problems = {
      email: EMAIL_RE.test(email.trim()) ? undefined : 'Enter a valid email address.',
      password: config.authMode !== 'dev' && !password ? 'Enter your password.' : undefined,
    };
    setFieldError(problems);
    setError(null);
    if (problems.email || problems.password) return;
    setBusy(true);
    try {
      await identity.signIn(email, password);
    } catch (e) {
      setError(authErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen edges={['top', 'bottom']} fill>
      <View style={{ gap: t.space.lg, paddingTop: t.space.xxl }}>
        <View style={{ width: 64, height: 64, borderRadius: 32, backgroundColor: c.primaryContainer, alignItems: 'center', justifyContent: 'center' }}>
          <Icon name="verified-user" size={32} color={c.onPrimaryContainer} />
        </View>
        <View style={{ gap: t.space.sm }}>
          <Text variant="headlineMedium">Authentik</Text>
          <Text variant="bodyLarge" muted>Check payments, messages and links before you trust them.</Text>
        </View>
      </View>

      {config.authMode === 'dev' ? (
        <Notice tone="warning" title="Development sign-in">Any email works and no password is checked. This only works against a development server.</Notice>
      ) : null}

      <View style={{ gap: t.space.lg }}>
        <TextField
          label="Email"
          value={email}
          onChangeText={(v) => { setEmail(v); if (fieldError.email) setFieldError({ ...fieldError, email: undefined }); }}
          error={fieldError.email}
          autoCapitalize="none"
          autoComplete="email"
          keyboardType="email-address"
          textContentType="emailAddress"
          returnKeyType="next"
          onSubmitEditing={() => passwordRef.current?.focus()}
        />
        <View style={{ gap: t.space.xs }}>
          <TextField
            ref={passwordRef}
            label="Password"
            value={password}
            onChangeText={(v) => { setPassword(v); if (fieldError.password) setFieldError({ ...fieldError, password: undefined }); }}
            error={fieldError.password}
            secureTextEntry={!showPassword}
            autoCapitalize="none"
            autoComplete="current-password"
            textContentType="password"
            returnKeyType="go"
            onSubmitEditing={submit}
            trailing={
              <IconButton
                name={showPassword ? 'visibility-off' : 'visibility'}
                label={showPassword ? 'Hide password' : 'Show password'}
                onPress={() => setShowPassword(!showPassword)}
                color={c.onSurfaceVariant}
              />
            }
          />
          <Button kind="ghost" title="Forgot password?" onPress={() => router.push('/forgot-password')} style={{ alignSelf: 'flex-end', paddingHorizontal: 12 }} />
        </View>

        {error ? <Notice tone="danger">{error}</Notice> : null}

        <View style={{ gap: t.space.sm }}>
          <Button title="Sign in" onPress={submit} loading={busy} />
          <Button kind="secondary" title="Create an account" onPress={() => router.push('/register')} />
        </View>
      </View>

      <View style={{ flex: 1 }} />
      <View style={{ flexDirection: 'row', gap: t.space.sm, alignItems: 'flex-start' }}>
        <Icon name="lock-outline" size={18} color={c.onSurfaceVariant} />
        <Text variant="bodySmall" muted style={{ flex: 1 }}>Your password is handled by our sign-in provider. Authentik never sees it.</Text>
      </View>
    </Screen>
  );
}

export function RegisterScreen() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!EMAIL_RE.test(email.trim())) return setError('Enter a valid email address.');
    if (config.authMode !== 'dev') {
      if (password.length < 8 || !/\d/.test(password) || !/[A-Za-z]/.test(password)) {
        return setError('Use at least 8 characters with both letters and numbers.');
      }
      if (password !== confirm) return setError('The passwords don’t match.');
    }
    setBusy(true);
    setError(null);
    try {
      await identity.register(email, password);
    } catch (e) {
      setError(authErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen>
      <Text muted>We only ask for an email address. Your password is handled by our sign-in provider — Authentik never sees it.</Text>
      <TextField label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" autoComplete="email" keyboardType="email-address" />
      <TextField label="Password" value={password} onChangeText={setPassword} secureTextEntry autoComplete="new-password" textContentType="newPassword" hint="At least 8 characters, letters and numbers." />
      <TextField label="Confirm password" value={confirm} onChangeText={setConfirm} secureTextEntry autoComplete="new-password" />
      {error ? <Notice tone="danger">{error}</Notice> : null}
      <Button title="Create account" onPress={submit} loading={busy} />
    </Screen>
  );
}

export function ForgotPasswordScreen() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!EMAIL_RE.test(email.trim())) return setError('Enter a valid email address.');
    setBusy(true);
    setError(null);
    try {
      await identity.sendPasswordReset(email);
    } catch (e) {
      // Only network problems are surfaced; "no such account" is never revealed.
      if ((e as { code?: string }).code === 'auth/network-request-failed') {
        setError(authErrorMessage(e));
        setBusy(false);
        return;
      }
    }
    setBusy(false);
    setSent(true);
  };

  return (
    <Screen>
      {sent ? (
        <>
          <Notice tone="ok" title="Check your email">If an account exists for that address, we’ve sent a link to reset the password.</Notice>
          <Button title="Back to sign in" kind="secondary" onPress={() => router.back()} />
        </>
      ) : (
        <>
          <Text muted>Enter your account email and we’ll send you a reset link.</Text>
          <TextField label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" autoComplete="email" />
          {error ? <Notice tone="danger">{error}</Notice> : null}
          <Button title="Send reset link" onPress={submit} loading={busy} />
        </>
      )}
    </Screen>
  );
}
