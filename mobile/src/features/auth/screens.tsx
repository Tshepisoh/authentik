import { useRef, useState, type ComponentRef } from 'react';
import { TextInput, View } from 'react-native';
import { Link, useRouter } from 'expo-router';
import { Button, Notice, Screen, Text, TextField } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { config } from '@/shared/config';
import { authErrorMessage, identity } from './identity';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function SignInScreen() {
  const t = useTheme();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<ComponentRef<typeof TextInput>>(null);

  const submit = async () => {
    if (!EMAIL_RE.test(email.trim())) return setError('Enter a valid email address.');
    if (config.authMode !== 'dev' && !password) return setError('Enter your password.');
    setBusy(true);
    setError(null);
    try {
      await identity.signIn(email, password);
    } catch (e) {
      setError(authErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen edges={['top', 'bottom']}>
      <View style={{ gap: t.space.sm, marginTop: t.space.xxl }}>
        <Text variant="title">Authentik</Text>
        <Text muted>Check websites, look at suspicious links safely, and catch payment tricks before you pay.</Text>
      </View>
      {config.authMode === 'dev' ? (
        <Notice tone="warning" title="Development sign-in">Any email works and no password is checked. This only works against a development server.</Notice>
      ) : null}
      <TextField label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" autoComplete="email" keyboardType="email-address" textContentType="emailAddress" returnKeyType="next" onSubmitEditing={() => passwordRef.current?.focus()} />
      <TextField ref={passwordRef} label="Password" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password" textContentType="password" returnKeyType="go" onSubmitEditing={submit} />
      {error ? <Notice tone="danger">{error}</Notice> : null}
      <Button title="Sign in" onPress={submit} loading={busy} />
      <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
        <Link href="/forgot-password"><Text color={t.colors.primary}>Forgot password?</Text></Link>
        <Link href="/register"><Text color={t.colors.primary}>Create account</Text></Link>
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
