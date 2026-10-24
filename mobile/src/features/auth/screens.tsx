import { useRef, useState, type ComponentRef } from 'react';
import { Image, TextInput, View } from 'react-native';
import { useRouter } from 'expo-router';
import { Button, FactRow, Icon, IconButton, Notice, Screen, Text, TextField } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { config } from '@/shared/config';
import { authErrorMessage, identity } from './identity';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// The A-check mark and the "Authentik" wordmark, white on transparent and tinted per theme.
// Rendered by mobile/.impeccable/logos/render-icons.mjs.
const BRAND_MARK = require('../../../assets/brand-mark.png');
const WORDMARK = require('../../../assets/wordmark.png');

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
    <Screen edges={['top', 'bottom']} fill background={c.authSurface}>
      <View style={{ alignItems: 'center', gap: t.space.lg, paddingTop: 56 }}>
        <Image source={BRAND_MARK} style={{ width: 72, height: 72, tintColor: c.authMark }} accessible={false} />
        <View accessible accessibilityRole="header" accessibilityLabel="Authentik">
          <Image source={WORDMARK} style={{ width: 144, height: 36, tintColor: c.authOnSurface }} />
        </View>
        <Text variant="bodyLarge" color={c.authMuted} style={{ textAlign: 'center', maxWidth: 280 }}>Check payments, messages and links before you trust them.</Text>
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
          fill={c.authField}
          outline={c.authFieldOutline}
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
            fill={c.authField}
            outline={c.authFieldOutline}
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
      <View style={{ flexDirection: 'row', gap: t.space.sm, alignItems: 'center', justifyContent: 'center' }}>
        <Icon name="lock-outline" size={16} color={c.authMuted} />
        <Text variant="bodySmall" color={c.authMuted}>Authentik never sees your password.</Text>
      </View>
    </Screen>
  );
}

/** Live password requirements: a filled check when met, an empty circle until then. */
function Requirement({ met, label }: { met: boolean; label: string }) {
  const t = useTheme();
  return (
    <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.sm }} accessible accessibilityLabel={`${label}: ${met ? 'done' : 'not yet'}`}>
      <Icon name={met ? 'check-circle' : 'radio-button-unchecked'} size={18} color={met ? t.colors.ok : t.colors.onSurfaceVariant} />
      <Text variant="bodyMedium" muted={!met}>{label}</Text>
    </View>
  );
}

export function RegisterScreen() {
  const t = useTheme();
  const c = t.colors;
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [fieldError, setFieldError] = useState<{ email?: string; password?: string; confirm?: string }>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<ComponentRef<typeof TextInput>>(null);
  const confirmRef = useRef<ComponentRef<typeof TextInput>>(null);

  const checkPassword = config.authMode !== 'dev';
  const longEnough = password.length >= 8;
  const lettersAndNumbers = /\d/.test(password) && /[A-Za-z]/.test(password);

  const submit = async () => {
    const problems = {
      email: EMAIL_RE.test(email.trim()) ? undefined : 'Enter a valid email address.',
      password: checkPassword && !(longEnough && lettersAndNumbers) ? 'Use at least 8 characters with both letters and numbers.' : undefined,
      confirm: checkPassword && password !== confirm ? 'The passwords don’t match.' : undefined,
    };
    setFieldError(problems);
    setError(null);
    if (problems.email || problems.password || problems.confirm) return;
    setBusy(true);
    try {
      await identity.register(email, password);
    } catch (e) {
      setError(authErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const clear = (field: 'email' | 'password' | 'confirm') => {
    if (fieldError[field]) setFieldError({ ...fieldError, [field]: undefined });
  };

  return (
    <Screen fill background={c.authSurface}>
      <View style={{ gap: t.space.sm }}>
        <Text variant="headlineSmall">Create your account</Text>
        <Text variant="bodyLarge" muted>An email address and a password are all we need.</Text>
      </View>

      <View style={{ gap: t.space.lg }}>
        <TextField
          label="Email"
          value={email}
          onChangeText={(v) => { setEmail(v); clear('email'); }}
          error={fieldError.email}
          fill={c.authField}
          outline={c.authFieldOutline}
          hint="We’ll send a link to confirm it, so you can recover your account."
          autoCapitalize="none"
          autoComplete="email"
          keyboardType="email-address"
          textContentType="emailAddress"
          returnKeyType="next"
          onSubmitEditing={() => passwordRef.current?.focus()}
        />

        <View style={{ gap: t.space.md }}>
          <TextField
            ref={passwordRef}
            label="Password"
            value={password}
            onChangeText={(v) => { setPassword(v); clear('password'); }}
            error={fieldError.password}
            fill={c.authField}
            outline={c.authFieldOutline}
            secureTextEntry={!showPassword}
            autoCapitalize="none"
            autoComplete="new-password"
            textContentType="newPassword"
            returnKeyType="next"
            onSubmitEditing={() => confirmRef.current?.focus()}
            trailing={
              <IconButton
                name={showPassword ? 'visibility-off' : 'visibility'}
                label={showPassword ? 'Hide passwords' : 'Show passwords'}
                onPress={() => setShowPassword(!showPassword)}
                color={c.onSurfaceVariant}
              />
            }
          />
          {checkPassword ? (
            <View style={{ gap: t.space.xs, paddingLeft: 4 }}>
              <Requirement met={longEnough} label="At least 8 characters" />
              <Requirement met={lettersAndNumbers} label="Letters and numbers" />
            </View>
          ) : null}
        </View>

        <TextField
          ref={confirmRef}
          label="Confirm password"
          value={confirm}
          onChangeText={(v) => { setConfirm(v); clear('confirm'); }}
          error={fieldError.confirm}
          fill={c.authField}
          outline={c.authFieldOutline}
          secureTextEntry={!showPassword}
          autoCapitalize="none"
          autoComplete="new-password"
          textContentType="newPassword"
          returnKeyType="go"
          onSubmitEditing={submit}
        />

        {error ? <Notice tone="danger">{error}</Notice> : null}

        <View style={{ gap: t.space.sm }}>
          <Button title="Create account" onPress={submit} loading={busy} />
          <Button kind="ghost" title="I already have an account" onPress={() => router.back()} />
        </View>
      </View>

      <View style={{ flex: 1 }} />
      <View style={{ flexDirection: 'row', gap: t.space.sm, alignItems: 'flex-start' }}>
        <Icon name="lock-outline" size={18} color={c.authMuted} />
        <Text variant="bodySmall" color={c.authMuted} style={{ flex: 1 }}>Your password is handled by our sign-in provider. Authentik never sees it.</Text>
      </View>
    </Screen>
  );
}

export function ForgotPasswordScreen() {
  const t = useTheme();
  const c = t.colors;
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    if (!EMAIL_RE.test(email.trim())) return setFieldError('Enter a valid email address.');
    setFieldError(null);
    setBusy(true);
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

  if (sent) {
    return (
      <Screen background={c.authSurface}>
        <View style={{ gap: t.space.lg, paddingTop: t.space.lg }}>
          <View style={{ width: 64, height: 64, borderRadius: 32, backgroundColor: c.primaryContainer, alignItems: 'center', justifyContent: 'center' }}>
            <Icon name="mark-email-read" size={32} color={c.onPrimaryContainer} />
          </View>
          <View style={{ gap: t.space.sm }}>
            <Text variant="headlineSmall">Check your email</Text>
            {/* Worded the same whether or not the account exists, so the screen can't be used to test addresses. */}
            <Text variant="bodyLarge" muted>If there’s an Authentik account for {email.trim()}, we’ve sent it a link to choose a new password.</Text>
          </View>
        </View>
        <View style={{ gap: t.space.md }}>
          <FactRow icon="schedule" title="It can take a few minutes" body="Check your spam or junk folder if it hasn’t arrived." />
          <FactRow icon="open-in-browser" title="The link opens in your browser" body="Set your new password there, then come back and sign in." />
        </View>
        <View style={{ gap: t.space.sm }}>
          <Button title="Back to sign in" onPress={() => router.back()} />
          <Button kind="ghost" title="Use a different email" onPress={() => setSent(false)} />
        </View>
      </Screen>
    );
  }

  return (
    <Screen background={c.authSurface}>
      <View style={{ gap: t.space.sm }}>
        <Text variant="headlineSmall">Reset your password</Text>
        <Text variant="bodyLarge" muted>Enter the email you signed up with. We’ll send you a link to choose a new password.</Text>
      </View>
      <View style={{ gap: t.space.lg }}>
        <TextField
          label="Email"
          value={email}
          onChangeText={(v) => { setEmail(v); if (fieldError) setFieldError(null); }}
          error={fieldError}
          fill={c.authField}
          outline={c.authFieldOutline}
          autoCapitalize="none"
          keyboardType="email-address"
          autoComplete="email"
          textContentType="emailAddress"
          returnKeyType="send"
          onSubmitEditing={submit}
        />
        {error ? <Notice tone="danger">{error}</Notice> : null}
        <View style={{ gap: t.space.sm }}>
          <Button title="Send reset link" onPress={submit} loading={busy} />
          <Button kind="ghost" title="Back to sign in" onPress={() => router.back()} />
        </View>
      </View>
    </Screen>
  );
}
