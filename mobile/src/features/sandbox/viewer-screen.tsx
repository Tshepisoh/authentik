import { useEffect, useRef, useState } from 'react';
import { Pressable, TextInput, View, type GestureResponderEvent, type LayoutChangeEvent } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useLocalSearchParams, useRouter } from 'expo-router';
import type { SandboxClientMessage, SandboxEvent, SandboxServerMessage, SandboxSessionResponse } from '@authentik/shared';
import { api, ApiError } from '@/shared/api/client';
import { wsUrl } from '@/shared/config';
import { Button, Notice, Screen, Text } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { sandboxHandoff } from './handoff';
import { paymentHandoff } from '@/features/payment-check/handoff';
import { FrameView } from './frame-view';

/** `unreachable`: the live view never connected (network, firewall) — distinct from a session that ended. */
type Status = 'connecting' | 'live' | 'reconnecting' | 'ended' | 'unreachable';

/** React Native's WebSocket takes a third options argument with headers; the DOM typings don't declare it. */
type NativeWebSocket = new (url: string, protocols: string[], options: { headers: Record<string, string> }) => WebSocket;

const EVENT_TEXT: Partial<Record<SandboxEvent['type'], string>> = {
  blocked_destination: 'Blocked a connection to a prohibited destination',
  download_blocked: 'Blocked a download',
  permission_denied: 'Denied a request for device access',
  popup_blocked: 'Blocked a pop-up window',
  cross_domain_redirect: 'The site moved you to a different website',
  file_chooser_blocked: 'Blocked a file upload request',
  dialog_dismissed: 'Dismissed a pop-up dialog',
};

export function SandboxViewerScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const t = useTheme();
  const [session] = useState<SandboxSessionResponse | null>(() => sandboxHandoff.take(id));
  const [frame, setFrame] = useState<string | null>(null);
  const [page, setPage] = useState<{ url: string; title: string } | null>(null);
  const [warning, setWarning] = useState<SandboxEvent | null>(null);
  const [warnings, setWarnings] = useState(0);
  const [status, setStatus] = useState<Status>('connecting');
  const [text, setText] = useState('');
  const [closing, setClosing] = useState(false);
  const [readingPayment, setReadingPayment] = useState(false);
  const [paymentError, setPaymentError] = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const box = useRef({ width: 1, height: 1 });
  const gesture = useRef<{ x: number; y: number; lastY: number } | null>(null);

  // Connect (and reconnect once on a dropped connection) to the stream.
  useEffect(() => {
    if (!session) return;
    let attempts = 0;
    let cancelled = false;
    let connectedOnce = false;
    const open = () => {
      // React Native's WebSocket accepts headers, so the view token never appears in a URL.
      const sock = new (WebSocket as unknown as NativeWebSocket)(wsUrl(session.streamPath), ['authentik.v1'], {
        headers: { Authorization: `Bearer ${session.viewToken}` },
      });
      ws.current = sock;
      sock.onopen = () => {
        connectedOnce = true;
        attempts = 0;
        setStatus('live');
      };
      sock.onmessage = (e) => {
        let msg: SandboxServerMessage;
        try {
          msg = JSON.parse(String(e.data));
        } catch {
          return;
        }
        if (msg.type === 'frame') setFrame(msg.data);
        else if (msg.type === 'navigated') setPage({ url: msg.url, title: msg.title });
        else if (msg.type === 'event' && msg.event.severity !== 'info') {
          setWarning(msg.event);
          setWarnings((n) => n + 1);
        } else if (msg.type === 'closed') {
          cancelled = true;
          setStatus('ended');
        }
      };
      sock.onclose = (e) => {
        if (cancelled || e.code === 4401 || e.code === 1000) {
          setStatus('ended');
          return;
        }
        if (attempts++ < 2) {
          setStatus(connectedOnce ? 'reconnecting' : 'connecting');
          setTimeout(open, 1000 * attempts);
        } else setStatus(connectedOnce ? 'ended' : 'unreachable');
      };
    };
    open();
    return () => {
      cancelled = true;
      ws.current?.close();
    };
  }, [session]);

  // Countdown to the server-side expiry.
  useEffect(() => {
    if (!session) return;
    const tick = () => setRemaining(Math.max(0, Math.round((new Date(session.expiresAt).getTime() - Date.now()) / 1000)));
    tick();
    const h = setInterval(tick, 1000);
    return () => clearInterval(h);
  }, [session]);

  const send = (m: SandboxClientMessage) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(JSON.stringify(m));
  };
  const scale = (e: GestureResponderEvent) => ({
    x: (e.nativeEvent.locationX / box.current.width) * (session?.viewport.width ?? 390),
    y: (e.nativeEvent.locationY / box.current.height) * (session?.viewport.height ?? 844),
  });

  // Reads the checkout the user has browsed to in the Sandbox and opens a pre-filled payment check.
  const checkPayment = async () => {
    setReadingPayment(true);
    setPaymentError(null);
    try {
      paymentHandoff.put(await api.extractPayment({ sandboxSessionId: id }));
      router.push('/payment-check');
    } catch (e) {
      setPaymentError(e instanceof ApiError ? e.message : 'The page could not be read.');
    } finally {
      setReadingPayment(false);
    }
  };

  const close = async () => {
    setClosing(true);
    try {
      const report = await api.closeSandbox(id);
      router.replace({ pathname: '/report/[id]', params: { id: report.id } });
    } catch {
      router.replace('/history');
    }
  };

  if (!session) {
    return (
      <Screen edges={['top', 'bottom']}>
        <Notice tone="warning" title="Session not available">For your security, a Sandbox session can only be viewed from the screen that started it. Start a new one.</Notice>
        <Button title="Close" onPress={() => router.replace('/')} />
      </Screen>
    );
  }

  const ratio = session.viewport.width / session.viewport.height;
  const host = page ? safeHost(page.url) : '';

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: t.colors.bg }} edges={['top', 'bottom']}>
      <View style={{ flexDirection: 'row', alignItems: 'center', paddingHorizontal: t.space.md, paddingVertical: t.space.sm, gap: t.space.sm }}>
        <View style={{ flex: 1 }}>
          <Text variant="caption" color={t.colors.ok}>● Isolated remote browser{status === 'reconnecting' ? ' · reconnecting' : ''}</Text>
          <Text variant="small" numberOfLines={1}>{host || session.scan.target.hostname}</Text>
        </View>
        {remaining !== null ? <Text variant="caption" muted accessibilityLabel={`${Math.ceil(remaining / 60)} minutes left`}>{fmt(remaining)}</Text> : null}
        <Button kind="danger" title="End" onPress={close} loading={closing} accessibilityHint="Ends the session, destroys the remote browser and shows the report" />
      </View>

      {warning ? (
        <Pressable onPress={() => setWarning(null)} accessibilityRole="button" accessibilityHint="Dismiss warning" style={{ paddingHorizontal: t.space.md }}>
          <Notice tone={warning.severity === 'critical' ? 'danger' : 'warning'} title={EVENT_TEXT[warning.type] ?? 'Security event'}>
            {`${warning.target ? `${warning.target} · ` : ''}${warnings > 1 ? `${warnings} events so far · ` : ''}Tap to dismiss`}
          </Notice>
        </Pressable>
      ) : null}

      <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: t.space.sm }}>
        <View
          onLayout={(e: LayoutChangeEvent) => { box.current = e.nativeEvent.layout; }}
          style={{ width: '100%', maxHeight: '100%', aspectRatio: ratio, backgroundColor: t.colors.surfaceAlt, borderRadius: t.radius.md, overflow: 'hidden' }}
          accessible
          accessibilityLabel={page?.title ? `Remote view of ${page.title}` : 'Remote view of the website'}
          onStartShouldSetResponder={() => status === 'live'}
          onMoveShouldSetResponder={() => status === 'live'}
          onResponderGrant={(e) => { gesture.current = { x: e.nativeEvent.locationX, y: e.nativeEvent.locationY, lastY: e.nativeEvent.locationY }; }}
          onResponderMove={(e) => {
            const g = gesture.current;
            if (!g) return;
            const dy = g.lastY - e.nativeEvent.locationY;
            if (Math.abs(dy) > 12) {
              send({ type: 'scroll', dx: 0, dy: (dy / box.current.height) * session.viewport.height });
              g.lastY = e.nativeEvent.locationY;
            }
          }}
          onResponderRelease={(e) => {
            const g = gesture.current;
            gesture.current = null;
            if (g && Math.abs(e.nativeEvent.locationX - g.x) < 8 && Math.abs(e.nativeEvent.locationY - g.y) < 8) send({ type: 'tap', ...scale(e) });
          }}
        >
          {frame ? (
            <FrameView frame={frame} />
          ) : (
            <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: t.space.lg, gap: t.space.sm }}>
              {status === 'unreachable' ? (
                <>
                  <Text variant="subheading" style={{ textAlign: 'center' }}>Couldn’t connect to the live view</Text>
                  <Text muted variant="small" style={{ textAlign: 'center' }}>
                    The isolated browser started, but your phone couldn’t reach its stream. Check you’re on the same network as the Authentik server, then end the session and try again.
                  </Text>
                </>
              ) : (
                <Text muted>{status === 'ended' ? 'Session ended' : 'Starting isolated browser…'}</Text>
              )}
            </View>
          )}
        </View>
      </View>

      {status === 'ended' || status === 'unreachable' ? (
        <View style={{ padding: t.space.md }}>
          <Button title="View report" onPress={close} loading={closing} />
        </View>
      ) : (
        <View style={{ padding: t.space.md, gap: t.space.sm }}>
          <View style={{ flexDirection: 'row', gap: t.space.sm }}>
            <TextInput
              value={text}
              onChangeText={setText}
              placeholder="Type into the page (not real details)"
              placeholderTextColor={t.colors.textMuted}
              autoCapitalize="none"
              autoCorrect={false}
              onSubmitEditing={() => { if (text) send({ type: 'type', text }); send({ type: 'key', key: 'Enter' }); setText(''); }}
              style={{ flex: 1, minHeight: 44, borderRadius: t.radius.md, borderWidth: 1, borderColor: t.colors.border, color: t.colors.text, paddingHorizontal: t.space.md, backgroundColor: t.colors.surface }}
              accessibilityLabel="Text to type into the remote page"
            />
            <Button kind="secondary" title="Send" onPress={() => { if (text) send({ type: 'type', text }); setText(''); }} />
          </View>
          <View style={{ flexDirection: 'row', gap: t.space.sm }}>
            <Button kind="secondary" title="‹ Back" onPress={() => send({ type: 'back' })} style={{ flex: 1 }} />
            <Button kind="secondary" title="Forward ›" onPress={() => send({ type: 'forward' })} style={{ flex: 1 }} />
            <Button kind="secondary" title="Reload" onPress={() => send({ type: 'reload' })} style={{ flex: 1 }} />
          </View>
          <Button
            title={readingPayment ? 'Reading payment page' : 'Check this payment'}
            onPress={checkPayment}
            loading={readingPayment}
            disabled={status !== 'live'}
            accessibilityHint="Reads the amount and recipient from the page you are viewing and opens a payment check"
          />
          {paymentError ? <Text variant="small" color={t.colors.danger}>{paymentError}</Text> : null}
        </View>
      )}
    </SafeAreaView>
  );
}

function safeHost(u: string) {
  try {
    return new URL(u).hostname;
  } catch {
    return '';
  }
}
const fmt = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
