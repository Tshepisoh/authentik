import { useState } from 'react';
import { Pressable, View } from 'react-native';
import { useRouter } from 'expo-router';
import type { PaymentCheckRequest, PaymentExtraction } from '@authentik/shared';
import { api, ApiError } from '@/shared/api/client';
import { Button, Card, Notice, Screen, Section, Text, TextField } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { money, parseAmount } from '@/shared/lib/format';
import { paymentHandoff } from './handoff';

const asField = (minor: number) => (minor / 100).toFixed(2);
const CONFIDENCE_TEXT = {
  high: 'Read clearly from the page.',
  medium: 'Read from the page — check it matches what you see.',
  low: 'We weren’t sure about this reading — check it carefully.',
} as const;

export function PaymentCheckScreen() {
  const t = useTheme();
  const router = useRouter();
  // A reading handed over from the Sandbox viewer pre-fills what the checkout shows.
  const [fromSandbox] = useState(() => paymentHandoff.take());
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [merchant, setMerchant] = useState('');
  const [amount, setAmount] = useState('');
  const [checkoutUrl, setCheckoutUrl] = useState('');
  const [recipient, setRecipient] = useState(fromSandbox?.recipientName ?? '');
  const [observedAmount, setObservedAmount] = useState(fromSandbox?.amountMinor != null ? asField(fromSandbox.amountMinor) : '');
  const [reading, setReading] = useState<PaymentExtraction | null>(fromSandbox);

  const applyReading = (r: PaymentExtraction) => {
    setReading(r);
    if (r.recipientName) setRecipient(r.recipientName);
    if (r.amountMinor != null) setObservedAmount(asField(r.amountMinor));
  };

  const readPage = async () => {
    if (!checkoutUrl.trim()) return setError('Enter the payment page address first.');
    setBusy('read');
    setError(null);
    try {
      applyReading(await api.extractPayment({ checkoutUrl: checkoutUrl.trim() }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The page could not be read. Enter the details yourself.');
    } finally {
      setBusy(null);
    }
  };

  const run = async (key: string, req: PaymentCheckRequest) => {
    setBusy(key);
    setError(null);
    try {
      const report = await api.paymentCheck(req);
      router.push({ pathname: '/report/[id]', params: { id: report.id } });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The check could not be completed.');
    } finally {
      setBusy(null);
    }
  };

  const submitManual = () => {
    const expected = parseAmount(amount);
    const observed = observedAmount ? parseAmount(observedAmount) : null;
    if (!merchant.trim()) return setError('Enter who you meant to pay.');
    if (expected === null) return setError('Enter the amount you expect to pay.');
    if (!checkoutUrl.trim() && !reading) return setError('Enter the payment page address.');
    void run('manual', {
      expected: { merchant: merchant.trim(), amountMinor: expected, currency: 'ZAR' },
      observed: {
        // A reading from the Sandbox carries its own (server-held) page address.
        checkoutUrl: checkoutUrl.trim() || undefined,
        extractionId: reading?.extractionId,
        recipientName: recipient.trim() || undefined,
        amountMinor: observed ?? undefined,
        currency: observed !== null ? (reading?.currency ?? 'ZAR') : undefined,
      },
    });
  };

  const multipleAmounts = reading && reading.amountMinor === null && reading.amountCandidates.length > 1;

  return (
    <Screen>
      <Text muted>
        Compare what you meant to pay with what the checkout shows. Authentik can read the amount and recipient from the payment page — it opens the page in its isolated browser, never on your phone.
      </Text>
      {error ? <Notice tone="danger">{error}</Notice> : null}

      <View style={{ gap: t.space.md }}>
        <Section title="What you expect">
          <TextField label="Merchant" placeholder="e.g. Takealot" value={merchant} onChangeText={setMerchant} />
          <TextField label="Amount (ZAR)" placeholder="e.g. 1 299,00" value={amount} onChangeText={setAmount} keyboardType="decimal-pad" />
        </Section>

        <Section title="What the checkout shows">
          {fromSandbox ? (
            <Card>
              <Text variant="small" muted>Payment page (from your Sandbox session)</Text>
              <Text variant="small">{fromSandbox.pageHost}</Text>
            </Card>
          ) : (
            <>
              <TextField
                label="Payment page address"
                value={checkoutUrl}
                onChangeText={(v) => {
                  setCheckoutUrl(v);
                  setReading(null);
                }}
                autoCapitalize="none"
                autoCorrect={false}
                keyboardType="url"
                hint="Copy it from the address bar on the payment page."
              />
              <Button kind="secondary" title={busy === 'read' ? 'Reading page' : 'Read details from page'} onPress={readPage} loading={busy === 'read'}
                accessibilityHint="Opens the page in Authentik's isolated browser and fills in the recipient and amount" />
            </>
          )}

          {reading ? (
            <Notice tone={reading.confidence === 'low' ? 'warning' : 'neutral'} title={`Read from ${reading.pageHost}`}>
              <Text variant="small">{CONFIDENCE_TEXT[reading.confidence]} A fake page can show false details, so compare with what your bank asks you to approve.</Text>
              {reading.notes.map((n) => <Text key={n} variant="small">• {n}</Text>)}
            </Notice>
          ) : null}

          {multipleAmounts ? (
            <View style={{ gap: t.space.xs }}>
              <Text variant="small" style={{ fontWeight: '600' }}>Which amount are you being asked to pay?</Text>
              <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: t.space.sm }}>
                {reading!.amountCandidates.map((c) => {
                  const selected = parseAmount(observedAmount) === c.amountMinor;
                  return (
                    <Pressable key={`${c.currency}${c.amountMinor}`} onPress={() => setObservedAmount(asField(c.amountMinor))} accessibilityRole="button" accessibilityState={{ selected }}
                      style={{ paddingHorizontal: 12, paddingVertical: 8, borderRadius: t.radius.pill, borderWidth: 1, borderColor: selected ? t.colors.primary : t.colors.border, backgroundColor: selected ? t.colors.surfaceAlt : t.colors.surface }}>
                      <Text variant="small">{money(c.amountMinor, c.currency)} · {c.label}</Text>
                    </Pressable>
                  );
                })}
              </View>
            </View>
          ) : null}

          <TextField label="Who is being paid" value={recipient} onChangeText={setRecipient} hint={reading ? undefined : 'The merchant or account name shown at checkout (optional).'} />
          <TextField label="Amount shown" value={observedAmount} onChangeText={setObservedAmount} keyboardType="decimal-pad" hint={reading ? undefined : 'Optional.'} />
        </Section>
        <Notice>Never enter card numbers, PINs or one-time passwords here — Authentik doesn’t need them.</Notice>
        <Button title="Check payment" onPress={submitManual} loading={busy === 'manual'} />
      </View>
    </Screen>
  );
}
