import { useState } from 'react';
import { Alert as RNAlert } from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import type { Report } from '@authentik/shared';
import { api } from '@/shared/api/client';
import { useAsync } from '@/shared/lib/use-async';
import { Button, Card, Loading, Notice, Screen, Section, Text } from '@/shared/ui';
import { AssessmentView } from './assessment-view';
import { dateTime, money, subjectOf } from '@/shared/lib/format';

export function ReportScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const { data: report, error, loading } = useAsync(() => api.report(id), [id]);
  const [showDetail, setShowDetail] = useState(false);

  if (loading) return <Loading label="Loading report" />;
  if (error || !report) return <Screen><Notice tone="warning" title="Report unavailable">{error ?? 'Not found.'}</Notice></Screen>;

  const a = report.assessment;
  const subject = subjectOf(report.type);

  const confirmDelete = () =>
    RNAlert.alert('Delete this report?', 'This removes the report and any alerts raised from it. Security audit logs are kept separately.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Delete', style: 'destructive', onPress: async () => { await api.deleteReport(report.id); router.back(); } },
    ]);

  return (
    <Screen>
      <AssessmentView assessment={a} subject={subject} target={report.target.hostname} />

      {report.payment ? <PaymentSummary report={report} /> : null}

      {report.redirects.length > 1 ? (
        <Section title="Redirects observed">
          <Card>
            {report.redirects.map((h, i) => (
              <Text key={i} variant="small">{i + 1}. {h.hostname}{h.status ? ` (${h.status})` : ''}{h.crossDomain ? ' — different site' : ''}</Text>
            ))}
          </Card>
        </Section>
      ) : null}

      {report.sandbox ? (
        <Section title="Sandbox session">
          <Card>
            <Text variant="small">Sites visited: {report.sandbox.visitedHosts.join(', ')}</Text>
            <Text variant="small">Ended: {report.sandbox.endReason.replace(/_/g, ' ')}</Text>
            <Text variant="small" muted>The remote browser and all of its data were destroyed when the session ended.</Text>
          </Card>
        </Section>
      ) : null}

      <Button kind="ghost" title={showDetail ? 'Hide technical detail' : 'Show technical detail'} onPress={() => setShowDetail(!showDetail)} />
      {showDetail ? (
        <Card>
          <Text variant="small">Checked address: {report.target.displayUrl}</Text>
          {a.checks.map((c) => (
            <Text key={c.check} variant="small" muted>{c.check}: {c.status}{c.detail ? ` — ${c.detail}` : ''}</Text>
          ))}
          <Text variant="caption" muted>Rules {a.rulesVersion} · kept until {dateTime(report.expiresAt)}</Text>
        </Card>
      ) : null}

      {report.type === 'website_scan' && report.verdict !== 'blocked' ? (
        <Button kind="secondary" title="Open in Sandbox" onPress={() => router.push({ pathname: '/sandbox', params: { url: `https://${report.target.hostname}/` } })} />
      ) : null}
      <Button kind="ghost" title="Delete report" onPress={confirmDelete} />
    </Screen>
  );
}

const SOURCE_TEXT = {
  page: 'read from the payment page',
  page_confirmed: 'read from the page and confirmed by you',
  user: 'entered by you',
  none: 'not available',
} as const;

function PaymentSummary({ report }: { report: Report }) {
  const p = report.payment!;
  return (
    <Section title="Payment">
      <Card>
        <Text variant="small">Expected: {p.merchantName} · {money(p.expected.amountMinor, p.expected.currency)}</Text>
        <Text variant="small">
          Observed: {p.observedRecipient ?? 'recipient not shown'} · {p.observedAmountMinor !== null ? money(p.observedAmountMinor, p.observedCurrency ?? p.expected.currency) : 'amount not shown'}
        </Text>
        {p.paymentProvider ? <Text variant="small" muted>Processed by {p.paymentProvider}</Text> : null}
        {p.observedSource && (p.observedSource.recipient || p.observedSource.amount) ? (
          <Text variant="small" muted>
            Recipient {SOURCE_TEXT[p.observedSource.recipient ?? 'none']}; amount {SOURCE_TEXT[p.observedSource.amount ?? 'none']}.
          </Text>
        ) : null}
      </Card>
    </Section>
  );
}
