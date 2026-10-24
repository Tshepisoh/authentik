import { useRouter } from 'expo-router';
import type { ReportSummary } from '@authentik/shared';
import { ListItem, VerdictBadge, type IconName } from '@/shared/ui';
import { REPORT_TYPE_LABEL, relativeTime, subjectOf } from '@/shared/lib/format';

const TYPE_ICON: Record<ReportSummary['type'], IconName> = {
  website_scan: 'link',
  payment_check: 'credit-card',
  sandbox_session: 'public',
};

export function ReportRow({ report, divider }: { report: ReportSummary; divider?: boolean }) {
  const router = useRouter();
  return (
    <ListItem
      icon={TYPE_ICON[report.type]}
      headline={report.target.hostname}
      supporting={`${REPORT_TYPE_LABEL[report.type]} · ${relativeTime(report.createdAt)}${report.completeness === 'partial' ? ' · partial' : ''}`}
      trailing={<VerdictBadge verdict={report.verdict} subject={subjectOf(report.type)} size="sm" />}
      onPress={() => router.push({ pathname: '/report/[id]', params: { id: report.id } })}
      accessibilityLabel={`${REPORT_TYPE_LABEL[report.type]} of ${report.target.hostname}, ${relativeTime(report.createdAt)}`}
      divider={divider}
    />
  );
}
