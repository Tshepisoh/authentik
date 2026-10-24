import { View } from 'react-native';
import type { Assessment, CheckRun, Finding } from '@authentik/shared';
import { Icon, Section, Text, VerdictBadge, type IconName } from '@/shared/ui';
import { useTheme, verdictColors, type Colors } from '@/shared/ui/theme';
import { checkLabel, relativeTime, type VerdictSubject } from '@/shared/lib/format';

/** Which findings a check produced, so "What we checked" can say whether it found something. */
function foundBy(check: string, findings: Finding[]): Finding[] {
  const base = check.replace(/\.destination$/, '');
  return findings.filter((f) => {
    if (f.kind !== 'confirmed_threat' && f.kind !== 'suspicious_indicator') return false;
    if (base.startsWith('reputation.')) return f.source === 'reputation' && f.data?.provider === base.slice('reputation.'.length);
    if (base === 'notification_rules') return f.source === 'notification';
    return f.source === base;
  });
}

function severityIcon(f: Finding, c: Colors): { name: IconName; color: string } {
  if (f.kind === 'reassurance') return { name: 'check-circle-outline', color: c.ok };
  if (f.severity === 'critical' || f.severity === 'high') return { name: 'warning-amber', color: c.danger };
  if (f.severity === 'medium') return { name: 'error-outline', color: c.warning };
  return { name: 'info-outline', color: c.neutral };
}

function checkRow(run: CheckRun, findings: Finding[], c: Colors) {
  if (run.status === 'completed') {
    const hits = foundBy(run.check, findings);
    return hits.length
      ? { icon: 'check-circle-outline' as IconName, iconColor: c.ok, status: 'Found something', statusColor: c.danger }
      : { icon: 'check-circle-outline' as IconName, iconColor: c.ok, status: 'Nothing found', statusColor: c.onSurfaceVariant };
  }
  return {
    icon: 'remove-circle-outline' as IconName,
    iconColor: c.neutral,
    status: run.status === 'skipped' ? 'Skipped' : 'Couldn’t check',
    statusColor: c.onSurfaceVariant,
  };
}

const sentence = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/**
 * A verdict and its evidence: what was found, every check with its honest
 * status ("Couldn't check" is never shown as a pass), and what to do.
 */
export function AssessmentView({ assessment: a, subject, target }: { assessment: Assessment; subject: VerdictSubject; target?: string }) {
  const t = useTheme();
  const c = t.colors;
  const vc = verdictColors(c, a.verdict);
  const found = a.findings.filter((f) => f.kind !== 'unknown');
  return (
    <View style={{ gap: t.space.xl }}>
      <View accessibilityLiveRegion="polite" style={{ backgroundColor: vc.bg, borderRadius: t.radius.xl, padding: 20, gap: t.space.md }}>
        <VerdictBadge verdict={a.verdict} subject={subject} strong />
        <Text variant="headlineSmall" color={vc.fg}>{a.headline}</Text>
        <Text variant="bodyMedium" color={vc.fg} style={{ opacity: 0.85 }}>
          {[target, `Checked ${relativeTime(a.assessedAt)}`].filter(Boolean).join(' · ')}
          {a.completeness === 'partial' ? ' · Some checks couldn’t run' : ''}
        </Text>
      </View>

      {found.length ? (
        <Section title="What we found">
          <View style={{ gap: t.space.lg, paddingHorizontal: 4 }}>
            {found.map((f, i) => {
              const ic = severityIcon(f, c);
              return (
                <View key={`${f.code}-${i}`} style={{ flexDirection: 'row', gap: t.space.lg, alignItems: 'flex-start' }}>
                  <View style={{ paddingTop: 2 }}><Icon name={ic.name} color={ic.color} /></View>
                  <View style={{ flex: 1, gap: 2 }}>
                    <Text variant="titleMedium">{f.title}</Text>
                    <Text variant="bodyMedium" muted>{f.reason}</Text>
                  </View>
                </View>
              );
            })}
          </View>
        </Section>
      ) : null}

      {a.checks.length ? (
        <Section title="What we checked">
          <View style={{ borderWidth: 1, borderColor: c.outlineVariant, borderRadius: t.radius.lg, overflow: 'hidden' }}>
            {a.checks.map((run, i) => {
              const row = checkRow(run, a.findings, c);
              return (
                <View
                  key={`${run.check}-${i}`}
                  accessible
                  accessibilityLabel={`${checkLabel(run.check)}: ${row.status}${run.status !== 'completed' && run.detail ? `, ${run.detail}` : ''}`}
                  style={{
                    flexDirection: 'row', alignItems: 'center', gap: t.space.lg, paddingHorizontal: t.space.lg, paddingVertical: t.space.md, minHeight: 56,
                    borderTopWidth: i ? 1 : 0, borderTopColor: c.outlineVariant,
                  }}
                >
                  <Icon name={row.icon} color={row.iconColor} />
                  <View style={{ flex: 1, minWidth: 0 }}>
                    <Text variant="bodyLarge">{checkLabel(run.check)}</Text>
                    {run.status !== 'completed' && run.detail ? <Text variant="bodyMedium" muted>{sentence(run.detail)}</Text> : null}
                  </View>
                  <Text variant="labelLarge" color={row.statusColor}>{row.status}</Text>
                </View>
              );
            })}
          </View>
        </Section>
      ) : null}

      {a.recommendedActions.length ? (
        <Section title="What to do">
          <View style={{ gap: t.space.md, paddingHorizontal: 4 }}>
            {a.recommendedActions.map((line) => <Text key={line} variant="bodyLarge">{line}</Text>)}
          </View>
        </Section>
      ) : null}
    </View>
  );
}
