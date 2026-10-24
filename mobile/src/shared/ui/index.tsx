import { forwardRef, type ComponentProps, type ComponentRef, type ReactNode } from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text as RNText,
  TextInput,
  View,
  type TextInputProps,
  type TextProps,
  type ViewStyle,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import MaterialIcons from '@expo/vector-icons/MaterialIcons';
import type { Verdict } from '@authentik/shared';
import { VERDICT_LABEL, type VerdictSubject } from '../lib/format';
import { useTheme, verdictColors, type TypeRole } from './theme';

export type IconName = ComponentProps<typeof MaterialIcons>['name'];

/** Material icons. Decorative by default; pass `label` when the icon carries meaning on its own. */
export function Icon({ name, size = 24, color, label }: { name: IconName; size?: number; color?: string; label?: string }) {
  const t = useTheme();
  return (
    <MaterialIcons
      name={name}
      size={size}
      color={color ?? t.colors.onSurfaceVariant}
      accessible={!!label}
      accessibilityLabel={label}
      importantForAccessibility={label ? 'yes' : 'no-hide-descendants'}
    />
  );
}

export function Text({ variant = 'body', muted, color, style, ...rest }: TextProps & { variant?: TypeRole; muted?: boolean; color?: string }) {
  const t = useTheme();
  const header = variant === 'title' || variant === 'heading' || variant.startsWith('headline') || variant === 'displaySmall';
  return (
    <RNText
      {...rest}
      style={[t.type[variant], { color: color ?? (muted ? t.colors.onSurfaceVariant : t.colors.onSurface) }, style]}
      accessibilityRole={header ? 'header' : rest.accessibilityRole}
    />
  );
}

export function Screen({ children, scroll = true, padded = true, edges = ['bottom'], refreshControl }: {
  children: ReactNode;
  scroll?: boolean;
  padded?: boolean;
  edges?: ('top' | 'bottom')[];
  refreshControl?: ComponentProps<typeof ScrollView>['refreshControl'];
}) {
  const t = useTheme();
  const content = padded ? { paddingHorizontal: t.space.lg, paddingTop: t.space.sm, gap: t.space.xl } : undefined;
  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: t.colors.surface }} edges={edges}>
      {scroll ? (
        <ScrollView contentContainerStyle={[content, { paddingBottom: t.space.xxl }]} keyboardShouldPersistTaps="handled" refreshControl={refreshControl}>
          {children}
        </ScrollView>
      ) : (
        <View style={[{ flex: 1 }, content]}>{children}</View>
      )}
    </SafeAreaView>
  );
}

/** M3 buttons. `primary` = filled, `tonal`, `secondary` = outlined, `ghost` = text, `danger` = filled error. */
type ButtonKind = 'primary' | 'tonal' | 'secondary' | 'ghost' | 'danger';

export function Button({
  title, onPress, kind = 'primary', disabled, loading, icon, accessibilityHint, style,
}: { title: string; onPress: () => void; kind?: ButtonKind; disabled?: boolean; loading?: boolean; icon?: IconName | ReactNode; accessibilityHint?: string; style?: ViewStyle }) {
  const t = useTheme();
  const c = t.colors;
  const inactive = disabled || loading;
  const bg = { primary: c.primary, tonal: c.secondaryContainer, secondary: 'transparent', ghost: 'transparent', danger: c.danger }[kind];
  const fg = { primary: c.onPrimary, tonal: c.onSecondaryContainer, secondary: c.primary, ghost: c.primary, danger: kind === 'danger' && t.scheme === 'dark' ? '#690005' : '#FFFFFF' }[kind];
  const filled = kind === 'primary' || kind === 'tonal' || kind === 'danger';
  return (
    <Pressable
      onPress={onPress}
      disabled={inactive}
      accessibilityRole="button"
      accessibilityState={{ disabled: !!inactive, busy: !!loading }}
      accessibilityHint={accessibilityHint}
      android_ripple={{ color: filled ? 'rgba(255,255,255,0.24)' : 'rgba(52,81,199,0.12)', borderless: false }}
      style={({ pressed }) => [
        styles.button,
        { backgroundColor: inactive && filled ? c.surfaceContainerHighest : bg, opacity: pressed ? 0.88 : 1 },
        kind === 'secondary' && { borderWidth: 1, borderColor: inactive ? c.outlineVariant : c.outline },
        style,
      ]}
    >
      {loading ? (
        <ActivityIndicator color={fg} size="small" />
      ) : typeof icon === 'string' ? (
        <Icon name={icon as IconName} size={18} color={inactive ? c.onSurfaceVariant : fg} />
      ) : (
        icon
      )}
      <RNText style={[t.type.labelLarge, { color: inactive ? c.onSurfaceVariant : fg }]}>{title}</RNText>
    </Pressable>
  );
}

export function IconButton({ name, label, onPress, color }: { name: IconName; label: string; onPress: () => void; color?: string }) {
  const t = useTheme();
  return (
    <Pressable
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={label}
      android_ripple={{ color: 'rgba(0,0,0,0.12)', borderless: true, radius: 24 }}
      style={({ pressed }) => ({ width: 48, height: 48, borderRadius: 24, alignItems: 'center', justifyContent: 'center', opacity: pressed ? 0.7 : 1 })}
    >
      <Icon name={name} color={color ?? t.colors.onSurfaceVariant} />
    </Pressable>
  );
}

/** M3 extended FAB: one per screen, for its single primary action. */
export function ExtendedFab({ icon, label, onPress, style }: { icon: IconName; label: string; onPress: () => void; style?: ViewStyle }) {
  const t = useTheme();
  return (
    <Pressable
      onPress={onPress}
      accessibilityRole="button"
      android_ripple={{ color: 'rgba(0,0,0,0.12)' }}
      style={({ pressed }) => [
        {
          height: 56, paddingLeft: 16, paddingRight: 20, borderRadius: 16, flexDirection: 'row', alignItems: 'center', gap: 12,
          backgroundColor: t.colors.primaryContainer, elevation: 3,
          shadowColor: '#000', shadowOpacity: 0.18, shadowRadius: 6, shadowOffset: { width: 0, height: 3 },
          opacity: pressed ? 0.9 : 1,
        },
        style,
      ]}
    >
      <Icon name={icon} color={t.colors.onPrimaryContainer} />
      <RNText style={[t.type.labelLarge, { color: t.colors.onPrimaryContainer }]}>{label}</RNText>
    </Pressable>
  );
}

/** M3 outlined text field. `trailing` holds a clear or paste button. */
export const TextField = forwardRef<ComponentRef<typeof TextInput>, TextInputProps & { label: string; error?: string | null; hint?: string; trailing?: ReactNode }>(
  function TextField({ label, error, hint, style, trailing, ...rest }, ref) {
    const t = useTheme();
    const c = t.colors;
    return (
      <View style={{ gap: t.space.xs }}>
        <Text variant="labelLarge" muted style={{ paddingLeft: 4 }}>{label}</Text>
        <View style={{ flexDirection: 'row', alignItems: 'center', minHeight: 56, borderWidth: error ? 2 : 1, borderColor: error ? c.danger : c.outline, borderRadius: t.radius.md, paddingLeft: 16, paddingRight: trailing ? 4 : 16 }}>
          <TextInput
            ref={ref}
            placeholderTextColor={c.onSurfaceVariant}
            selectionColor={c.primary}
            cursorColor={c.primary}
            accessibilityLabel={label}
            accessibilityHint={hint}
            {...rest}
            style={[t.type.bodyLarge, { flex: 1, color: c.onSurface, paddingVertical: 14 }, style]}
          />
          {trailing}
        </View>
        {error ? (
          <Text variant="bodySmall" color={c.danger} accessibilityLiveRegion="polite" style={{ paddingLeft: 4 }}>{error}</Text>
        ) : hint ? (
          <Text variant="bodySmall" muted style={{ paddingLeft: 4 }}>{hint}</Text>
        ) : null}
      </View>
    );
  },
);

/** M3 cards. Default `outlined`; `filled` for grouped content; `tint` overrides the container colour. */
export function Card({ children, style, onPress, accessibilityLabel, variant = 'outlined', tint }: {
  children: ReactNode;
  style?: ViewStyle;
  onPress?: () => void;
  accessibilityLabel?: string;
  variant?: 'outlined' | 'filled';
  tint?: string;
}) {
  const t = useTheme();
  const base: ViewStyle = {
    backgroundColor: tint ?? (variant === 'filled' ? t.colors.surfaceContainer : t.colors.surface),
    borderRadius: t.radius.lg,
    padding: t.space.lg,
    gap: t.space.sm,
    ...(variant === 'outlined' && !tint ? { borderWidth: 1, borderColor: t.colors.outlineVariant } : null),
  };
  if (!onPress) return <View style={[base, style]}>{children}</View>;
  return (
    <Pressable onPress={onPress} accessibilityRole="button" accessibilityLabel={accessibilityLabel} android_ripple={{ color: 'rgba(0,0,0,0.08)' }}
      style={({ pressed }) => [base, { opacity: pressed ? 0.88 : 1 }, style]}>
      {children}
    </Pressable>
  );
}

/** Verdict chip. `strong` is the filled form with an icon, for the top of a result. */
export function VerdictBadge({ verdict, subject = 'website', size = 'md', strong }: { verdict: Verdict; subject?: VerdictSubject; size?: 'sm' | 'md'; strong?: boolean }) {
  const t = useTheme();
  const vc = verdictColors(t.colors, verdict);
  const icon: IconName = verdict === 'high_risk' ? 'warning-amber' : verdict === 'suspicious' ? 'error-outline' : verdict === 'no_obvious_warnings' ? 'check-circle-outline' : 'remove-circle-outline';
  const bg = strong ? vc.solid : vc.bg;
  const fg = strong ? (t.scheme === 'dark' ? t.colors.surface : '#FFFFFF') : vc.fg;
  return (
    <View style={{ alignSelf: 'flex-start', flexDirection: 'row', alignItems: 'center', gap: 6, backgroundColor: bg, borderRadius: t.radius.sm, paddingLeft: strong ? 8 : 10, paddingRight: strong ? 12 : 10, paddingVertical: size === 'sm' ? 4 : 6 }}>
      {strong ? <Icon name={icon} size={18} color={fg} /> : null}
      <RNText style={[size === 'sm' ? t.type.labelMedium : t.type.labelLarge, { color: fg }]}>{VERDICT_LABEL[subject][verdict]}</RNText>
    </View>
  );
}

/** Inline message. Container colour and an icon carry the tone; never a coloured side stripe. */
export function Notice({ tone = 'neutral', title, children }: { tone?: 'neutral' | 'warning' | 'danger' | 'ok'; title?: string; children?: ReactNode }) {
  const t = useTheme();
  const c = t.colors;
  const map = {
    neutral: { bg: c.surfaceContainerHigh, fg: c.onSurface, icon: 'info-outline' as IconName, ic: c.onSurfaceVariant },
    warning: { bg: c.warningContainer, fg: c.onWarningContainer, icon: 'error-outline' as IconName, ic: c.onWarningContainer },
    danger: { bg: c.dangerContainer, fg: c.onDangerContainer, icon: 'warning-amber' as IconName, ic: c.onDangerContainer },
    ok: { bg: c.okContainer, fg: c.onOkContainer, icon: 'check-circle-outline' as IconName, ic: c.onOkContainer },
  }[tone];
  return (
    <View style={{ backgroundColor: map.bg, borderRadius: t.radius.md, padding: t.space.lg, flexDirection: 'row', gap: t.space.md }} accessibilityRole="summary">
      <Icon name={map.icon} size={20} color={map.ic} />
      <View style={{ flex: 1, gap: t.space.xs }}>
        {title ? <Text variant="titleSmall" color={map.fg}>{title}</Text> : null}
        {typeof children === 'string' ? <Text variant="bodyMedium" color={map.fg}>{children}</Text> : children}
      </View>
    </View>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  const t = useTheme();
  return (
    <View style={{ alignItems: 'center', paddingVertical: t.space.xxl, gap: t.space.sm }}>
      <Text variant="titleMedium" style={{ textAlign: 'center' }}>{title}</Text>
      <Text variant="bodyMedium" muted style={{ textAlign: 'center', maxWidth: 320 }}>{body}</Text>
      {action}
    </View>
  );
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  const t = useTheme();
  return (
    <View style={{ padding: t.space.xxl, alignItems: 'center', gap: t.space.sm }} accessibilityLabel={label}>
      <ActivityIndicator color={t.colors.primary} />
      <Text muted variant="bodyMedium">{label}…</Text>
    </View>
  );
}

/** M3 list item: leading icon, headline, supporting text, trailing element. */
export function ListItem({ icon, iconColor, headline, supporting, trailing, onPress, accessibilityLabel, divider, destructive }: {
  icon?: IconName;
  iconColor?: string;
  headline: string;
  supporting?: string;
  trailing?: ReactNode;
  onPress?: () => void;
  accessibilityLabel?: string;
  divider?: boolean;
  destructive?: boolean;
}) {
  const t = useTheme();
  const body = (
    <>
      {icon ? <Icon name={icon} color={iconColor ?? (destructive ? t.colors.danger : t.colors.onSurfaceVariant)} /> : null}
      <View style={{ flex: 1, minWidth: 0 }}>
        <Text variant="bodyLarge" numberOfLines={1} color={destructive ? t.colors.danger : undefined}>{headline}</Text>
        {supporting ? <Text variant="bodyMedium" muted numberOfLines={2}>{supporting}</Text> : null}
      </View>
      {trailing ? <View style={{ alignSelf: 'center' }}>{trailing}</View> : null}
    </>
  );
  const style: ViewStyle = {
    flexDirection: 'row', alignItems: 'center', gap: t.space.lg, paddingHorizontal: t.space.lg, paddingVertical: t.space.md,
    minHeight: supporting ? 72 : 56,
    ...(divider ? { borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: t.colors.outlineVariant } : null),
  };
  if (!onPress) return <View style={style}>{body}</View>;
  return (
    <Pressable onPress={onPress} accessibilityRole="button" accessibilityLabel={accessibilityLabel ?? headline} android_ripple={{ color: 'rgba(0,0,0,0.08)' }}
      style={({ pressed }) => [style, { opacity: pressed ? 0.8 : 1 }]}>
      {body}
    </Pressable>
  );
}

/** Older name for a simple navigation row. */
export function Row({ label, value, onPress, destructive }: { label: string; value?: string; onPress?: () => void; destructive?: boolean }) {
  const t = useTheme();
  return (
    <ListItem
      headline={label}
      destructive={destructive}
      onPress={onPress}
      divider
      trailing={
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.xs, flexShrink: 1 }}>
          {value ? <Text variant="bodyMedium" muted numberOfLines={1} style={{ flexShrink: 1 }}>{value}</Text> : null}
          {onPress ? <Icon name="chevron-right" /> : null}
        </View>
      }
    />
  );
}

/** M3 switch (52×32 track, check in the thumb when on). */
export function Switch({ value, onValueChange, label, disabled }: { value: boolean; onValueChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  const t = useTheme();
  const c = t.colors;
  return (
    <Pressable
      onPress={() => onValueChange(!value)}
      disabled={disabled}
      accessibilityRole="switch"
      accessibilityLabel={label}
      accessibilityState={{ checked: value, disabled }}
      hitSlop={8}
      style={{ opacity: disabled ? 0.38 : 1 }}
    >
      <View style={{
        width: 52, height: 32, borderRadius: 16, padding: value ? 4 : 6, justifyContent: 'center',
        alignItems: value ? 'flex-end' : 'flex-start',
        backgroundColor: value ? c.primary : c.surfaceContainerHighest,
        borderWidth: value ? 0 : 2, borderColor: c.outline,
      }}>
        <View style={{ width: value ? 24 : 16, height: value ? 24 : 16, borderRadius: 12, backgroundColor: value ? c.onPrimary : c.outline, alignItems: 'center', justifyContent: 'center' }}>
          {value ? <Icon name="check" size={16} color={c.primary} /> : null}
        </View>
      </View>
    </Pressable>
  );
}

export function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  const t = useTheme();
  const c = t.colors;
  return (
    <Pressable
      onPress={() => onChange(!checked)}
      accessibilityRole="checkbox"
      accessibilityState={{ checked }}
      android_ripple={{ color: 'rgba(0,0,0,0.08)' }}
      style={{ flexDirection: 'row', alignItems: 'center', gap: t.space.md, minHeight: 56, paddingVertical: t.space.sm }}
    >
      <View style={{ width: 48, height: 48, alignItems: 'center', justifyContent: 'center' }}>
        <View style={{ width: 20, height: 20, borderRadius: 3, borderWidth: 2, borderColor: checked ? c.primary : c.onSurfaceVariant, backgroundColor: checked ? c.primary : 'transparent', alignItems: 'center', justifyContent: 'center' }}>
          {checked ? <Icon name="check" size={16} color={c.onPrimary} /> : null}
        </View>
      </View>
      <Text variant="bodyLarge" style={{ flex: 1 }}>{label}</Text>
    </Pressable>
  );
}

/** Segmented progress for a short setup flow. */
export function StepProgress({ step, total }: { step: number; total: number }) {
  const t = useTheme();
  return (
    <View style={{ gap: t.space.sm }}>
      <View
        accessibilityRole="progressbar"
        accessibilityLabel="Setup progress"
        accessibilityValue={{ min: 1, max: total, now: step }}
        style={{ flexDirection: 'row', gap: 6 }}
      >
        {Array.from({ length: total }, (_, i) => (
          <View key={i} style={{ flex: 1, height: 4, borderRadius: 2, backgroundColor: i < step ? t.colors.primary : t.colors.primaryContainer }} />
        ))}
      </View>
      <Text variant="labelMedium" muted>Step {step} of {total}</Text>
    </View>
  );
}

/** An icon, a title and a sentence: for explanations and disclosures. */
export function FactRow({ icon, title, body, iconColor }: { icon: IconName; title: string; body: string; iconColor?: string }) {
  const t = useTheme();
  return (
    <View style={{ flexDirection: 'row', gap: t.space.lg, alignItems: 'flex-start' }}>
      <View style={{ paddingTop: 2 }}><Icon name={icon} color={iconColor ?? t.colors.primary} /></View>
      <View style={{ flex: 1, gap: 2 }}>
        <Text variant="titleMedium">{title}</Text>
        <Text variant="bodyMedium" muted>{body}</Text>
      </View>
    </View>
  );
}

export function Section({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  const t = useTheme();
  return (
    <View style={{ gap: t.space.sm }}>
      <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 4, minHeight: action ? 48 : undefined }}>
        <Text variant="titleSmall" muted accessibilityRole="header">{title}</Text>
        {action}
      </View>
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  button: { minHeight: 48, paddingHorizontal: 24, borderRadius: 24, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, overflow: 'hidden' },
});
