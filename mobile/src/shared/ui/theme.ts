import { useColorScheme } from 'react-native';
import type { Verdict } from '@authentik/shared';

/**
 * Material 3 colour roles, light and dark, from one calm blue seed. Severity
 * roles (danger/warning/ok/neutral) follow M3's container pattern: a strong
 * colour for icons and text on surfaces, a container fill, and on-container text.
 * The older names (bg, surfaceAlt, textMuted, …) map onto these roles so every
 * screen shares one system.
 */
const light = {
  // M3 roles
  primary: '#3451C7',
  onPrimary: '#FFFFFF',
  primaryContainer: '#DDE1FF',
  onPrimaryContainer: '#001356',
  onPrimaryContainerMuted: '#2D3A6E',
  secondaryContainer: '#DFE1F9',
  onSecondaryContainer: '#171B2C',
  surface: '#FBF8FF',
  surfaceContainerLow: '#F5F2FA',
  surfaceContainer: '#EFEDF4',
  surfaceContainerHigh: '#E9E7EF',
  surfaceContainerHighest: '#E4E1E9',
  onSurface: '#1B1B21',
  onSurfaceVariant: '#46464F',
  outline: '#777680',
  outlineVariant: '#C7C5D0',
  scrim: 'rgba(0, 0, 0, 0.32)',

  danger: '#BA1A1A',
  dangerContainer: '#FFDAD6',
  onDangerContainer: '#410002',
  onDangerContainerMuted: '#6B1F1A',
  dangerSurface: '#FFF0EE',
  warning: '#7A5900',
  warningContainer: '#FFDF9E',
  onWarningContainer: '#261A00',
  ok: '#1F6B3E',
  okContainer: '#C4EED0',
  onOkContainer: '#00210D',
  onOkContainerMuted: '#0F3D22',
  neutral: '#5D5E68',
  neutralContainer: '#E2E2EC',
  onNeutralContainer: '#1A1B23',
};

const dark: typeof light = {
  primary: '#B9C3FF',
  onPrimary: '#08218A',
  primaryContainer: '#2A3E9E',
  onPrimaryContainer: '#DDE1FF',
  onPrimaryContainerMuted: '#C3CBF5',
  secondaryContainer: '#424659',
  onSecondaryContainer: '#DFE1F9',
  surface: '#121318',
  surfaceContainerLow: '#1B1B21',
  surfaceContainer: '#1F1F25',
  surfaceContainerHigh: '#2A292F',
  surfaceContainerHighest: '#34343A',
  onSurface: '#E4E1E9',
  onSurfaceVariant: '#C7C5D0',
  outline: '#918F9A',
  outlineVariant: '#46464F',
  scrim: 'rgba(0, 0, 0, 0.5)',

  danger: '#FFB4AB',
  dangerContainer: '#93000A',
  onDangerContainer: '#FFDAD6',
  onDangerContainerMuted: '#FFC9C2',
  dangerSurface: '#3B1714',
  warning: '#F3BF48',
  warningContainer: '#5C4300',
  onWarningContainer: '#FFDF9E',
  ok: '#8DD5A2',
  okContainer: '#00522D',
  onOkContainer: '#C4EED0',
  onOkContainerMuted: '#A9DDB8',
  neutral: '#C5C6D0',
  neutralContainer: '#44464F',
  onNeutralContainer: '#E1E2EC',
};

function withAliases(c: typeof light) {
  return {
    ...c,
    // Older names, kept so existing screens follow the new system.
    bg: c.surface,
    surfaceAlt: c.surfaceContainer,
    border: c.outlineVariant,
    text: c.onSurface,
    textMuted: c.onSurfaceVariant,
    primaryText: c.onPrimary,
    dangerBg: c.dangerContainer,
    warningBg: c.warningContainer,
    okBg: c.okContainer,
    neutralBg: c.neutralContainer,
    focus: c.primary,
  };
}

const palette = { light: withAliases(light), dark: withAliases(dark) };

export type Colors = typeof palette.light;

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 } as const;
/** M3 shape scale: small 8, medium 12, large 16, extra-large 28. */
export const radius = { sm: 8, md: 12, lg: 16, xl: 24, xxl: 28, pill: 999 } as const;

/** M3 type scale (Roboto is the system face on Android). */
export const type = {
  displaySmall: { fontSize: 36, lineHeight: 44, fontWeight: '400' as const },
  headlineMedium: { fontSize: 28, lineHeight: 36, fontWeight: '400' as const },
  headlineSmall: { fontSize: 24, lineHeight: 32, fontWeight: '400' as const },
  titleLarge: { fontSize: 22, lineHeight: 28, fontWeight: '400' as const },
  titleMedium: { fontSize: 16, lineHeight: 24, fontWeight: '500' as const, letterSpacing: 0.15 },
  titleSmall: { fontSize: 14, lineHeight: 20, fontWeight: '500' as const, letterSpacing: 0.1 },
  bodyLarge: { fontSize: 16, lineHeight: 24, fontWeight: '400' as const, letterSpacing: 0.15 },
  bodyMedium: { fontSize: 14, lineHeight: 20, fontWeight: '400' as const, letterSpacing: 0.25 },
  bodySmall: { fontSize: 12, lineHeight: 16, fontWeight: '400' as const, letterSpacing: 0.4 },
  labelLarge: { fontSize: 14, lineHeight: 20, fontWeight: '500' as const, letterSpacing: 0.1 },
  labelMedium: { fontSize: 12, lineHeight: 16, fontWeight: '500' as const, letterSpacing: 0.5 },
  // Older names, mapped to M3 roles.
  title: { fontSize: 28, lineHeight: 36, fontWeight: '400' as const },
  heading: { fontSize: 22, lineHeight: 28, fontWeight: '400' as const },
  subheading: { fontSize: 16, lineHeight: 24, fontWeight: '500' as const, letterSpacing: 0.15 },
  body: { fontSize: 16, lineHeight: 24, fontWeight: '400' as const, letterSpacing: 0.15 },
  small: { fontSize: 14, lineHeight: 20, fontWeight: '400' as const, letterSpacing: 0.25 },
  caption: { fontSize: 12, lineHeight: 16, fontWeight: '500' as const, letterSpacing: 0.5 },
};

export type TypeRole = keyof typeof type;

export function useTheme() {
  const scheme = useColorScheme();
  const colors = scheme === 'dark' ? palette.dark : palette.light;
  return { colors, scheme: scheme ?? 'light', space, radius, type };
}

/**
 * Verdict colours: `fg` is text on `bg` (the container); `solid` is the strong
 * colour for icons on ordinary surfaces. "No obvious warnings" is a calm green,
 * deliberately not a celebratory "safe".
 */
export function verdictColors(c: Colors, v: Verdict) {
  switch (v) {
    case 'high_risk':
      return { fg: c.onDangerContainer, bg: c.dangerContainer, solid: c.danger };
    case 'suspicious':
      return { fg: c.onWarningContainer, bg: c.warningContainer, solid: c.warning };
    case 'no_obvious_warnings':
      return { fg: c.onOkContainer, bg: c.okContainer, solid: c.ok };
    case 'inconclusive':
    case 'blocked':
      return { fg: c.onNeutralContainer, bg: c.neutralContainer, solid: c.neutral };
  }
}
