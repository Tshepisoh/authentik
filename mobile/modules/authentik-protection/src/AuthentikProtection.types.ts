import type { Severity, Verdict } from '@authentik/shared';

export interface ProtectionStatus {
  /** False on iOS, in Expo Go, and on web: the native module isn't there. */
  supported: boolean;
  /** The user granted notification access in Android Settings. */
  notificationAccess: boolean;
  /** Android has bound the listener. Can lag behind `notificationAccess`. */
  listenerConnected: boolean;
  /** The user's in-app switch. */
  enabled: boolean;
  /** Authentik may post notifications (Android 13+ asks separately). */
  warningsAllowed: boolean;
}

export interface ProtectionReason {
  code: string;
  title: string;
  reason: string;
  severity: Severity;
}

export interface NotificationAnalysis {
  verdict: Verdict;
  headline: string;
  recommendedAction: string;
  reasons: ProtectionReason[];
  /** Hostnames only, never full URLs. */
  linkHosts: string[];
  rulesVersion: string;
}

export interface SampleAnalysis extends NotificationAnalysis {
  shouldWarn: boolean;
}

/** A stored warning. Holds no notification text. */
export interface ProtectionWarning extends NotificationAnalysis {
  id: string;
  /** ISO-8601, when the flagged notification was posted. */
  postedAt: string;
  appLabel: string;
  packageName: string;
}

export interface ThreatListInfo {
  /** Null until the first download. */
  version: string | null;
  /** Epoch milliseconds of the last successful update. */
  fetchedAt: number | null;
  entries: number;
  /** False when missing or older than the server's max age: links can be flagged but not cleared. */
  fresh: boolean;
}

export interface VpnStatus {
  /** The user turned web protection on (it restarts after the process is killed while this is true). */
  enabled: boolean;
  /** Android's VPN consent is in place for Authentik. False after another VPN app takes over. */
  permitted: boolean;
  running: boolean;
  /** Epoch milliseconds, while running. */
  startedAt: number | null;
  /** Lookups seen since it started. Counts only, never names. */
  lookups: number;
  blocked: number;
  warned: number;
  /** DNS servers the real network provides. Zero means the fallback resolvers are used. */
  upstreamServers: number;
  /** Private DNS provider in strict mode. Lookups bypass the VPN while it's set. */
  privateDnsHost: string | null;
  lastError: string | null;
}

/** A lookup the VPN blocked, or a look-alike it warned about. Ordinary lookups aren't kept. */
export interface DnsEvent {
  host: string;
  /** Epoch milliseconds. */
  at: number;
  kind: 'blocked' | 'lookalike';
  /** Threat label for blocks, the imitated brand for look-alikes. */
  detail: string;
}

export type ProtectionEvents = {
  onVpnStatus(status: VpnStatus): void;
  onWarning(warning: ProtectionWarning): void;
  /** Something was shared to Authentik while it was running. Read it with `consumeSharedText()`. */
  onSharedText(): void;
};
