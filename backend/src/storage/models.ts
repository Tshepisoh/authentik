import type {
  Alert,
  Profile,
  Report,
  SandboxEvent,
  SandboxSessionState,
  UserSettings,
} from '@authentik/shared';
import type { Doc } from './types.js';

export type ProfileDoc = Doc & Profile;

export type SettingsDoc = Doc & UserSettings & { updatedAt: string };

export interface DeviceDoc extends Doc {
  /** FCM registration token. Stored so we can push; deleted with the account. */
  token: string;
  platform: 'ios' | 'android';
}

export type ReportDoc = Doc & Report & { uid: string };

export type AlertDoc = Doc &
  Alert & {
    /** uid-scoped key used to avoid repeating the same alert. */
    dedupeKey: string;
  };

export interface SandboxSessionDoc extends Doc {
  state: SandboxSessionState;
  /** Redacted target, for display. The full URL is only held by the worker for the session's life. */
  displayUrl: string;
  hostname: string;
  scanReportId: string;
  /** sha256 of the view token. The token itself is only returned once. */
  viewTokenHash: string;
  /** When the browser session itself ends. (`expiresAt` is when this record is purged.) */
  sessionExpiresAt: string;
  expiresAt: string;
  lastActivityAt: string;
  endedAt: string | null;
  endReason: string | null;
  events: SandboxEvent[];
  visitedHosts: string[];
  reportId: string | null;
}
