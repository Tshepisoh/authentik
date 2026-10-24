import type {
  Alert,
  CreateSandboxSessionRequest,
  DomainAnalysis,
  DomainAnalyzeRequest,
  NotificationAnalysis,
  NotificationAnalyzeRequest,
  PaymentCheckRequest,
  PaymentExtraction,
  PaymentExtractRequest,
  PrivacyStatement,
  Profile,
  RegisterDeviceRequest,
  Report,
  ReportSummary,
  SandboxSessionResponse,
  ThreatListUpdate,
  UserSettings,
} from '@authentik/shared';
import { config } from '../config';
import { identity } from '@/features/auth/identity';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown, retried = false): Promise<T> {
  const token = await identity.getToken(retried);
  let res: Response;
  try {
    res = await fetch(`${config.apiUrl}${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'network', 'Could not reach Authentik. Check your connection and try again.');
  }
  // One retry with a refreshed token covers expiry between app resume and the request.
  if (res.status === 401 && !retried) {
    const peek = (await res.clone().json().catch(() => null)) as { error?: { code?: string } } | null;
    if (peek?.error?.code === 'unauthenticated') return call(method, path, body, true);
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const e = (data as { error?: { code: string; message: string } } | null)?.error;
    throw new ApiError(res.status, e?.code ?? 'unknown', e?.message ?? 'Something went wrong. Please try again.');
  }
  return data as T;
}

export const api = {
  me: () => call<Profile>('GET', '/v1/me'),
  completeOnboarding: () => call<Profile>('PATCH', '/v1/me', { onboardingCompleted: true }),
  revokeSessions: () => call<void>('POST', '/v1/me/sessions/revoke'),
  deleteAccount: () => call<void>('DELETE', '/v1/me'),

  scan: (url: string) => call<Report>('POST', '/v1/scans', { url }),

  analyzeDomain: (req: DomainAnalyzeRequest) => call<DomainAnalysis>('POST', '/v1/domains/analyze', req),
  analyzeNotification: (req: NotificationAnalyzeRequest) => call<NotificationAnalysis>('POST', '/v1/notifications/analyze', req),
  threatUpdates: (since?: string) =>
    call<ThreatListUpdate>('GET', `/v1/threats/updates${since ? `?since=${encodeURIComponent(since)}` : ''}`),

  paymentCheck: (req: PaymentCheckRequest) => call<Report>('POST', '/v1/payment-checks', req),
  extractPayment: (req: PaymentExtractRequest) => call<PaymentExtraction>('POST', '/v1/payment-checks/extract', req),

  reports: () => call<ReportSummary[]>('GET', '/v1/reports'),
  report: (id: string) => call<Report>('GET', `/v1/reports/${encodeURIComponent(id)}`),
  deleteReport: (id: string) => call<void>('DELETE', `/v1/reports/${encodeURIComponent(id)}`),

  alerts: (unreviewed = false) => call<Alert[]>('GET', `/v1/alerts${unreviewed ? '?unreviewed=true' : ''}`),
  reviewAlert: (id: string) => call<Alert>('POST', `/v1/alerts/${encodeURIComponent(id)}/review`),

  settings: () => call<UserSettings>('GET', '/v1/settings'),
  updateSettings: (patch: Partial<UserSettings>) => call<UserSettings>('PUT', '/v1/settings', patch),
  privacy: () => call<PrivacyStatement>('GET', '/v1/privacy'),
  registerDevice: (req: RegisterDeviceRequest) => call<void>('POST', '/v1/devices', req),

  startSandbox: (req: CreateSandboxSessionRequest) => call<SandboxSessionResponse>('POST', '/v1/sandbox/sessions', req),
  closeSandbox: (id: string) => call<Report>('DELETE', `/v1/sandbox/sessions/${encodeURIComponent(id)}`),
};
