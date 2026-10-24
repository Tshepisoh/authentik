/**
 * Request/response contracts for the Authentik HTTP API (`/v1`).
 * The mobile app imports these as types only.
 */
import type { Assessment, Finding, Verdict } from './risk.js';

export interface ApiError {
  error: { code: string; message: string; details?: unknown };
}

// ── Profile & account ────────────────────────────────────────────────────

export interface Profile {
  uid: string;
  /** Only the email is kept; no names, phone numbers or addresses. */
  email: string | null;
  emailVerified: boolean;
  onboardingCompletedAt: string | null;
  createdAt: string;
}

export interface UpdateProfileRequest {
  onboardingCompleted?: boolean;
}

// ── Targets & reports ────────────────────────────────────────────────────

/** A target URL as it is safe to store and display. */
export interface TargetSummary {
  /** Scheme + host + path, with sensitive query values redacted. */
  displayUrl: string;
  hostname: string;
  registrableDomain: string | null;
}

export interface RedirectHop {
  /** Redacted, like `TargetSummary.displayUrl`. */
  url: string;
  hostname: string;
  status: number | null;
  /** True when this hop moved to a different registrable domain. */
  crossDomain: boolean;
}

export type ReportType = 'website_scan' | 'payment_check' | 'sandbox_session';

export interface ReportSummary {
  id: string;
  type: ReportType;
  target: TargetSummary;
  verdict: Verdict;
  completeness: Assessment['completeness'];
  headline: string;
  createdAt: string;
}

export interface Report extends ReportSummary {
  assessment: Assessment;
  redirects: RedirectHop[];
  /** Present on payment checks. */
  payment?: PaymentCheckDetail;
  /** Present on sandbox session reports. */
  sandbox?: SandboxReportDetail;
  /** Links a sandbox report back to the scan that preceded it. */
  relatedReportId?: string;
  expiresAt: string;
}

// ── Website scanning ─────────────────────────────────────────────────────

export interface CreateScanRequest {
  url: string;
}

export type CreateScanResponse = Report;

// ── Domain analysis, notifications and the device threat list ────────────

/** Where a domain check came from. Recorded in the audit log only. */
export type DomainCheckSource = 'manual' | 'share' | 'notification' | 'dns';

/** `quick`: reputation, impersonation, registration and URL signals. `full` also fetches the page. */
export type DomainCheckDepth = 'quick' | 'full';

export interface DomainAnalyzeRequest {
  /** A bare hostname (`absa-secure.help`) or a URL. */
  target: string;
  source?: DomainCheckSource;
  /** Defaults to `quick`. */
  depth?: DomainCheckDepth;
}

/** Not stored: use `POST /v1/scans` for a saved report. */
export interface DomainAnalysis {
  target: TargetSummary;
  depth: DomainCheckDepth;
  assessment: Assessment;
}

/**
 * Correlates what the phone found in a notification with server-side domain
 * checks. No notification text is sent: only finding codes and hostnames.
 */
export interface NotificationAnalyzeRequest {
  /** Package of the app that posted the notification. */
  packageName: string;
  /** Codes from the on-device rules. The server owns their severity and wording. */
  findingCodes: string[];
  /** Hostnames of links in the notification, at most 5. Never full URLs. */
  linkHosts: string[];
  localRulesVersion: string;
}

export interface NotificationAnalysis {
  assessment: Assessment;
  links: DomainAnalysis[];
}

export interface ThreatEntry {
  /** Registrable domain or hostname; subdomains are included. */
  domain: string;
  threatType: string;
}

/** A brand the phone checks for impersonation offline. */
export interface BrandEntry {
  name: string;
  isBank: boolean;
  domains: string[];
  /** Whole host labels that name the brand. */
  brandTokens: string[];
  /** How the brand appears in message text, lowercase. */
  mentions: string[];
}

export interface ThreatListUpdate {
  version: string;
  generatedAt: string;
  /** True: replace the local list with `added`. False: apply `added` and `removed` to the version the client sent. */
  full: boolean;
  added: ThreatEntry[];
  removed: string[];
  /** Always complete. */
  brands: BrandEntry[];
  /** After this long without a successful update, the phone treats its list as stale. */
  maxAgeSeconds: number;
}

// ── Payment integrity ────────────────────────────────────────────────────

export interface ExpectedPayment {
  /** Id from the merchant registry, or a free-text name. */
  merchant: string;
  /** Amount in minor units (cents). */
  amountMinor: number;
  currency: string;
  /** Legitimate adjustment the user expects (fees, shipping), minor units. */
  allowedAdjustmentMinor?: number;
}

export interface ObservedPayment {
  /** Required unless `extractionId` is given (the server then uses the page it read). */
  checkoutUrl?: string;
  /** Optional chain the client already observed; otherwise the server follows redirects. */
  redirectChain?: string[];
  recipientName?: string;
  amountMinor?: number;
  currency?: string;
  /** From `POST /v1/payment-checks/extract`. Values the user leaves unset are taken from the page. */
  extractionId?: string;
}

/** Where an observed value came from. */
export type ObservedSource = 'page' | 'page_confirmed' | 'user' | null;

export type PaymentExtractRequest = { checkoutUrl: string } | { sandboxSessionId: string };

export interface AmountCandidate {
  amountMinor: number;
  currency: string;
  /** The label it was found next to, e.g. "Total", or the data source, e.g. "structured data". */
  label: string;
}

/**
 * What Authentik read from a payment page rendered in the isolated worker.
 * These are claims made by the page itself — a fraudulent page can display
 * false values — so the user confirms them before the check runs.
 */
export interface PaymentExtraction {
  extractionId: string;
  /** Redacted; the full address stays on the server, referenced by `extractionId`. */
  displayUrl: string;
  pageHost: string;
  pageTitle: string;
  recipientName: string | null;
  amountMinor: number | null;
  currency: string | null;
  confidence: 'high' | 'medium' | 'low';
  /** Distinct amounts found; more than one means the user should pick. */
  amountCandidates: AmountCandidate[];
  recipientCandidates: string[];
  notes: string[];
  expiresAt: string;
}

export interface PaymentCheckRequest {
  expected: ExpectedPayment;
  observed: ObservedPayment;
}

export interface PaymentCheckDetail {
  expected: ExpectedPayment;
  observedRecipient: string | null;
  observedAmountMinor: number | null;
  observedCurrency: string | null;
  merchantId: string | null;
  merchantName: string;
  paymentProvider: string | null;
  simulated: boolean;
  /** Whether the recipient and amount were read from the page, typed by the user, or both and they agree. */
  observedSource?: { recipient: ObservedSource; amount: ObservedSource };
}

export interface DemoScenario {
  id: string;
  title: string;
  description: string;
  request: PaymentCheckRequest;
}

// ── Sandbox ──────────────────────────────────────────────────────────────

export type SandboxSessionState = 'starting' | 'active' | 'closing' | 'closed' | 'failed';

export type SandboxEventType =
  | 'navigation'
  | 'cross_domain_redirect'
  | 'blocked_destination'
  | 'download_blocked'
  | 'permission_denied'
  | 'popup_blocked'
  | 'dialog_dismissed'
  | 'file_chooser_blocked'
  | 'browser_crashed'
  | 'session_expired'
  | 'isolation_failure';

export interface SandboxEvent {
  type: SandboxEventType;
  at: string;
  /** Redacted hostname or URL, never full query strings. */
  target?: string;
  detail?: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface CreateSandboxSessionRequest {
  url: string;
  /** Required when the preliminary scan rated the target high risk. */
  acknowledgeRisk?: boolean;
}

export interface SandboxSessionResponse {
  sessionId: string;
  state: SandboxSessionState;
  /** Short-lived credential for the stream only; revoked on close. */
  viewToken: string;
  streamPath: string;
  expiresAt: string;
  viewport: { width: number; height: number };
  scan: ReportSummary;
}

export interface SandboxReportDetail {
  sessionId: string;
  startedAt: string;
  endedAt: string;
  endReason: string;
  events: SandboxEvent[];
  visitedHosts: string[];
}

/** Messages the server sends down the sandbox stream socket. */
export type SandboxServerMessage =
  | { type: 'frame'; data: string; width: number; height: number }
  | { type: 'navigated'; url: string; title: string }
  | { type: 'event'; event: SandboxEvent }
  | { type: 'closed'; reason: string };

/** Messages the viewer sends up the sandbox stream socket. Coordinates are viewport pixels. */
export type SandboxClientMessage =
  | { type: 'tap'; x: number; y: number }
  | { type: 'scroll'; dx: number; dy: number }
  | { type: 'type'; text: string }
  | { type: 'key'; key: SandboxAllowedKey }
  | { type: 'back' }
  | { type: 'forward' }
  | { type: 'reload' }
  | { type: 'navigate'; url: string };

export const SANDBOX_ALLOWED_KEYS = [
  'Enter',
  'Backspace',
  'Tab',
  'Escape',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
] as const;
export type SandboxAllowedKey = (typeof SANDBOX_ALLOWED_KEYS)[number];

// ── Alerts & notifications ───────────────────────────────────────────────

export interface Alert {
  id: string;
  reportId: string;
  code: string;
  title: string;
  /** Safe to show in-app; push notifications use generic text instead. */
  summary: string;
  hostname: string | null;
  severity: Finding['severity'];
  createdAt: string;
  reviewedAt: string | null;
}

// ── Settings & privacy ───────────────────────────────────────────────────

export interface UserSettings {
  pushNotifications: boolean;
  /** When false, alerts are still recorded in-app but never pushed. */
  showDomainInNotifications: boolean;
  /** How long reports are kept, within the server's allowed range. */
  reportRetentionDays: number;
}

export interface PrivacyStatement {
  reportRetentionDays: { default: number; min: number; max: number };
  collected: string[];
  notCollected: string[];
  deletion: { reportDeletion: string; accountDeletion: string; auditLogs: string };
}

export interface RegisterDeviceRequest {
  token: string;
  platform: 'ios' | 'android';
}
