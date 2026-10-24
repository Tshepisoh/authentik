import type { Logger } from 'pino';
import type { Config } from './config.js';
import type { Store } from './storage/types.js';
import { createMemoryStore } from './storage/memory.js';
import { systemClock, type Clock } from './lib/ids.js';
import { AuditLog } from './security/audit/index.js';
import { SafeFetcher } from './security/ssrf-protection/index.js';
import { DevIdentityProvider, type IdentityProvider } from './modules/auth/verifier.js';
import { AccountService } from './modules/auth/account.js';
import { EntityRegistry } from './modules/merchant-verification/registry.js';
import {
  isThreatListSource,
  LocalBlocklistProvider,
  ReputationService,
  SafeBrowsingProvider,
  ThreatFeedProvider,
  type ReputationProvider,
} from './modules/reputation/index.js';
import { CachedRegistrationLookup, RdapRegistrationLookup, type RegistrationLookup } from './modules/scans/registration.js';
import { NotificationAnalysisService } from './modules/notification-analysis/service.js';
import { ThreatListService } from './modules/threat-intel/service.js';
import { ScanService, type PageFetcher } from './modules/scans/service.js';
import { SettingsService } from './modules/settings/service.js';
import { ReportService } from './modules/reports/service.js';
import { AlertService, type PushSender } from './modules/notifications/service.js';
import { PaymentIntegrityService } from './modules/payment-integrity/service.js';
import { PaymentExtractionService } from './modules/payment-integrity/extraction.js';
import { HttpSandboxWorker, type SandboxWorker } from './sandbox-control/workers/client.js';
import { SandboxService } from './sandbox-control/sessions/service.js';

export interface Overrides {
  store?: Store;
  identity?: IdentityProvider;
  fetcher?: PageFetcher;
  reputationProviders?: ReputationProvider[];
  registration?: RegistrationLookup | null;
  push?: PushSender | null;
  worker?: SandboxWorker;
  clock?: Clock;
}

export type Deps = ReturnType<typeof buildDeps>;

/**
 * Builds the object graph. Firebase-backed pieces are created in `index.ts`
 * and passed in as overrides, so tests and local dev never need credentials.
 */
export function buildDeps(config: Config, log: Logger, o: Overrides = {}) {
  const clock = o.clock ?? systemClock;
  const store = o.store ?? createMemoryStore(clock);
  const identity = o.identity ?? new DevIdentityProvider();
  const audit = new AuditLog(log.child({ component: 'audit' }), config.AUDIT_SALT);
  const safeFetcher = new SafeFetcher();
  const fetcher = o.fetcher ?? safeFetcher;
  const registry = new EntityRegistry();

  const feedUrls = config.THREAT_FEED_URLS.split(',').map((u) => u.trim()).filter(Boolean);
  const feeds = !o.reputationProviders && feedUrls.length > 0 ? new ThreatFeedProvider(feedUrls, log.child({ component: 'threat-feeds' })) : null;
  const providers = o.reputationProviders ?? [
    new SafeBrowsingProvider(config.GOOGLE_SAFE_BROWSING_API_KEY),
    LocalBlocklistProvider.fromFile(config.BLOCKLIST_PATH),
    ...(feeds ? [feeds] : []),
  ];
  const reputation = new ReputationService(providers, clock);
  const registration =
    o.registration !== undefined
      ? o.registration
      : config.RDAP_ENABLED
        ? new CachedRegistrationLookup(new RdapRegistrationLookup(safeFetcher, config.RDAP_BASE_URL), clock)
        : null;

  const settings = new SettingsService(store, config, clock);
  const reports = new ReportService(store, settings, clock);
  const alerts = new AlertService(store, settings, o.push ?? null, audit, log, clock);
  const scans = new ScanService({ config, registry, reputation, registration, fetcher, reports, alerts, audit });
  const worker = o.worker ?? new HttpSandboxWorker(config.SANDBOX_WORKER_URL, config.SANDBOX_WORKER_SECRET);
  const sandbox = new SandboxService({ config, store, worker, scans, reports, alerts, audit, log, clock });
  const extractions = new PaymentExtractionService({ worker, sandbox, audit, clock });
  const payments = new PaymentIntegrityService({ config, registry, reputation, fetcher, reports, alerts, audit, extractions });
  const account = new AccountService(store, identity, audit, clock, (uid) => sandbox.closeAllForUser(uid));
  const notificationAnalysis = new NotificationAnalysisService({ scans, audit });
  const threatList = new ThreatListService({ sources: providers.filter(isThreatListSource), registry, config, clock });

  return {
    config, log, clock, store, identity, audit, registry, reputation, settings, reports, alerts, scans, payments, extractions,
    sandbox, account, notificationAnalysis, threatList, feeds,
    async shutdown() {
      feeds?.stop();
      await sandbox.stop();
      await safeFetcher.close();
    },
  };
}
