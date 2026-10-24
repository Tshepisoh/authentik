import { loadConfig } from './config.js';
import { createLogger } from './lib/logger.js';
import { buildDeps, type Overrides } from './container.js';
import { createHttpServer } from './server.js';
import { startRetentionSweeper } from './storage/retention.js';

const config = loadConfig();
const log = createLogger(config);

async function firebaseOverrides(): Promise<Overrides> {
  const needsFirebase = config.AUTH_MODE === 'firebase' || config.STORAGE === 'firestore';
  if (!needsFirebase) return {};

  // Credentials come from GOOGLE_APPLICATION_CREDENTIALS or the runtime's service account — never from the repo.
  const { initializeApp, applicationDefault } = await import('firebase-admin/app');
  const fbApp = initializeApp({ credential: applicationDefault(), projectId: config.FIREBASE_PROJECT_ID });
  const o: Overrides = {};
  if (config.AUTH_MODE === 'firebase') {
    const { getAuth } = await import('firebase-admin/auth');
    const { FirebaseIdentityProvider } = await import('./modules/auth/verifier.js');
    o.identity = new FirebaseIdentityProvider(getAuth(fbApp));
    const { getMessaging } = await import('firebase-admin/messaging');
    const { FcmPushSender } = await import('./modules/notifications/fcm.js');
    o.push = new FcmPushSender(getMessaging(fbApp));
  }
  if (config.STORAGE === 'firestore') {
    const { getFirestore } = await import('firebase-admin/firestore');
    const { createFirestoreStore } = await import('./storage/firestore.js');
    o.store = createFirestoreStore(getFirestore(fbApp));
  }
  return o;
}

const deps = buildDeps(config, log, await firebaseOverrides());
const server = createHttpServer(deps);
const stopSweeper = startRetentionSweeper(deps.store, deps.clock, log);
deps.feeds?.start(config.THREAT_FEED_REFRESH_MINUTES);

server.listen(config.PORT, () => {
  log.info(
    {
      port: config.PORT,
      auth: config.AUTH_MODE,
      storage: config.STORAGE,
      sandbox: config.SANDBOX_WORKER_URL ? 'configured' : 'disabled (fails closed)',
      reputation: deps.reputation.providers.map((p) => p.id).join(' + '),
      ...(config.GOOGLE_SAFE_BROWSING_API_KEY ? {} : { warning: 'no Safe Browsing key: scans will be inconclusive' }),
    },
    'authentik api listening',
  );
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    log.info({ signal }, 'shutting down');
    stopSweeper();
    server.close();
    void deps.shutdown().finally(() => process.exit(0));
  });
}
