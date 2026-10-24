import { pino } from 'pino';
import { z } from 'zod';
import { SessionManager } from './lifecycle/manager.js';
import { createWorkerServer } from './server.js';

const env = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(8090),
    HOST: z.string().default('0.0.0.0'),
    LOG_LEVEL: z.string().default('info'),
    WORKER_SECRET: z.string().min(16, 'WORKER_SECRET must be at least 16 characters'),
    MAX_SESSIONS: z.coerce.number().int().positive().default(4),
    MAX_SESSION_SECONDS: z.coerce.number().int().positive().default(900),
    /** Chromium's own process sandbox. Only disable for local development on hosts that can't support it. */
    CHROMIUM_SANDBOX: z.enum(['true', 'false']).default('true').transform((v) => v === 'true'),
    CHROMIUM_EXECUTABLE_PATH: z.string().optional(),
  })
  .superRefine((e, ctx) => {
    if (e.NODE_ENV === 'production' && !e.CHROMIUM_SANDBOX) {
      ctx.addIssue({ code: 'custom', path: ['CHROMIUM_SANDBOX'], message: 'the Chromium sandbox must stay enabled in production' });
    }
    if (e.NODE_ENV === 'production' && e.WORKER_SECRET.length < 32) {
      ctx.addIssue({ code: 'custom', path: ['WORKER_SECRET'], message: 'use at least 32 characters in production' });
    }
  })
  .parse(process.env);

const log = pino({ level: env.LOG_LEVEL, base: { service: 'authentik-sandbox-worker' } });

// The worker must not hold platform credentials. Refuse to start if any leaked into its environment.
const forbidden = Object.keys(process.env).filter((k) =>
  /^(GOOGLE_APPLICATION_CREDENTIALS|FIREBASE_|FIRESTORE_|GCLOUD_|AWS_|AZURE_|DATABASE_URL|SANDBOX_WORKER_SECRET$)/.test(k),
);
if (forbidden.length) {
  log.fatal({ variables: forbidden }, 'refusing to start: platform credentials present in worker environment');
  process.exit(1);
}

const manager = new SessionManager({
  maxSessions: env.MAX_SESSIONS,
  maxSessionSeconds: env.MAX_SESSION_SECONDS,
  chromiumSandbox: env.CHROMIUM_SANDBOX,
  executablePath: env.CHROMIUM_EXECUTABLE_PATH,
  log,
});
const server = createWorkerServer(manager, env.WORKER_SECRET);
server.listen(env.PORT, env.HOST, () => log.info({ port: env.PORT, maxSessions: env.MAX_SESSIONS }, 'sandbox worker listening'));

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    server.close();
    void manager.closeAll('worker_shutdown').finally(() => process.exit(0));
  });
}
