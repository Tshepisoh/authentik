import { z } from 'zod';

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(8080),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    /** Comma-separated origins allowed to call the API from a browser. Mobile apps don't need CORS. */
    CORS_ORIGINS: z.string().default(''),
    /** Number of reverse-proxy hops to trust for client IPs (rate limiting). */
    TRUST_PROXY_HOPS: z.coerce.number().int().min(0).default(0),

    /** `firebase` verifies Firebase ID tokens. `dev` accepts `dev:<uid>` tokens and is refused in production. */
    AUTH_MODE: z.enum(['firebase', 'dev']).default('firebase'),
    /** `firestore` in deployed environments; `memory` for local development and tests. */
    STORAGE: z.enum(['firestore', 'memory']).default('firestore'),
    FIREBASE_PROJECT_ID: z.string().optional(),

    /** Google Safe Browsing v4 key: free, non-commercial use. Without it, reputation is reported as unavailable. */
    GOOGLE_SAFE_BROWSING_API_KEY: z.string().optional(),
    /** Comma-separated plain-text domain feeds (e.g. URLhaus hostfile, OpenPhish). Empty disables them. */
    THREAT_FEED_URLS: z.string().default(''),
    THREAT_FEED_REFRESH_MINUTES: z.coerce.number().int().min(5).default(60),
    /** Cap on known-bad domains sent to each phone. */
    THREAT_LIST_MAX_ENTRIES: z.coerce.number().int().positive().default(50_000),
    /** Phones treat their list as stale after this long without an update (3 days). */
    THREAT_LIST_MAX_AGE_SECONDS: z.coerce.number().int().positive().default(259_200),
    /** Extra local blocklist file (one domain or URL per line). */
    BLOCKLIST_PATH: z.string().optional(),
    /** RDAP lookups for domain registration age. */
    RDAP_ENABLED: bool.default(true),
    RDAP_BASE_URL: z.string().url().default('https://rdap.org/domain/'),

    SCAN_FETCH_TIMEOUT_MS: z.coerce.number().int().positive().default(8000),
    SCAN_MAX_BODY_BYTES: z.coerce.number().int().positive().default(1_000_000),
    SCAN_MAX_REDIRECTS: z.coerce.number().int().min(0).max(10).default(5),

    REPORT_RETENTION_DAYS_DEFAULT: z.coerce.number().int().positive().default(30),
    REPORT_RETENTION_DAYS_MIN: z.coerce.number().int().positive().default(1),
    REPORT_RETENTION_DAYS_MAX: z.coerce.number().int().positive().default(90),

    /** Internal URL of the sandbox worker. Empty disables the Sandbox (it fails closed). */
    SANDBOX_WORKER_URL: z.string().default(''),
    /** Shared secret for control-plane → worker calls. Never given to the mobile app. */
    SANDBOX_WORKER_SECRET: z.string().default(''),
    SANDBOX_SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(600),
    SANDBOX_IDLE_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(120),
    SANDBOX_MAX_SESSIONS_PER_USER: z.coerce.number().int().positive().default(1),
    SANDBOX_VIEWPORT_WIDTH: z.coerce.number().int().positive().default(390),
    SANDBOX_VIEWPORT_HEIGHT: z.coerce.number().int().positive().default(844),

    /** Salt for pseudonymising user ids in audit logs. */
    AUDIT_SALT: z.string().default('authentik-dev-salt'),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production') {
      if (env.AUTH_MODE === 'dev') {
        ctx.addIssue({ code: 'custom', path: ['AUTH_MODE'], message: 'dev auth is not allowed in production' });
      }
      if (env.STORAGE === 'memory') {
        ctx.addIssue({ code: 'custom', path: ['STORAGE'], message: 'memory storage is not allowed in production' });
      }
      if (env.AUDIT_SALT === 'authentik-dev-salt') {
        ctx.addIssue({ code: 'custom', path: ['AUDIT_SALT'], message: 'set a unique AUDIT_SALT in production' });
      }
      if (env.SANDBOX_WORKER_URL && env.SANDBOX_WORKER_SECRET.length < 32) {
        ctx.addIssue({
          code: 'custom',
          path: ['SANDBOX_WORKER_SECRET'],
          message: 'SANDBOX_WORKER_SECRET must be at least 32 characters',
        });
      }
    }
    if (env.REPORT_RETENTION_DAYS_MIN > env.REPORT_RETENTION_DAYS_MAX) {
      ctx.addIssue({ code: 'custom', path: ['REPORT_RETENTION_DAYS_MIN'], message: 'min exceeds max' });
    }
  });

export type Config = z.infer<typeof schema>;

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid configuration:\n${issues}`);
  }
  return parsed.data;
}

/** Config for tests and local tooling: memory storage, dev auth, no network checks. */
export function testConfig(overrides: Partial<Record<keyof Config, string>> = {}): Config {
  return loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    AUTH_MODE: 'dev',
    STORAGE: 'memory',
    RDAP_ENABLED: 'false',
    ...overrides,
  });
}
