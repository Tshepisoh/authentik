# Authentik

An Android-first financial security companion. It watches the signals Android exposes,
checks suspicious notifications and domains, and warns you before you trust a fake payment
claim or a fraudulent website. See the [product scope](docs/scope.md).

- **Notification detection** (planned): a native `NotificationListenerService` flags fake bank alerts, fake "payment received" messages, delivery-fee and refund scams.
- **Domain protection** (domain engine built, VPN planned): reputation, look-alike and impersonation checks, domain age and redirects. Full URLs come from the share sheet or notification links. A local `VpnService` adds DNS-level blocking of known threats.
- **Payment-risk signals** (planned): correlates a suspicious notification with domain and impersonation evidence into one warning.

Everything feeds one deterministic risk engine. Authentik says what it verified, what it
detected and what it couldn't check. Missing evidence is reported as **inconclusive**, never as
safe. It doesn't claim to see everything on the phone: Android doesn't allow that, and the
[scope](docs/scope.md#android-capabilities-and-their-limits) lists the limits.

Built before the scope change and still in the codebase: isolated **Sandbox** browsing (now the
isolated scanner for pages a plain fetch can't render) and **payment-integrity** checks.

```
authentik/
├── packages/shared/   types, URL redaction, destination policy (shared by API + worker)
├── backend/           Express 5 API: auth, scans, risk engine, payments, reports, alerts, Sandbox control
├── sandbox-worker/    isolated Chromium sessions behind per-session egress proxies
├── mobile/            Expo (React Native) app; native Kotlin services planned under mobile/modules/
└── docs/              architecture, feature flows, threat model, data retention, roadmap
```

## Quick start (no Firebase needed)

Requirements: Node 20.11+ (tested on 24), npm 10+.

```sh
npm install                       # API, worker and shared package (npm workspaces)
npm test                          # 174 tests across shared, backend and worker

# API: dev auth + in-memory storage
cp backend/.env.example backend/.env
npm run dev:backend               # http://localhost:8080

# Sandbox worker (optional; without it the Sandbox fails closed)
npm run browsers -w @authentik/sandbox-worker      # one-time Chromium download
cp sandbox-worker/.env.example sandbox-worker/.env  # WORKER_SECRET must match the API's SANDBOX_WORKER_SECRET
npm run dev:worker                # http://127.0.0.1:8090

# Mobile app
cd mobile && npm install
cp .env.example .env              # EXPO_PUBLIC_API_URL: use your computer's LAN IP on a real device
npx expo start
```

Try it:

```sh
curl -s -X POST localhost:8080/v1/scans -H 'authorization: Bearer dev:me' \
  -H 'content-type: application/json' -d '{"url":"takealot.com"}'
```

Without `GOOGLE_SAFE_BROWSING_API_KEY` that scan comes back **inconclusive**, because the
critical reputation check couldn't run. That is intended. Add a key to get complete verdicts.

## Production

- `NODE_ENV=production` refuses dev auth, memory storage, the default audit salt, a short worker secret, and a worker without Chromium's sandbox.
- API: `AUTH_MODE=firebase`, `STORAGE=firestore`, credentials from the runtime service account. Deploy `firestore.rules` and `firestore.indexes.json` (`firebase deploy --only firestore`). Firebase project: `authentik-5e5f1` (free Spark plan, Firestore in Johannesburg).
- On a slow network with broken IPv6 (outbound calls to Google time out), add `NODE_OPTIONS=--dns-result-order=ipv4first --no-network-family-autoselection` to your local `.env`.
- Worker: a private network, a read-only container, the seccomp profile in `sandbox-worker/docker/`, and network-level egress deny rules for private and metadata ranges. See `docker-compose.yml` and [docs/architecture.md](docs/architecture.md#production-deployment).

```sh
cp .env.example .env && cp backend/.env.example backend/.env   # then edit both
docker compose up --build
```

## Tests

| Suite | What it covers |
|---|---|
| `packages/shared` | IP classification, the destination policy, DNS rebinding, URL normalisation and redaction |
| `backend` | Risk rules, impersonation detection, SSRF fetcher against a live local server, every API route, ownership, retention, alerts, expected-vs-observed payment checks, the Sandbox lifecycle over real WebSockets |
| `sandbox-worker` | Egress proxy blocking, lifecycle manager, control-API auth and re-validation |
| `sandbox-worker` E2E | Real Chromium: isolation self-test, screencast, and in-page fetches to metadata and loopback blocked. Run with `SANDBOX_E2E=1 npm test -w @authentik/sandbox-worker`. |
| `mobile` | `npm run typecheck`; `npx expo export --platform android` to verify bundling |

## Docs

- [Product scope](docs/scope.md): Android automatic fraud detection, platform limits, pipelines, planned API
- [Architecture](docs/architecture.md): components, risk model, request pipeline, Sandbox lifecycle, API
- [Feature flows](docs/feature-flows.md): the 11 product flows, each mapped to code
- [Threat model](docs/threat-model.md): threats, mitigations, residual risk, runbook
- [Data retention](docs/data-retention.md): what's stored, for how long, and who deletes it
- [Roadmap](docs/roadmap.md): the four phases of the new scope, and what's already built
