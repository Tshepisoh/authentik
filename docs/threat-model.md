# Threat model

Scope: the mobile app, the API, the Sandbox worker and the Firebase services they use.
Method: assets → trust boundaries → threats (STRIDE-style) → mitigations, with a status and
the residual risk for each.

## Assets

| Asset | Why it matters |
|---|---|
| User identity and sessions | Account takeover exposes history and alerts |
| Reports and alerts | Reveal which sites and payments a person was dealing with |
| Platform credentials (Firebase Admin, service accounts) | Full data access |
| Internal network and cloud metadata | Pivot point into the platform (SSRF) |
| The user's phone and browser data | The thing the Sandbox exists to protect |
| Verdict integrity | A false "no warnings" can lead someone into a scam |

## Trust boundaries

1. **Phone ↔ API**: TLS, Firebase ID token, per-user rate limits.
2. **API ↔ the internet** (scanner fetches): untrusted responses; destination policy on every hop.
3. **API ↔ Sandbox worker**: private network plus a shared secret. The worker is treated as *potentially compromised*.
4. **Worker ↔ the internet**: hostile pages run here. The egress proxy is the only route out.
5. **API ↔ Firebase**: Admin SDK through a service account. Clients have no direct Firestore access.

## Threats and mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | **SSRF through the scanner**: a user submits `http://169.254.169.254/` or an internal name | Static policy (`packages/shared/src/policy.ts`): http/https only, ports 80/443, no IP literals in private, reserved, CGNAT, link-local or ULA ranges, no `localhost`/`.internal`/`.local` or single-label names. Blocked before any fetch, as a `blocked` verdict. | Done, tested |
| T2 | **DNS rebinding / mixed records**: a public name resolves to private addresses | `resolveAndCheck` requires *every* resolved address to be public; the connection's `lookup` pins to the validated address, so there is no second resolution. | Done, tested |
| T3 | **Redirect-based SSRF** | Redirects are followed manually; every `Location` is re-normalised and re-checked; capped at 5 hops; non-http schemes refused. | Done, tested |
| T4 | **Sandbox browser reaches internal networks** | Per-session egress proxy (CONNECT and absolute-URI) applying T1/T2 to every connection; `--proxy-bypass-list=<-loopback>`; QUIC disabled; WebRTC limited to proxied UDP (none); an **isolation self-test** before any untrusted content loads; the proxy listens on loopback only. **Required in production:** network-layer egress deny rules for private ranges and metadata as a second layer. | Proxy done and tested with real Chromium; network rules are deployment work |
| T5 | **Sandbox worker compromise** (Chromium RCE) | Chromium's own sandbox stays on (production refuses to start without it); a non-root user; read-only root filesystem; `cap_drop: ALL`; `no-new-privileges`; seccomp allow-list; CPU/memory/PID limits; one browser process per session with a throwaway profile. The worker holds **only** the control secret and refuses to start if Firebase, cloud or database credentials appear in its environment. The control plane validates every worker message against a schema, so a compromised worker can only send bounded frames and events to phones. | Done; container hardening in `docker-compose.yml` |
| T6 | **Cross-session leakage** in the Sandbox | A separate Chromium process, profile and proxy per session; nothing shared; `serviceWorkers: 'block'`; profiles deleted on close. | Done |
| T7 | **Stealing the Sandbox stream** | A 256-bit view token, returned once, stored only as SHA-256, compared in constant time, revoked on close, sent in the `Authorization` header (never the URL), passed between screens in memory only. The WebSocket `Origin` must be allow-listed (native apps send none). A new viewer replaces the old one. | Done, tested |
| T8 | **Abuse of viewer input** (scripting the remote browser) | Zod schema per message; key allow-list (no shortcut chords); text capped at 500 characters; 30 messages/s token bucket; navigate targets re-validated by both the API and the worker. No `evaluate`. | Done, tested |
| T9 | **Broken authentication / IDOR** | `verifyIdToken(…, checkRevoked=true)`; every collection keyed by `uid`; missing and not-yours both return 404; no list-all operations; `firestore.rules` deny all client access. | Done, tested |
| T10 | **Account deletion abuse** | Requires `auth_time` within 5 minutes (re-authentication), plus a rate limit. | Done |
| T11 | **False reassurance** | "No obvious warnings" requires every critical check to have run; otherwise `inconclusive`. Confidence is never `high` for an absence of warnings. HTTPS gives no reassurance. Copy states the limits plainly. | Done, tested |
| T12 | **False accusation** (legitimate sites flagged) | Severity and evidence quality are separate; weak signals (new domain, unusual TLD, IDN) alone cannot make a site high risk; known payment processors are recognised; short brand tokens are only matched as whole parts of a name. | Done; tune with real data |
| T13 | **Sensitive data in storage or logs** | URLs redacted before storage (query values, fragments, token-like path segments); request logs record the route path only; pino redaction of auth headers and tokens; the audit log uses an HMAC'd uid; Safe Browsing receives scheme + host + path only. | Done, tested |
| T14 | **Notification leakage on the lock screen** | Generic text by default; domain only by opt-in; never a URL or an amount; Android `PRIVATE` visibility. | Done |
| T15 | **Denial of service / cost abuse** | Per-IP and per-user rate limits; body caps (32 KB API, 1 MB fetched pages); fetch timeouts; one Sandbox per user; a worker capacity cap; TTL plus idle reaping. | Done (in-memory limiter; needs a shared store when running several instances) |
| T16 | **Malicious deep links** | `authentik://scan?url=` only **pre-fills** the field; the user still chooses to scan. | Done |
| T17 | **Credential entry inside the Sandbox** | The Sandbox protects the phone, not what the user types. Warned at onboarding, on the start screen, and in the input placeholder. | Mitigated by UX; residual |
| T19 | **Lying checkout pages**: a fraudulent page displays a false amount or recipient to the extractor | Extracted values are labelled as page claims; contradictions between the page and the user raise a finding; low-confidence readings say so; the app always tells the user to confirm on their bank's approval screen. Pages are rendered only in the isolated worker; the in-page script only collects raw text, and interpretation runs outside the page. | Mitigated by design; inherent residual |
| T20 | **Payment-session tokens in checkout URLs** | The full URL never reaches the phone: it's held server-side for 10 minutes under an owner-bound `extractionId`; the phone gets a redacted address. | Done, tested |
| T18 | **Supply chain** | Lockfiles committed; `npm ci` in images; install scripts are gated by npm's allow-list; the Playwright image is pinned to the library version. | Partial: add Dependabot/Renovate and image scanning |

### Planned (Android scope)

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T21 | **Notification content leaks** (OTPs, balances, private messages) | Redaction on the device before analysis; rules run on the phone; stored warnings hold no text; the warning notification is `PRIVATE` with a generic public version; server analysis (later) only with opt-in and only redacted text | Done on device (Phase 1); server side planned |
| T22 | **Spoofed notifications that copy a bank's wording** | The posting package is evidence, not proof, either way. A payment claim is never treated as confirmation, and every payment warning says to check the banking app | Done (Phase 1 rules) |
| T23 | **VPN visibility gaps** (Private DNS, DoH, cached lookups, direct IP) | Strict Private DNS is detected and named ("bypassed" state); "no lookups seen" is flagged; the rest are listed as limits. Never shown as "protected" for traffic it can't see | Done (needs device verification) |
| T27 | **The VPN as a surveillance or crash surface** | DNS-only routing, so it never sees other traffic; lookups are never stored or sent; the packet parser refuses anything unexpected and is fuzz-tested; a bounded thread pool drops the oldest work under flood; Authentik excludes its own traffic from the tunnel | Done (needs device verification) |
| T24 | **Poisoned or stale threat list** | Served only over TLS to signed-in users; versioned; feeds are parsed through the destination policy (no private or local names); the phone's copy expires after `THREAT_LIST_MAX_AGE_SECONDS` and a stale copy can flag links but never clear them | Done except signing (planned) |
| T26 | **Phone inflating its own findings** in `POST /v1/notifications/analyze` | The phone sends codes only; the server owns severities and ignores unknown codes and the phone's link codes | Done, tested |
| T25 | **Play policy rejection or user distrust** from sensitive permissions | Separate, explained consent for each permission; no accessibility service; Play declarations reviewed before release | Planned |

## Residual risks and known gaps

- **Zero-day Chromium escape plus a container escape** would bypass the worker boundary. Run workers on separate nodes or VMs (e.g. gVisor/Kata, or dedicated node pools) for production.
- **Reputation coverage**: one critical provider (Safe Browsing, free and non-commercial). `THREAT_FEED_URLS` adds non-critical feeds, but a Safe Browsing outage, or no key, still makes results inconclusive. A commercial provider (e.g. Web Risk, which needs billing) is deferred.
- **Merchant registry accuracy**: a wrong "official domain" produces false reassurance. Entries need provenance and review.
- **Single-instance session relay**: live Sandbox sockets live in the owning API instance's memory.
- **iOS push**: needs the FCM iOS SDK or a relay; alerts are in-app only on iOS for now.

## Incident runbook (short)

1. **Isolation failure or suspected worker compromise**: the affected session is already terminated automatically. Drain and replace the worker pool (`docker compose up -d --force-recreate sandbox-worker` or a node-pool rotation), rotate `SANDBOX_WORKER_SECRET`, preserve the audit logs (`action: sandbox.isolation_failure`), and review the egress-firewall logs.
2. **Reputation provider outage**: scans become inconclusive, which is expected. Confirm with `checks[].status = unavailable` and don't hot-patch around it.
3. **Credential exposure** (Firebase Admin key): revoke the key, rotate, check the Firestore audit logs, and call `revokeRefreshTokens` for affected users if user tokens were exposed.
4. **Repeated policy violations** (`repeated policy violations` error log): rate-limit or disable the actor's account, then investigate the attempted targets in the audit logs.
