# Roadmap

The product scope is now **Android automatic fraud detection** ([scope](scope.md)).
✅ done and tested · 🟡 done with a stated limit · ⬜ not started.

Plan: build Phases 1 and 2 together (automatic fake-notification detection, the shared domain
engine, and warnings that link the two). Ship the VPN (Phase 3) as its own milestone after that.

## Phase 1: Notification detection
Code: `mobile/modules/authentik-protection/` (native) and `mobile/src/features/protection/` (UI).
🟡 here means the Android-specific Kotlin and the screens haven't been compiled for Android or run on a device yet, because the dev machine has no Android SDK. The JS bundle builds and the rules pass their tests. See "Verifying on a device" below.
- 🟡 Local Expo module (Kotlin), autolinked; the service is declared in the module's own `AndroidManifest.xml`, so no config plugin is needed. Needs a development build
- 🟡 `ProtectionListenerService`: native, runs without the JS runtime, skips ongoing/summary/system notifications, dedupes re-posts
- 🟡 Onboarding step and a Protection screen that explain access before opening Settings; status for granted, paused, not yet bound (with `requestRebind`), and warnings blocked (Android 13+)
- ✅ On-device redaction of OTPs, card and account numbers before any rule runs (`rules/Redactor.kt`)
- ✅ Local rules: payment claims, release-the-goods pressure, credential requests, verify-through-link, account threats, urgency, delivery-fee, refund and prize links, look-alike/IP/shortened/punycode links (`rules/NotificationRules.kt`)
- ✅ Verdicts through `rules/LocalVerdict.kt`, an on-device copy of `decideVerdict`. Links stay `inconclusive` until the threat list exists
- 🟡 Warning notification: private on the lock screen, opens `authentik://protection`
- ✅ 40 JVM unit tests with synthetic notifications (`android/src/test`)
- 🟡 Sample checker on the Protection screen: runs the same rules on pasted text, stores nothing

### Verifying on a device
```sh
cd mobile
npx expo prebuild --platform android      # generates android/ (don't commit it)
cd android && ./gradlew :authentik-protection:testDebugUnitTest && cd ..
npx expo run:android                       # development build on a device or emulator
```
Then grant access from the Protection screen and send yourself a test SMS such as
"Payment successful. You have received R4,500.00. Release the item now."

## Phase 2: Domain engine
Backend tests: `backend/src/test/protection.test.ts`. Kotlin: `ThreatIntelTest.kt`.
- ✅ `POST /v1/domains/analyze`: hostname or URL; `quick` skips the page fetch; nothing stored
- 🟡 Reputation stays on free sources: Safe Browsing (free key, non-commercial), the local blocklist and free feeds. **No billing.** Google Web Risk (needs billing) is deferred to a commercial launch
- 🟡 Second source: `THREAT_FEED_URLS` loads plain-text domain feeds on a timer (non-critical). Off by default: pick feeds and check their licences
- ✅ Reputation cache (30 min per provider, host and path; failures never cached) and RDAP cache (1 day)
- ✅ `GET /v1/threats/updates`: blocklist + feeds + brands, versioned, with deltas against the last 5 versions
- ✅ `POST /v1/notifications/analyze`: phone's finding codes + link checks → one `notification` assessment. Codes and hostnames only, no text. `RULES_VERSION` 2026.10.2
- 🟡 Phone downloads the threat list (`threat-sync.ts`, every 6 h while the app opens) into native storage (`ThreatListStore.kt`); the listener flags listed links offline and only clears links while the list is fresh. The store's Android code is untested (needs the SDK)
- ✅ Downloaded brands replace the built-in seed in the Kotlin rules
- 🟡 "Check links online" on warnings and in the sample checker
- 🟡 Share-sheet target (`plugins/with-share-target.js`): a shared link pre-fills the website check, other text pre-fills the message checker. Plugin output verified with `expo config`; not run on a device
- 🟡 Isolated scanner for JS redirects and checkout pages: the existing `sandbox-worker`
- ⬜ Signed threat-list updates (currently TLS + auth only)

## Phase 3: Device protection (VPN)
Code: `VpnProtectionService.kt`, `dns/` (packets and policy), `web-protection-screen.tsx`.
- 🟡 `VpnProtectionService`: a local, **DNS-only** VPN. Only the VPN's own DNS address (10.111.222.2) is routed into the tunnel, so other traffic never passes through it. Listed domains get NXDOMAIN; look-alikes of known brands (judged on the registrable label only) are allowed with a warning; everything else goes to the real network's DNS servers through protected sockets. Ordinary lookups are counted, never recorded
- 🟡 Start/stop in the app after a separate Play-style disclosure with an explicit checkbox, then Android's VPN consent. Status: running, lookups/blocked counts, stopped-with-reason, and a stop action in the ongoing notification
- 🟡 Recovery: `START_STICKY` restarts it after the process is killed while the user has it on; always-on VPN (`SUPPORTS_ALWAYS_ON`) keeps it on across reboots; `onRevoke` (another VPN took over) stops it and says why
- 🟡 Limits shown to the user: Private DNS in strict mode is detected and named; "no lookups seen" after 2 minutes points at apps' own secure DNS; cached and direct-IP connections are listed as not covered; a stale threat list is shown
- ✅ JVM tests: IPv4/UDP/DNS parsing and building (checksums, NXDOMAIN replies, TCP/IPv6/fragments/compression refused, 25,000 random and mangled packets without a crash) and the DNS policy. 56 Kotlin tests in total
- ⬜ On-device tests (need the Android SDK and a phone; checklist below)

### Phase 3 device checklist
1. Turn on; browse normally for 10 minutes. Pages load; the lookup count rises; battery use in Settings › Battery stays small.
2. Sync the threat list (open the app online), then open a domain that is on the threat list (from `THREAT_FEED_URLS` or the `BLOCKLIST_PATH` file) in Chrome. The VPN answers NXDOMAIN before any real lookup and one "Blocked a known scam site" notification appears. Open `fnb-verify.co.za`: it loads (or fails normally) and a look-alike warning appears.
3. Turn on another VPN app: Authentik shows "stopped" with the reason. Turn Authentik on again: the other VPN disconnects.
4. Set Private DNS to a hostname: the warning names it. Set it back to Automatic: lookups are counted again.
5. Force-stop isn't a fair test (it disables restarts); instead kill the process with `adb shell am kill app.authentik.mobile` and check it comes back.
6. Turn on always-on VPN for Authentik and reboot: it's running after boot.
7. Switch Wi-Fi ↔ mobile data while running: lookups keep working (the upstream DNS follows the network).
8. Check that DNS over TCP (large answers) degrades gracefully: e.g. `dig +tcp` from Termux fails, ordinary lookups don't.

## Phase 4: Hardening and release
- ⬜ Measure false positives, missed detections and notification delay
- ⬜ Privacy disclosures; Google Play `VpnService` declaration and notification-access policy review
- ⬜ Test across manufacturers and battery-optimisation settings
- ⬜ Measure detection quality and resource use before turning on more aggressive blocking
- ⬜ `POST /v1/reports/feedback` for false-positive and missed-scam reports

## Already built (before the scope change)
These came from the original blueprint and stay in the codebase.
- ✅ Architecture, threat model, data-retention and feature-flow docs
- ✅ URL validation and SSRF-safe fetching (`packages/shared`, `backend/src/security/ssrf-protection`)
- ✅ Auth, authorisation and rate limits (🟡 in-memory limiter: needs a shared store with several instances)
- 🟡 Website scanning: Safe Browsing, a local blocklist, RDAP age, page evidence, look-alike detection
- ✅ Evidence-based risk engine with explanations (`modules/risk-engine`)
- ✅ Isolated Sandbox browsing (`sandbox-worker/`): per-session Chromium, egress proxy, screencast, cleanup
- ✅ Payment-integrity checks: expected-vs-observed comparison, extraction from pages
- ✅ Report history, privacy controls, alerts and FCM push
