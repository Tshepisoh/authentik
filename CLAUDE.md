# Authentik — working notes

Scope (since 2026-10-24): **Android automatic fraud detection**: notification listener, domain
engine, then a local VPN. See `docs/scope.md` and `docs/roadmap.md`. Sandbox and payment-integrity
code predates the change and is reused, not removed.

npm-workspaces monorepo: `packages/shared`, `backend`, `sandbox-worker`. `mobile/` is a
separate Expo project with its own `node_modules`, and is **not** a workspace.

## Commands
- `npm test` (root): builds shared, then tests shared + backend + worker.
- `npm run typecheck`: shared build plus backend/worker `tsc --noEmit`.
- `cd mobile && npm run typecheck`; use `npx expo install <pkg>` for mobile dependencies (SDK 58).
- Kotlin rule tests (needs the Android SDK): `npx expo prebuild --platform android`, then `./gradlew :authentik-protection:testDebugUnitTest` in `mobile/android/`. The `rules/` package has no Android imports, so a plain Kotlin/JVM Gradle project can also compile and test it.
- Host on this PC (Docker + ngrok tunnel, APK builds): the `host` skill, `.claude/skills/host/SKILL.md`; overview in `docs/hosting.md`.
- Worker real-browser test: `SANDBOX_E2E=1 npx vitest run src/browser` in `sandbox-worker/`.
- Rebuild `packages/shared` (`npm run build -w @authentik/shared`) after changing it. Backend and worker import its `dist/`.

## Rules that matter
- **The mobile app imports only types from `@authentik/shared`** (`import type`). It's mapped to the shared *source* via tsconfig paths, and Metro can't resolve the shared package at runtime. UI labels live in `mobile/src/shared/lib/format.ts`.
- **Verdicts are decided in one place**: `backend/src/modules/risk-engine/engine.ts` (`decideVerdict`). Modules emit findings and `CheckRun`s; they never pick a verdict. Bump `RULES_VERSION` when rules change.
- Never turn missing evidence into a safe result. A failed or unavailable check must be recorded as a `CheckRun` with `critical` set correctly.
- Any server-side fetch of a user-supplied URL goes through `SafeFetcher` (backend) or the egress proxy (worker). Never call `fetch` on user URLs directly.
- Store URLs only through `redactUrl`. Log route paths, not query strings.
- The worker must never receive platform credentials. It refuses to start if it does.
- A missing resource and someone else's resource both return 404.
- Mobile: use `@firebase/auth`, not `firebase/auth`. Only the former has the react-native export, which carries `getReactNativePersistence`. See `mobile/src/types/firebase-auth-rn.d.ts`.
- Notification finding codes are defined twice: Kotlin `NotificationRules.kt` emits them, and `backend/src/modules/notification-analysis/service.ts` (`NOTIFICATION_FINDINGS`) owns their server-side weights. Add a code to both.
- `POST /v1/notifications/analyze` takes codes and hostnames, never notification text. Keep it that way.
- On-device verdicts use `mobile/modules/authentik-protection/.../rules/LocalVerdict.kt`, a copy of `decideVerdict`. Change both together. Bump `NotificationRules.RULES_VERSION` when the Kotlin rules change.
- Notification listener, VPN and local rules are **native Kotlin services** (an Expo module in `mobile/modules/`), never JS background tasks. Needs a dev build; Expo Go won't load it.
- No accessibility service. Don't promise visibility Android doesn't give (full URLs via VPN, in-app messages, other apps' WebViews).
- Notification text is redacted on the device and leaves the phone only with opt-in consent. Never collect OTPs or notification history.
- A "payment received" notification is a claim, never proof. The warning always says to check the user's own banking app.
- **No paid or billing-required services** (no Google Cloud billing, no Firebase Blaze). Reputation is Safe Browsing (free, non-commercial) plus the local blocklist and free feeds. A commercial provider is a later decision.
- The VPN is DNS-only: route only its DNS address, never the default route. Never record or send ordinary lookups; only blocks and look-alike warnings are kept on the phone. Block only threat-list matches; look-alikes are warnings.
- Keep the VPN disclosure (`web-protection-screen.tsx`) separate from other disclosures, with an explicit checkbox. Google Play requires it. Update it if what the VPN sees or does changes.
- New endpoints use the `/v1` prefix and return the existing `Assessment`. No numeric or model-derived confidence scores.
- The sideloaded judge APK (`eas.json` profile `judge`, `EXPO_PUBLIC_NOTIFICATION_LISTENER=off`) has no notification listener: `plugins/with-notification-listener.js` removes it because Play Protect blocks sideloaded apps that declare one. The app shows the `not_in_build` state. Don't tell users to turn Play Protect off.
- Windows: don't `rm -rf node_modules` from Git Bash in this workspace (it follows workspace junctions).
