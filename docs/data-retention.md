# Data collection and retention

This document describes what the backend **actually does**. The in-app privacy screen is
generated from `SettingsService.privacyStatement()`, so update both together.

| Data | Where | Contents | Retention | Deleted by |
|---|---|---|---|---|
| Identity | Firebase Auth | Email, password hash (Firebase), sign-in metadata | Until account deletion | `DELETE /v1/me` → `auth.deleteUser` |
| Profile | `profiles/{uid}` | uid, email, emailVerified, onboarding timestamp, createdAt | Until account deletion | Account deletion |
| Settings | `settings/{uid}` | Push preference, domain-in-notification preference, retention days | Until account deletion | Account deletion |
| Devices | `devices/{id}` | FCM token, platform | Until unregistered, invalid (pruned on send) or account deletion | `DELETE /v1/devices`, account deletion |
| Reports | `reports/{id}` | Target (hostname, registrable domain, **redacted** URL), assessment, redirect hostnames and statuses, payment comparison (merchant, amounts, recipient name), Sandbox events and visited hostnames | User-selectable 1–90 days (default 30) via `expiresAt` | Expiry (retention sweeper), `DELETE /v1/reports/:id`, account deletion |
| Alerts | `alerts/{id}` | Code, title, summary, hostname, severity, reviewedAt | Same expiry as the source report | Report deletion, expiry, account deletion |
| Sandbox sessions | `sandboxSessions/{id}` | State, hostname, redacted URL, view-token **hash** (cleared on close), events | 90 days | Expiry, account deletion |
| Audit log | Log sink (stdout → your logging platform) | Pseudonymous actor (HMAC of uid), action, hostname, outcome | **Configure 90 days** in the log sink | Not deleted by user actions; the pseudonymous id can't be read back to an account without the secret salt |
| Sandbox browser data | Worker tmpfs | Everything a page stores | Session lifetime only (≤ 15 min) | Destroyed when the session closes |

## On the phone (Android scope)

Phases 1–3 are built.

| Data | Where | Contents | Retention |
|---|---|---|---|
| Notification analysis | Phone memory only | Raw text for the length of one analysis; rules see only the redacted copy | Never stored, logged or sent |
| Fraud warnings | Phone, private `SharedPreferences` (`authentik_protection`) | Posting app and label, verdict, headline, reason titles, link **hostnames**, rules version. **No notification text** | Latest 20, at most 30 days; the user can dismiss or clear them |
| "Check links online" | Backend, in memory for the request only | Posting app, finding codes, link hostnames. **No text** | Not stored; the audit log records the verdict and link count, not the hosts |
| Web protection (VPN) lookups | Phone memory only, while answering | The looked-up name | Never stored or sent to Authentik. Forwarded to the network's DNS server (or Cloudflare/Google if the network provides none). Only a count is kept |
| Web protection events | Phone, private `SharedPreferences` (`authentik_vpn`) | Blocked or look-alike hostname, time, threat label or brand | Latest 50, at most 7 days; the user can clear them |
| Threat list | Phone, private file (`authentik-threat-list.json`) | Known-bad domains and brands, no user data | Replaced or patched on each update; stale after 3 days |

## Never collected

- Passwords (Firebase handles them), banking credentials, card numbers, PINs and OTPs.
- Full URLs with query strings or fragments, page HTML or screenshots from scans.
- Sandbox frames, or anything typed in the Sandbox (inputs are relayed, never stored).

## Redaction

`redactUrl` (`packages/shared/src/url.ts`) keeps the scheme, host and path. It replaces every
query *value* with `[redacted]` (keys stay, because they explain what a link does), drops
fragments and credentials, and replaces path segments that look like tokens (24+ URL-safe
characters, or 6+ digits).

## How expired data is deleted

The project runs on Firebase's free **Spark** plan, and Firestore's built-in TTL policies need
billing enabled. Instead, the API runs a **retention sweeper**
(`backend/src/storage/retention.ts`) at startup and then hourly. It physically deletes every
`reports`, `alerts` and `sandboxSessions` document whose `expiresAt` has passed. Between sweeps,
expired documents are already hidden, because every read filters them out.

The sweeper only runs while the API is running. If the API is scaled to zero for a long
stretch, expired documents stay hidden but are not physically removed until it next starts.
Every document also carries `_ttl` (a Firestore `Timestamp`). If you later move to the Blaze
plan, you can add TTL policies on `_ttl` for these three collections as a second mechanism.

Deletes count toward Spark's free quota of 20,000 per day.

## Third parties

| Recipient | What | Why |
|---|---|---|
| Google Safe Browsing (Lookup API, free) | Scheme + host + path of the checked URL (no query) | Threat reputation |
| Threat-feed hosts (if `THREAT_FEED_URLS` is set) | Nothing about users: the API downloads the feed | Known-bad domains |
| rdap.org → registry RDAP servers | Registrable domain | Registration age |
| The scanned site | One GET from the API's address, with a scanner user-agent and no cookies | Page evidence |
| Firebase (Google) | Identity, stored data, push | Platform |
