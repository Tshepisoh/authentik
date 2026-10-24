# Feature flows

The product blueprint's flows, each mapped to the code that implements it. Where the
implementation goes further than the original flow, or differs from it, a note says so.

## 1. Account creation and onboarding

```mermaid
flowchart TD
  A[Open Authentik] --> B{Authenticated?}
  B -- Yes --> D[Open dashboard]
  B -- No --> C{Existing account?}
  C -- No --> E[Register with email and password] --> F[Validate input and create Firebase account] --> G[Verify email if required] --> H
  C -- Yes --> I[Sign in with Firebase Auth] --> J{Credentials valid?}
  J -- No --> K[Show safe error and retry] --> I
  J -- Yes --> H[Create or retrieve Authentik profile]
  H --> L[Show privacy and security onboarding] --> M[Explain scanning and Sandbox limitations] --> N[Choose Scan, Sandbox or History]
```

| Step | Implementation |
|---|---|
| Register / sign in / reset | `mobile/src/features/auth/identity.ts`. Passwords go to Firebase only. Error messages never reveal whether an account exists. |
| Profile create-or-retrieve | `GET /v1/me` → `AccountService.profile` |
| Onboarding | `mobile/src/app/onboarding.tsx` (three steps, plus the email-verification prompt); `PATCH /v1/me` |
| Route guards | `Stack.Protected` in `mobile/src/app/_layout.tsx`: signed out → auth screens; not onboarded → onboarding; otherwise the app |
| Sign out, revoke, delete, recovery | Settings → `POST /v1/me/sessions/revoke`, `DELETE /v1/me` (requires a recent sign-in), Firebase password reset |

## 2. Website scanning

```mermaid
flowchart TD
  A[Paste or share URL] --> B[Normalize and parse URL] --> C{Valid http/https URL?}
  C -- No --> D[Reject invalid URL: 400]
  C -- Yes --> E[Apply URL and SSRF safety checks] --> F{Allowed to scan?}
  F -- No --> G[Block and explain: verdict = blocked]
  F -- Yes --> H[Extract hostname and registrable domain]
  H --> I[Check reputation and known malicious URLs]
  H --> J[Check lookalike domains and impersonation]
  H --> K[Collect domain signals and registration age]
  H --> L[Fetch page safely: redirects and page evidence]
  I & J & K & L --> M[Apply deterministic risk rules] --> N[Generate evidence-based assessment] --> O[Save scan summary] --> P[Show verdict, evidence and recommended action]
```

Implemented in `backend/src/modules/scans/service.ts`. The checks run in parallel, and each records
a `CheckRun`. When the page redirects to another domain, impersonation and reputation checks also
run on the destination.

| Outcome | Meaning | Rule |
|---|---|---|
| High risk | Credible malicious indicators or strong impersonation | Confirmed threat ≥ high; a critical indicator; high severity with high-quality evidence; or ≥ 2 high |
| Suspicious | One or more concerning signals | Any high/medium indicator, or ≥ 2 low |
| No obvious warnings | Every critical check ran and nothing was found | — |
| Inconclusive | A critical check (reputation) was unavailable | Never silently becomes "no warnings" |
| Scan blocked | The target violates the destination policy | Hard block (private IPs, internal names, non-web ports) |

A new or unrated domain is a *signal* (`recently_registered`, medium), not a threat. HTTPS
produces no reassurance at all.

## 3. Sandbox: isolated browsing

```mermaid
flowchart TD
  A[User selects Open in Sandbox] --> B[Validate URL and permissions] --> C{Target permitted?}
  C -- No --> D[Reject or explain restrictions]
  C -- Yes --> E[Run initial website scan] --> E2{High risk?}
  E2 -- Yes, not acknowledged --> E3[Ask the user to acknowledge the risk]
  E2 -- No / acknowledged --> F[Create unique session ID] --> G[Start disposable isolated browser]
  G --> H[Apply network, permission and resource policies] --> H2{Isolation self-test passed?}
  H2 -- No --> X[Refuse: the site is never opened]
  H2 -- Yes --> I[Open target in remote browser] --> J[Stream rendered view to mobile app]
  J --> K[Monitor navigation and selected behaviours] --> L{Security event?}
  L -- Yes --> M[Block where possible and show warning] --> N
  L -- No --> N[Continue restricted browsing] --> O{Continue or close?}
  O -- Continue --> K
  O -- Close --> P[Revoke session access] --> Q[Terminate browser and delete temporary profile] --> R[Save permitted report metadata]
```

| Subflow | Behaviour | Where |
|---|---|---|
| Unexpected redirect | Main-frame domain change without user input within 2 s → `cross_domain_redirect` warning; the proxy still enforces the destination policy | `sandbox-worker/src/browser/session.ts` |
| Prohibited destination | Refused by the per-session egress proxy → `blocked_destination` (critical) | `network-policy/egress-proxy.ts` |
| Download attempt | `acceptDownloads: false` plus cancel → `download_blocked` | `session.ts` |
| Permission request | Empty permission set (always denied) plus a probe → `permission_denied` | `session.ts` |
| Pop-ups, dialogs, file pickers | Closed, dismissed or blocked, then reported | `session.ts` |
| Crash or timeout | `browser_crashed` → session destroyed; a new session can be started | `lifecycle/manager.ts`, `sessions/service.ts` |
| Expiry or idle | TTL (10 min default; worker hard cap 15 min) and idle timeout (2 min with no viewer) | reaper in `sessions/service.ts`; timer in `manager.ts` |
| Isolation failure | Proxy stops, or the self-test fails → `isolation_failure`, immediate teardown, error-level audit | `session.ts`, `sessions/service.ts` |
| User navigates to a blocked address | The viewer is told and the user's action is audited, but it is **not** counted against the site | `sessions/service.ts` |

The Sandbox never imports the user's cookies, profile or sessions. Every session gets a fresh
browser process with a throwaway profile.

## 4. Payment-flow integrity

```mermaid
flowchart TD
  A[User starts purchase] --> B[Record expected merchant and amount] --> C[Observe or receive checkout URL]
  C --> D[Validate redirect chain] --> E[Identify destination and payment provider] --> F[Obtain observed recipient and amount if available]
  F --> G[Compare expected and observed details] --> H{Sufficient trusted evidence?}
  H -- No --> I[Verification incomplete]
  H -- Yes --> J{Material discrepancy or threat?}
  J -- Yes --> K[Flag suspicious payment flow]
  J -- No --> L[No discrepancy detected]
  I & K & L --> M[Show evidence and next steps] --> N[User verifies independently before authorising]
```

Implemented in `backend/src/modules/payment-integrity/service.ts`. The MVP uses a **simulated
checkout** (seven scenarios on reserved `.test` domains) or details the user types in. It cannot
see inside third-party apps.

| Check | Finding codes |
|---|---|
| Unexpected or unrecognised redirects | `unrecognised_payment_redirect` (medium; high when the host imitates a brand), `unexpected_payment_provider` (low) |
| Imitation of a merchant or provider | `lookalike_domain`, `brand_in_subdomain`, … (shared with the scanner) |
| Recipient ≠ merchant | `payment_recipient_mismatch` (high) |
| Amount differences | `amount_matches`, `amount_within_adjustment` (allowed fees and delivery), `payment_amount_mismatch` (medium/high), `payment_amount_lower` (low), `payment_currency_mismatch` |
| Missing or contradictory evidence | `merchant_unknown`, `recipient_not_observed`, `amount_not_observed` → `inconclusive` |

A redirect to a recognised payment provider that the merchant is known to use produces
reassurance. A new or unknown processor is "suspicious — verify", never automatically
"malicious". Each organisation in the redirect chain is judged once, so a provider moving
between its own domains (`payfast.co.za` → `payfast.io`) counts as a single signal.

### Reading the amount and recipient automatically

`POST /v1/payment-checks/extract` takes either `{ checkoutUrl }` (opened in a throwaway
isolated browser) or `{ sandboxSessionId }` (reads the page the user has browsed to in the
Sandbox). The page is rendered **only in the worker**, never on the API, because it's untrusted and
often needs JavaScript to show its total.

- **What gets read** (`sandbox-worker/src/browser/extract.ts`): structured data (JSON-LD, microdata, price meta tags), then text next to labels ("Total due", "Amount payable", "Pay to", "Merchant", …), then "Pay R…" buttons, then loose amounts on the page, which count as weak evidence. Kinds of evidence that agree raise confidence. Two strongly labelled, different totals are never guessed between: the user picks.
- **Where the logic runs**: the in-page part only collects size-capped raw text. Interpretation happens in the worker, outside the page's reach.
- **Where the full address stays**: page URLs can carry payment-session tokens, so the full URL stays on the server for 10 minutes under an `extractionId`. The phone receives only a redacted address and the values read.
- **How values are merged**: in `POST /v1/payment-checks`, any value the user leaves empty is taken from the page. A value the user types that differs from the page raises `contradictory_payment_evidence` (medium). Reports record each value's source as `page`, `page_confirmed` or `user`.
- **The limit**: these are the page's own claims, and a fraudulent page can display false values. The app says so, and still tells the user to confirm on their bank's approval screen.

## 5. Unified risk engine

```mermaid
flowchart LR
  A[Website scan findings] --> D
  B[Sandbox observations] --> D
  C[Payment-flow findings] --> D
  D[Normalize security evidence] --> E[Check evidence quality and freshness] --> F[Apply deterministic rules] --> G[Assign risk level and confidence] --> H[Generate explanation from evidence] --> I[Save assessment and evidence references] --> J[Display recommended action]
```

`backend/src/modules/risk-engine/`. See [architecture.md](architecture.md#the-risk-model).

## 6. History and detailed reports

```mermaid
flowchart TD
  A[Open History] --> B[Authenticate and authorise] --> C[Load the user's report summaries] --> D{Reports available?}
  D -- No --> E[Empty state]
  D -- Yes --> F[Select a report] --> G[Show verdict, timestamp and findings] --> H{More detail?}
  H -- Yes --> I[Load evidence details] --> J[Explain source, limitations and next steps]
  H -- No --> K[Return to history]
  J --> L{Delete report?}
  L -- Yes --> M[Confirm] --> N[Delete the report and its alerts]
  L -- No --> O[Finish]
```

Every report shows the domain and time; findings grouped as confirmed threats, warning signs,
unknowns and reassurance, each with its source and evidence quality; redirects; recommended
actions; and whether the assessment was partial. Stored URLs are redacted: no query values, no
fragments, and no path segments that look like tokens.

## 7. Alerts and notifications

```mermaid
flowchart TD
  A[New security finding] --> B[Validate and deduplicate] --> C{Meets alert policy?}
  C -- No --> D[Keep the finding in its report]
  C -- Yes --> E[Create alert record] --> F[Show in-app warning] --> G{Push enabled?}
  G -- Yes --> H[Send privacy-conscious notification]
  G -- No --> I[Keep alert in app]
  H & I --> J[User opens alert] --> K[Show explanation and recommended action] --> L[Mark reviewed]
```

The policy (`modules/notifications/service.ts`): a confirmed threat of high severity or above,
or one of these codes at high severity or above: `credential_harvest`, `lookalike_domain`,
`blocked_destination`, `payment_recipient_mismatch`, `payment_amount_mismatch`, and similar.
Each report raises at most one alert, and alerts are deduplicated per code and domain for 24
hours. Push text is generic by default, never includes a URL or an amount, and Android shows it
with `PRIVATE` lock-screen visibility.

## 8. Settings, privacy and account controls

```mermaid
flowchart TD
  A[Open Settings] --> B{Choose setting}
  B --> C[Notification preferences] --> G[Validate and save]
  B --> D[Privacy and retention] --> H[Explain data collected and retention]
  B --> E[Manage account and sessions] --> I[Sign out or revoke sessions]
  B --> F[Request account deletion] --> J[Confirm and re-authenticate] --> K[Delete profile and associated data]
  G & H & I & K --> L[Show updated state]
```

The privacy screen is rendered from `GET /v1/privacy`, which is generated by
`SettingsService.privacyStatement()` from the live configuration. It states plainly that
deleting a report does **not** delete audit-log entries.

## 9. Backend security and Sandbox session management

```mermaid
flowchart TD
  A[Receive API request] --> B[Validate request schema] --> C[Authenticate Firebase token] --> D{Valid identity?}
  D -- No --> E[Reject 401]
  D -- Yes --> F[Apply rate and resource limits] --> G[Check ownership and session state] --> H{Authorised and within policy?}
  H -- No --> I[Reject and log security event]
  H -- Yes --> J[Execute operation] --> K[Return minimal response] --> L[Record permitted audit metadata]
```

In the implementation, authentication happens before schema validation, so unauthenticated
callers learn nothing about the schema. The Sandbox lifecycle manager is described in
[architecture.md](architecture.md#sandbox-session-lifecycle).

## 10. Future retailer, payment-provider and banking integrations

```mermaid
flowchart TD
  A[User begins checkout] --> B[Retailer or payment-provider integration] --> C[Obtain authorised order or payment context]
  C --> D[Verify source and transaction reference] --> E[Obtain authorised payment details] --> F[Compare merchant, recipient and amount]
  F --> G{Trusted data available?}
  G -- No --> H[Verification incomplete]
  G -- Yes --> I{Mismatch or known threat?}
  I -- Yes --> J[Warn and explain discrepancy]
  I -- No --> K[No discrepancy detected]
  H & J & K --> L[Display result]
```

The extension point is `backend/src/integrations/types.ts` (`PaymentContextProvider`). An
integration supplies an `ObservedPayment` from an official, consented interface, and the
existing payment-integrity comparison does the rest. Authentik must not bypass another app's
security controls.

## 11. Operations and incident handling

```mermaid
flowchart TD
  A[Service or security event] --> B[Classify] --> C{Security incident?}
  C -- Yes --> D[Contain affected worker or session] --> E[Revoke access and isolate] --> F[Preserve audit evidence] --> G[Investigate and remediate]
  C -- No --> H[Check health, timeout or capacity] --> I{Recoverable?}
  I -- Yes --> J[Retry within safe limits] --> K[Resume or return result]
  I -- No --> L[Fail closed with a useful error] --> M[Notify the user the operation was incomplete]
  G --> N[Verify recovery and review controls]
```

Fail-closed behaviours in code:

- Reputation provider down → the scan is `inconclusive` and the check reads "unavailable".
- Page fetch failed → the assessment is `partial`, and the explanation says which check is missing.
- Worker not configured, unreachable, or failing the isolation self-test → `503`, and the site is never opened.
- Isolation failure mid-session → immediate teardown and an error-level log.
- Worker protocol errors (more than 20 malformed messages) → the session is terminated.
- Repeated policy violations from one actor → an error-level audit log entry for paging.

See [threat-model.md](threat-model.md) for the incident runbook.
