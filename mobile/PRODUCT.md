# Product

<!-- impeccable:product-schema 1 -->

## Platform

android

## Users

Everyday South African phone users. They get bank SMSes, WhatsApp messages about payments,
delivery-fee and refund texts, and links from strangers. Their tech confidence is mixed, and
many use mid-range Android phones. Their job: decide, in the moment, whether a message,
payment claim or website can be trusted, before they hand over goods, money or details.

## Product Purpose

Authentik is an Android-first financial security companion. It watches the signals Android
lets an app see (notifications, website lookups, shared links), checks them on the phone and
against threat data, and warns the user before they trust a fake payment claim or a fraudulent
site. Success: the user stops at the right moment, understands why, and knows the one thing to
do next (usually "check your own banking app").

## Positioning

It says what it checked, what it found and what it couldn't check. Missing evidence is shown
as "inconclusive", never as safe. A "payment received" notification is treated as a claim,
never as proof. Notification text never leaves the phone. Protection runs on the device
without the app being open.

## Operating Context

- Warnings arrive as Android notifications, often while the user is mid-conversation with a
  buyer, seller or "bank". The app is opened from that notification, under time pressure.
- Two always-on protections, each with its own Android permission and in-app disclosure:
  notification protection (notification access) and web protection (a local DNS-only VPN).
- Manual checks: website check (paste or share a link), payment check, a message checker
  for pasted text.
- History of reports, alerts, recent warnings and blocked sites; settings, privacy and
  account controls.
- Lock-screen notifications stay generic; details show only after unlock.

## Capabilities and Constraints

- Expo / React Native app (SDK 58); native Kotlin services for the listener and the VPN.
  Expo Router, existing shared UI kit in `src/shared/ui`.
- Verdicts: High risk, Suspicious, No obvious warnings, Inconclusive, Blocked. These come from
  the backend risk engine or the on-device mirror; the UI never invents its own.
- Google Play requires a separate VPN disclosure with an explicit accept, and explained
  consent before notification access.
- No paid services or billing-required features at this stage.
- iOS, web and Expo Go only get the manual features; protection screens must say so plainly.

## Brand Commitments

- Name: Authentik.
- Voice: calm, plain-spoken guardian. Steady and direct, never alarmist. Says what was checked
  and what wasn't. Like a sensible friend at the bank.
- Visual pattern (chosen 2026-10-24): the category standard, played straight. A Material 3
  Android security app, executed at full craft, with no novelty world. Quality bar: Google Play
  Protect / Android Security, Capitec and TymeBank apps, and Bitdefender / Norton Mobile.

## Evidence on Hand

- No real users, testimonials, partner banks, statistics or press yet. Do not fabricate any.
- Example scam messages in tests and docs are synthetic and must be labelled as examples.

## Product Principles

1. Stop the user at the right moment, then give one clear next step.
2. Never turn missing evidence into reassurance.
3. Process on the phone first; send the least possible.
4. Be honest about what Android lets us see.
5. Calm over alarm: severity is shown, not shouted.
