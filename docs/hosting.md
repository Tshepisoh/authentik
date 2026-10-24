# Hosting

Authentik runs on one PC with Docker, using free services only:
- the API
- the sandbox worker
- an ngrok tunnel that gives phones a fixed `https://` address

The step-by-step runbook is `.claude/skills/host/SKILL.md`. On the hosting PC, open Claude Code in the repo and say **"host"**. It follows that runbook. You can also follow it by hand.

## What you copy by hand (never committed)

| File | From the old PC |
|---|---|
| `.env` | `SANDBOX_WORKER_SECRET`, `NGROK_AUTHTOKEN`, `NGROK_DOMAIN` (see `.env.example`) |
| `backend/.env` | API settings and keys (see `backend/.env.example`) |
| `firebase-adminsdk.json` | Firebase Admin service-account key |

Use a USB stick or a password manager, not email or chat. Put them at the same paths in the new clone.

## What the hosting PC needs
- Docker Desktop with WSL 2, and about 6 GB of RAM for Docker (Chromium in the worker uses up to 3 GB).
- Node.js 24+, only for building APKs.
- A free ngrok account (no card). Its authtoken and static domain go in `.env`.
- The PC must stay on and awake while people use the app.

## APKs
- `judge` profile: no notification listener. Play Protect's enhanced fraud protection blocks sideloaded apps that declare one, so this is the APK to share. "Check a message yourself" runs the same on-device rules.
- `hosted` profile: the full app. It's blocked when sideloaded. Use it on your own phone (Play Protect off, or `adb install`), or ship it through Google Play later.

Both profiles get the API address from `build.hosted.env.EXPO_PUBLIC_API_URL` in `mobile/eas.json`.

## Limits of this setup
- One PC is a single point of failure: no redundancy and no backups beyond Firestore's own.
- Free ngrok has monthly bandwidth limits. That's fine for judging, but not for a public launch.
- Safe Browsing's free tier is for non-commercial use. A real launch needs a commercial reputation provider and hosting (a later decision).
