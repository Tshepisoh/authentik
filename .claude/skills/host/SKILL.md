---
name: host
description: Host the Authentik API, sandbox worker and public https tunnel on this PC with Docker, check it works end to end, and build the judge and full APKs pointed at it. Use when the user says "host", "host the project", "start the server", "deploy here", or asks to update or restart the hosted stack.
---

# Host Authentik on this PC

The whole stack runs from `docker-compose.yml` at the repo root:

```
phone ──https──► ngrok (tunnel) ──► api :8080 ──(internal network)──► sandbox-worker :8090 ──► internet
```

- `api`: Express backend. Firebase Auth and Firestore are free Spark-plan services. Safe Browsing is free.
- `sandbox-worker`: Chromium for the remote "open safely" view. It needs about 3 GB of RAM and is never exposed.
- `tunnel`: ngrok with the account's free static domain, so the APK's API address never changes.

Work from the repo root. Follow the steps in order, and stop to tell the user when a step needs them.

## Rules (don't break these)
- **Never print, log, commit or paste secret values.** This covers `.env`, `backend/.env`, `sandbox-worker/.env`, `firebase-adminsdk.json` and the ngrok authtoken. Check them by presence and length only. They're already in `.gitignore` and `.dockerignore`. Keep it that way.
- Never handle the user's passwords. When a login is needed, ask the user to run it themselves, e.g. `! npx eas-cli@latest login`.
- Keep `NODE_ENV=production` in Docker. Don't switch to `AUTH_MODE=dev` or `STORAGE=memory` to get past an error. Fix the real cause.
- Never set `CHROMIUM_SANDBOX=false`, publish port 8090, or forward the tunnel to anything except `api:8080`. The worker opens scam sites, so its isolation matters.
- No paid services. Ask before installing software, or before changing Windows power or sleep settings.

## 1. Prerequisites
1. `git pull` to get the latest code.
2. Docker: `docker info`. If Docker is missing, ask the user, then install it with `winget install -e --id Docker.DockerDesktop`. Docker Desktop needs a sign-out or a reboot after installing. If Docker is installed but not running, start Docker Desktop and wait for `docker info` to succeed.
3. Memory: `docker info --format "{{.MemTotal}}"` should be at least about 6 GB (6000000000). If it's lower, tell the user how to raise it: Docker Desktop › Settings › Resources, or `%UserProfile%\.wslconfig` with `[wsl2]` and `memory=8GB`, then `wsl --shutdown`.
4. Node.js 24+ and npm (`node -v`) are only needed for step 5, building the APK.

## 2. Secrets (copied by hand from the old PC, never in git)
These files must exist:

| File | Holds |
|---|---|
| `.env` (repo root) | `SANDBOX_WORKER_SECRET` (32+ chars), `NGROK_AUTHTOKEN`, `NGROK_DOMAIN` |
| `backend/.env` | API settings: `FIREBASE_PROJECT_ID`, `AUDIT_SALT`, `GOOGLE_SAFE_BROWSING_API_KEY`, etc. |
| `firebase-adminsdk.json` (repo root) | Firebase Admin service-account key, used by the API for Auth and Firestore |

Check them without showing values:

```bash
for f in .env backend/.env firebase-adminsdk.json; do [ -s "$f" ] && echo "ok  $f" || echo "MISSING  $f"; done
awk -F= '/^SANDBOX_WORKER_SECRET=/{print "SANDBOX_WORKER_SECRET length", length($2)} /^NGROK_AUTHTOKEN=/{print "NGROK_AUTHTOKEN set:", length($2)>0} /^NGROK_DOMAIN=/{print "NGROK_DOMAIN =", $2}' .env
node -e "const k=require('./firebase-adminsdk.json');console.log('service account for project', k.project_id, k.private_key?'(has key)':'(NO KEY)')"
```

- **If `backend/.env` or `firebase-adminsdk.json` is missing:** stop. Ask the user to copy it from the old PC (USB stick or password manager, not email or chat) into the same path. The ones on the old PC are at `C:\Users\TshepisoHlahla\authentik\`. If the Firebase key is lost, the user can make a new one: Firebase console › Project settings › Service accounts › Generate new private key (project `authentik-5e5f1`).
- **If `.env` is missing:** copy `.env.example` to `.env`. Generate the worker secret with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` and write it into the file without echoing it.
- **If `NGROK_AUTHTOKEN` or `NGROK_DOMAIN` is empty:** the user needs a free ngrok account (no card). They copy the authtoken from dashboard.ngrok.com › Your Authtoken, and the static domain from dashboard.ngrok.com › Domains (every free account has one, e.g. `something.ngrok-free.app`). Ask them to paste both into `.env` themselves. `NGROK_DOMAIN` is the bare hostname, with no `https://`.

## 3. Start the stack
```bash
docker compose --profile tunnel up -d --build
```
The first build takes 5–15 minutes, mostly pulling the Playwright image. Later starts take seconds. Every service has `restart: unless-stopped`, so the stack comes back after a reboot once Docker Desktop starts.

## 4. Check it works (all of these, not just one)
```bash
docker compose --profile tunnel ps            # api "healthy"; sandbox-worker and tunnel "running"
curl -fsS http://127.0.0.1:8080/health        # {"status":"ok"}
curl -fsS "https://$NGROK_DOMAIN/health"      # same, through the tunnel (read NGROK_DOMAIN from .env)
curl -s -o /dev/null -w "%{http_code}\n" "https://$NGROK_DOMAIN/v1/reports"   # 401 = auth is enforced
docker compose logs api --tail 40             # "authentik api listening", sandbox "configured", reputation includes google_safe_browsing
docker compose logs sandbox-worker --tail 40  # "sandbox worker listening", no Chromium sandbox errors
docker compose logs tunnel --tail 20          # "started tunnel" with the static domain
```

Common failures:
- **`Invalid configuration:` in the api logs:** a value in `backend/.env` fails `backend/src/config.ts`. Production refuses `AUTH_MODE=dev`, `STORAGE=memory` and the default `AUDIT_SALT`. Tell the user which key is wrong, not its value.
- **Firebase errors (`Could not load the default credentials`, `invalid_grant`):** `firebase-adminsdk.json` is missing, malformed or revoked. It's mounted at `/run/secrets/firebase_admin`. Also check the PC's clock is right.
- **`ERR_NGROK_…` in the tunnel logs:** a wrong authtoken, or a domain that doesn't belong to that account. `ERR_NGROK_108` means another tunnel already uses this account, so stop the old one (for example on the old PC).
- **The worker fails to launch Chromium:** usually low memory or Docker Desktop not using WSL 2. Report it to the user. Don't turn the sandbox off. The rest of the app works without the worker, because the Sandbox fails closed.
- **Port 8080 in use:** something else on the PC uses it. Stop that process, or change only the host side of `127.0.0.1:8080:8080`.

## 5. Build the APKs (only when needed)
The APK has the API address built in. Rebuild only when `build.hosted.env.EXPO_PUBLIC_API_URL` in `mobile/eas.json` isn't `https://<NGROK_DOMAIN>`, or the app code changed.

1. Set `EXPO_PUBLIC_API_URL` in `mobile/eas.json` (profile `hosted`; `judge` extends it) to `https://<NGROK_DOMAIN>`. Commit and push the change.
2. `cd mobile && npm ci`
3. Check the Expo login with `npx eas-cli@latest whoami`. It must be **tshepiso22** (the user's personal account, never the work account). If it isn't, ask the user to run `! npx eas-cli@latest login`.
4. Build both:
   - `npx eas-cli@latest build -p android --profile judge --non-interactive --no-wait`: **for judges and testers.** It has no notification listener, so Play Protect lets it install from a link (the in-app "Check a message yourself" uses the same on-device rules).
   - `npx eas-cli@latest build -p android --profile hosted --non-interactive --no-wait`: the full app with automatic notification protection. Play Protect blocks it when sideloaded, so it's for the owner's phone (Play Protect off) or `adb install`.
5. Check progress with `npx eas-cli@latest build:list --limit 2`. Each build takes about 15 minutes on the free tier. Give the user both APK links from expo.dev.

## 6. Hand-off message to the user
Tell the user:
- The public API address.
- That the stack restarts automatically.
- That the PC must stay on and awake while judges test. Offer, and only with permission: `powercfg /change standby-timeout-ac 0` and `powercfg /change hibernate-timeout-ac 0`. Also tick Docker Desktop › Settings › General › "Start Docker Desktop when you sign in".
- The APK links: judge build for judges.

## Day-to-day
- **Update after a `git pull`:** `docker compose --profile tunnel up -d --build`
- **Logs:** `docker compose logs -f api`
- **Stop:** `docker compose --profile tunnel down` (data lives in Firestore, so nothing is lost)
