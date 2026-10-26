# API on Render (free)

`render.yaml` at the repo root runs the API and the ngrok tunnel on a free Render web service.
Phones keep using the ngrok address, so the APKs don't change. Free, no card.

## Limits
- **No Sandbox.** The free plan has 512 MB, too little for Chromium. "Open safely in the
  Sandbox" and automatic checkout reading report themselves unavailable. Everything else works.
- Free services sleep after 15 minutes without visits through Render. `start.sh` visits the
  service's own address every 10 minutes. One service running all month fits the 750 free hours.
- Restarts (deploys, maintenance) take about a minute.

## Set up
1. Sign in at render.com with GitHub.
2. **New › Blueprint**, pick this repository. Render reads `render.yaml`.
3. Fill in the values it asks for. Copy them from this PC, never through chat:

| Name | Copy from |
|---|---|
| `FIREBASE_ADMIN_JSON` | Whole contents of `firebase-adminsdk.json` |
| `AUDIT_SALT`, `GOOGLE_SAFE_BROWSING_API_KEY`, `FIREBASE_PROJECT_ID` | `backend/.env` |
| `NGROK_AUTHTOKEN`, `NGROK_DOMAIN` | `.env` |
| `THREAT_FEED_URLS` | Optional, see `backend/.env.example` (leave empty to skip) |

4. Only one machine can hold the ngrok domain at a time. Before the first deploy finishes,
   stop the tunnel on the PC: `docker compose stop tunnel`.

Pushes to `main` that touch the API redeploy it automatically.
