#!/usr/bin/env bash
# Starts the API and the ngrok tunnel in one Render container.
# If either exits, the container exits and Render restarts it.
set -uo pipefail

: "${FIREBASE_ADMIN_JSON:?add FIREBASE_ADMIN_JSON in the Render environment}"
: "${AUDIT_SALT:?add AUDIT_SALT in the Render environment}"
: "${NGROK_AUTHTOKEN:?add NGROK_AUTHTOKEN in the Render environment}"
: "${NGROK_DOMAIN:?add NGROK_DOMAIN in the Render environment}"
PORT=${PORT:-8080}

umask 077
printf '%s' "$FIREBASE_ADMIN_JSON" > /tmp/firebase-admin.json

# SANDBOX_WORKER_URL/SECRET point at the Hugging Face worker; left empty, the Sandbox fails closed.
env -u FIREBASE_ADMIN_JSON -u NGROK_AUTHTOKEN \
  PORT="$PORT" AUTH_MODE=firebase STORAGE=firestore TRUST_PROXY_HOPS=1 \
  GOOGLE_APPLICATION_CREDENTIALS=/tmp/firebase-admin.json \
  node backend/dist/index.js &

health() { node -e "fetch('http://127.0.0.1:$PORT/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"; }
for _ in $(seq 60); do health && break; sleep 1; done
health || { echo "API did not become healthy" >&2; exit 1; }

# Phones reach the API through the same ngrok address as before, so the APKs don't change.
env -i PATH="$PATH" HOME=/tmp NGROK_AUTHTOKEN="$NGROK_AUTHTOKEN" \
  ngrok http "$PORT" --url="$NGROK_DOMAIN" --log=stdout --log-level=warn &

# Free services sleep without visits (Render after 15 minutes, Hugging Face after 48 hours),
# and ngrok traffic doesn't count. Visit this service and the sandbox worker every 10 minutes.
while sleep 600; do
  for url in "${RENDER_EXTERNAL_URL:-}" "${SANDBOX_WORKER_URL:-}"; do
    [ -n "$url" ] && URL="$url" node -e "fetch(process.env.URL.replace(/\/$/,'')+'/health').then(r=>{if(!r.ok)console.log('keep-alive',process.env.URL,r.status)},e=>console.log('keep-alive failed',process.env.URL,e.message))"
  done
done &

wait -n
echo "A process exited; stopping so Render restarts the service." >&2
exit 1
