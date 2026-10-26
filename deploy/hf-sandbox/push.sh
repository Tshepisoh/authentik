#!/usr/bin/env bash
# Builds the sandbox worker and pushes it, with the Space files, to a Hugging Face Space.
# Only manifests and built output go up: no source of the API, no .env files, no keys.
# Usage: deploy/hf-sandbox/push.sh <hf-username>/<space-name>
set -euo pipefail
SPACE=${1:?usage: deploy/hf-sandbox/push.sh <hf-username>/<space-name>}
ROOT=$(git rev-parse --show-toplevel)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

cd "$ROOT"
npm run build -w @authentik/shared
npm run build -w @authentik/sandbox-worker

# npm ci checks every workspace manifest against the lockfile, so backend's manifest comes too.
mkdir -p "$OUT/packages/shared" "$OUT/sandbox-worker" "$OUT/backend"
cp package.json package-lock.json "$OUT/"
cp packages/shared/package.json "$OUT/packages/shared/"
cp -r packages/shared/dist "$OUT/packages/shared/"
cp sandbox-worker/package.json "$OUT/sandbox-worker/"
cp -r sandbox-worker/dist "$OUT/sandbox-worker/"
cp backend/package.json "$OUT/backend/"
cp deploy/hf-sandbox/app.py deploy/hf-sandbox/packages.txt deploy/hf-sandbox/README.md "$OUT/"
find "$OUT" -name '*.test.*' -delete

cd "$OUT"
git init -q -b main
git add -A
git -c user.name="$(git -C "$ROOT" config user.name)" -c user.email="$(git -C "$ROOT" config user.email)" \
  commit -qm "Deploy sandbox worker $(git -C "$ROOT" rev-parse --short HEAD)"
# Each deploy replaces the Space's files with this snapshot.
git push --force "https://huggingface.co/spaces/$SPACE" main
