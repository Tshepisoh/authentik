---
title: Authentik Sandbox
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: gradio
sdk_version: 5.9.1
app_file: app.py
pinned: false
---

# Authentik sandbox worker on a Hugging Face Space

Runs only the sandbox worker: the isolated browser behind "Open safely in the Sandbox" and
automatic checkout reading. The API runs elsewhere (Render) and calls this Space over HTTPS
with the shared secret in an `x-worker-secret` header.

`app.py` installs Node.js and Chromium on first start (a few minutes), then runs the worker
on port 7860. `packages.txt` installs Chromium's system libraries.

## Weaker than docker-compose.yml
- No separate networks, seccomp profile or dropped capabilities.
- Chromium's own sandbox is used if the Space allows it; otherwise it's off (the log says so).
- This Space holds no keys except the worker secret, so a browser escape reaches nothing else.
- The worker's egress proxy still blocks private ranges and cloud metadata.

## Settings
| Name | Kind | Value |
|---|---|---|
| `SANDBOX_WORKER_SECRET` | secret | Same value as on the API (32+ characters) |

The Space is public, because a private one uses the `authorization` header for its own login.
Only the worker's built code is here, and every call except `/health` needs the secret.
