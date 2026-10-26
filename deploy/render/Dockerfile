# Render free web service: the API and the ngrok tunnel in one container. No sandbox worker
# (512 MB is too small for Chromium), so the Sandbox reports itself unavailable.
# Build context: repository root. See deploy/render/README.md.
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json packages/shared/
COPY backend/package.json backend/
COPY sandbox-worker/package.json sandbox-worker/
RUN npm ci --workspace @authentik/shared --workspace @authentik/backend --include-workspace-root --ignore-scripts
COPY packages/shared packages/shared
COPY backend backend
RUN npm run build -w @authentik/shared && npm run build -w @authentik/backend \
 && npm prune --omit=dev --workspace @authentik/shared --workspace @authentik/backend

FROM node:24-slim
ADD https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz /tmp/ngrok.tgz
RUN tar -xzf /tmp/ngrok.tgz -C /usr/local/bin && rm /tmp/ngrok.tgz
ENV NODE_ENV=production \
    NODE_OPTIONS=--max-old-space-size=384
WORKDIR /app
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/packages/shared/package.json packages/shared/
COPY --from=build /app/packages/shared/dist packages/shared/dist
COPY --from=build /app/backend/package.json backend/
COPY --from=build /app/backend/dist backend/dist
COPY deploy/render/start.sh ./
RUN chmod 755 start.sh
USER node
CMD ["./start.sh"]
