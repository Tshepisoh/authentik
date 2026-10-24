# Build context: repository root (docker build -f sandbox-worker/Dockerfile .)
# The Playwright image ships Chromium and its system dependencies. Its tag MUST match the
# playwright-core version in sandbox-worker/package.json, or the browser won't be found.
FROM mcr.microsoft.com/playwright:v1.64.1-noble AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json packages/shared/
COPY backend/package.json backend/
COPY sandbox-worker/package.json sandbox-worker/
RUN npm ci --workspace @authentik/shared --workspace @authentik/sandbox-worker --include-workspace-root --ignore-scripts
COPY packages/shared packages/shared
COPY sandbox-worker sandbox-worker
RUN npm run build -w @authentik/shared && npm run build -w @authentik/sandbox-worker \
 && npm prune --omit=dev --workspace @authentik/shared --workspace @authentik/sandbox-worker

FROM mcr.microsoft.com/playwright:v1.64.1-noble
ENV NODE_ENV=production \
    CHROMIUM_SANDBOX=true \
    HOME=/tmp
WORKDIR /app
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/packages/shared/package.json packages/shared/
COPY --from=build /app/packages/shared/dist packages/shared/dist
COPY --from=build /app/sandbox-worker/package.json sandbox-worker/
COPY --from=build /app/sandbox-worker/dist sandbox-worker/dist
# Unprivileged user provided by the Playwright image. Browser profiles live in /tmp (a tmpfs at runtime).
USER pwuser
EXPOSE 8090
CMD ["node", "sandbox-worker/dist/index.js"]
