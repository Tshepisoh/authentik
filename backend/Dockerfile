# Build context: repository root (docker build -f backend/Dockerfile .)
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
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/packages/shared/package.json packages/shared/
COPY --from=build /app/packages/shared/dist packages/shared/dist
COPY --from=build /app/backend/package.json backend/
COPY --from=build /app/backend/dist backend/dist
USER node
EXPOSE 8080
CMD ["node", "backend/dist/index.js"]
