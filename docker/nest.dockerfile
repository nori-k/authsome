# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM node:24-slim AS builder
WORKDIR /app
COPY . .
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

# ---------- test ----------
FROM node:24-slim AS test
WORKDIR /app
COPY --from=builder /app /app
RUN corepack enable && pnpm install --frozen-lockfile --prod=false
CMD ["pnpm", "test"]

# ---------- production ----------
FROM gcr.io/distroless/nodejs24-debian12 AS production
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json .
COPY .env .env
ENV NODE_ENV=production
CMD ["dist/main.js"]
