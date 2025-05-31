# syntax=docker/dockerfile:1.16

FROM node:24-slim
WORKDIR /app
COPY ./frontend/package.json ./frontend/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY ./frontend ./
CMD ["pnpm", "run", "dev", "--", "--host"]
