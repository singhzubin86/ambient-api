# ── Build stage ────────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (production + dev needed for tsc)
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and compile
COPY tsconfig.json ./
COPY src/ ./src/
COPY migrations/ ./migrations/
RUN npm run build

# ── Production stage ───────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

# Non-root user for security
RUN addgroup -S ambient && adduser -S ambient -G ambient

WORKDIR /app

# Production dependencies only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Compiled output
COPY --from=builder /app/dist ./dist
COPY migrations/ ./migrations/

# WAL volume mount point — must be a real named volume, not tmpfs (Sentinel Decision 2)
# Fly mounts ambient_wal at /data/wal; ensure the dir exists in the image
RUN mkdir -p /data/wal/dead_letter && chown -R ambient:ambient /data

USER ambient

EXPOSE 8080

# SIGTERM triggers graceful shutdown in src/index.ts
CMD ["node", "dist/src/index.js"]
