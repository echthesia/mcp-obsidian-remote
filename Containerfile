# ---------------------------------------------------------------------------
# Stage 1: build — install all deps + compile TypeScript
# ---------------------------------------------------------------------------
FROM node:22-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: deps — production dependencies only
# ---------------------------------------------------------------------------
FROM node:22-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ---------------------------------------------------------------------------
# Stage 3: runtime — minimal final image
# ---------------------------------------------------------------------------
FROM node:22-slim AS runtime

RUN mkdir -p /data/vault && chown node:node /data/vault

WORKDIR /app

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/mcp').then(r=>{if(r.status>=500)throw r.status}).catch(()=>{process.exit(1)})"

ENTRYPOINT ["node"]
CMD ["dist/index.js"]
