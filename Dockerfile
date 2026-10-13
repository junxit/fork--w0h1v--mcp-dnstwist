# Build stage: compile the TypeScript server
FROM node:24-slim AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Production dependencies only
FROM node:24-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# dnstwist and its optional dependencies, in a virtualenv. py-tlsh has no wheel
# for some architectures, so this stage carries a compiler that the runtime
# image does not need. "full" adds dnspython, idna, tld, ppdeep, py-tlsh and
# geoip2 (WHOIS and banners need nothing extra).
FROM node:24-slim AS python
ARG DNSTWIST_VERSION=20250130
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-dev gcc g++ \
 && python3 -m venv /opt/dnstwist \
 && /opt/dnstwist/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/dnstwist/bin/pip install --no-cache-dir "dnstwist[full]==${DNSTWIST_VERSION}"

# Runtime stage: Node 24 + Python 3 + dnstwist. The server runs the bundled
# dnstwist directly, so no Docker-in-Docker is needed. The GeoLite2 database is
# not bundled: mount one and set GEOLITE2_MMDB to use the geoip option.
FROM node:24-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=python /opt/dnstwist /opt/dnstwist

WORKDIR /app
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY --from=builder /app/build ./build

ENV NODE_ENV=production \
    DNSTWIST_RUNNER=local \
    PATH=/opt/dnstwist/bin:$PATH
USER node
ENTRYPOINT ["node", "build/index.js"]
