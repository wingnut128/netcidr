# syntax=docker/dockerfile:1
#
# Build args:
#   FEATURES  - Cargo feature flags (default: "default" which includes swagger + dashboard)
#
# Examples:
#   docker build .                                          # full build with dashboard
#   docker build --build-arg FEATURES=swagger .             # no dashboard
#   docker build --build-arg FEATURES="" .                  # slim: no swagger, no dashboard
#
ARG FEATURES=default
ARG WITH_DASHBOARD=true

# ---------- Dashboard build (skipped when WITH_DASHBOARD=false) -----------
FROM oven/bun:alpine AS dashboard-build
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/bun.lock ./
RUN bun install --frozen-lockfile
COPY dashboard/ ./
RUN bun run build

FROM alpine:3.21 AS dashboard-false
RUN mkdir -p /app/dashboard/dist

FROM dashboard-build AS dashboard-true

# ---------- Select dashboard stage based on build arg ---------------------
FROM dashboard-${WITH_DASHBOARD} AS dashboard

# ---------- Rust build ---------------------------------------------------
FROM rust:1.88-alpine AS builder

ARG FEATURES

RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --no-default-features --features "${FEATURES}" && \
    rm -rf src

# Copy dashboard output (real or empty depending on WITH_DASHBOARD)
COPY --from=dashboard /app/dashboard/dist ./dashboard/dist

# Copy actual source code
COPY src ./src
COPY tests ./tests

# Build the release binary
RUN touch src/main.rs && \
    cargo build --release --no-default-features --features "${FEATURES}"

# ---------- Runtime -------------------------------------------------------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

RUN addgroup -g 1000 netcidr && \
    adduser -u 1000 -G netcidr -s /bin/sh -D netcidr

WORKDIR /app

COPY --from=builder /app/target/release/netcidr /usr/local/bin/netcidr

USER netcidr

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["netcidr"]
CMD ["--help"]
