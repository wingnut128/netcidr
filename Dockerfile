# syntax=docker/dockerfile:1
#
# Build args:
#   FEATURES       - Cargo feature flags (default: "default" which includes swagger + dashboard)
#   WITH_DASHBOARD - "true" builds the React dashboard; "false" skips it (default: true)
#
# Examples:
#   docker build .                                          # full build with dashboard
#   docker build --build-arg FEATURES=swagger .             # no dashboard
#   docker build --build-arg FEATURES="" .                  # slim: no swagger, no dashboard
#
# Runtime is Chainguard's distroless `static` image: no shell, no package manager,
# minimal CVE surface. Because there is no shell, HEALTHCHECK is delegated to the
# orchestrator (Kubernetes probe, docker-compose healthcheck with TCP probe, etc.).
#
ARG FEATURES=default
ARG WITH_DASHBOARD=true

# ---------- Dashboard build (skipped when WITH_DASHBOARD=false) -----------
FROM oven/bun:1-alpine@sha256:07235578f79ef8c6f97d94aee7938e76f5cdba5f21ae5dbfdd3d3d38058437eb AS dashboard-build
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/bun.lock ./
RUN bun install --frozen-lockfile
COPY dashboard/ ./
RUN bun run build

# When dashboards are disabled, use the same Rust builder image to create an empty
# placeholder directory. Chainguard/static has no shell, so we can't `mkdir` there.
FROM rust:1.95-alpine3.23@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS dashboard-false
RUN mkdir -p /app/dashboard/dist

FROM dashboard-build AS dashboard-true

# ---------- Select dashboard stage based on build arg ---------------------
FROM dashboard-${WITH_DASHBOARD} AS dashboard

# ---------- Rust build ---------------------------------------------------
# Alpine's official Rust image produces a fully statically-linked musl binary.
# Chainguard's `rust:latest-dev` (Wolfi) does not ship a musl rust-std target,
# so we keep Alpine for the build stage and rely on Chainguard only for the
# runtime — the artifact copied into the final image is what matters for CVE
# surface.
FROM rust:1.95-alpine3.23@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS builder

ARG FEATURES

# musl-dev: static linking; curl: required by utoipa-swagger-ui build script
RUN apk add --no-cache musl-dev curl

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
COPY build.rs ./build.rs

# Build the release binary. The .git directory is not present in the build
# context, so build.rs falls back to "unknown" for GIT_SHA_{SHORT,FULL}.
RUN touch src/main.rs && \
    cargo build --release --no-default-features --features "${FEATURES}"

# ---------- Runtime -------------------------------------------------------
# cgr.dev/chainguard/static:latest — distroless, nonroot by default, CA bundle
# bundled at /etc/ssl/certs/ca-certificates.crt, no shell, no package manager.
# Tag + digest pinning: the tag tells digestabot what to track, the digest
# guarantees reproducibility. Chainguard's `static` image is not versioned
# beyond `:latest` / `:latest-glibc`, so `:latest` is the recommended tag per
# their docs. Digestabot refreshes the digest on a schedule (.github/workflows/digestabot.yml).
FROM cgr.dev/chainguard/static:latest@sha256:96d02f455d5a73b817c0602910748609cf8471b1cc9522f78c75cedb1f67d072

COPY --from=builder /app/target/release/netcidr /usr/local/bin/netcidr

WORKDIR /app

# Chainguard/static runs as uid 65532 (nonroot) by default.
USER nonroot

EXPOSE 8080

# No HEALTHCHECK: the distroless runtime has no shell. Delegate to the
# orchestrator (Kubernetes probe, docker-compose TCP/HTTP probe on :8080/health).

ENTRYPOINT ["netcidr"]
CMD ["--help"]
