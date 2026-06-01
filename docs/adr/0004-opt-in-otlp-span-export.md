# Opt-in OTLP span export: HTTP/protobuf, env-gated, per-invocation flush on Lambda

**Status:** Accepted
**Date:** 2026-05-29
**Issue:** [#218](https://github.com/wingnut128/netcidr/issues/218) (ENG-91)
**Related:** [[ADR-0002 — RBAC role config and per-handler extractors]](./0002-rbac-role-config-and-per-handler-extractors.md)

## Context

Telemetry is `tracing` + `tracing-subscriber` (JSON) → stderr → CloudWatch.
The API handlers already carry `#[instrument]` spans, but nothing exports them
to an APM. We want opt-in span export to an OTLP collector (Honeycomb, or any
OTLP backend) without imposing cost on local dev or unconfigured deployments,
and without leaking credentials/PII into the exported spans.

## Decisions

1. **Off by default, env-gated, behind a Cargo feature.** Span export lives
   behind the optional `otel` feature (not in `default`). Even when compiled
   in, the OTel layer is attached only when `OTEL_EXPORTER_OTLP_ENDPOINT` is
   set at runtime — otherwise no layer is attached and the SDK is never
   initialized. Local dev and unconfigured deployments pay zero overhead. The
   default build pulls none of the OTel crates.

2. **HTTP/protobuf transport over reqwest+rustls — no gRPC/tonic.**
   `opentelemetry-otlp` is configured with `http-proto` + `reqwest-client` +
   `reqwest-rustls-webpki-roots` (`default-features = false`). reqwest and
   rustls are already in the tree. We deliberately avoid the `grpc-tonic`
   transport (no native deps, smaller surface, simpler in Lambda). Note: the
   `opentelemetry-proto` crate still pulls `tonic-prost` for protobuf *message*
   types (not the gRPC client/transport), and `tonic` was **already** present
   in the default tree via `tower_governor` — so OTel adds no net-new tonic.

3. **Lambda export = batch + per-invocation `force_flush()`.** A Lambda
   execution environment can freeze between invocations, so a plain batch
   exporter risks losing buffered spans. We keep the batch processor but add an
   **outermost middleware** that calls `provider.force_flush()` after every
   response (bounded latency at request end, no in-flight loss). `netcidr serve`
   has no freeze problem — it uses the plain batch processor and flushes on
   graceful shutdown.

4. **PII allowlist is enforced at the export boundary, not just documented.**
   The `tracing`→OTel bridge exports *every* field recorded on a span, and some
   `#[instrument]` sites legitimately record `owner_email` for CloudWatch logs.
   To guarantee credentials/PII never reach the collector, a `RedactingExporter`
   wraps the OTLP exporter and strips any attribute whose key matches a PII /
   credential pattern (`*email`, `sub`/`*_sub`, `*token*`, `*secret*`,
   `*password*`, `authorization`, `*api_key*`, `*credential*`, `database_url`,
   `bearer`) before the batch leaves the process. Intended attributes are
   `http.route`, `http.method`, `http.status_code`, `netcidr.tenant_id`,
   `netcidr.role`.

   **Why a denylist (strip PII) rather than a strict allowlist (emit only the
   five):** a strict allowlist would also drop operationally useful, non-PII
   fields the calc/IPAM handlers already record (`cidr`, `prefix`, `count`, …)
   and tower-http's `http.*`. The pattern denylist preserves those while
   guaranteeing no email/sub/token/secret/DB-URL is ever exported. The patterns
   match by shape, so fields added at future `#[instrument]` sites (e.g. another
   `*_email`) are covered without code changes. The tradeoff — a brand-new
   sensitive field with a non-matching key name could slip through — is
   mitigated by the broad shape patterns and is called out here for reviewers.

5. **Sampling: parent-based ratio from `OTEL_TRACES_SAMPLER_ARG`** (default
   `1.0` = sample everything; clamped to `[0,1]`). Low traffic today; the env
   hook lets us dial it down later without a code change.

6. **OTel-generic env convention** (`OTEL_EXPORTER_OTLP_ENDPOINT`,
   `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER_ARG`)
   rather than Honeycomb-specific vars — Honeycomb works as one configuration
   (`OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=<key>`). Keeps us vendor-
   portable.

## Consequences

- Default builds and unconfigured/local runs are unaffected (no OTel crates, no
  layer, no overhead).
- Measured one-time pipeline init cost is **~5 ms** locally (exporter + provider
  construction) — well within the +50 ms p99 cold-start budget. The per-request
  `force_flush` on Lambda adds bounded latency only when spans are buffered.
- `cargo audit` introduces **no new advisories** (the existing `rand 0.8.5`
  warning via `termwiz` is pre-existing and unrelated).
- Net-new crates are limited to the `opentelemetry*` family + `prost` /
  `opentelemetry-proto`, all compiled only under `--features otel`.

## Out of scope (follow-ups)

- Positively enriching request spans with `netcidr.tenant_id` / `netcidr.role`
  (the redaction guarantees safety today; enrichment is additive).
- Metrics export, logs-over-OTLP, deployment-side Honeycomb config in
  `netcidr-deploy`.
