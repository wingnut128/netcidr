# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.27.0](https://github.com/wingnut128/netcidr/compare/v0.26.12...v0.27.0) - 2026-06-18

### Security

- *(auth)* cap active PATs per tenant (default 25, configurable via `max_pats_per_tenant`); `POST /me/tokens` returns 429 when the cap is reached (ENG-108)
- *(api)* enable per-IP rate limiting under Lambda via tower-governor's `SmartIpKeyExtractor`, which keys on the `X-Forwarded-For` header API Gateway sets (falls back to the TCP peer for direct clients). The Lambda limit is tunable with `NETCIDR_RATE_LIMIT` / `NETCIDR_RATE_LIMIT_BURST`. Auth-specific throttling is explicitly deferred — see ADR-0005 (ENG-103)

## [0.26.12](https://github.com/wingnut128/netcidr/compare/v0.26.11...v0.26.12) - 2026-06-18

### Fixed

- *(dashboard)* use delVoid for CIDR block delete to handle 204 No Content

### Other

- prohibit direct commits to main in CLAUDE.md

## [0.26.11](https://github.com/wingnut128/netcidr/compare/v0.26.10...v0.26.11) - 2026-06-18

### Other

- replace Cloudsmith API key auth with OIDC
- fix Cloudsmith image path and add ipam-postgres feature flags
- add Cloudsmith multi-arch image publish workflow
- add kill chain x STRIDE threat analysis report
- add STRIDE threat model report

## [0.26.10](https://github.com/wingnut128/netcidr/compare/v0.26.9...v0.26.10) - 2026-06-17

### Added

- *(ipam)* add tenant_id to allocation_tags for defense-in-depth isolation ([#266](https://github.com/wingnut128/netcidr/pull/266))
- *(ipam)* paginate list endpoints and cap audit limit ([#265](https://github.com/wingnut128/netcidr/pull/265))

### Fixed

- *(ipam)* restrict SQLite DB perms to 0600 and cap auto-allocate count ([#264](https://github.com/wingnut128/netcidr/pull/264))
- *(mcp)* encode remote-client URLs and send bearer token ([#257](https://github.com/wingnut128/netcidr/pull/257))
- *(mcp)* refuse non-loopback HTTP bind without --allow-public-bind ([#255](https://github.com/wingnut128/netcidr/pull/255))
- *(dashboard)* bump vite 8.0.10 -> 8.0.16 to clear GHSA-fx2h-pf6j-xcff ([#256](https://github.com/wingnut128/netcidr/pull/256))

### Other

- *(deps)* bump the npm-minor-and-patch group in /dashboard with 7 updates ([#249](https://github.com/wingnut128/netcidr/pull/249))
- remove S3-backed SQLite persistence for Lambda ([#258](https://github.com/wingnut128/netcidr/pull/258))
- *(deps)* bump release-plz/action from 0.5.129 to 0.5.130 ([#248](https://github.com/wingnut128/netcidr/pull/248))
- *(dashboard)* pin npm deps to exact versions and harden install config ([#247](https://github.com/wingnut128/netcidr/pull/247))

### Added

- Pagination for the IPAM list endpoints. `GET /ipam/cidr-blocks`, `GET /ipam/cidr-blocks/{id}/allocations`, `GET /ipam/hostnames`, and `GET /ipam/hostnames/history` now accept `limit` and `offset` query params, applied as SQL `LIMIT`/`OFFSET` (SQLite and Postgres). The HTTP layer defaults `limit` to 100 and clamps it to a maximum of 1000, bounding response size and memory; CLI and internal callers remain unbounded ([#260](https://github.com/wingnut128/netcidr/issues/260)).

### Removed

- Removed the S3-backed SQLite persistence mode for the Lambda binary (`NETCIDR_S3_BUCKET`/`NETCIDR_S3_KEY`, the `s3_sync` module, and the `hmac` dependency). The Lambda binary now uses the Postgres backend exclusively (`NETCIDR_DATABASE_URL`). This removes the attack surface behind the S3 sync finding — no integrity check on pull, no client-side encryption, and a symlink-unsafe local DB path ([#254](https://github.com/wingnut128/netcidr/issues/254)).

### Security

- **Harden dashboard package files (supply-chain).** Pinned every dashboard dependency in `dashboard/package.json` to an exact version (removed `^` caret ranges) matching the resolved `bun.lock`, so the manifest is the source of truth and nothing silently floats forward. Added a `packageManager` pin (`bun@1.3.14`) and an `engines` constraint, plus `dashboard/bunfig.toml` with `[install] exact = true` so future `bun add` invocations stay pinned. Lifecycle/postinstall scripts remain disabled by Bun's default (no `trustedDependencies`).
- Bump dashboard `vite` from 8.0.10 to 8.0.16, clearing high-severity advisory [GHSA-fx2h-pf6j-xcff](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) (`server.fs.deny` bypass via Windows alternate paths). The dev server isn't shipped in the embedded single-file build, but the bump unblocks the CI `bun audit` gate.
- The MCP HTTP transport now refuses to bind to a non-loopback address unless the new `--allow-public-bind` flag is passed. The HTTP transport has no authentication, so a non-loopback bind previously exposed every IPAM tool (read and write) to any reachable client. The default bind (`127.0.0.1`) is unaffected; operators who intentionally front the server with their own auth (reverse proxy, network policy) can opt back in with `--allow-public-bind` ([#252](https://github.com/wingnut128/netcidr/issues/252)).
- The MCP remote IPAM client (`mcp-serve --api-url`) now percent-encodes caller-controlled path segments and builds query strings via the request builder, so an `id`/`resource_id`/`address` containing `/`, `?`, or `#` can no longer inject extra path segments or a query string into the upstream request. It also sends a bearer token via the new `--api-token` flag (or `NETCIDR_API_TOKEN`), letting the remote `netcidr serve` enforce authentication instead of running open; the token header is marked sensitive so it is redacted from logs ([#253](https://github.com/wingnut128/netcidr/issues/253)).
- The SQLite IPAM database file is now created with owner-only (`0600`) permissions on Unix, instead of inheriting the umask (typically world-readable `0644`). The database holds all CIDR blocks, allocations, hostnames, and the audit log ([#261](https://github.com/wingnut128/netcidr/issues/261)).
- Auto-allocate now rejects a `count` above 1000 at both the CLI (`--count` value range) and the operations layer (covering the HTTP API), preventing an unbounded number of allocation writes from a single request ([#263](https://github.com/wingnut128/netcidr/issues/263)).
- The IPAM list endpoints now bound their result sets via `limit`/`offset` pagination (default 100, max 1000), and the audit endpoint (`GET /ipam/audit`) defaults and clamps its `limit` so omitting it can no longer dump the entire audit log ([#260](https://github.com/wingnut128/netcidr/issues/260)).
- `allocation_tags` now carries a `tenant_id` column (migration 012, SQLite + Postgres) — backfilled from the parent allocation, filtered on in tag reads/writes, and enforced by a tenant-match trigger. Previously cross-tenant tag isolation rested solely on an application-layer pre-check plus UUID unguessability; this adds DB-level defense-in-depth consistent with the other tenant-scoped tables ([#262](https://github.com/wingnut128/netcidr/issues/262)).

## [0.26.9](https://github.com/wingnut128/netcidr/compare/v0.26.8...v0.26.9) - 2026-06-08

### Added

- `just docker-push` and `just docker-login` recipes for publishing the Docker image. `docker-push` pushes both the `:<version>` and `:latest` tags; the registry target is the `docker_image` just variable (default `netcidr`), overridable on the command line (e.g. `just docker_image=ghcr.io/you/netcidr docker-push`). `docker-login` is a Cloudsmith convenience that authenticates using `CLOUDSMITH_API_KEY` (and optional `CLOUDSMITH_USER`, default `token`) from the environment via stdin.

## [0.26.8](https://github.com/wingnut128/netcidr/compare/v0.26.7...v0.26.8) - 2026-06-08

### Fixed

- *(deps)* bump rand to 0.8.6 to clear GHSA-cq8v-f236-94qc ([#240](https://github.com/wingnut128/netcidr/pull/240))
- patch react-router-dom DoS vuln and bump opentelemetry group to 0.32 ([#238](https://github.com/wingnut128/netcidr/pull/238))

### Security

- Bump `rand` from 0.8.5 to 0.8.6 to clear [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc) (rand is unsound with a custom logger using `rand::rng()`). 0.8.6 is an API-identical soundness patch — no source changes. Direct `rand = "0.8.6"` bump plus a `--precise` lockfile update; transitive consumers (jsonwebtoken, num-bigint-dig via rsa) resolve up automatically.
### Changed

- Bump `react-router-dom` from 7.14.2 to 7.17.0 in the dashboard, fixing high-severity DoS vulnerability GHSA-8x6r-g9mw-2r78
- Bump `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` from 0.31 to 0.32 and `tracing-opentelemetry` from 0.32 to 0.33; adapt `RedactingExporter::shutdown` and `force_flush` to the new `&self` receiver required by `SpanExporter` 0.32

## [0.26.7](https://github.com/wingnut128/netcidr/compare/v0.26.6...v0.26.7) - 2026-06-01

### Added

- *(dashboard)* hostname pointers page (set/list/history/delete) ([#228](https://github.com/wingnut128/netcidr/pull/228)) ([#229](https://github.com/wingnut128/netcidr/pull/229))

### Added

- **Dashboard Hostnames page.** Hostname pointers (shipped headless in the CLI/API/MCP) now have a dashboard UI at `/#/hostnames`: list current IP↔hostname pointers with filter-by-IP / filter-by-hostname, a set form (IP + hostname + optional allocation id / notes; create-or-update), per-row delete, and a per-pointer **History** modal showing the append-only change trail (create/update/delete, actor, timestamp). Visible whenever IPAM is enabled; reads need Reader and set/delete need Allocator, with the backend's role/validation errors surfaced inline. Completes the dashboard half of the hostname-pointers feature ([#228](https://github.com/wingnut128/netcidr/issues/228)).

## [0.26.6](https://github.com/wingnut128/netcidr/compare/v0.26.5...v0.26.6) - 2026-06-01

### Added

- *(telemetry)* opt-in OpenTelemetry / OTLP span export ([#218](https://github.com/wingnut128/netcidr/pull/218)) ([#224](https://github.com/wingnut128/netcidr/pull/224))

### Other

- *(ci)* invoke prebuilt binary directly instead of `cargo run` ([#226](https://github.com/wingnut128/netcidr/pull/226)) ([#227](https://github.com/wingnut128/netcidr/pull/227))

### Added

- **Opt-in OpenTelemetry / OTLP span export.** A new off-by-default `otel` Cargo feature exports the existing `tracing` `#[instrument]` spans to any OTLP collector (Honeycomb or otherwise) over HTTP/protobuf via reqwest+rustls — no gRPC/tonic, no native deps. The layer attaches only when built with `--features otel` **and** `OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise no layer is attached and the SDK is never initialized (true no-op — local dev and unconfigured deployments pay zero overhead). Works in both `netcidr serve` (batch exporter, flush on graceful shutdown) and AWS Lambda (batch + per-invocation `force_flush()` middleware, so frozen execution environments never lose buffered spans). Configured via OTel-generic env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER_ARG`); parent-based ratio sampling defaults to 100%. A **PII allowlist is enforced at the export boundary** — a redacting exporter strips any attribute keyed like a credential or PII (`*email`, `sub`, `*token*`, `*secret*`, `database_url`, …) before spans leave the process, so email/sub/bearer/PAT-secret/`DATABASE_URL` are never exported even though `#[instrument]` records some for CloudWatch. Measured pipeline init ~5 ms (well within the +50 ms cold-start budget); `cargo audit` shows no new advisories. See ADR-0004. Closes [#218](https://github.com/wingnut128/netcidr/issues/218).

### Changed

- **CI: integration tests no longer shell out to `cargo run`.** `tests/integration_tests.rs` invoked the binary via `cargo run` on every CLI call, so under nextest's parallel execution all 83 integration tests serialized on Cargo's build-directory file lock — stretching the `Format, Lint & Test` step to ~29 minutes (each integration test reported 60–240s+ in nextest's SLOW warnings). The helpers now invoke the prebuilt binary directly via `env!("CARGO_BIN_EXE_netcidr")`: no per-call dependency-graph walk, no build-lock contention, and the binary matches the test harness's feature set. Locally the full integration suite dropped from being the dominant cost to ~2s. ([#226](https://github.com/wingnut128/netcidr/issues/226))

## [0.26.5](https://github.com/wingnut128/netcidr/compare/v0.26.4...v0.26.5) - 2026-06-01

### Fixed

- **Startup crash (stack overflow) when Swagger is enabled.** `0.26.4` shipped recursive `ToSchema` types for the hierarchical split tree (`Ipv4SplitTreeNode`/`Ipv6SplitTreeNode`, each with `children: Vec<Self>`). With `enable_swagger` on (the default, and the Lambda deployment setting), building the OpenAPI document expanded these self-referential schemas inline without bound, overflowing the stack and aborting the process on startup — so every request returned an internal server error. The recursive fields are now annotated `#[schema(no_recursion)]`, which the build path never exercised in CI. Added a regression test that builds the full OpenAPI document (`ApiDoc::openapi()`) under the `swagger` feature so this class of recursion can never ship past CI again. Note: CI's test job now needs the spec build exercised — the new test runs whenever the `swagger` feature is enabled.

### Added

- *(dashboard)* admin Users page for role-email management ([#215](https://github.com/wingnut128/netcidr/pull/215)) ([#217](https://github.com/wingnut128/netcidr/pull/217))
- *(rbac)* move role-email membership to DB with env bootstrap ([#216](https://github.com/wingnut128/netcidr/pull/216))
- *(dashboard)* admin Activity tab for audit visibility ([#214](https://github.com/wingnut128/netcidr/pull/214))
- *(audit)* per-user/per-PAT audit filtering + admin CLI + token last-used ([#213](https://github.com/wingnut128/netcidr/pull/213))
- *(ipam)* hostname pointers HTTP API + MCP tools ([#211](https://github.com/wingnut128/netcidr/pull/211))
- *(ipam)* hostname pointers with append-only change history ([#210](https://github.com/wingnut128/netcidr/pull/210))
- *(split)* hierarchical (recursive) subnet splitting ([#208](https://github.com/wingnut128/netcidr/pull/208))
- *(split)* VLSM variable-length subnet allocation ([#206](https://github.com/wingnut128/netcidr/pull/206))

### Added

- **Opt-in OpenTelemetry / OTLP span export.** A new off-by-default `otel` Cargo feature exports the existing `tracing` `#[instrument]` spans to any OTLP collector (Honeycomb or otherwise) over HTTP/protobuf via reqwest+rustls — no gRPC/tonic, no native deps. The layer attaches only when built with `--features otel` **and** `OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise no layer is attached and the SDK is never initialized (true no-op — local dev and unconfigured deployments pay zero overhead). Works in both `netcidr serve` (batch exporter, flush on graceful shutdown) and AWS Lambda (batch + per-invocation `force_flush()` middleware, so frozen execution environments never lose buffered spans). Configured via OTel-generic env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER_ARG`); parent-based ratio sampling defaults to 100%. A **PII allowlist is enforced at the export boundary** — a redacting exporter strips any attribute keyed like a credential or PII (`*email`, `sub`, `*token*`, `*secret*`, `database_url`, …) before spans leave the process, so email/sub/bearer/PAT-secret/`DATABASE_URL` are never exported even though `#[instrument]` records some for CloudWatch. Measured pipeline init ~5 ms (well within the +50 ms cold-start budget); `cargo audit` shows no new advisories. See ADR-0004. Closes [#218](https://github.com/wingnut128/netcidr/issues/218).

- **Runtime role-email management (env → DB).** Role membership now lives in a global `role_assignments` table (migration 011, both backends) instead of env-vars-only, so RBAC changes survive restarts and need no redeploy. Managed via `netcidr admin user grant <email> --role reader|allocator|admin` / `revoke` / `list`, and `GET/POST/DELETE /admin/users` (Admin-gated). Role resolution (`AuthConfig::role_for_email`) now reads the DB per request (with an in-memory env fallback for bearer-only/non-IPAM deploys). Env lists (`NETCIDR_ADMIN_EMAILS` etc.) become a **first-start bootstrap seed only** — seeded once when the table is empty, ignored thereafter. Guards prevent revoking the last remaining admin or your own admin; every grant/revoke is audited (`entity_type=role_assignment`, visible in the Activity view). Roles are global; data stays tenant-isolated separately. See ADR-0003. An admin-only **Users** dashboard page (`/#/admin/users`) lists assignments and grants/revokes roles via the `/admin/users` API, surfacing the last-admin/self-revoke guards inline — completing [#215](https://github.com/wingnut128/netcidr/issues/215).

- **Audit visibility — per-user / per-PAT filtering + PAT last-used in CLI.** The audit log can now be filtered by caller email and PAT id: `AuditFilter` gains `caller_email`/`pat_id`, honored by both store backends (with new `(tenant_id, caller_email)` and `(tenant_id, pat_id)` indexes, migration 010) and the `GET /ipam/audit` endpoint (`?caller_email=&pat_id=`). New `netcidr admin` command group with `admin audit --user <email> --pat-id <id> --entity-type --action --limit`. `netcidr token list` now shows a **Last used** column (text + CSV; JSON and the dashboard already had it). A new admin-only **Activity** dashboard tab shows recent audited mutations grouped by day, with a filter-by-user box and per-day write/admin counts. Closes [#212](https://github.com/wingnut128/netcidr/issues/212). Audit retention is tracked separately.

- **IPAM hostname pointers with change history.** Record which hostname(s) live at an IP and track every change over time. `netcidr ipam hostname set <ip> <fqdn>` (create/update), `get <ip>`, `list`, `history <ip|hostname>`, and `delete <ip> <hostname>`. Many-to-many (an IP can carry several names; a name can move between IPs), hostnames RFC 1123-validated and lowercased, IPs canonicalized. Deletes are hard but preserved in a dedicated append-only `hostname_pointer_history` table capturing actor, timestamp, and before/after snapshots — so the assignment period of each pair is reconstructable. Tenant-scoped in both the SQLite and Postgres backends (schema migration 009). Exposed via CLI (`netcidr ipam hostname …`), REST API (`POST`/`GET`/`DELETE /ipam/hostnames` + `GET /ipam/hostnames/history`, role-gated), and MCP tools (`ipam_hostname_set`/`_list`/`_history`/`_delete`, local + remote backends). Closes [#209](https://github.com/wingnut128/netcidr/issues/209).
- **VLSM (variable-length) subnet splitting.** `netcidr split <cidr> --vlsm 26,28,28` carves a supernet into differently-sized sub-allocations in one pass, allocating each prefix greedily from the network address forward (Red Hat `ipcalc --split` style). Prefixes must be ordered largest-block-first (non-decreasing prefix length); out-of-order lists and allocations that overflow the supernet are rejected with a clear error naming the offending entry and the space remaining. Works for IPv4 and IPv6, across all four output formats (json/text/csv/yaml), and is exposed over HTTP at `GET /v4/vlsm` and `GET /v6/vlsm` (`?cidr=…&prefixes=26,28,28`). First phase of [#205](https://github.com/wingnut128/netcidr/issues/205); hierarchical/recursive splitting (`--steps`) follows in a second PR.
- **Hierarchical (recursive) subnet splitting.** `netcidr split <cidr> --steps 22,24` carves a supernet level-by-level into a tree — each step prefix is applied to every node of the level above it. Steps must be strictly increasing prefix lengths; the total tree size is bounded by the existing `MAX_GENERATED_SUBNETS` (1,000,000) guard. Text output renders an ASCII tree, CSV flattens with a `depth` column, JSON/YAML nest. Works for IPv4 and IPv6, over HTTP at `GET /v4/split-tree` and `GET /v6/split-tree` (`?cidr=…&steps=22,24`), and in the interactive TUI (a comma-separated list in the prefix field renders the tree). Second phase of [#205](https://github.com/wingnut128/netcidr/issues/205).

## [0.26.3](https://github.com/wingnut128/netcidr/compare/v0.26.2...v0.26.3) - 2026-05-28

### Other

- *(deps)* bump sqlx from 0.8.6 to 0.9.0 (with compat fix) ([#200](https://github.com/wingnut128/netcidr/pull/200))

## [0.26.2](https://github.com/wingnut128/netcidr/compare/v0.26.1...v0.26.2) - 2026-05-28

### Added

- *(ci)* adopt digestabot for automated base-image digest refresh ([#203](https://github.com/wingnut128/netcidr/pull/203))
- *(ipam)* log chosen backend at startup with password-safe URL parsing ([#201](https://github.com/wingnut128/netcidr/pull/201))

### Other

- *(image-scan)* only upload SARIF when Grype actually ran ([#202](https://github.com/wingnut128/netcidr/pull/202))
- *(deps)* bump EmbarkStudios/cargo-deny-action from 2.0.18 to 2.0.19 ([#196](https://github.com/wingnut128/netcidr/pull/196))
- *(deps)* bump github/codeql-action from 4.35.5 to 4.36.0 ([#197](https://github.com/wingnut128/netcidr/pull/197))
- name Linear + GitHub as dual trackers; ban linear.app URLs in public artifacts ([#193](https://github.com/wingnut128/netcidr/pull/193))

### Added

- **Digestabot keeps pinned base-image digests fresh.** New scheduled workflow (`.github/workflows/digestabot.yml`, daily 06:00 UTC + `workflow_dispatch`) runs `chainguard-dev/digestabot@v1.3.1` to resolve the upstream tag for every `image:tag@sha256:…` reference in the `Dockerfile` and open a PR when the digest has drifted. Complements `dependabot.yml`'s `docker` and `github-actions` ecosystems (which handle *tag* bumps) by handling *digest* refreshes for already-pinned references. Pins still gate every build through CI + branch protection; digestabot just turns the refresh into a reviewable PR instead of an unreviewable rot.

### Changed

- **Dockerfile base-image pins refreshed and brought into the digestabot-friendly format.** The runtime stage's `cgr.dev/chainguard/static@sha256:1f14…` (digest-only, untracked by digestabot) became `cgr.dev/chainguard/static:latest@sha256:77d8b89…` (tag + current digest, digestabot-tracked). The dashboard-builder's `oven/bun:1-alpine` digest moved from `sha256:4de4…` to `sha256:5acc90a…` to match upstream. The `rust:1.95-alpine3.23` pin was already current and unchanged. Triggering context: the previous Chainguard pin briefly became unreachable during a Chainguard registry outage on 2026-05-26, which surfaced as a misleading "missing SARIF file" error in the `Image Scan` workflow.

### Fixed

- **`image-scan` workflow no longer masks upstream failures with a misleading SARIF error.** When the `Build image` step failed (e.g. the base-image registry returned a 500 on the HEAD request for the pinned distroless digest), the subsequent `Upload SARIF to code-scanning` step ran anyway because of `if: always()` and then errored with `Input required and not supplied: sarif_file`, burying the real cause. The guard is now `if: always() && steps.grype.outputs.sarif != ''`, so SARIF upload only runs when Grype actually produced output; transient registry hiccups now surface as the original `docker build` error instead of a confusing missing-input error.

### Added

- **Startup log line naming the chosen IPAM backend ([#195](https://github.com/wingnut128/netcidr/issues/195)).** `ipam::create_store` now emits a single `tracing::info!` event when the store is constructed: `backend=sqlite path=...` or `backend=postgres host=... port=... database=...`. Both `netcidr serve` and the AWS Lambda entrypoint benefit — operators can grep CloudWatch / journald to confirm which backend a process is talking to, instead of inferring from env vars or the "data persists across cold starts" smell test. The Postgres branch parses the connection URL with `sqlx::postgres::PgConnectOptions::from_str` and emits only `get_host()` / `get_port()` / `get_database()`; the raw URL is never logged because it normally carries a password. A new unit test (`postgres_log_never_contains_credentials`) captures the log output via a `MakeWriter` buffer and asserts the password and username are absent — the test is the regression gate. In addition, the Lambda entrypoint logs the persistence-mode decision (`mode=s3-sqlite bucket=... key=... db_path=...` vs `mode=direct`) where `s3_syncer` is decided, so Lambda-specific routing is visible alongside the store-level log.

### Documentation

- **`CLAUDE.md` workflow now names both trackers.** The `Workflow` section opens by stating that work is tracked in the Linear project `netcidr` (workspace `beavis`, team `Engineering`, prefix `ENG-`) alongside GitHub Issues at `wingnut128/netcidr`, and step 1 explicitly says to attach the GitHub issue URL to the Linear ticket so cross-references live on the Linear side. Adds a guardrail: never publish `linear.app/...` URLs in public-facing places — PR descriptions, PR/issue comments, commit messages, CHANGELOG, or README. GitHub issue numbers (e.g., `#102`) remain freely usable everywhere.

## [0.26.1](https://github.com/wingnut128/netcidr/compare/v0.26.0...v0.26.1) - 2026-05-21

### Added

- **Dashboard support for per-PAT roles.** Completes the 0.26.0 feature on the React side. The Create Token dialog now has a Role selector (reader / allocator / admin) defaulting to `admin` to match pre-feature semantics, with helper text explaining that the server clamps requested roles to the caller's role on mint. The Tokens list gains a Role column so existing tokens' roles are visible at a glance, and the post-mint reveal modal echoes the stored role on the prefix/expires summary line so users see immediately whether mint-time clamping took effect. The TypeScript interfaces (`PersonalAccessTokenSummary`, `CreateTokenResponse`, `CreateTokenRequest`) gain the `role` field, and a `Role` union + `ROLES` array are exported from `auth/tokens.ts`.

## [0.26.0](https://github.com/wingnut128/netcidr/compare/v0.25.0...v0.26.0) - 2026-05-21

### Added

- **Per-PAT roles.** Personal access tokens now carry their own role, stored on `personal_access_tokens.role` (TEXT NOT NULL, CHECK constraint, default `admin` to preserve pre-feature semantics — for any PAT minted before this release, `min(owner_role, admin) == owner_role` so no behaviour changes). The minting flow exposes the role on every user-facing surface: CLI gains `netcidr token create --role reader|allocator|admin`, the HTTP API's `POST /me/tokens` accepts an optional `role` field and echoes the role actually stored on the response, and the `token list` / `token create` text + CSV views include a `ROLE` column. At mint time `mint_for_principal` clamps the requested role by the minting principal's resolved role (so an allocator asking for `admin` is silently stored as `allocator`); at auth time `AuthConfig::finalize_principal` re-clamps `min(email_resolved_role, stored_pat_role)` on every use, so a PAT can narrow the owner's privileges (e.g. an admin mints a reader-only CI token) but never widen them, and a later demotion of the owner's email automatically narrows every existing PAT without operator action. OIDC and static-bearer principals are unaffected — their email-resolved role remains authoritative.

## [0.25.0](https://github.com/wingnut128/netcidr/compare/v0.24.3...v0.25.0) - 2026-05-20

### Added

- S3-backed SQLite sync for Lambda deployments (`NETCIDR_S3_BUCKET` env var). Setting this variable switches the Lambda binary from Postgres to SQLite, pulling the database from S3 on cold start and pushing it back after every mutating request. Eliminates the need for an RDS instance (~$0.01/mo in S3 costs vs ~$15/mo for RDS). Requires `reserved_concurrency = 1` on the Lambda function to prevent split-brain from concurrent containers.

- **Role-based authorization for the IPAM API ([#102](https://github.com/wingnut128/netcidr/issues/102), shipped across PR1+PR2).** New `Role` enum (`Reader < Allocator < Admin`, `Ord`-derived) carried on `AuthenticatedPrincipal`; resolved from `AuthConfig` via the precedence admin > allocator > reader > Default. Two new env vars `NETCIDR_ALLOCATOR_EMAILS` / `NETCIDR_READER_EMAILS` (comma-separated) plus matching `oidc_allocator_emails` / `oidc_reader_emails` config-file fields. New `NetcidrError::Forbidden { required, actual }` variant; the error presenter maps it to 403 with a fixed-safe `"Forbidden"` string (required/actual roles are never echoed to the client — they go to the WARN log the extractor emits). New `src/authorization.rs` exporting `RequireReader`, `RequireAllocator`, `RequireAdmin` Axum extractors, applied per-handler across every IPAM route so adding a future endpoint without a role gate is a compile error. **⚠️ BREAKING (default-Reader policy).** Any authenticated OIDC user whose email is not in `NETCIDR_ADMIN_EMAILS`, `NETCIDR_ALLOCATOR_EMAILS`, or `NETCIDR_READER_EMAILS` resolves to `Role::Reader` (read-only) and will receive 403 on every write or admin endpoint. To preserve the pre-release behaviour for a user, add their email to `NETCIDR_ADMIN_EMAILS`. Static bearer-token mode (`NETCIDR_AUTH_MODE=bearer`) is the documented carve-out — bearer principals carry no email, so they continue to resolve to `Role::Admin` as before; if you need read-only service-to-service automation, use OIDC + a reader-role email. New [ADR-0002](docs/adr/0002-rbac-role-config-and-per-handler-extractors.md) records the per-handler-extractor + per-user-config + default-Reader + bearer-carve-out decisions and the rejected alternatives.

### Changed

- Removed stale Google IAP references — `AuthMode::Oidc` doc comment in `src/config.rs` no longer says "intended for Cloud Run behind Google IAP" (deployment-environment-agnostic phrasing), and the `.gitleaks.toml` allowlist no longer carries a dedicated entry for the long-gone `tests/fixtures/iap-test-private.pem` fixture (the `tests/fixtures/*.pem` catch-all already covers all test fixtures). Tracking issue [#110](https://github.com/wingnut128/netcidr/issues/110) closed as superseded — the IAP-specific JWT path was removed earlier (see v0.x.x history), and the tenancy mechanism it asked for is already in place via ADR-0001 + the multi-tenant isolation spec.

## [0.24.3](https://github.com/wingnut128/netcidr/compare/v0.24.2...v0.24.3) - 2026-05-12

### Other

- *(ipam)* move idempotency into IpamOps with wire-format-agnostic cache ([#176](https://github.com/wingnut128/netcidr/pull/176))
- *(ipam_api)* collapse HTTP body → domain-model field shuffles ([#174](https://github.com/wingnut128/netcidr/pull/174))
- *(pat)* deepen PatLifecycle to own principal-to-owner translation + tidy-ups ([#172](https://github.com/wingnut128/netcidr/pull/172))
- ADR-0001 (tenancy-via-explicit-parameter) + consolidate Tenant::LOCAL ([#170](https://github.com/wingnut128/netcidr/pull/170))
- extract single error-presentation seam across HTTP, /me, and MCP frontends ([#168](https://github.com/wingnut128/netcidr/pull/168))
- *(api)* document auth endpoints + bearerAuth in OpenAPI ([#165](https://github.com/wingnut128/netcidr/pull/165))
- *(deps)* bump the cargo-minor-and-patch group across 1 directory with 6 updates ([#161](https://github.com/wingnut128/netcidr/pull/161))

### Changed

- **Idempotency lives in `IpamOps`, not the HTTP layer.** New `allocate_specific_idempotent`, `allocate_auto_idempotent`, and `batch_allocate_idempotent` methods accept an `Idempotency-Key` and return `IdempotentOutcome<T> { Fresh(T) | Replayed(T) }`. The HTTP API now calls these; the old HTTP-layer `idempotent_post` wrapper is gone. The cache became wire-format-agnostic — operations serialize domain values via serde_json — so CLI and MCP callers can use the same replay protection by forwarding a key. HTTP behaviour is bit-for-bit preserved (replay status, `Idempotent-Replay: true` header, 409 on same-key-different-body, 24h TTL, 64KB body cap, identical scope strings). New `NetcidrError::IdempotencyConflict { key, scope }` variant; the error presenter maps it to 409 with a fixed safe message (the caller-supplied key is never echoed back). Subtle improvement: the request hash now hashes the deserialized input via `serde_json` rather than raw request bytes, so two clients sending logically identical requests with different JSON formatting (whitespace, field order) both replay instead of one getting a spurious 409.

- **`ipam_api`: HTTP body → domain-model field shuffles collapsed.** `AllocateSpecificRequest` and `AutoAllocateBody` each gain an `into_*` method that combines the body with the path-supplied `cidr_block_id`. The handlers' two 12-line field-by-field copies become one-liners; the knowledge of how to translate an HTTP body into a domain input now sits next to the body struct.

- **`PatLifecycle` now owns the principal-to-owner translation it was already documented as owning.** New `mint_for_principal` / `list_for_principal` / `revoke_for_principal` methods take `&AuthenticatedPrincipal` directly; failure modes are reported via a new `MintForPrincipalError` enum that distinguishes "no verified email" (403, defense-in-depth) from downstream lifecycle errors. The `*_for_owner` methods remain public for tests and lower-level callers.
- **`me_api` handlers no longer re-implement principal extraction.** The 15-line `match owner_from_principal(&principal)` boilerplate in each of `create_token`, `list_tokens`, `revoke_token` is gone; handlers are now ~10 lines each.
- **`PatLifecycle` is injected via Axum `Extension`** instead of being constructed per-request in three handlers. Matches the existing `IpamOps` wiring pattern.
- **Removed the duplicate `PatLifecycle::verify_bearer_token` method.** It delegated to the standalone `pat_lifecycle::verify_bearer_token` function used by `auth.rs::verify_pat`. Tests now call the free function directly.

### Added

- **ADR-0001 (`docs/adr/0001-tenancy-via-explicit-parameter.md`).** Formalises the existing multi-tenant isolation design decision: every `IpamOps` and `IpamStore` method that touches tenant-scoped data takes `tenant_id: &str` as an explicit parameter; no task-local context. Records the rejected alternative (task-local tenancy mirroring `audit_context`) and the conditions under which to revisit. Establishes `docs/adr/` as the location for future architectural decisions.

- **`Tenant::LOCAL` constant** on the existing `Tenant` newtype, naming the `"local"` tenant id used by single-tenant frontends. Replaces the duplicated `CLI_TENANT_ID` in `src/ipam_cli.rs` and `MCP_LOCAL_TENANT_ID` in `src/mcp.rs` so they can't drift.

- **Error presenter seam (`src/error_presenter.rs`).** A single `present(&NetcidrError) → PresentedError { status, client_msg, log_level }` is now the only place `NetcidrError` becomes a caller-visible response. IPAM HTTP API, `/me/tokens` HTTP API, and MCP tool results all call it; classification, scrubbing, and the "log this at error" decision live in one place. Table-driven unit tests assert every variant against `(status, message, log_level)`; the match has no catch-all, so adding a new variant produces a compile error rather than a silent 500. Added `Error Presenter` and `Presented Error` to `CONTEXT.md`.

- **`NetcidrError::Upstream { status, message }`** for HTTP-client adapters. Replaces the previous flattening of upstream HTTP non-2xx responses to `DatabaseError(body)`, which lost the status code and overloaded a name that should mean "the SQL backend failed."

- **OpenAPI coverage for auth endpoints.** `/me`, `/admin/allowlist`, `/me/tokens` (GET/POST), `/me/tokens/{id}` (DELETE), and `/features` are now annotated with `utoipa::path` and registered in the `ApiDoc`. A new `bearerAuth` security scheme (HTTP Bearer; accepts OIDC JWT, PAT, or static bearer) is declared via a `SecurityAddon` modifier and attached to every protected handler — `/ipam/*` plus the new `/me/*` and `/admin/*` paths — so Swagger UI's "Authorize" button now works. Added an `auth` tag for the identity/allowlist/PAT endpoints and exposed `MeResponse`, `AllowlistResponse`, `FeaturesResponse`, `CreateTokenRequest`, `CreateTokenResponse`, `TokenListResponse`, and `PersonalAccessTokenSummary` as schemas.

### Fixed

- **MCP no longer leaks SQL backend text.** Before, MCP tool errors used `format!("Error: {e}")` directly on `NetcidrError`, so a `DatabaseError` would expose raw SQL driver messages (table names, file paths, constraint names) to the MCP client. The MCP frontend now goes through the error presenter and surfaces `"Error: internal server error"` plus a server-side `tracing::error!`.

- **`mcp_client.rs` and `token_cli.rs` preserve upstream status.** Both used to flatten every non-2xx upstream HTTP response (incl. 401/403/404/409/422) to `DatabaseError(body)`, which the IPAM frontend then mapped back to 500. They now emit `NetcidrError::Upstream { status, message }`, so a 409 from the upstream stays a 409 at the MCP boundary, and a 401 stays a 401 at the CLI.

### Changed

- **Dropped substring-based `DatabaseError` classification in `ipam_api`.** The legacy shim mapped `DatabaseError(msg)` containing `"overlap"`/`"conflict"`/`"not found"` to 409/404. Verified vestigial — overlap rejection has gone through the typed `AllocationConflict` variant since well before this change. All `DatabaseError` now collapses to 500. If a future SQL backend error needs a non-500 status, classify it at the source (in `operations.rs` or the store adapter), not by sniffing strings at the response boundary.

- **`PatNotFound` is canonicalised to `"token not found"` across all HTTP paths.** Previously this was only enforced in the `/me/tokens` mapper; PAT lookups via `/ipam/*` paths fell through to 500. Both surfaces now agree, and the caller-supplied id is never echoed back.

## [0.24.2](https://github.com/wingnut128/netcidr/compare/v0.24.1...v0.24.2) - 2026-05-11

### Other

- Disable StepSecurity workflows ([#162](https://github.com/wingnut128/netcidr/pull/162))

## [0.24.1](https://github.com/wingnut128/netcidr/compare/v0.24.0...v0.24.1) - 2026-05-06

### Added

- personal access tokens ([#153](https://github.com/wingnut128/netcidr/pull/153))

### Other

- Configure release-plz for git-only releases ([#155](https://github.com/wingnut128/netcidr/pull/155))
- Rename IPAM supernets to CIDR blocks ([#154](https://github.com/wingnut128/netcidr/pull/154))
- *(deps)* bump lambda_http from 0.13.0 to 1.1.3 ([#152](https://github.com/wingnut128/netcidr/pull/152))
- *(deps)* bump the cargo-minor-and-patch group with 3 updates ([#149](https://github.com/wingnut128/netcidr/pull/149))
- *(deps)* bump step-security/harden-runner from 2.18.0 to 2.19.1 ([#147](https://github.com/wingnut128/netcidr/pull/147))
- *(deps)* bump github/codeql-action from 4.35.2 to 4.35.3 ([#148](https://github.com/wingnut128/netcidr/pull/148))

### Added

- **Personal access tokens (PATs).** Long-lived opaque bearer tokens (`ncdr_pat_<43 b64url chars>`) that authenticate against `/ipam/*` and let users call netcidr from CLIs, scripts, and CI without keeping an OIDC ID token fresh. End-to-end across six phases:
  - **Storage layer.** New `personal_access_tokens` table (SQLite + Postgres migration `007`) with `(tenant_id)`, `(prefix)`, and `UNIQUE(token_hash)` indexes. `IpamStore` gains six methods (`pat_create`, `pat_get_by_hash`, `pat_list_for_owner`, `pat_revoke`, `pat_touch_last_used`, `pat_reap_expired`); `pat_get_by_hash` filters `revoked_at IS NULL AND expires_at > now` in a single SQL predicate. Contract tests in `tests/ipam_store_contract.rs` lock the behavior so any third backend hits the same surface.
  - **Hashing + minting (`src/pat.rs`).** Pure-function module — `PatPepper` (env-loaded from `NETCIDR_PAT_PEPPER`, redacted `Debug`, ≥16-byte minimum), `MintedToken` (one-time plaintext, public prefix, hash; redacted `Debug`), `mint()` (32 random bytes from `OsRng` + URL-safe-no-pad b64), `hash_for_lookup()` (regex-gated SHA-256 of `secret || pepper`). No I/O, no DB, no clock.
  - **Auth middleware.** `require_auth` now dispatches by header prefix: `Bearer ncdr_pat_…` → `verify_pat`, `Bearer <jwt>` → existing OIDC, `Bearer <static>` → existing bearer. `Principal` carries `auth_method` (`oidc | pat | bearer`) and `pat_id`. Successful PAT auth fires a detached `tokio::spawn` to `pat_touch_last_used` so the request path never blocks on a write. `serve` startup refuses to boot in OIDC mode without `NETCIDR_PAT_PEPPER` set.
  - **REST endpoints `/me/tokens`.** `POST` mints (returns plaintext exactly once), `GET` lists summaries (no hash, no plaintext), `DELETE /{id}` revokes idempotently. The router is gated by a `require_oidc` middleware layer so PATs and static-bearer callers cannot mint PATs (closes the privilege-escalation path). Cross-tenant or unknown id on revoke returns 404, never 403, to avoid leaking existence. Seven integration tests in `tests/pat_api_tests.rs` cover the lifecycle, isolation, and validation.
  - **CLI: `netcidr token list|create|revoke`.** Talks to a remote `netcidr serve` instance over `/me/tokens`. Auth from `NETCIDR_API_TOKEN` (an OIDC ID token, since /me/tokens is OIDC-only); base URL from `NETCIDR_API_URL` or `--api-url`. `create --name <NAME> [--expires-in <DURATION>]` accepts a tightly-bounded `<N><unit>` shape with `unit ∈ {d, w, y}` (no `m` to dodge minute/month ambiguity, no decimals, no compounds, no leading zeros). Output respects `--format json|text|csv|yaml`. End-to-end `tests/cli_token.rs` spawns the in-process router on an ephemeral port and drives the real CLI binary.
  - **Dashboard `/tokens` page.** React UI with create/list/revoke. The create modal has an expiry picker (30/60/90/180/365 days); the success modal shows the plaintext exactly once with copy-to-clipboard and an explicit "I've saved it" dismiss before the plaintext leaves the DOM. The revoke modal requires explicit confirm with red styling. Sidebar entry only appears for authenticated users.
- **Audit-log attribution.** `audit_log` rows now carry `auth_method` (default `oidc`) and `pat_id` columns so operations performed via a PAT are distinguishable from interactive OIDC sessions in `query_audit` results.

### Changed

- **Gitleaks: allowlist test fixtures.** Added `.gitleaks.toml` extending the default ruleset to allowlist `tests/fixtures/*.pem` (test private-key fixtures) and the deliberately-fake `ghp_validlookingbutwrongprefix...` literal in `src/pat.rs` used to assert PAT prefix validation. Unblocks the scheduled `gitleaks` workflow on `main`.

### Fixed

- Configure release-plz for git-only releases so version detection comes from Git tags and `cargo publish` is skipped. This lets the release PR/tag/draft GitHub Release flow work for the private binary distribution model, while the existing release workflow continues attaching and publishing the built `netcidr` artifact.

## [0.24.0] - 2026-05-02

### Changed

- **Multi-tenant IPAM isolation.** Every CIDR block, allocation, audit entry, and idempotency record is now scoped to the authenticated user's email. The `IpamStore` trait and `IpamOps` struct expose `tenant_id: &str` as an explicit parameter on every method, making per-tenant filtering unforgettable at the type level. HTTP middleware extracts the tenant from the OIDC principal's verified email and exposes it via Axum extensions; cross-tenant access returns 404 (not 403) to prevent existence enumeration. CLI invocations and stdio MCP both pass the literal `"local"`. Schema is destructive: migration `006` drops and recreates `cidr_blocks`, `allocations`, `audit_log`, `idempotency_keys`, and `allocation_tags` with `tenant_id` columns, `UNIQUE(tenant_id, cidr)` on cidr_blocks, composite tenant indexes, and triggers enforcing the cross-table invariant `allocations.tenant_id == cidr_blocks.tenant_id`. Five-test isolation matrix in `tests/ipam_isolation.rs` proves the guarantee end-to-end (cidr_blocks, same-CIDR-different-tenant, allocations, audit log, idempotency keys). Sub-project 1 of 3 toward a remote MCP endpoint.

## [0.23.0] - 2026-04-30

### Changed

- **Release binary now ships with `mcp`, `tui`, and `ipam-postgres` features enabled.** The release workflow's `cargo build --release` step previously compiled with default features only (`swagger`, `dashboard`), so published binaries silently lacked `netcidr mcp-serve`, the terminal UI, and the Postgres IPAM backend. The `lambda` bin remains a separate `[[bin]]` target and is not built here, so we enumerate features explicitly rather than using `--all-features`. Also corrects the `Dispatch netcidr-deploy` step's comment to name the actually-required PAT scope (Contents: read+write, not Actions). Removes the obsolete `cloudbuild.yaml` left over from the GCP build pipeline.

- **Visualizer: block grid + Hilbert curve, IPv6-aware.** The IPAM Visualizer's address-space view is now a cell grid with a Block ⇄ Hilbert toggle (persisted in `localStorage`). Replaces the prior single-color line strip, which made small allocations invisible at typical container widths and only handled IPv4. Cell granularity auto-snaps so total cells stay ≤ 1024; IPv6 cidr_blocks coarsen to /64 (or larger if the cidr_block is bigger than /54). Status colors carry over (active/reserved/released/free), and clicking a cell still opens the allocation detail. `dashboard/src/lib/cidr.ts` is rewritten on `BigInt` so the same code paths handle v4 and v6 — `start`/`end`/`size` are now `bigint` instead of `number`. WhatIfPanel still grades candidates as fits/conflict/outside; its map-overlay re-paint on top of the new grids is tracked as a follow-up.

### Fixed

- **Mobile sidebar drawer closed itself the moment it opened.** The "auto-close on route change" effect in `Sidebar.tsx` depended on the inline `onClose` arrow from `MainLayout`, which React re-creates on every parent render. Tapping the hamburger flipped `drawerOpen` to `true`, the parent re-rendered, the effect's dependency array saw a "new" `onClose`, fired immediately, and snapped the drawer shut. Tracking the previous pathname with a `useRef` so the effect only fires on actual route changes. Net effect: hamburger now opens the drawer and the page is interactive on mobile.

## [0.22.0] - 2026-04-30

### Security

- **Idempotency keys for IPAM allocation endpoints.** Clients can now send `Idempotency-Key: <opaque>` on `POST /ipam/cidr-blocks/{id}/allocate`, `POST /ipam/cidr-blocks/{id}/allocate-specific`, and `POST /ipam/batch/allocate` to make retries safe. Same key + same body returns the cached response (with `Idempotent-Replay: true`); same key + different body returns `409`. Records are scoped per-endpoint + per-cidr_block, persist for 24h, and only request bodies up to 64 KiB are cached (oversize bodies execute uncached). New `idempotency_keys` table (SQLite + Postgres migration `005`), `IpamStore::idempotency_{get,put,reap_expired}` trait methods, helpers in `src/ipam/idempotency.rs`, and an `idempotent_post` wrapper in `src/ipam_api.rs` that the three handlers funnel through. Six HTTP integration tests in `tests/ipam_idempotency.rs` cover replay, payload-conflict, no-key passthrough, and per-endpoint/per-cidr_block scoping. Closes #104.
- **CSV output hardening.** Cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return are now prefixed with a single quote per OWASP CSV-injection guidance — preserves the visible value but prevents Excel/Sheets/LibreOffice from auto-evaluating it. CSV HTTP responses also carry `Content-Type: text/csv; charset=utf-8` and `Content-Disposition: attachment; filename="netcidr.csv"`, so a browser saves the file rather than rendering it inline. Combined with the existing global `X-Content-Type-Options: nosniff` and the per-field length limits in `validation.rs`, this closes the spreadsheet/browser-origin injection surface for the `csv` output format. Closes #106.
- IPAM allocations are now serialized per-cidr_block so the "check overlap → insert" sequence is atomic within a single process. `IpamOps` carries a `HashMap<cidr_block_id, Arc<tokio::sync::Mutex<()>>>` and acquires the relevant lock at the top of `allocate_specific`, `allocate_auto`, `release_allocation`, and `update_allocation`. Two new tests in `tests/ipam_concurrency.rs` prove the invariant: 8 racing tasks for the same CIDR yield exactly 1 winner and 7 `AllocationConflict` errors; 16 racing auto-allocations on a /22 yield exactly 4 non-overlapping /24s and 12 `NoFreeSpace` errors. Cross-process callers (multiple netcidr instances against a shared database) still need DB-level locking — tracked separately. Closes #105.
- IPAM audit log now records caller identity on every mutation: `caller_sub` (stable subject — Google `sub` for OIDC, `"bearer-token"` for static-bearer mode), `caller_email` (verified email when available), `source_ip` (HTTP peer IP), and `request_id` (UUID v4 generated per request). New `audit_context` module threads these via tokio task-locals so existing `IpamOps` mutation methods don't change signature; CLI invocations leave the context unset and the new columns stay `NULL`. SQLite + Postgres migration `004` adds the columns and indexes on `request_id` and `caller_sub`. Closes #103.
- New `.github/workflows/cargo-deny.yml` runs `cargo deny check advisories|bans|licenses|sources` on PRs that touch `Cargo.{toml,lock}` or `deny.toml`, on push to `main`, and weekly on a cron. `deny.toml` allowlists the project's actual transitive license set and ignores two pre-existing advisories (RUSTSEC-2023-0071 RSA Marvin Attack, RUSTSEC-2026-0097 rand 0.8 unsoundness) — neither is exploitable in this codebase (we never use RSA private-key ops; we don't define a custom logger that calls `rand::rng()`). Both clear automatically when `jsonwebtoken` upgrades past `rand 0.8` / a patched `rsa` ships.
- New `.github/workflows/gitleaks.yml` scans every PR, push to main, and weekly cron for committed secrets using `gitleaks-action@v2`.
- New `.github/workflows/dependency-review.yml` runs GitHub's `dependency-review-action` on every PR, failing on `high` severity advisories and posting a summary comment on failure. Catches risky deps at PR time before they hit lockfiles.
- Closes #107.
- CI now runs `bun audit --audit-level=high` on the dashboard dependency tree and
  fails the build if known-compromised npm package names appear in
  `dashboard/bun.lock`. Initial denylist covers the StepSecurity advisory
  packages `mbt` and `@cap-js/sqlite` (Shai-Hulud-style supply-chain compromise).
  Audited at advisory time: neither package — nor any of their transitive
  dependencies — is present in this repo, so the change is preventive.

### Changed

- **Dashboard mobile support, phase 2.** Polish pass on top of phase 1: stat grids, `DataRow`, `BitGrid`, base typography, and modals:
  - Splitter's 3-up stat grid now collapses to one column on `< sm:` (`grid-cols-1 sm:grid-cols-3`).
  - `DataRow` stacks the label above the value on `< sm:` (`flex-col sm:flex-row`) so long CIDRs/IPs get a full-width line instead of being cropped to the right.
  - `BitGrid` no longer pushes the page wider than the viewport: the bit row is wrapped in `overflow-x-auto` on `< md:` (horizontal scroll) and continues to wrap on `md:`+.
  - Body font bumps from 14px to 15px under `(max-width: 640px)` for readability.
  - `Modal` is full-screen on `< sm:` (`h-full sm:h-auto sm:max-w-lg sm:mx-4`); the close button gets a 44×44 tap target on mobile and a sticky header so it stays reachable while scrolling long forms.
  - Shared `INPUT` and `BTN_PRIMARY` style tokens get `text-base md:text-sm` and `min-h-[44px] md:min-h-0` respectively, so every form across the dashboard inherits iOS-friendly sizing without per-component touch-ups. Closes #96.
- **Dashboard mobile support, phase 1.** Layout, navigation, tables, and touch targets now work on narrow viewports (phase 2 — stat grids, BitGrid, typography, modals — tracked in #96):
  - Sidebar becomes a slide-in drawer on `< md` with a hamburger button in a new mobile top bar; backdrop dismiss + auto-close on route change. Stays as a fixed sidebar on `md:`+ (`MainLayout.tsx`, `Sidebar.tsx`).
  - `AllocationTable` and `CidrBlockTable` render as stacked cards on `< md` (one card per row, key fields in a `<dl>`) and as the existing tables on `md:`+. Filter rows are now `flex-col sm:flex-row` so inputs stack on narrow screens; `min-w-[…]` constraints are scoped to `sm:`+.
  - Primary action buttons across Calculator, Splitter, Contains, Summarize, FromRange, IpamSearch, and the IPAM tables now have `min-h-[44px]` on mobile (iOS minimum tap target) and stay compact on `md:`+.
  - All form inputs use `text-base md:text-sm` so iOS doesn't zoom on focus.
- Dashboard audit pass against the `netcidr-design` skill. All mechanical drift fixes:
  - `font-bold` swapped to `font-medium` (form labels, secondary headings) or `font-semibold` (table headers) to match the skill's typography hierarchy. ~22 occurrences across `Splitter`, `FromRange`, `Contains`, `Summarize`, `IpamSearch`, `Modal`, and `AllocationDetailModal`.
  - Modal titles converted from Title Case to sentence case: "Create CIDR block", "Allocate specific block", "Auto-allocate", "Allocation detail".
  - Panel titles converted: "Free blocks", "Audit log", "Bit visualization".
  - SignInCard's `shadow-sm` replaced with the canonical hairline `shadow-[0_1px_2px_rgba(15,23,42,0.04)]` — the only ambient shadow the system uses.
  - Modal inline error badges normalized to the system's tinted-background recipe (`border border-red/40 bg-red/10 text-red rounded-md`) to match StatusBadge and the Calculator scope pill.

### Added

- Release workflow now dispatches a `repository_dispatch: netcidr-released` event at `wingnut128/netcidr-deploy` after a tag is published, auto-rolling out the new version to AWS. Uses a fine-grained PAT (`DEPLOY_DISPATCH_TOKEN`) scoped to that repo with `Actions: read+write`; payload is `{ ref: "vX.Y.Z" }`.
- Sidebar footer now shows the build's short git SHA next to the version (e.g., `v0.21.0 · 39146f7a`). The SHA links to the commit on GitHub. New `build.rs` injects `GIT_SHA_SHORT` / `GIT_SHA_FULL` at compile time (falls back to `unknown` when `.git` is absent, e.g., source tarballs); `/version` exposes both as `commit` and `commit_full`. Closes #94.
- **Allowlist onboarding flow.** Three coordinated surfaces, all using the existing visual primitives:
  - **Sign-in card** — entry point for anonymous users, unchanged content but now part of the gate.
  - **Request-access card** — shown when a Google-authenticated user is *not* on the allowlist. Displays the user's verified email, a copy-able admin contact, and a clear sign-out path. Honest about the env-var-managed reality of the allowlist; no fake "pending approval" copy.
  - **Allowlist admin page** at `/admin/allowlist` — viewable only by users in `NETCIDR_ADMIN_EMAILS`. Lists every allowlisted email, marks admins, and includes step-by-step instructions for adding/removing emails via `samconfig.toml.tpl` + redeploy. The sidebar shows an "Admin" section with a link to this page only when the signed-in user is an admin.
- New `GET /me` HTTP endpoint — returns `{ email, is_allowlisted, is_admin, admin_contact }` for any authenticated principal (independent of the allowlist gate). Powers the new `unallowlisted` auth state in the dashboard so the UI can route to the request-access card without first failing every IPAM API call.
- New `GET /admin/allowlist` HTTP endpoint — admin-only. Returns the configured allowlist + admin emails sourced from env vars / config.
- `NETCIDR_ADMIN_EMAILS` env var (comma-separated) and `admin_emails` config field. Members of this list see the Admin section in the sidebar and can hit `/admin/allowlist`.

### Changed

- `AuthContext` adds two new states: `unallowlisted` (token valid, email not on list) and surfaces `isAdmin` + `adminContact` for downstream components. After sign-in, the context calls `/me` to determine the right state.
- Ipam and Visualizer pages now use a shared `<AuthGate>` component instead of duplicating the routing logic. AuthGate routes by status: loading → spinner, anonymous/disabled → SignInCard, unallowlisted (or admin-only with non-admin) → RequestAccessCard, allowed → children.

## [0.21.0] - 2026-04-28

### Added

- IPAM-aware **Allocation Map** (replaces the standalone Subnet Visualizer): pick a cidr_block, render its full address space as a horizontal strip with each allocation colored by status (active / reserved / released / free). Auto multi-row layout for larger cidr_blocks so even small allocations stay visible. Hover for details, click an allocation to drill into its detail modal.
- **What-if overlay** on the Allocation Map: paste candidate CIDRs in the new "What if" panel and they render as outlined overlays — cyan dashed = fits, red dashed = conflicts, plus a per-CIDR verdict list (Fits / Conflict / Outside / Invalid). Useful for sanity-checking a proposed allocation before committing it.
- Dashboard sidebar shows an "API Docs ↗" link to `/swagger-ui` when the server reports the `swagger` feature enabled (via `/features`).
- `oidc_allowed_emails` config field and `NETCIDR_OIDC_ALLOWED_EMAILS` env var (comma-separated) — when set, only verified Google identities whose email matches the allowlist may call `/ipam/*`.
- Dashboard now signs in to Google directly via `oidc-client-ts` (implicit `id_token` flow) and attaches `Authorization: Bearer <id_token>` to `/ipam/*` requests. Configure with `VITE_OAUTH_WEB_CLIENT_ID` at build time. Server serves the SPA at `/auth/callback` and `/auth/silent-callback` so the OAuth redirect can complete.
- Dashboard light/dark theme toggle in the sidebar (also `⌘+J` / `Ctrl+J`). Light is the default; first-visit theme follows the OS `prefers-color-scheme`; choice persists in `localStorage`.
- Inline Google sign-in card on the IPAM tab when unauthenticated; the public tools (Calc/Split/Contains/Summarize/Range/Visualize) remain available without sign-in.
- New `lambda` Cargo feature and `lambda` binary (`src/bin/lambda.rs`) that wraps the Axum router with `lambda_http` for AWS Lambda deployment. Reads runtime config from env vars (`NETCIDR_AUTH_MODE`, `NETCIDR_OIDC_AUDIENCE`, `NETCIDR_OIDC_ALLOWED_EMAILS`, `NETCIDR_DATABASE_URL`, `NETCIDR_IPAM_BACKEND`, `NETCIDR_IPAM_ENABLED`). Build with `cargo lambda build --release --arm64 --bin lambda --features lambda,ipam-postgres`. The standard `netcidr` binary is unchanged.
- New `CI Status` aggregator job in `.github/workflows/ci.yml` that always runs (even when `verify`/`audit` are skipped by the `Detect Changes` paths filter) and aggregates their results. This gives branch protection a single stable required-check name that handles the skipped-required-check trap, replacing the per-job names (`Format & Lint`, `Test`, `Analyze (rust)`) that were renamed/removed when the CI jobs were consolidated in #111.

### Changed

- OIDC mode now validates Google OAuth ID tokens (RS256, JWKS at `https://www.googleapis.com/oauth2/v3/certs`, issuer `accounts.google.com`) read from `Authorization: Bearer <id_token>`. Replaces the previous IAP JWT validation against `x-goog-iap-jwt-assertion`. The expected audience (`oidc_audience` / `NETCIDR_OIDC_AUDIENCE`) is now your Google OAuth Web Client ID.
- HTTP authentication is now scoped to `/ipam/*` only. Calculator, split, contains, summarize, from-range, batch, health, version, and features endpoints are public regardless of `auth_mode`.
- Dashboard color tokens (`bg-bg`, `text-text`, `text-cyan`, …) now resolve through CSS variables on `:root[data-theme]`, so the same utility classes paint correctly in both themes without duplication.
- Dashboard visual refresh: switched body/UI typography to **Inter** (variable, bundled via `@fontsource-variable/inter`) and dropped the brutalist all-caps + tight tracking. Borders softened from 2px to 1px, cards get rounded corners + a subtle shadow, sidebar active state is now a left accent bar instead of an inverted block. Dark palette desaturated from the original neon to a softer cyan/slate set. JetBrains Mono is no longer bundled — system mono fallback is fine for the small amount of technical data still rendered in mono.

### Removed

- `recharts` dropped from the dashboard bundle — the new Allocation Map is pure SVG/CSS, and the old Visualizer's bar chart is gone. Saves ~100 kB gzipped.

## [0.20.0] - 2026-04-23

### Added

- New `.github/workflows/image-scan.yml` — builds the Docker image on PRs touching `Dockerfile`/`Cargo.lock` and scans with Grype + Syft. Generates CycloneDX + SPDX SBOMs. Weekly cron detects new fixable CVEs in pinned base images and opens a tracking issue. Release events attach signed SBOM attestations via Sigstore (keyless — no signing keys required).
- Release binaries now carry Sigstore-signed build provenance (`actions/attest-build-provenance`). Consumers verify with `gh attestation verify <binary> --owner wingnut128`. No signing keys — uses GitHub OIDC + Fulcio + Rekor.

### Changed

- Replace the GNU `Makefile` with a `justfile` driven by [`just`](https://github.com/casey/just). All ~30 task targets preserved 1:1. `just --list` now serves as the task index. Notable syntax change: `make fuzz FUZZ_TARGET=x FUZZ_DURATION=30` is now `just fuzz x 30`. Contributors need `just` installed locally (`brew install just` / `cargo install just`).
- Migrate Dockerfile runtime to Chainguard's distroless `cgr.dev/chainguard/static` image (digest-pinned), producing a statically-linked musl binary on a near-zero-CVE rootfs. The Alpine-based Rust builder is retained because Chainguard's `rust:latest-dev` does not ship a musl `rust-std` target; the builder stage now also installs `curl`, which the `utoipa-swagger-ui` build script requires.
- Remove the container-level `HEALTHCHECK` directive — the distroless runtime has no shell, so in-container probes are delegated to the orchestrator (Kubernetes `httpGet` probe or a host-run check against `/health`).
- Rework the README Docker section for the shell-less runtime: docker-compose ordering now uses `depends_on: { condition: service_started }` plus a host-run `curl http://localhost:8080/health`, with a Kubernetes `httpGet` probe snippet as the production-grade example.

### Security

- Add top-level `permissions: contents: read` to `.github/workflows/release.yml` so the `detect` job runs with a least-privilege `GITHUB_TOKEN`. The `release` job retains its explicit `contents: write` override. Resolves CodeQL alert `actions/missing-workflow-permissions`.
- Tighten `.github/workflows/dependabot-automerge.yml` to use `secrets.GITHUB_TOKEN` (no PAT required). Top-level perms are `contents: read`; `contents: write` + `pull-requests: write` are scoped to the `automerge` job only. Matches GitHub's documented auto-merge pattern. Resolves Scorecard `TokenPermissionsID` alert (#68) and fixes auto-merge failures on Dependabot PRs (#87).
- Replace the unmaintained `daemonize` crate with the actively maintained `daemonize-me` 2.x fork. Resolves RUSTSEC-2025-0069. No user-visible change — `--daemonize` behavior is preserved.
- New `.github/workflows/pin-check.yml` fails PRs that add tag-pinned GitHub Actions (e.g., `@v1` or `@main`). All `uses:` lines must be 40-char commit SHAs. Defense-in-depth against action-tag force-push attacks (c.f. aquasecurity/trivy-action, March 2026).
- Drop `paths:` filter from `.github/workflows/pin-check.yml` so the check runs on every PR. Makes pin-check safe to mark as a required status check — with a `paths:` filter, GitHub leaves unrelated PRs in a permanent "expected — waiting for status" state and blocks merge. The check runs in ~20s so always-on has negligible cost.

### Removed

- Removed `.github/workflows/dependency-review.yml` — redundant with `cargo-audit` (RUSTSEC DB, runs in CI) and Dependabot alerts (GHSA DB). Dropping this workflow reduces CI cost without reducing coverage. Dependabot still covers the cargo, npm, github-actions, and docker ecosystems.

### Fixed

- Bump `rustls-webpki` to 0.103.13 to address RUSTSEC-2026-0104 (reachable panic in certificate revocation list parsing). Supersedes the earlier 0.103.12 bump for RUSTSEC-2026-0098/0099.
- Cap audit log `LIMIT` at 10,000 and bind it as a typed parameter in both SQLite and Postgres backends, preventing a full-table-scan DoS via `u32::MAX` (closes #53)
- Validate `AuditFilter` fields (`entity_type`, `entity_id`, `action`) through the shared validation layer before reaching the store, consistent with all other IPAM operations (closes #53)
- Sanitize `DatabaseError` responses in the HTTP API: raw DB messages (table names, file paths, constraint names) are now logged internally and replaced with generic strings for clients (closes #53)
- Replace `GovernorConfigBuilder::finish().unwrap()` with a `match` to avoid a startup panic when `rate_limit_burst = 0` is set alongside a non-zero `rate_limit_per_second` (closes #53)

## [0.19.3] - 2026-04-13

### Fixed

- Bump Dockerfile base images to Alpine 3.23 (builder: `rust:1.94-alpine3.23`, runtime: `alpine:3.23`) to pick up patched `libssl3`, addressing CVE-2026-28387, CVE-2026-31790, CVE-2026-28388, and related openssl vulnerabilities reported by Snyk
- Pin dashboard build image to `oven/bun:1-alpine` instead of the floating `oven/bun:alpine` tag

### Changed

- Release workflow now auto-triggers on pushes to `main` that bump the `Cargo.toml` version, in addition to the existing manual `workflow_dispatch`. A new `detect` job compares the old and new versions and skips release if the version is unchanged, malformed, or the tag already exists.
- Move CodeQL from GitHub default setup to an advanced workflow (`.github/workflows/codeql.yml`) so docs-only changes (`**/*.md`, `doc/**`, `LICENSE`) skip scans via `paths-ignore`. Scans still run weekly on schedule.

### Note

- `v0.19.2` was skipped because a release tag was previously published against an unrelated commit before the Dockerfile CVE patches landed. This release (`v0.19.3`) is the first tag that actually contains the libssl3 fixes.

## [0.19.2] - 2026-04-13

### Fixed

- Bump Dockerfile base images to Alpine 3.23 (builder: `rust:1.94-alpine3.23`, runtime: `alpine:3.23`) to pick up patched `libssl3`, addressing CVE-2026-28387, CVE-2026-31790, CVE-2026-28388, and related openssl vulnerabilities reported by Snyk
- Pin dashboard build image to `oven/bun:1-alpine` instead of the floating `oven/bun:alpine` tag

## [0.19.1] - 2026-04-13

### Added

- Add `cloudbuild.yaml` for GCP Cloud Build with parameterized substitutions

## [0.19.0] - 2026-04-13

### Added

- Add man page (`doc/netcidr.1`) covering all commands, options, IPAM subcommands, environment variables, and examples
- Add `dashboard` feature flag — embedded dashboard is now optional (included in default features); build with `--no-default-features` to exclude it
- Dashboard sidebar hides IPAM tab when server reports IPAM is not enabled via `/features` endpoint

### Changed

- Switch dashboard tooling from npm to bun
- Dockerfile supports `FEATURES` and `WITH_DASHBOARD` build args for slim builds

## [0.18.3] - 2026-04-13

### Fixed

- Bump Dockerfile builder image from `rust:1.83-alpine` to `rust:1.87-alpine`

## [0.18.2] - 2026-03-28

### Changed

- Merge CI format and lint jobs into a single job — saves a runner spin-up
- Switch CI test runner from `cargo test` to `cargo nextest run` for parallel test execution
- Replace `rustsec/audit-check@v2` with `taiki-e/install-action@cargo-audit` — pre-built binary avoids 3-minute compilation and removes `checks: write` permission requirement

### Removed

- Remove `rust-toolchain.toml` — pinning `stable` adds no value; CI is the formatting authority via `dtolnay/rust-toolchain@stable`

### Fixed

- Cap `batch_release` allocation IDs at 10,000 to prevent uncontrolled memory allocation from user input (CodeQL alert #10)

## [0.18.1] - 2026-03-28

### Changed

- Replace `cargo install cargo-audit` with `rustsec/audit-check@v2` GitHub Action in CI — faster (pre-built binary), fixes CVSS v4.0 parsing failures
- Add `rust-toolchain.toml` to pin stable channel for consistent builds across environments

## [0.18.0] - 2026-03-27

### Added

- Batch IPAM endpoints on the API server: `POST /ipam/batch/allocate`, `POST /ipam/batch/release`, `GET /ipam/batch/summary`
- MCP remote mode now supports batch operations and allocation summary (previously local-only)
- `netcidr serve --daemonize` flag to run the API server as a background daemon with PID file support

### Changed

- Replace `softprops/action-gh-release@v2` with `gh release create` in release workflow — eliminates third-party action dependency
- Extract `daemonize_process` into shared `daemon` module; `daemonize` crate is now a non-optional dependency

## [0.17.0] - 2026-03-27

### Added

- MCP batch operations for reduced token usage in bulk workflows:
  - `ipam_batch_allocate` — allocate multiple CIDR blocks across CIDR blocks in a single call (up to 100 items), returns compact output with per-item error handling
  - `ipam_batch_release` — release allocations by IDs, resource_id, or cidr_block_id in one call
  - `ipam_allocation_summary` — grouped overview of allocations across CIDR blocks organized by resource ID, with utilization stats
- Compact allocation/cidr_block models (`CompactAllocation`, `CompactCidrBlock`) that omit null fields, timestamps, and tags to minimize response size
- Batch allocate returns ~85% fewer tokens vs individual calls; batch release returns ~96% fewer tokens

## [0.16.1] - 2026-03-27

### Fixed

- Fix MCP server `--daemonize` failing with "Bad file descriptor (os error 9)" — daemonize now forks before the tokio runtime is created so kqueue/epoll fds are not corrupted

## [0.16.0] - 2026-03-27

### Added

- MCP server now supports Streamable HTTP transport (default) in addition to stdio
- New `--transport http|stdio` flag for `mcp-serve` (defaults to `http`)
- New `--address` and `--port` flags for MCP HTTP transport (defaults to `127.0.0.1:3000`)
- New `--daemonize` flag to run MCP HTTP server as a background daemon with PID file and log file support
- Graceful shutdown via Ctrl+C for MCP HTTP server
- systemd unit file (`contrib/systemd/netcidr-mcp.service`) for Linux deployment
- launchd plist (`contrib/launchd/com.netcidr.mcp.plist`) for macOS deployment

### Changed

- Migrate CI/CD from GitLab CI to GitHub Actions (ci, lint, test, audit, semgrep, CodeQL, release)
- Add Dependabot configuration for GitHub Actions, Cargo, and npm dependencies
- Update all documentation references from GitLab to GitHub (README, SECURITY, CHANGELOG, CLAUDE.md)

### Fixed

- Update GitHub Actions to Node 22 versions: checkout v4→v6, setup-node v4→v6, cache v4→v5
- Disable Semgrep CI job temporarily
- Remove custom CodeQL workflow in favor of GitHub's default setup to fix SARIF processing conflict
- Bump Node.js version from 20 to 22 in CI and release workflows

## [0.15.0] - 2026-03-21

### Added

- DNS management module (`src/dns/`) with `DnsService` for allocation binding, auto-PTR generation, and BIND zone file export

### Fixed

- Dashboard: IPAM modal errors (e.g., allocation overlap conflicts) now display inline instead of being hidden behind the modal overlay
- Dashboard: IPAM sections (CidrBlocks, Allocations, Search, Free Blocks, Audit Log) are now collapsible via header toggle

## [0.14.0] - 2026-03-20

### Added

- Per-IP rate limiting on the API server via `tower-governor` — uses existing `rate_limit_per_second` and `rate_limit_burst` config fields; set `rate_limit_per_second = 0` to disable
- Shell completion generation via `netcidr completions <shell>` (supports bash, zsh, fish, elvish, powershell)
- IPAM dashboard: RE-ACTIVATE button on released allocations to restore them to active status
- React + Vite + TypeScript dashboard scaffolding (`dashboard/` directory) — replaces Alpine.js single-file dashboard
- Dashboard: Calculator page with bit grid visualization, IPv4/IPv6 results, hextet display
- Dashboard: Splitter, Contains, Summarize, and FromRange pages
- Dashboard: Full IPAM page — cidr_block management, allocation CRUD with filters, search, free blocks, audit log, 4 modals (create cidr_block, allocate specific, auto-allocate, allocation detail with tags)
- Dashboard: Visualizer page with address space grid and subnet split distribution chart (recharts)

### Removed

- Old Alpine.js single-file dashboard (`dashboard.html`) — fully replaced by React dashboard
- Legacy dashboard route (`/dashboard/legacy`)
- Legacy dashboard remains accessible at `/dashboard/legacy` during transition
- `make dashboard` and `make dashboard-dev` targets for frontend build and development
- IP version guard: cross-family allocations rejected (e.g., IPv4 CIDR in IPv6 cidr_block)

### Fixed

- IPAM: re-allocating a previously released CIDR no longer creates duplicate records; the existing released allocation is reactivated with updated metadata
- IPAM: `released_at` timestamp is now cleared when an allocation transitions back to active or reserved status
- IPAM: reactivating a released allocation via status update now checks for overlap with other active/reserved allocations
- Prefix length validation in auto-allocate (rejects prefix > 32 for IPv4, > 128 for IPv6)
- IPv6 unit tests for range arithmetic: `parse_range`, `ranges_overlap`, `range_contains`, `find_gaps`, `find_free_blocks`, `range_to_cidrs`, `split_cidr_to_prefix`
- IPv6 IPAM integration tests: cidr_block CRUD, allocate specific, auto-allocate, overlap rejection, utilization, free blocks, find-by-IP, release/re-allocate
- IPv6 CLI integration test: end-to-end IPAM workflow via subprocess

### Changed

- Upgraded rusqlite 0.32 → 0.39 and r2d2_sqlite 0.25 → 0.33 (no API changes required)
- Upgraded reqwest 0.12 → 0.13 (feature `rustls-tls` renamed to `rustls`, added `query` feature)
- CI: removed auto-merge workflow (security improvement — no more actor-based exemptions)
- CI: merged MCP test job into main test job using `--all-features`
- CI: added semgrep scanning as a CI job (previously only ran locally)
- CI: added Dependabot configuration for GitHub Actions and Cargo dependencies
- Version bumps now happen at release time, not per-PR

## [0.13.4] - 2026-03-18

### Added

- Schema migration v3: `total_hosts_text` TEXT column on `cidr_blocks` and `allocations` tables, enabling correct storage of IPv6 host counts that exceed i64 range (e.g., 2^96 for a /32 cidr_block)

### Fixed

- IPv6 /0 prefix no longer panics (`1u128 << 128` overflow) in `parse_cidr_metadata`; capped at `u128::MAX`

## [0.13.3] - 2026-03-18

### Added

- MCP server remote backend: `--api-url <url>` flag on `netcidr mcp-serve` proxies IPAM tool calls to a running `netcidr serve` HTTP API instead of using a local database (mutually exclusive with `--ipam-db`)

## [0.13.2] - 2026-03-16

### Added

- JSON export/import: `ipam dump` exports all cidr_blocks and allocations to JSON, `ipam load` imports into an empty store
- Reservation TTL/expiry: `--ttl <seconds>` flag on `ipam allocate` and `ipam auto-allocate`, `expires_at` column (schema migration v2), lazy expiry via `reap_expired()`
- Auto-merge CI workflow for PRs from repo owner and Dependabot (squash merge)
- Utilization report now includes per-status breakdown (active/reserved/released addresses and counts)
- Property-based tests (proptest) for CIDR tiling, gap completeness, and no-overlap invariants
- Trait-contract test suite for IpamStore backend parity (18 contract tests via macro harness)
- Migration upgrade path tests (data survival, complex state, schema version tracking)

### Removed

- Legacy Node.js MCP server (`mcp-server/`) — fully superseded by Rust-native implementation in `src/mcp.rs`

### Fixed

- CI and CodeQL workflows now run on all PRs, fixing deadlock where docs-only PRs could never satisfy required checks
- Removed stale `javascript-typescript` language from CodeQL matrix (no JS/TS source remains)

### Changed

- Reorganized planning and PRD documents into `.context/` directory
- Removed obsolete `TODO-ipam.md` and `prd/` directory
- Updated SECURITY.md supported versions table
- Added SECURITY.md update rule to CLAUDE.md post-commit documentation guidelines
## [0.13.1] - 2026-03-07

### Added

- IPAM persistence layer with SQLite backend for tracking IP address allocations
  - `IpamStore` async trait defining a pluggable storage backend interface
  - `SqliteStore` implementation with r2d2 connection pooling and WAL mode
  - CidrBlock management (create, list, get, delete with active-allocation guard)
  - Allocation lifecycle (create, auto-allocate, update, release with conflict detection)
  - Free space discovery and utilization reporting
  - IP address and resource ID reverse lookup
  - Immutable audit log for all mutations
  - Flexible key-value tags on allocations
  - DB path resolution: CLI flag > env var > config file > XDG default
  - Embedded schema migrations with version tracking
- IPAM CLI integration via `netcidr ipam` subcommand with full command suite:
  - `ipam cidr_block create/list/get/delete` — manage top-level address spaces
  - `ipam allocate` / `ipam auto-allocate` — specific or next-available allocation
  - `ipam allocation get/list/update` — query and update allocations
  - `ipam release` — mark allocations as released
  - `ipam utilization` / `ipam free-blocks` — capacity reporting
  - `ipam find-ip` / `ipam find-resource` — reverse lookup
  - `ipam audit` — query the immutable audit log
- IPAM REST API endpoints via `netcidr serve --ipam-enabled`:
  - `POST /ipam/cidr-blocks` — create cidr_block; `GET` — list all
  - `GET /ipam/cidr-blocks/{id}` — get cidr_block; `DELETE` — delete (guarded by active allocations)
  - `POST /ipam/cidr-blocks/{id}/allocate` — auto-allocate next-available blocks
  - `POST /ipam/cidr-blocks/{id}/allocate-specific` — allocate a specific CIDR
  - `GET /ipam/cidr-blocks/{id}/allocations` — list allocations with filters
  - `GET /ipam/cidr-blocks/{id}/free` — free block discovery
  - `GET /ipam/cidr-blocks/{id}/utilization` — utilization report
  - `GET /ipam/allocations/{id}` — get allocation; `PATCH` — update metadata
  - `POST /ipam/allocations/{id}/release` — release allocation
  - `PUT /ipam/allocations/{id}/tags` — set tags
  - `GET /ipam/find-ip/{address}` — reverse lookup by IP
  - `GET /ipam/find-resource/{resource_id}` — reverse lookup by resource
  - `GET /ipam/audit` — query audit log
- OpenAPI/Swagger documentation for all IPAM REST endpoints (requires `--enable-swagger`)
  - `ipam tags get/set` — manage key-value tags on allocations
  - `--db <path>` flag for database location override
  - All output formats supported (JSON, text, CSV, YAML)
- Rust-native MCP (Model Context Protocol) server replacing the Node.js implementation
  - Uses `rmcp` (official Rust SDK) with `#[tool]` macros for zero-overhead tool definitions
  - Calls library functions directly instead of shelling out to the binary
  - 5 calculator tools: `subnet_calc`, `subnet_split`, `contains_check`, `from_range`, `summarize`
  - 10 IPAM tools: `ipam_create_cidr_block`, `ipam_list_cidr_blocks`, `ipam_allocate`, `ipam_allocate_specific`, `ipam_release`, `ipam_list_allocations`, `ipam_free_blocks`, `ipam_utilization`, `ipam_find_ip`, `ipam_find_resource`
  - IPAM tools enabled via `netcidr mcp-serve --ipam-db <path>`
  - Runs via `netcidr mcp-serve` subcommand over stdio transport
  - Enabled with `--features mcp` cargo feature flag
  - 15 unit tests covering all tools and error paths
- Full web application dashboard replacing the IPAM-only dashboard
  - 7-page SPA using Alpine.js with hash-based routing
  - Subnet Calculator with bit-grid visualization for IPv4/IPv6
  - Subnet Splitter, Contains Check, Summarize, From Range tools
  - IPAM Dashboard with utilization charts (Chart.js), search, tag management
  - Subnet Visualizer with address space map and split distribution chart
  - Brutalist Industrial design: monospace everything, high-contrast dark theme, thick borders
  - Dashboard always served at `/` and `/dashboard` (no longer requires IPAM)
  - `GET /features` endpoint for frontend feature detection (IPAM, Swagger)
  - Responsive layout with sidebar collapsing to bottom bar on mobile
- Shared input validation module (`src/validation.rs`) for CIDR, IP, text field, and identifier scrubbing
  - Centralized length checks, control character rejection, and path traversal detection
- PostgreSQL IPAM storage backend (feature-gated behind `ipam-postgres`)
  - `PostgresStore` implementing the `IpamStore` trait using `sqlx` with `PgPool`
  - Embedded schema migrations matching the SQLite schema (uses `SMALLINT`, `BIGINT`, `BIGSERIAL`)
  - Backend selection via `--ipam-backend postgres` CLI flag
  - Connection URL via `--ipam-db-url`, `NETCIDR_IPAM_DB_URL` env var, or `[ipam.postgres]` config
  - Configurable connection pool (`max_connections`, `min_connections`)
  - `Backend` enum and `PostgresConfig` in IPAM config module
  - Docker-based PostgreSQL integration tests
  - Replaces inline `MAX_INPUT_LENGTH` in `ipv4.rs` and `ipv6.rs`
  - Wired into all IPAM `IpamOps` public methods

## [0.12.0] - 2026-03-02

### Removed

- **BREAKING**: Removed deprecated `v4` and `v6` CLI subcommands — use `netcidr <cidr>` directly (deprecated since v0.1.7)
- Removed unused `tower_governor` dependency from `Cargo.toml`

### Refactored

- Extracted `ipv4_mask()` and `ipv6_mask()` helpers to eliminate duplicated mask calculation across `ipv4.rs`, `ipv6.rs`, `contains.rs`, and `summarize.rs`
- Deduplicated `TextOutput` implementations for `SummaryResult` and `FromRangeResult` pairs via macros
- Simplified `logging.rs` initialization from 4 near-identical subscriber blocks to 2 (JSON vs plain) with shared writer setup
- Extracted `handle_result` helper in `main.rs` to collapse 10 repetitive match/Ok/Err blocks
- Unified `count_subnets` IPv4/IPv6 branches into a single validation flow in `subnet_generator.rs`
- Extracted `validate_and_summarize` helper to deduplicate `summarize_ipv4_with_limit` / `summarize_ipv6_with_limit`
- Simplified `init_logging` return type from `Option<WorkerGuard>` to `WorkerGuard`

## [0.11.1] - 2026-02-27

### Added

- `make semgrep` target for security scanning with Semgrep (p/owasp-top-ten and p/rust rulesets)
- Semgrep added to `make check` pipeline

### Fixed

- Release workflow: fixed 6 shell injection findings by routing `inputs.version` through environment variable instead of inline `${{ }}` interpolation in `run:` steps
- Fixed nosemgrep annotation in `config.rs` to use full rule ID so suppression takes effect

### Changed

- CI: replaced tag-triggered release workflow with `workflow_dispatch` release workflow that validates Cargo.toml version, extracts CHANGELOG release notes, and creates GitHub release with cross-platform binaries
- CI: removed `mcp-server/**` from `paths-ignore` in CI and CodeQL workflows
- CI: added `mcp-server` job with TypeScript lint, build, and test steps
- CodeQL: added `javascript-typescript` to language scanning matrix
- CodeQL: upgraded `github/codeql-action` from v3 to v4 ahead of v3 deprecation

## [0.11.0] - 2026-02-25

### Added

- MCP (Model Context Protocol) server for AI assistant integration via stdio transport
  - TypeScript implementation in `mcp-server/` using `@modelcontextprotocol/sdk`
  - 5 tools: `subnet_calc`, `subnet_split`, `contains_check`, `from_range`, `summarize`
  - Delegates all calculations to the `netcidr` binary (JSON output)
  - Auto-detects IPv4 vs IPv6 from input
  - 13 unit tests covering all tools and error paths
- MCP server setup instructions in README for Claude Code and Claude Desktop
- `make build-mcp` / `make test-mcp` targets
- `test-mcp` added to `make check` pipeline

## [0.10.0] - 2026-02-20

### Changed

- Restructured `Ipv4Subnet` to store IP addresses as native `Ipv4Addr` instead of `String`, eliminating parse-format-reparse overhead
- Restructured `Ipv6Subnet` to store `network`/`last` as native `Ipv6Addr` instead of `String`
- JSON API output unchanged — backward compatibility preserved via `#[serde(rename)]` attributes
- Replaced `split('/').collect::<Vec<&str>>()` with `split_once('/')` in CIDR parsing for both IPv4 and IPv6
- Optimized `Ipv6Subnet::format_full` from `Vec<String>` intermediate allocation to a single `format!()` call
- Improved error-masking tests across all modules to assert specific `NetcidrError` variants instead of generic `is_err()` checks

### Fixed

- TUI: `c`/`C` and `m`/`M` keys were unconditionally captured by shortcut handlers, preventing IPv6 hex address entry in the CIDR input field

## [0.9.0] - 2026-02-19

### Added

- TOML config file support (`--config path`) for server settings
- CLI flags for all configurable limits (`--max-batch-size`, `--max-range-cidrs`, `--max-summarize-inputs`, `--max-body-size`, `--rate-limit-per-second`, `--rate-limit-burst`, `--timeout`)
- `--enable-swagger` flag to opt-in to Swagger UI (disabled by default)
- CSV output format (`--format csv`, `?format=csv`) for spreadsheet-importable subnet data
- YAML output format (`--format yaml`, `?format=yaml`) for IaC workflow integration
- `format` query parameter on all API endpoints supporting `json`, `text`, `csv`, and `yaml`
- Batch CIDR processing via multiple positional arguments
- `--stdin` flag for reading CIDRs from standard input
- `POST /batch` API endpoint with mixed IPv4/IPv6 auto-detection
- Partial failure tolerance for invalid CIDRs in batch operations
- Fuzz testing with `cargo-fuzz` and `libfuzzer-sys` for CIDR parsing, address containment, range conversion, and subnet operations
- `make fuzz` target with configurable `FUZZ_TARGET` and `FUZZ_DURATION`

### Security

- Request body size limit (default 1 MB), configurable via `max_body_size`
- Batch size cap (default 10K), from-range output cap (default 1M), summarize input cap (default 10K)
- Per-IP rate limiting support via `tower_governor` (configurable burst/sustained)
- Request timeout (default 30s), configurable via `timeout_seconds`
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`
- Restrictive CORS policy (no origins allowed by default)
- Swagger UI disabled by default, opt-in via `--enable-swagger` flag
- Graceful shutdown on SIGTERM/SIGINT
- Response builder `.unwrap()` replaced with safe fallbacks
- Bind-address warning when using non-loopback addresses
- Input length validation (256 byte max) on CIDR parsing
- Dockerfile HEALTHCHECK directive

### Changed

- Added Rust build caching (`Swatinem/rust-cache@v2`) to CodeQL CI workflow for faster analysis runs

## [0.8.1] - 2026-02-11

### Added

- 29 unit tests for TUI `AppState` methods, gated behind `#[cfg(all(test, feature = "tui"))]`
- `make test-tui` target and added it to `make check` for CI coverage

### Changed

- Organized `lib.rs` with crate-level documentation and module grouping by domain
- Removed unused `NetcidrError` re-export from public API
- Updated CLAUDE.md with `test-tui` build command and workflow instructions

## [0.8.0] - 2026-02-10

### Added

- `from-range` CLI subcommand to convert arbitrary IP address ranges to minimal CIDR notation
- `GET /v4/from-range` and `GET /v6/from-range` API endpoints with OpenAPI documentation
- Automatic IPv4/IPv6 detection for range-to-CIDR conversion
- JSON and text output formats for range conversion results
- Unit and integration tests for IP range to CIDR conversion

## [0.7.0] - 2026-02-10

### Added

- `summarize` CLI subcommand to aggregate adjacent/overlapping CIDR ranges into the minimal covering set
- `GET /v4/summarize` and `GET /v6/summarize` API endpoints with OpenAPI documentation
- Automatic IPv4/IPv6 detection for summarize command
- JSON and text output formats for summarization results
- Unit and integration tests for CIDR summarization

## [0.6.1] - 2026-02-10

### Added

- IPv4 `address_type` field classifying network addresses into 16 RFC-referenced special-use ranges (RFC 1918, RFC 6598, RFC 5737, RFC 1122, RFC 3927, RFC 6890, RFC 7526, RFC 2544, RFC 5771, RFC 1112)
- IPv6 Documentation range detection for `2001:db8::/32` → `Documentation (RFC 3849)`
- RFC references added to all IPv6 address type strings (e.g., `Loopback` → `Loopback (RFC 4291)`)

## [0.6.0] - 2026-02-10

### Added

- `count-only=true` hyphenated query parameter alias for API split endpoints (web-friendly convention alongside `count_only=true`)
- TUI count-only mode: press `C` in Split mode to show available subnet count without generating subnets
- API test for hyphenated `count-only` query parameter

## [0.5.0] - 2026-02-10

### Added

- `--count-only` CLI flag and `count_only=true` API query parameter to return the available subnet count via pure math with zero allocation
- `SplitSummary` struct for count-only responses (JSON and text output)
- Hard limit of 1,000,000 on generated subnets to prevent out-of-memory on large splits
- `SubnetLimitExceeded` error variant with descriptive message guiding users to `--count-only` or `-n`
- 5 new CLI integration tests and 3 new API integration tests for count-only and limit enforcement

### Fixed

- Out-of-memory crash when splitting large IPv6 cidr_blocks (e.g., /64 → /96 = 4.3B subnets)

## [0.4.1] - 2026-02-09

### Added

- 15 in-process API integration tests covering all 8 HTTP endpoints using tower's `oneshot()` pattern
- `tower` and `http-body-util` dev-dependencies for API test infrastructure

## [0.4.0] - 2026-02-09

### Added

- `contains` CLI subcommand to check if an IP address belongs to a CIDR range (IPv4 and IPv6)
- `GET /v4/contains` and `GET /v6/contains` API endpoints for address containment checks
- New `ContainsResult` data structure shared between CLI and API
- Unit and integration tests for containment checks

## [0.3.2] - 2026-02-07

### Security

- Updated `bytes` from 1.11.0 to 1.11.1 — fixes integer overflow in `BytesMut::reserve`
- Updated `time` from 0.3.45 to 0.3.47 — fixes stack exhaustion Denial of Service
- Deprecated v0.3.1 release due to vulnerable transitive dependencies

### Changed

- Added personality, commit rules, and security filters to CLAUDE.md

## [0.3.1] - 2026-01-20

### Added

- Optional `?pretty=true` query parameter for API endpoints to format JSON output with indentation
- Improved API readability for browser and debugging use cases

### Security

- Fixed RUSTSEC-2026-0002 / GHSA-rhfx-m35p-ff5j: Updated `ratatui` from 0.26 to 0.30, which resolves low severity vulnerability in `lru` crate (IterMut Stacked Borrows violation)
- Updated `lru` transitive dependency from 0.12.5 to 0.16.3 (patched version)

### Changed

- Updated deprecated `Frame::size()` call to `Frame::area()` for ratatui 0.30 compatibility
- API responses default to compact JSON for optimal performance

## [0.3.0] - 2026-01-20 [YANKED]

**This version has been yanked due to a security vulnerability in a transitive dependency. Please use 0.3.1 or later.**

### Added

- Interactive Terminal User Interface (TUI) mode with dual-mode operation (optional `tui` feature)
  - Calculate mode for real-time subnet information display
  - Split mode for interactive subnet generation with scrollable results
  - TAB key to switch between Calculate and Split modes
  - Support for MAX mode to generate all possible subnets
  - Arrow key navigation for scrolling through generated subnet lists
  - Color-coded input fields with active field highlighting
  - Real-time validation and error messages
  - Automatic IPv4/IPv6 detection
- `--tui` command-line flag to launch TUI mode (only available when built with `tui` feature)
- Optional dependencies: `ratatui`, `crossterm`, and `ipnet` for TUI functionality

### Changed

- TUI feature is opt-in and not included in default builds to maintain smaller binary size
- Module structure reorganized: `tui` module now part of `lib.rs` instead of `main.rs`

## [0.2.1] - 2026-01-16

### Fixed

- Swagger endpoints now only appear in help text when swagger feature is enabled

## [0.2.0] - 2026-01-16

### Added

- OpenAPI 3.0 documentation for all API endpoints via optional `swagger` feature (enabled by default)
- New `/api-docs/openapi.json` endpoint to retrieve OpenAPI specification
- Comprehensive schema documentation for all request/response types
- Support for importing API spec into Swagger Editor, Postman, Insomnia, and other tools

### Changed

- API documentation is now machine-readable and can be consumed by API tooling
- Binary can be built without swagger support using `--no-default-features` for smaller size

## [0.1.8] - 2026-01-16

### Changed

- CLI now displays help message when run without arguments instead of showing an error
- Improved user experience with exit code 0 (success) when showing help

## [0.1.7] - 2026-01-16

### Added

- Direct CIDR notation support: use `netcidr <cidr>` instead of subcommands
- Auto-detection of IPv4 vs IPv6 based on input format
- Integration tests for direct CIDR input and deprecation warnings

### Changed

- Simplified CLI interface - CIDR can now be passed directly as a positional argument
- Users should now use `netcidr 192.168.1.0/24` instead of `netcidr v4 192.168.1.0/24`

### Deprecated

- `v4` subcommand - use `netcidr <cidr>` instead
- `v6` subcommand - use `netcidr <cidr>` instead

## [0.1.6] - 2026-01-16

### Fixed

- Broken pipe panic when output is piped to commands like `head`

## [0.1.5] - 2025-01-16

### Changed

- Updated axum from 0.7 to 0.8
- Updated thiserror from 1 to 2
- Updated tower-http from 0.5 to 0.6

## [0.1.4] - 2025-01-16

### Added

- `--max` (`-m`) option for split command to generate maximum number of subnets possible
- API support for `max=true` query parameter on `/v4/split` and `/v6/split` endpoints

### Changed

- IPv6 help text now uses "prefix" terminology instead of "CIDR" for consistency with IPv6 conventions
- IPv6 example in help changed from `/32` to `/48` (more typical enterprise allocation)
- Split command now requires either `--count` or `--max` (mutually exclusive)

## [0.1.3] - 2025-01-16

### Added

- CI and license status badges to README

### Fixed

- Code formatting to comply with rustfmt standards

## [0.1.2] - 2025-01-16

### Added

- Pre-commit git hook for automated linting and format checks
- `make setup` command to install git hooks for development

## [0.1.1] - 2025-01-16

### Added

- CI workflow with automated testing, linting, and format checks
- CodeQL security scanning (on push, PR, and weekly schedule)
- cargo-audit for dependency vulnerability scanning

## [0.1.0] - 2025-01-16

### Added

- IPv4 subnet calculation with network address, broadcast, subnet mask, wildcard mask, host ranges
- IPv4 network class detection (A, B, C, D, E) and private address identification
- IPv6 prefix calculation with full hextet expansion
- IPv6 address type detection (global unicast, link-local, ULA, multicast, loopback)
- Subnet generator to split cidr_blocks into smaller subnets
- CLI interface with `v4`, `v6`, `split`, and `serve` commands
- JSON output format (default)
- Plain text output format (`--format text`)
- File output option (`-o, --output`)
- HTTP API server with REST endpoints
- API endpoints: `/health`, `/v4`, `/v6`, `/v4/split`, `/v6/split`
- Structured logging with tracing (stdout, file output, JSON format)
- Configurable log levels (trace, debug, info, warn, error)
- HTTP request tracing via tower-http
- Unit tests for IPv4, IPv6, and subnet generation
- Integration tests for CLI
- Dockerfile for containerized deployment
- Makefile for common development tasks

[Unreleased]: https://github.com/wingnut128/netcidr/compare/v0.22.0...HEAD
[0.22.0]: https://github.com/wingnut128/netcidr/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/wingnut128/netcidr/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/wingnut128/netcidr/compare/v0.19.3...v0.20.0
[0.19.3]: https://github.com/wingnut128/netcidr/compare/v0.19.2...v0.19.3
[0.19.2]: https://github.com/wingnut128/netcidr/compare/v0.19.1...v0.19.2
[0.19.1]: https://github.com/wingnut128/netcidr/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/wingnut128/netcidr/compare/v0.18.3...v0.19.0
[0.18.3]: https://github.com/wingnut128/netcidr/compare/v0.18.2...v0.18.3
[0.18.2]: https://github.com/wingnut128/netcidr/compare/v0.18.1...v0.18.2
[0.18.1]: https://github.com/wingnut128/netcidr/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/wingnut128/netcidr/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/wingnut128/netcidr/compare/v0.16.1...v0.17.0
[0.16.1]: https://github.com/wingnut128/netcidr/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/wingnut128/netcidr/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/wingnut128/netcidr/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/wingnut128/netcidr/compare/v0.13.4...v0.14.0
[0.13.4]: https://github.com/wingnut128/netcidr/compare/v0.13.3...v0.13.4
[0.13.3]: https://github.com/wingnut128/netcidr/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/wingnut128/netcidr/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/wingnut128/netcidr/compare/v0.12.0...v0.13.1
[0.12.0]: https://github.com/wingnut128/netcidr/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/wingnut128/netcidr/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/wingnut128/netcidr/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/wingnut128/netcidr/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/wingnut128/netcidr/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/wingnut128/netcidr/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/wingnut128/netcidr/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/wingnut128/netcidr/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/wingnut128/netcidr/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/wingnut128/netcidr/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/wingnut128/netcidr/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/wingnut128/netcidr/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/wingnut128/netcidr/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/wingnut128/netcidr/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/wingnut128/netcidr/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/wingnut128/netcidr/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/wingnut128/netcidr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/wingnut128/netcidr/compare/v0.1.8...v0.2.0
[0.1.8]: https://github.com/wingnut128/netcidr/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/wingnut128/netcidr/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/wingnut128/netcidr/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wingnut128/netcidr/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wingnut128/netcidr/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wingnut128/netcidr/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wingnut128/netcidr/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wingnut128/netcidr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wingnut128/netcidr/releases/tag/v0.1.0
