# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Idempotency keys for IPAM allocation endpoints.** Clients can now send `Idempotency-Key: <opaque>` on `POST /ipam/supernets/{id}/allocate`, `POST /ipam/supernets/{id}/allocate-specific`, and `POST /ipam/batch/allocate` to make retries safe. Same key + same body returns the cached response (with `Idempotent-Replay: true`); same key + different body returns `409`. Records are scoped per-endpoint + per-supernet, persist for 24h, and only request bodies up to 64 KiB are cached (oversize bodies execute uncached). New `idempotency_keys` table (SQLite + Postgres migration `005`), `IpamStore::idempotency_{get,put,reap_expired}` trait methods, helpers in `src/ipam/idempotency.rs`, and an `idempotent_post` wrapper in `src/ipam_api.rs` that the three handlers funnel through. Six HTTP integration tests in `tests/ipam_idempotency.rs` cover replay, payload-conflict, no-key passthrough, and per-endpoint/per-supernet scoping. Closes #104.
- **CSV output hardening.** Cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return are now prefixed with a single quote per OWASP CSV-injection guidance — preserves the visible value but prevents Excel/Sheets/LibreOffice from auto-evaluating it. CSV HTTP responses also carry `Content-Type: text/csv; charset=utf-8` and `Content-Disposition: attachment; filename="netcidr.csv"`, so a browser saves the file rather than rendering it inline. Combined with the existing global `X-Content-Type-Options: nosniff` and the per-field length limits in `validation.rs`, this closes the spreadsheet/browser-origin injection surface for the `csv` output format. Closes #106.
- IPAM allocations are now serialized per-supernet so the "check overlap → insert" sequence is atomic within a single process. `IpamOps` carries a `HashMap<supernet_id, Arc<tokio::sync::Mutex<()>>>` and acquires the relevant lock at the top of `allocate_specific`, `allocate_auto`, `release_allocation`, and `update_allocation`. Two new tests in `tests/ipam_concurrency.rs` prove the invariant: 8 racing tasks for the same CIDR yield exactly 1 winner and 7 `AllocationConflict` errors; 16 racing auto-allocations on a /22 yield exactly 4 non-overlapping /24s and 12 `NoFreeSpace` errors. Cross-process callers (multiple netcidr instances against a shared database) still need DB-level locking — tracked separately. Closes #105.
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

- **Dashboard mobile support, phase 1.** Layout, navigation, tables, and touch targets now work on narrow viewports (phase 2 — stat grids, BitGrid, typography, modals — tracked in #96):
  - Sidebar becomes a slide-in drawer on `< md` with a hamburger button in a new mobile top bar; backdrop dismiss + auto-close on route change. Stays as a fixed sidebar on `md:`+ (`MainLayout.tsx`, `Sidebar.tsx`).
  - `AllocationTable` and `SupernetTable` render as stacked cards on `< md` (one card per row, key fields in a `<dl>`) and as the existing tables on `md:`+. Filter rows are now `flex-col sm:flex-row` so inputs stack on narrow screens; `min-w-[…]` constraints are scoped to `sm:`+.
  - Primary action buttons across Calculator, Splitter, Contains, Summarize, FromRange, IpamSearch, and the IPAM tables now have `min-h-[44px]` on mobile (iOS minimum tap target) and stay compact on `md:`+.
  - All form inputs use `text-base md:text-sm` so iOS doesn't zoom on focus.
- Dashboard audit pass against the `netcidr-design` skill. All mechanical drift fixes:
  - `font-bold` swapped to `font-medium` (form labels, secondary headings) or `font-semibold` (table headers) to match the skill's typography hierarchy. ~22 occurrences across `Splitter`, `FromRange`, `Contains`, `Summarize`, `IpamSearch`, `Modal`, and `AllocationDetailModal`.
  - Modal titles converted from Title Case to sentence case: "Create supernet", "Allocate specific block", "Auto-allocate", "Allocation detail".
  - Panel titles converted: "Free blocks", "Audit log", "Bit visualization".
  - SignInCard's `shadow-sm` replaced with the canonical hairline `shadow-[0_1px_2px_rgba(15,23,42,0.04)]` — the only ambient shadow the system uses.
  - Modal inline error badges normalized to the system's tinted-background recipe (`border border-red/40 bg-red/10 text-red rounded-md`) to match StatusBadge and the Calculator scope pill.

### Added

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

- IPAM-aware **Allocation Map** (replaces the standalone Subnet Visualizer): pick a supernet, render its full address space as a horizontal strip with each allocation colored by status (active / reserved / released / free). Auto multi-row layout for larger supernets so even small allocations stay visible. Hover for details, click an allocation to drill into its detail modal.
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
  - `ipam_batch_allocate` — allocate multiple CIDR blocks across supernets in a single call (up to 100 items), returns compact output with per-item error handling
  - `ipam_batch_release` — release allocations by IDs, resource_id, or supernet_id in one call
  - `ipam_allocation_summary` — grouped overview of allocations across supernets organized by resource ID, with utilization stats
- Compact allocation/supernet models (`CompactAllocation`, `CompactSupernet`) that omit null fields, timestamps, and tags to minimize response size
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
- Dashboard: IPAM sections (Supernets, Allocations, Search, Free Blocks, Audit Log) are now collapsible via header toggle

## [0.14.0] - 2026-03-20

### Added

- Per-IP rate limiting on the API server via `tower-governor` — uses existing `rate_limit_per_second` and `rate_limit_burst` config fields; set `rate_limit_per_second = 0` to disable
- Shell completion generation via `netcidr completions <shell>` (supports bash, zsh, fish, elvish, powershell)
- IPAM dashboard: RE-ACTIVATE button on released allocations to restore them to active status
- React + Vite + TypeScript dashboard scaffolding (`dashboard/` directory) — replaces Alpine.js single-file dashboard
- Dashboard: Calculator page with bit grid visualization, IPv4/IPv6 results, hextet display
- Dashboard: Splitter, Contains, Summarize, and FromRange pages
- Dashboard: Full IPAM page — supernet management, allocation CRUD with filters, search, free blocks, audit log, 4 modals (create supernet, allocate specific, auto-allocate, allocation detail with tags)
- Dashboard: Visualizer page with address space grid and subnet split distribution chart (recharts)

### Removed

- Old Alpine.js single-file dashboard (`dashboard.html`) — fully replaced by React dashboard
- Legacy dashboard route (`/dashboard/legacy`)
- Legacy dashboard remains accessible at `/dashboard/legacy` during transition
- `make dashboard` and `make dashboard-dev` targets for frontend build and development
- IP version guard: cross-family allocations rejected (e.g., IPv4 CIDR in IPv6 supernet)

### Fixed

- IPAM: re-allocating a previously released CIDR no longer creates duplicate records; the existing released allocation is reactivated with updated metadata
- IPAM: `released_at` timestamp is now cleared when an allocation transitions back to active or reserved status
- IPAM: reactivating a released allocation via status update now checks for overlap with other active/reserved allocations
- Prefix length validation in auto-allocate (rejects prefix > 32 for IPv4, > 128 for IPv6)
- IPv6 unit tests for range arithmetic: `parse_range`, `ranges_overlap`, `range_contains`, `find_gaps`, `find_free_blocks`, `range_to_cidrs`, `split_cidr_to_prefix`
- IPv6 IPAM integration tests: supernet CRUD, allocate specific, auto-allocate, overlap rejection, utilization, free blocks, find-by-IP, release/re-allocate
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

- Schema migration v3: `total_hosts_text` TEXT column on `supernets` and `allocations` tables, enabling correct storage of IPv6 host counts that exceed i64 range (e.g., 2^96 for a /32 supernet)

### Fixed

- IPv6 /0 prefix no longer panics (`1u128 << 128` overflow) in `parse_cidr_metadata`; capped at `u128::MAX`

## [0.13.3] - 2026-03-18

### Added

- MCP server remote backend: `--api-url <url>` flag on `netcidr mcp-serve` proxies IPAM tool calls to a running `netcidr serve` HTTP API instead of using a local database (mutually exclusive with `--ipam-db`)

## [0.13.2] - 2026-03-16

### Added

- JSON export/import: `ipam dump` exports all supernets and allocations to JSON, `ipam load` imports into an empty store
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
  - Supernet management (create, list, get, delete with active-allocation guard)
  - Allocation lifecycle (create, auto-allocate, update, release with conflict detection)
  - Free space discovery and utilization reporting
  - IP address and resource ID reverse lookup
  - Immutable audit log for all mutations
  - Flexible key-value tags on allocations
  - DB path resolution: CLI flag > env var > config file > XDG default
  - Embedded schema migrations with version tracking
- IPAM CLI integration via `netcidr ipam` subcommand with full command suite:
  - `ipam supernet create/list/get/delete` — manage top-level address spaces
  - `ipam allocate` / `ipam auto-allocate` — specific or next-available allocation
  - `ipam allocation get/list/update` — query and update allocations
  - `ipam release` — mark allocations as released
  - `ipam utilization` / `ipam free-blocks` — capacity reporting
  - `ipam find-ip` / `ipam find-resource` — reverse lookup
  - `ipam audit` — query the immutable audit log
- IPAM REST API endpoints via `netcidr serve --ipam-enabled`:
  - `POST /ipam/supernets` — create supernet; `GET` — list all
  - `GET /ipam/supernets/{id}` — get supernet; `DELETE` — delete (guarded by active allocations)
  - `POST /ipam/supernets/{id}/allocate` — auto-allocate next-available blocks
  - `POST /ipam/supernets/{id}/allocate-specific` — allocate a specific CIDR
  - `GET /ipam/supernets/{id}/allocations` — list allocations with filters
  - `GET /ipam/supernets/{id}/free` — free block discovery
  - `GET /ipam/supernets/{id}/utilization` — utilization report
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
  - 10 IPAM tools: `ipam_create_supernet`, `ipam_list_supernets`, `ipam_allocate`, `ipam_allocate_specific`, `ipam_release`, `ipam_list_allocations`, `ipam_free_blocks`, `ipam_utilization`, `ipam_find_ip`, `ipam_find_resource`
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

- Out-of-memory crash when splitting large IPv6 supernets (e.g., /64 → /96 = 4.3B subnets)

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
- Subnet generator to split supernets into smaller subnets
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

[Unreleased]: https://github.com/wingnut128/netcidr/compare/v0.13.1...HEAD
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
