# CI hardening: image scanning, action pinning, Chainguard bases

**Status:** Approved
**Date:** 2026-04-22
**Owner:** @wingnut128

## Context

Scorecard alert #21 flagged RUSTSEC-2026-0104 (rustls-webpki CRL panic) — fixed in PR #73. That surfaced two broader gaps in the netcidr CI baseline:

1. **No image scanning.** The Dockerfile ships Alpine 3.23 but nothing in CI scans the built image for base-OS CVEs. Historically this has been caught by Snyk running externally, which is fragile and not self-owned.
2. **Pinning is done but not enforced.** All workflows currently SHA-pin actions, but nothing prevents a future PR from reintroducing tag-pinned references. The March 2026 `aquasecurity/trivy-action` force-push incident (TeamPCP / RUSTSEC ecosystem compromise) demonstrated tag pinning is the load-bearing defense against this class of attack.

Audit of existing tooling also showed redundant dep-scanning coverage (`dependency-review-action` overlaps Dependabot + `cargo-audit`).

Once this lands end-to-end on netcidr, the same templates should graduate into the `repo-bootstrap` skill so future repos get the baseline for free.

## Goals

- Self-own base-image CVE detection (replace reliance on external scanners).
- Enforce SHA-pinning of all GitHub Actions on every PR.
- Reduce base-image CVE surface by migrating to Chainguard images.
- Emit a signed, verifiable SBOM with each release.
- Emit signed, verifiable build provenance for each release binary.
- Rationalize overlapping dep-scanning tools.
- Codify all of the above into `repo-bootstrap` templates.

## Non-goals

- Full SLSA L3 compliance (hermetic builds, reproducible builds — separate spec).
- Long-lived cosign signing keys (explicitly avoided in favor of keyless Sigstore).
- Container image signing (netcidr does not publish container images).
- Semgrep-vs-CodeQL redundancy audit (tracked as a follow-up issue — needs 6 months of findings data to decide correctly).
- Migration off GitHub-hosted runners / self-hosted runner firewalling.

## Design

### 1. Dockerfile migration to Chainguard

Multi-stage build with Chainguard bases pinned **by digest**, not tag (free-tier Chainguard rotates `:latest` daily; digest pinning is the only way to get reproducibility without the Enterprise tier).

- **Build stage:** `cgr.dev/chainguard/rust:latest-dev@sha256:<digest>` — includes Rust toolchain + shell + apk for build-time deps.
- **Runtime stage:** chosen at implementation time based on an audit of netcidr's runtime linkage:
  - **Preferred:** `cgr.dev/chainguard/static@sha256:<digest>` — requires fully-static binary (musl target). Zero-CVE floor.
  - **Fallback:** `cgr.dev/chainguard/glibc-dynamic@sha256:<digest>` — if any dep (e.g., sqlite, openssl) blocks musl cross-compile.
  - **Last resort:** `cgr.dev/chainguard/wolfi-base@sha256:<digest>` — only if `--daemonize` or another runtime path needs `/bin/sh` or apk.

Dependabot's `docker` ecosystem handles digest updates automatically.

### 2. Image scanning workflow (`.github/workflows/image-scan.yml`)

Single workflow, three triggers:

- **PR trigger:** `paths: ['Dockerfile', 'Cargo.lock', '.github/workflows/image-scan.yml']`. Runs docker build → Syft SBOM → Grype scan. Gate: `--fail-on high --only-fixed` (unfixable CVEs don't block). SARIF uploaded to code-scanning tab.
- **Weekly cron:** `schedule: '0 12 * * 1'` on `main`. Same scan. If findings changed vs previous run, open/update a single tracking issue via `gh issue create` (or update existing). Catches new CVEs landing in the pinned base image without waiting for a code change.
- **Release trigger:** `on: release: types: [published]`. Same scan, plus:
  - Upload `sbom.cyclonedx.json` + `sbom.spdx.json` as release assets via `gh release upload`.
  - Generate signed attestation via `actions/attest-sbom@<sha>` using GitHub OIDC — no key management.

Actions used (all SHA-pinned): `anchore/sbom-action`, `anchore/scan-action`, `actions/upload-artifact`, `actions/attest-sbom`.

### 2a. Release binary provenance

In the existing `release.yml` release job (after binary tarballs are built, before `gh release upload`):

- `actions/attest-build-provenance@<sha>` pointed at the built tarball(s). Same keyless Sigstore flow as `attest-sbom` — OIDC → Fulcio → Rekor.
- Requires `permissions: id-token: write` + `attestations: write` on the release job (already needed for SBOM attestation in step 2).
- Consumers verify with `gh attestation verify <tarball> --owner wingnut128`.
- No key management. No rotation. Verifies the exact workflow run + repo + ref that produced the binary.

Graduated into `repo-bootstrap` as part of the release-workflow template.

### 3. Action pin enforcement (`.github/workflows/pin-check.yml`)

`suzuki-shunsuke/pinact-action@<sha>` on PRs touching `.github/workflows/**`. Fails if any `uses:` line is not a 40-char SHA. Runs in ~5s. Clear failure message telling contributors to pin-by-SHA.

### 4. Drop `.github/workflows/dependency-review.yml`

Redundant: `cargo-audit` (RUSTSEC DB, already in CI) + Dependabot alerts (GHSA DB) cover the same ground with better Rust-specific coverage.

### 5. Dependabot config verification

Confirm `.github/dependabot.yml` includes both `package-ecosystem: github-actions` and `package-ecosystem: docker`. Add whichever is missing.

### 6. Follow-up issue (tracked, not implemented in this spec)

"Audit Semgrep vs CodeQL finding overlap for netcidr; drop whichever is redundant." Needs ≥6 months of CI findings data to make the call. Filed as a GitHub issue at implementation time.

### 7. `repo-bootstrap` skill update

After all of 1–5 land and prove out on netcidr, graduate into `~/.claude/skills/repo-bootstrap/`:

- Add new **"CI hardening"** step in `SKILL.md` (not a separate skill — belongs in the same baseline-security bucket as branch protection and Dependabot setup).
- New templates under `skills/repo-bootstrap/templates/workflows/`:
  - `image-scan.yml` (parameterized for repos without a Dockerfile — skip cleanly if none).
  - `pin-check.yml`.
- Add `templates/Dockerfile.chainguard` as the recommended starting point, with a commented-out Alpine fallback for projects that need apk at runtime.
- Idempotency: detect existing equivalents and skip; detect `dependency-review.yml` and offer to remove it.

## Implementation sequence

Order matters — later steps depend on earlier ones producing a clean signal:

1. **Dockerfile → Chainguard** (one PR). Audit runtime deps, pick base, migrate, verify `just release` + smoke-test the built binary.
2. **`image-scan.yml`** (one PR). Lands with near-zero findings thanks to step 1 — proves the pipeline works rather than drowning in Alpine noise.
3. **`pin-check.yml`** (one PR). Small, independent.
4. **Drop `dependency-review.yml` + verify Dependabot config** (one PR).
5. **File Semgrep-vs-CodeQL audit issue.**
6. **`repo-bootstrap` skill update** (separate PR, separate repo/dir).
7. **Validation:** run updated `repo-bootstrap` skill against a throwaway repo; confirm clean apply.

## Testing strategy

- Each PR above includes its own tests and CI run on netcidr — the repo itself is the integration test.
- For the weekly cron: one manual `workflow_dispatch` after merge to verify the issue-creation path.
- For attestations: after first release, verify with `gh attestation verify --owner wingnut128 sbom.cyclonedx.json`.
- For `repo-bootstrap` graduation: dry-run against a scratch repo before declaring done.

## Risks and mitigations

- **Chainguard `:latest` digest drift.** Mitigated by digest-pinning + Dependabot docker ecosystem updates.
- **Grype false-positive noise from base image.** Mitigated by `--only-fixed` and Chainguard's near-zero-CVE floor.
- **pinact false-positives on non-GitHub actions (`docker://` refs).** pinact-action handles these; verify in implementation.
- **Musl cross-compile breakage.** If it blocks, fall back to `glibc-dynamic` — explicitly documented fallback, not a surprise.
- **Attestation verification requires gh 2.50+.** Document minimum version in README if we recommend consumers verify.

## Out of scope (explicit)

- Cosign signing of release binaries — separate spec.
- Container registry publishing — netcidr currently doesn't publish images; if it ever does, that's a separate spec.
- Migration of harden-runner settings (already in place, not changing).
