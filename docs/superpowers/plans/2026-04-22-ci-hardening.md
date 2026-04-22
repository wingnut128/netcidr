# CI Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden netcidr's CI pipeline with Chainguard base images, Grype/Syft image scanning, signed SBOM + build-provenance attestations, and `pinact`-based SHA-pin enforcement, then graduate the patterns into the `repo-bootstrap` skill.

**Architecture:** Seven independent PRs landing in order, each producing working, testable software on its own. Chainguard migration first (to eliminate baseline CVE noise), then scan workflow, then provenance, then pin enforcement, then tool rationalization, then skill graduation.

**Tech Stack:** GitHub Actions, Chainguard images (cgr.dev), Anchore Grype + Syft, Sigstore (Fulcio + Rekor) via `actions/attest-*`, `suzuki-shunsuke/pinact-action`, Docker, Rust with `x86_64-unknown-linux-musl` target.

**Reference spec:** `docs/superpowers/specs/2026-04-22-ci-hardening-design.md`

**Research findings used throughout:**
- Static linking is feasible — reqwest uses rustls, sqlx avoids native-tls, rusqlite uses bundled feature, no `openssl-sys`/`libpq`/`librdkafka`. Go with `cgr.dev/chainguard/static`.
- Action SHAs (all verified Node 24 or composite):
  - `anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2 # v7.4.0`
  - `anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0`
  - `actions/attest-sbom@c604332985a26aa8cf1bdc465b92731239ec6b9e # v4.1.0`
  - `actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32 # v4.1.0`
  - `suzuki-shunsuke/pinact-action@cf51507d80d4d6522a07348e3d58790290eaf0b6 # v2.0.0`

---

## File Structure

| File | Action | Purpose |
|---|---|---|
| `Dockerfile` | Modify | Migrate to Chainguard static runtime + musl build |
| `.github/workflows/image-scan.yml` | Create | Grype + Syft + SBOM attestation on PR/cron/release |
| `.github/workflows/release.yml` | Modify | Add `attest-build-provenance` on binary upload |
| `.github/workflows/pin-check.yml` | Create | `pinact-action` enforces SHA pinning on PRs |
| `.github/workflows/dependency-review.yml` | Delete | Redundant with cargo-audit + Dependabot |
| `CHANGELOG.md` | Modify | Entry under `[Unreleased]` per post-commit rule |
| `README.md` | Modify | Add "Verifying release artifacts" section |
| `~/.claude/skills/repo-bootstrap/templates/workflows/image-scan.yml` | Create | Template for graduation |
| `~/.claude/skills/repo-bootstrap/templates/workflows/pin-check.yml` | Create | Template for graduation |
| `~/.claude/skills/repo-bootstrap/templates/Dockerfile.chainguard` | Create | Template for graduation |
| `~/.claude/skills/repo-bootstrap/SKILL.md` | Modify | Add "CI hardening" step |

---

## PR 1: Dockerfile → Chainguard (static musl runtime)

**Branch:** `refactor/dockerfile-chainguard`

### Task 1.1: Audit current image size + linkage baseline

**Files:**
- Read: `Dockerfile`

- [ ] **Step 1: Build current image and record baseline**

Run:
```bash
docker build -t netcidr:pre-chainguard .
docker image inspect netcidr:pre-chainguard --format '{{.Size}}'
docker run --rm --entrypoint sh netcidr:pre-chainguard -c 'ldd /usr/local/bin/netcidr 2>&1 || echo STATIC'
```
Expected: record size (bytes) and linkage. Save both as a comment in the PR description.

- [ ] **Step 2: Fetch current Chainguard image digests**

Run:
```bash
docker pull cgr.dev/chainguard/rust:latest-dev
docker pull cgr.dev/chainguard/static:latest
docker inspect cgr.dev/chainguard/rust:latest-dev --format '{{index .RepoDigests 0}}'
docker inspect cgr.dev/chainguard/static:latest --format '{{index .RepoDigests 0}}'
```
Expected: two `cgr.dev/chainguard/<name>@sha256:<hex>` lines. Record both. Use these exact digests in Task 1.2.

### Task 1.2: Rewrite Dockerfile

**Files:**
- Modify: `Dockerfile` (entire file rewritten)

- [ ] **Step 1: Replace Dockerfile content**

Use the digests from Task 1.1 Step 2 in place of `<BUILDER_DIGEST>` and `<RUNTIME_DIGEST>` below.

```dockerfile
# syntax=docker/dockerfile:1
#
# Build args:
#   FEATURES        - Cargo feature flags (default: "default")
#   WITH_DASHBOARD  - "true" or "false" (default: true)
#
# Examples:
#   docker build .
#   docker build --build-arg FEATURES=swagger --build-arg WITH_DASHBOARD=false .
#
ARG FEATURES=default
ARG WITH_DASHBOARD=true

# ---------- Dashboard build (skipped when WITH_DASHBOARD=false) -----------
FROM oven/bun:1-alpine@sha256:4de475389889577f346c636f956b42a5c31501b654664e9ae5726f94d7bb5349 AS dashboard-build
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/bun.lock ./
RUN bun install --frozen-lockfile
COPY dashboard/ ./
RUN bun run build

FROM cgr.dev/chainguard/static@sha256:<RUNTIME_DIGEST> AS dashboard-false
# No-op stage producing an empty dashboard directory. chainguard/static has no shell,
# but the COPY in the builder stage does not require one — the directory just needs
# to exist on disk. We cheat by using the builder image to create it.

FROM dashboard-build AS dashboard-true

FROM dashboard-${WITH_DASHBOARD} AS dashboard

# ---------- Rust build (Chainguard rust:latest-dev has shell + apk + musl) -
FROM cgr.dev/chainguard/rust:latest-dev@sha256:<BUILDER_DIGEST> AS builder

ARG FEATURES
USER root

WORKDIR /app

# Install musl target (Chainguard rust image may need it explicitly)
RUN rustup target add x86_64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl \
        --no-default-features --features "${FEATURES}" && \
    rm -rf src

COPY --from=dashboard /app/dashboard/dist ./dashboard/dist

COPY src ./src
COPY tests ./tests

RUN touch src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl \
        --no-default-features --features "${FEATURES}"

# ---------- Runtime (Chainguard static: distroless, zero-CVE floor) -------
FROM cgr.dev/chainguard/static@sha256:<RUNTIME_DIGEST>

# chainguard/static ships ca-certificates, /etc/passwd with a `nonroot` user (uid 65532),
# tzdata, and nothing else. No shell. No package manager.

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/netcidr /usr/local/bin/netcidr

USER nonroot

EXPOSE 8080

# chainguard/static has no wget/curl/sh — the previous shell-based healthcheck will not work.
# Rely on external orchestrator healthchecks (k8s livenessProbe, docker-compose healthcheck
# with TCP probe, etc.). Document this in README.

ENTRYPOINT ["/usr/local/bin/netcidr"]
CMD ["--help"]
```

**Note on the `dashboard-false` stage:** Since `chainguard/static` has no shell, `RUN mkdir -p` won't work. The stage above resolves this by relying on the later `COPY --from=dashboard` — if `WITH_DASHBOARD=false` resolves to the `chainguard/static` stage (which has no `/app/dashboard/dist`), the `COPY` will fail. If the dashboard-false path turns out to be needed in CI, switch `dashboard-false` to use `FROM cgr.dev/chainguard/rust:latest-dev@sha256:<BUILDER_DIGEST> AS dashboard-false` + `RUN mkdir -p /app/dashboard/dist`. Test both paths before committing.

- [ ] **Step 2: Build with dashboard**

Run: `docker build -t netcidr:chainguard .`
Expected: clean build, no errors. Image tagged successfully.

- [ ] **Step 3: Build without dashboard**

Run: `docker build -t netcidr:chainguard-nodash --build-arg WITH_DASHBOARD=false .`
Expected: clean build. If fails because `chainguard/static` can't `mkdir`, update the `dashboard-false` stage per the note in Step 1 and rebuild.

- [ ] **Step 4: Verify static linkage**

Run:
```bash
docker create --name check netcidr:chainguard
docker cp check:/usr/local/bin/netcidr /tmp/netcidr.chainguard
docker rm check
file /tmp/netcidr.chainguard
```
Expected: `ELF 64-bit LSB executable, x86-64, ..., statically linked, ...` (the word "statically" must appear).

- [ ] **Step 5: Smoke-test the binary**

Run:
```bash
docker run --rm netcidr:chainguard 192.168.1.0/24
docker run --rm netcidr:chainguard --version
```
Expected: subnet calculation output + version string. Non-zero exit for either fails this task.

- [ ] **Step 6: Record image size delta**

Run: `docker image inspect netcidr:chainguard --format '{{.Size}}'`
Compare to pre-Chainguard baseline from Task 1.1 Step 1. Record in PR description.

### Task 1.3: CHANGELOG + README

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `README.md`

- [ ] **Step 1: Add CHANGELOG entry**

Insert under `## [Unreleased]` → `### Changed` (create the subsection if it doesn't exist, before `### Security`):

```markdown
- Migrate Dockerfile to Chainguard base images (`cgr.dev/chainguard/rust:latest-dev` build stage, `cgr.dev/chainguard/static` runtime stage) with digest pinning. Produces a statically-linked musl binary with a distroless runtime — near-zero-CVE baseline. Image has no shell; container-level healthchecks now rely on the orchestrator (k8s probe, docker-compose TCP healthcheck).
```

- [ ] **Step 2: Update README "Docker" section**

Find the Docker section in README.md. If there is a `HEALTHCHECK` or wget-based probe example, replace with:

```markdown
> **Note:** The Chainguard-based image is distroless (no shell, no wget/curl). For Kubernetes or Docker healthchecks, use a TCP probe on port 8080 or an HTTP probe against `/health` via the orchestrator rather than an in-image `HEALTHCHECK`.
```

- [ ] **Step 3: Commit**

```bash
git add Dockerfile CHANGELOG.md README.md
git commit -m "refactor: migrate Dockerfile to Chainguard static base

Produces a statically-linked musl binary on a distroless runtime.
Near-zero-CVE baseline; image has no shell, so HEALTHCHECK is
delegated to the orchestrator."
```

### Task 1.4: Open PR and merge

- [ ] **Step 1: Push + open PR**

```bash
git push -u origin refactor/dockerfile-chainguard
gh pr create --title "refactor: migrate Dockerfile to Chainguard static base" --body "$(cat <<'EOF'
## Summary
- Chainguard rust:latest-dev (build) + chainguard/static (runtime), digest-pinned
- Static musl binary, distroless runtime, near-zero-CVE floor
- Dockerfile HEALTHCHECK removed (no shell in runtime); orchestrator probes take over

## Test plan
- [x] `docker build -t netcidr:chainguard .` succeeds
- [x] `docker build --build-arg WITH_DASHBOARD=false .` succeeds
- [x] Binary is statically linked (`file` reports "statically linked")
- [x] Smoke test: `docker run --rm netcidr:chainguard 192.168.1.0/24` works
EOF
)"
```

- [ ] **Step 2: Poll CI and merge**

```bash
gh pr checks --watch
gh pr merge --squash --delete-branch
git checkout main && git pull
```

---

## PR 2: Image scan workflow (Grype + SBOM + attestation)

**Branch:** `feat/image-scan-workflow`

### Task 2.1: Create image-scan.yml

**Files:**
- Create: `.github/workflows/image-scan.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: Image Scan

on:
  pull_request:
    paths:
      - 'Dockerfile'
      - 'Cargo.lock'
      - '.github/workflows/image-scan.yml'
  schedule:
    # Weekly drift scan, Mondays 12:00 UTC
    - cron: '0 12 * * 1'
  release:
    types: [published]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    name: Build + Grype + SBOM
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # for SARIF upload
      id-token: write        # for attestations (release only)
      attestations: write    # for attestations (release only)
      issues: write          # for cron issue creation
    steps:
      - name: Harden the runner
        uses: step-security/harden-runner@8d3c67de8e2fe68ef647c8db1e6a09f647780f40 # v2.19.0
        with:
          egress-policy: audit

      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      - name: Build image
        run: docker build -t netcidr:scan .

      - name: Generate SBOM (CycloneDX)
        uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0
        with:
          image: netcidr:scan
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json
          upload-artifact: true
          upload-artifact-retention: 90

      - name: Generate SBOM (SPDX)
        uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0
        with:
          image: netcidr:scan
          format: spdx-json
          output-file: sbom.spdx.json
          upload-artifact: true
          upload-artifact-retention: 90

      - name: Scan image with Grype
        id: grype
        uses: anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2 # v7.4.0
        with:
          image: netcidr:scan
          fail-build: ${{ github.event_name == 'pull_request' }}
          severity-cutoff: high
          only-fixed: true
          output-format: sarif

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@ce64ddcb0d8d890d2df4a9d1c04ff297367dea2a # v3.35.2
        with:
          sarif_file: ${{ steps.grype.outputs.sarif }}
          category: grype-image-scan

      # ---- Release-only: attach + attest SBOMs ----
      - name: Attest SBOM (CycloneDX)
        if: github.event_name == 'release'
        uses: actions/attest-sbom@c604332985a26aa8cf1bdc465b92731239ec6b9e # v4.1.0
        with:
          subject-path: sbom.cyclonedx.json
          sbom-path: sbom.cyclonedx.json

      - name: Upload SBOMs to release
        if: github.event_name == 'release'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GH_REPO: ${{ github.repository }}
        run: |
          gh release upload "${{ github.event.release.tag_name }}" \
            sbom.cyclonedx.json sbom.spdx.json --clobber

      # ---- Cron-only: open/update drift tracking issue ----
      - name: Open drift-tracking issue
        if: github.event_name == 'schedule' && steps.grype.outputs.vulnerabilities != ''
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GH_REPO: ${{ github.repository }}
        run: |
          TITLE="Weekly image scan: new fixable CVEs detected"
          BODY="Weekly Grype drift scan found fixable HIGH/CRITICAL CVEs in the built image. See the [workflow run](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}) for the SARIF report. Bump the Chainguard digests in \`Dockerfile\` to pick up patched base images."
          EXISTING=$(gh issue list --label image-scan-drift --state open --json number --jq '.[0].number // empty')
          if [ -n "$EXISTING" ]; then
            gh issue comment "$EXISTING" --body "$BODY"
          else
            gh issue create --title "$TITLE" --body "$BODY" --label image-scan-drift
          fi
```

- [ ] **Step 2: Create the `image-scan-drift` label**

Run:
```bash
gh label create image-scan-drift --description "Weekly Grype scan found new fixable CVEs" --color c5def5 --force
```
Expected: label created or updated. `--force` suppresses "already exists" errors.

### Task 2.2: Validate the workflow locally before pushing

**Files:**
- None (validation only)

- [ ] **Step 1: Lint with actionlint**

Run:
```bash
# Install actionlint if not present
command -v actionlint >/dev/null || brew install actionlint
actionlint .github/workflows/image-scan.yml
```
Expected: no output (silent success).

- [ ] **Step 2: Dry-run the scan locally**

Run:
```bash
docker build -t netcidr:scan .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  anchore/grype:latest netcidr:scan --only-fixed --fail-on high
echo "exit=$?"
```
Expected: Grype runs; exit 0 (no fixable HIGH/CRITICAL) is the goal post-Chainguard migration. If exit 1, record which CVEs and whether they're upstream-unfixed.

### Task 2.3: CHANGELOG + commit + PR

- [ ] **Step 1: Add CHANGELOG entry**

Insert under `## [Unreleased]` → `### Added`:

```markdown
- New `.github/workflows/image-scan.yml` — builds the Docker image on PRs touching `Dockerfile`/`Cargo.lock` and scans with Grype + Syft. Generates CycloneDX + SPDX SBOMs. Weekly cron detects new fixable CVEs in pinned base images and opens a tracking issue. Release events attach signed SBOM attestations via Sigstore (keyless — no signing keys required).
```

- [ ] **Step 2: Commit + PR**

```bash
git add .github/workflows/image-scan.yml CHANGELOG.md
git commit -m "feat(ci): add image-scan workflow with Grype + signed SBOMs"
git push -u origin feat/image-scan-workflow
gh pr create --title "feat(ci): add image-scan workflow with Grype + signed SBOMs" --body "$(cat <<'EOF'
## Summary
- Grype scan on PRs touching Dockerfile/Cargo.lock — fails on HIGH/CRITICAL with a fixed version
- Weekly cron opens/updates an issue if new fixable CVEs appear in the pinned base image
- Release events attach CycloneDX + SPDX SBOMs with Sigstore keyless attestation
- SARIF uploaded to code-scanning tab

## Test plan
- [x] actionlint passes
- [x] Local Grype scan of the Chainguard image exits clean
- [x] Verify SARIF appears in Security tab after merge
EOF
)"
```

- [ ] **Step 3: After merge, trigger workflow_dispatch**

```bash
gh pr merge --squash --delete-branch
git checkout main && git pull
gh workflow run image-scan.yml
gh run watch
```
Expected: run succeeds, SARIF uploaded (check Security → Code scanning → filter by `grype-image-scan`).

---

## PR 3: Release binary build provenance

**Branch:** `feat/release-attestations`

### Task 3.1: Add attestation step to release.yml

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Add permissions + attestation step**

Edit `.github/workflows/release.yml`. In the `build` job `permissions:` block, replace:

```yaml
    permissions:
      contents: write
```

with:

```yaml
    permissions:
      contents: write
      id-token: write
      attestations: write
```

Then, **immediately before** the existing `Upload binary and publish release` step, insert:

```yaml
      - name: Attest build provenance
        uses: actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32 # v4.1.0
        with:
          subject-path: target/release/netcidr
```

### Task 3.2: README verification instructions

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add "Verifying release artifacts" section**

Insert after the existing "Install" / "Download" section (whatever is currently there):

```markdown
## Verifying release artifacts

Starting with the first post-2026-04-22 release, the `netcidr` binary and the container image SBOMs are signed with [Sigstore](https://www.sigstore.dev/) via GitHub's keyless attestation flow — no public keys to manage.

Verify a downloaded binary:

```bash
gh attestation verify netcidr --owner wingnut128
```

Verify the SBOM attached to a release:

```bash
gh release download vX.Y.Z --pattern 'sbom.cyclonedx.json'
gh attestation verify sbom.cyclonedx.json --owner wingnut128
```

Requires `gh` 2.50+.
```

### Task 3.3: CHANGELOG + commit + PR

- [ ] **Step 1: Add CHANGELOG entry**

Insert under `## [Unreleased]` → `### Added`:

```markdown
- Release binaries now carry Sigstore-signed build provenance (`actions/attest-build-provenance`). Consumers verify with `gh attestation verify <binary> --owner wingnut128`. No signing keys — uses GitHub OIDC + Fulcio + Rekor.
```

- [ ] **Step 2: Commit + PR**

```bash
git add .github/workflows/release.yml README.md CHANGELOG.md
git commit -m "feat(ci): attest release binary provenance via Sigstore keyless flow"
git push -u origin feat/release-attestations
gh pr create --title "feat(ci): attest release binary provenance (Sigstore keyless)" --body "$(cat <<'EOF'
## Summary
- actions/attest-build-provenance on the release binary
- No key management — uses OIDC + Fulcio + Rekor
- README documents verification via `gh attestation verify`

## Test plan
- [x] Workflow YAML parses (actionlint)
- [ ] Verified end-to-end on next release: `gh attestation verify netcidr --owner wingnut128`
EOF
)"
gh pr merge --squash --delete-branch
```

---

## PR 4: pinact SHA-pin enforcement

**Branch:** `feat/pinact-enforcement`

### Task 4.1: Create pin-check.yml

**Files:**
- Create: `.github/workflows/pin-check.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: Pin Check

on:
  pull_request:
    paths:
      - '.github/workflows/**'
      - '.github/actions/**'

permissions:
  contents: read

jobs:
  pinact:
    name: Verify all actions pinned by SHA
    runs-on: ubuntu-latest
    steps:
      - name: Harden the runner
        uses: step-security/harden-runner@8d3c67de8e2fe68ef647c8db1e6a09f647780f40 # v2.19.0
        with:
          egress-policy: audit

      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      - name: Run pinact
        uses: suzuki-shunsuke/pinact-action@cf51507d80d4d6522a07348e3d58790290eaf0b6 # v2.0.0
        with:
          skip_push: true
          fail_on_diff: true
```

### Task 4.2: Validate + CHANGELOG + PR

- [ ] **Step 1: Lint**

Run: `actionlint .github/workflows/pin-check.yml`
Expected: silent success.

- [ ] **Step 2: Add CHANGELOG entry**

Under `## [Unreleased]` → `### Security`:

```markdown
- New `.github/workflows/pin-check.yml` fails PRs that add tag-pinned GitHub Actions (e.g., `@v1` or `@main`). All `uses:` lines must be 40-char commit SHAs. Defense-in-depth against action-tag force-push attacks (c.f. aquasecurity/trivy-action, March 2026).
```

- [ ] **Step 3: Commit + PR**

```bash
git add .github/workflows/pin-check.yml CHANGELOG.md
git commit -m "feat(ci): enforce SHA pinning on all GitHub Actions via pinact"
git push -u origin feat/pinact-enforcement
gh pr create --title "feat(ci): enforce SHA pinning via pinact-action" --body "$(cat <<'EOF'
## Summary
- New pin-check.yml runs on PRs touching .github/workflows/** or .github/actions/**
- Fails if any uses: is not a 40-char SHA
- Defense against tag force-push supply-chain attacks

## Test plan
- [x] Workflow itself is SHA-pinned (self-hosting the rule)
- [ ] Post-merge: open a test PR with a tag-pinned action, confirm it fails
EOF
)"
gh pr checks --watch
gh pr merge --squash --delete-branch
```

- [ ] **Step 4: Verify with a deliberate failure**

Create a throwaway branch, add a tag-pinned action, push, confirm pin-check fails, close the PR:

```bash
git checkout -b test/pinact-negative
cat >> .github/workflows/image-scan.yml <<'EOF'

      - name: Deliberate tag-pin for testing
        uses: actions/checkout@v4
EOF
git add .github/workflows/image-scan.yml
git commit -m "test: deliberate tag pin (should fail pin-check)"
git push -u origin test/pinact-negative
gh pr create --title "TEST: pin-check negative" --body "should fail"
gh pr checks --watch
# Expected: pin-check fails. Close the PR.
gh pr close --delete-branch
```

---

## PR 5: Drop dependency-review.yml + verify Dependabot

**Branch:** `chore/drop-dependency-review`

### Task 5.1: Verify Dependabot config is complete

**Files:**
- Read: `.github/dependabot.yml`

- [ ] **Step 1: Confirm ecosystems**

Run: `grep -E 'package-ecosystem' .github/dependabot.yml`
Expected output:
```
  - package-ecosystem: "github-actions"
  - package-ecosystem: "cargo"
  - package-ecosystem: "npm"
  - package-ecosystem: docker
```

All four must be present. If `docker` or `github-actions` is missing, add it before proceeding — use the YAML entries already in `.github/dependabot.yml` as the pattern (matching quoting/indent style).

### Task 5.2: Delete dependency-review.yml

**Files:**
- Delete: `.github/workflows/dependency-review.yml`

- [ ] **Step 1: Delete**

Run: `git rm .github/workflows/dependency-review.yml`
Expected: file removed from index.

### Task 5.3: CHANGELOG + commit + PR

- [ ] **Step 1: Add CHANGELOG entry**

Under `## [Unreleased]` → `### Removed`:

```markdown
- Removed `.github/workflows/dependency-review.yml` — redundant with `cargo-audit` (RUSTSEC DB, runs in CI) and Dependabot alerts (GHSA DB). Dropping this workflow reduces CI cost without reducing coverage.
```

- [ ] **Step 2: Commit + PR**

```bash
git add .github/workflows/ CHANGELOG.md .github/dependabot.yml
git commit -m "chore(ci): drop dependency-review.yml (redundant with cargo-audit + Dependabot)"
git push -u origin chore/drop-dependency-review
gh pr create --title "chore(ci): drop dependency-review.yml" --body "$(cat <<'EOF'
## Summary
- Removes dependency-review.yml — redundant with cargo-audit + Dependabot
- Verified Dependabot config covers cargo, npm, github-actions, docker ecosystems

## Test plan
- [x] Dependabot config still includes all four ecosystems
- [x] cargo-audit still runs in ci.yml
EOF
)"
gh pr merge --squash --delete-branch
```

---

## PR 6: File Semgrep-vs-CodeQL audit tracking issue

**Files:**
- None (issue only)

- [ ] **Step 1: Create the tracking issue**

Run:
```bash
gh issue create --title "Audit: Semgrep vs CodeQL finding overlap — drop whichever is redundant" --body "$(cat <<'EOF'
## Context

netcidr runs both Semgrep (via \`make check\`) and CodeQL (via \`.github/workflows/codeql.yml\`). Both are SAST tools with significant overlap on Rust source analysis. Running both is only justified if they catch different things.

## What to do

After 6 months of findings data (i.e., around 2026-10-22):

1. Export Semgrep findings history (from CI logs or Semgrep Cloud if used)
2. Export CodeQL findings from the Security → Code scanning tab
3. Compare: how many findings are unique to each tool? How many are duplicates?
4. If Semgrep adds no unique findings, drop it from \`make check\` and document the decision.
5. If CodeQL adds no unique findings, disable \`.github/workflows/codeql.yml\`.
6. If both add unique findings, document why we keep both.

## References

- Scoped out of: \`docs/superpowers/specs/2026-04-22-ci-hardening-design.md\`
- Background: [Claude conversation on netcidr-sec-patches branch, 2026-04-22]
EOF
)" --label chore,security
```
Expected: issue URL printed.

---

## PR 7: Graduate templates into repo-bootstrap skill

**Branch:** (separate working directory: `~/.claude/skills/repo-bootstrap/`)

**Note:** This is not in the netcidr repo. The `repo-bootstrap` skill lives in `~/.claude/skills/repo-bootstrap/`. Work there.

### Task 7.1: Add Dockerfile template

**Files:**
- Create: `~/.claude/skills/repo-bootstrap/templates/Dockerfile.chainguard`

- [ ] **Step 1: Copy netcidr's final Dockerfile as a starting template**

Run:
```bash
cp /Volumes/data/dev/netcidr/Dockerfile \
   ~/.claude/skills/repo-bootstrap/templates/Dockerfile.chainguard
```

- [ ] **Step 2: Parameterize for generic use**

Edit `~/.claude/skills/repo-bootstrap/templates/Dockerfile.chainguard`:
- Replace `netcidr` → `<BINARY_NAME>` (comment at top of file explains substitution)
- Replace references to `dashboard/` with a comment block `# ---- Optional asset build (remove if not needed) ----`
- Add header comment:

```dockerfile
# ==============================================================================
# Chainguard-based Rust Dockerfile template
#
# Before using:
#   1. Replace <BINARY_NAME> with your binary name (typically matches crate name)
#   2. Run the two `docker pull` + `docker inspect` commands below to get current
#      digests, then replace <BUILDER_DIGEST> and <RUNTIME_DIGEST>:
#
#        docker pull cgr.dev/chainguard/rust:latest-dev
#        docker inspect cgr.dev/chainguard/rust:latest-dev --format '{{index .RepoDigests 0}}'
#        docker pull cgr.dev/chainguard/static:latest
#        docker inspect cgr.dev/chainguard/static:latest --format '{{index .RepoDigests 0}}'
#
#   3. If your binary needs glibc (e.g., dynamically-linked OpenSSL), replace
#      `cgr.dev/chainguard/static` with `cgr.dev/chainguard/glibc-dynamic`.
#   4. If your binary needs a shell at runtime, use `cgr.dev/chainguard/wolfi-base`.
#   5. Dependabot's `docker` ecosystem will keep digests updated automatically.
# ==============================================================================
```

### Task 7.2: Add workflow templates

**Files:**
- Create: `~/.claude/skills/repo-bootstrap/templates/workflows/image-scan.yml`
- Create: `~/.claude/skills/repo-bootstrap/templates/workflows/pin-check.yml`

- [ ] **Step 1: Copy image-scan.yml**

Run:
```bash
cp /Volumes/data/dev/netcidr/.github/workflows/image-scan.yml \
   ~/.claude/skills/repo-bootstrap/templates/workflows/image-scan.yml
```

- [ ] **Step 2: Parameterize image-scan.yml**

Edit the copy:
- Replace `netcidr:scan` → `<IMAGE_NAME>:scan`
- Add a header comment block explaining substitutions and the fact that the weekly-issue step requires the `image-scan-drift` label.

- [ ] **Step 3: Copy pin-check.yml**

Run:
```bash
cp /Volumes/data/dev/netcidr/.github/workflows/pin-check.yml \
   ~/.claude/skills/repo-bootstrap/templates/workflows/pin-check.yml
```

pin-check.yml needs no parameterization — it's generic.

### Task 7.3: Update SKILL.md

**Files:**
- Modify: `~/.claude/skills/repo-bootstrap/SKILL.md`

- [ ] **Step 1: Read current SKILL.md**

Run: `wc -l ~/.claude/skills/repo-bootstrap/SKILL.md`
Expected: ~288 lines (per earlier check). Read the file in full before editing to understand existing structure and voice.

- [ ] **Step 2: Add "CI hardening" section**

Append or insert (at the appropriate structural point — after existing Dependabot/branch-protection guidance, before "Idempotency" or similar closing sections) a new section:

```markdown
## CI hardening

Baseline security controls every new or hardened repo should have. All are SHA-pinned; SHAs in templates were current at 2026-04-22 and should be bumped before first use per the global GitHub Actions pinning rule.

### Image scanning (if the repo has a Dockerfile)

1. Copy `templates/Dockerfile.chainguard` → `Dockerfile` (if none exists) or offer to migrate an existing Alpine/Debian Dockerfile. Fill in BINARY_NAME + two Chainguard digests.
2. Copy `templates/workflows/image-scan.yml` → `.github/workflows/image-scan.yml`. Replace `<IMAGE_NAME>`.
3. Create the `image-scan-drift` label: `gh label create image-scan-drift --color c5def5`.
4. Verify `.github/dependabot.yml` includes `package-ecosystem: docker`. Add if missing.

### Action pin enforcement

1. Copy `templates/workflows/pin-check.yml` → `.github/workflows/pin-check.yml`. No substitution needed.
2. Verify `.github/dependabot.yml` includes `package-ecosystem: github-actions`. Add if missing.

### Release binary provenance

If the repo publishes release binaries via GitHub Releases:

1. In the existing release workflow, add to the release job's `permissions:`:
   ```yaml
   id-token: write
   attestations: write
   ```
2. Add this step immediately before the `gh release upload` step (adjust `subject-path` to the built artifact):
   ```yaml
   - name: Attest build provenance
     uses: actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32 # v4.1.0
     with:
       subject-path: path/to/built/binary
   ```
3. Add a "Verifying release artifacts" section to README with `gh attestation verify` instructions.

### Dependency scanning rationalization

1. If `.github/workflows/dependency-review.yml` exists AND Dependabot alerts are enabled AND the repo runs a language-native audit (cargo-audit, npm audit, etc.) in CI, offer to delete `dependency-review.yml` as redundant.
2. If only one of the two is present, keep what's there.
```

- [ ] **Step 3: Commit to the ~/.claude/skills/repo-bootstrap repo (if it's a git repo)**

Run:
```bash
cd ~/.claude/skills/repo-bootstrap
git status 2>&1 | head -5
```

If it's a git repo, commit:
```bash
git add templates/ SKILL.md
git commit -m "feat(repo-bootstrap): add CI hardening step (image scan, pin check, provenance)

Graduates Grype image scanning, pinact SHA enforcement, Chainguard
Dockerfile template, and Sigstore build-provenance patterns from
the netcidr CI hardening rollout (see netcidr commit history
2026-04-22)."
```

If it's not a git repo, just leave the files in place and note it in the plan's completion summary.

### Task 7.4: Validate by running the skill against a scratch repo

**Files:**
- None (validation only)

- [ ] **Step 1: Create a scratch repo**

```bash
TMPDIR=$(mktemp -d)
cd "$TMPDIR"
git init scratch-repo
cd scratch-repo
echo "# scratch" > README.md
git add . && git commit -m "initial"
```

- [ ] **Step 2: Invoke repo-bootstrap and follow its CI hardening prompts**

In a fresh Claude Code session in the scratch repo, invoke the `repo-bootstrap` skill and explicitly request the CI hardening step. Verify it offers to add `image-scan.yml`, `pin-check.yml`, and the Dockerfile template, and that the files land cleanly.

- [ ] **Step 3: Run actionlint on the generated workflows**

Run: `actionlint .github/workflows/*.yml`
Expected: silent success. If any template has lint errors after substitution, fix the template and re-test.

- [ ] **Step 4: Clean up**

```bash
rm -rf "$TMPDIR"
```

---

## Completion checklist

- [ ] PR 1 merged: Dockerfile → Chainguard
- [ ] PR 2 merged: image-scan.yml
- [ ] PR 3 merged: release binary provenance
- [ ] PR 4 merged: pin-check.yml + negative test confirmed failing then closed
- [ ] PR 5 merged: dependency-review.yml dropped
- [ ] PR 6 done: tracking issue filed for Semgrep-vs-CodeQL audit
- [ ] PR 7 done: repo-bootstrap skill updated, templates added, SKILL.md covers CI hardening step, scratch-repo validation passed
- [ ] CHANGELOG updated at each step
- [ ] README "Verifying release artifacts" section present
- [ ] All tests pass on main after each PR
- [ ] Next release triggered: verify `gh attestation verify netcidr --owner wingnut128` succeeds
- [ ] Spec checkboxes in `docs/superpowers/specs/2026-04-22-ci-hardening-design.md` (none currently — spec is prose; no action needed)

## Out of scope (explicit reminder)

- Cosign with long-lived keys
- SLSA L3 / hermetic builds / reproducible builds
- Container image signing (netcidr doesn't publish images)
- Semgrep vs CodeQL audit (tracked in PR 6's issue — do not implement now)
