# STRIDE Threat Model — netcidr — Pre/Post Report

**Instrument:** `stride.machine.rune` — a finite-state machine encoding STRIDE-per-element.
Initial `unanalyzed` → `spoofing → tampering → repudiation → disclosure → denial → elevation`
→ absorbing `classified`; each edge emits a `check-*` signal; each category is framed as the
negation of one CIA+ property (authenticity, integrity, non-repudiation, confidentiality,
availability, authorization).

**Scope:** one run per surface element. 9 elements walked:

- E1 HTTP API
- E2 Auth (OIDC / PAT / static bearer)
- E3 Authorization + multi-tenancy
- E4 MCP server (stdio + HTTP transports)
- E5 MCP → remote `netcidr serve` client
- E6 IPAM datastore (SQLite / Postgres)
- E7 S3 sync (Lambda DB persistence)
- E8 CLI / local file I/O
- E9 Telemetry / logging export

Every element reached `classified` (all six categories checked).

## Findings: pre → post

| ID | Element / category | Severity | Pre-state | Post-state |
|----|--------------------|----------|-----------|------------|
| ENG-100 / #252 | E4 MCP HTTP — Spoofing/Elevation | **Critical** | HTTP transport mounted all IPAM tools with no auth; non-loopback bind exposed full read/write | **Fixed** — fail-closed loopback gate + `--allow-public-bind` (`a659ba9`) |
| ENG-101 / #253 | E5 MCP client — Spoofing/Tampering | **High** | No credential to remote; caller input raw-interpolated into URLs | **Fixed** — percent-encoded path segments + bearer token (`20a6fba`) |
| ENG-102 / #254 | E7 S3 sync — Tampering/Disclosure | **High** | No pull integrity check, no at-rest encryption, symlink-unsafe path | **Fixed by removal** — S3 backend deleted; Lambda is Postgres-only (`328d62e`) |
| ENG-104 / #260 | E1/E3 — Denial-of-service | Medium | List endpoints unbounded; audit `limit` unbounded when omitted | **Fixed** — limit/offset pagination (default 100 / max 1000) + audit clamp (`b3170b7`) |
| ENG-105 / #261 | E6 datastore — Disclosure | Medium | SQLite DB file world-readable (umask `0644`) | **Fixed** — `0600` on create (`568585f`) |
| ENG-106 / #262 | E3 tenancy — Disclosure | Medium | `allocation_tags` had no `tenant_id`; isolation rested on one pre-check + UUID unguessability | **Fixed** — `tenant_id` column + backfill + tenant-match trigger, both backends (`fbff1c9`) |
| ENG-107 / #263 | E6 datastore — Denial-of-service | Medium | `auto-allocate --count` unbounded `u32` | **Fixed** — capped at 1000 (CLI + ops) (`568585f`) |
| ENG-103 / #259 | E2/E3 — Denial-of-service | Medium | **Reframed during analysis** — `serve` *does* rate-limit; the gap is the Lambda binary disables it (`rate_limit_per_second: 0`) + no auth-specific throttling | **Open** — needs a deployment decision (API Gateway throttling vs. a header-based limiter), not a clear code change |

**Low / by-design (accepted, not actioned):** CLI `--output`/`--config` path traversal
(local-user footgun), local logs unredacted (OTLP export *is* redacted), PAT `last_used_at`
fire-and-forget, 4xx errors echo input, empty allowlist = any-verified-Google.

**Confirmed strengths (no action):** constant-time bearer compare; OIDC issuer/audience/alg
pinning + `email_verified` + **fail-closed JWKS**; peppered 256-bit PAT hashing with role
clamping; parameterized SQL + tenant-match triggers; enforced OTLP PII redaction; deployment
validation that fail-closes auth/public-bind/IPAM; 5xx error scrubbing.

**Tally:** 1 Critical + 2 High + 4/5 Medium remediated and merged; 1 Medium open pending a
deployment decision. Low-tier accepted.

## Feedback on the FSM itself (for the author)

### What worked well

- **The closed/exhaustive taxonomy is the FSM's best feature.** Forcing all six categories per
  element surfaced findings a free-form review skips — the `allocation_tags` disclosure gap and
  the audit/repudiation thinness only showed up *because* the walk refused to terminate before
  `elevation`. The "one category negates one CIA+ property" framing is a genuinely good forcing
  function.
- **The `rosetta` metadata blocks make the rune self-documenting** — an analyst (human or agent)
  gets a consistent per-category lens without external reference. The absorbing `classified`
  state cleanly signals per-element completeness.
- **Ordering is a sensible default** (identity forgery underlies later threats).

### Gaps worth a future revision

1. **No surface-enumeration phase.** The hardest, most error-prone part of STRIDE in practice is
   decomposing the system / drawing trust boundaries — and the rune *assumes* the element is
   already chosen ("one surface element per run"). A companion machine for DFD / surface
   decomposition would close the biggest real-world gap. As-is, the machine models the easy part;
   choosing *what* to walk is left to the analyst.
2. **No severity/risk dimension.** STRIDE classifies threat *type*; the rune has no
   likelihood/impact. Every Crit/High/Med tier in this report came from outside the machine.
   Consider an orthogonal scoring pass (DREAD-like, or a simple per-threat severity field).
3. **No mitigation lifecycle.** The walk ends at `classified` (enumeration). The other half of
   threat modeling — `identified → accepted | mitigated | transferred | eliminated` — is exactly
   the work that followed (fix / accept / remove). A second machine, or post-`classified` states,
   would make it end-to-end.
4. **STRIDE-per-element misses chained/interaction threats.** The E5 ↔ remote-`serve`
   combination is a multi-element kill chain that per-element walks under-weight. The rune is
   faithful to STRIDE-per-element and inherits its known blind spot — worth at least a documented
   "interaction pass."
5. **"named or cleared" has no state distinction.** `classified` doesn't record whether each
   category found a threat or was cleared. For an audit trail you'd want the terminal state to
   carry the per-category verdict set, not just "done."
6. **Repudiation was the thinnest category in practice** — the CIA+ mapping treats it as
   co-equal, but analysts need more prompting (what to log, retention, tamper-evidence). Richer
   `how` text for that state would help.

### One caution

The machine produces *hypotheses*, not confirmed findings. Two outputs needed analyst
correction — a JWKS "stale-key" claim that was actually fail-closed, and the rate-limiting
finding that was wrong until reframed for the Lambda deployment. High signal-to-noise overall,
but the verify step is non-optional.

---

*Generated from a STRIDE walk of netcidr `main` and the subsequent remediation work
(PRs #252–#266). Remaining open item: ENG-103 / #259.*
