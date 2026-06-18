# Kill Chain × STRIDE Threat Analysis — netcidr

**Instruments:** `kill-chain.machine.rune` (outer FSM) × `stride.machine.rune` (inner FSM)
Composition: the kill chain provides the sequential phase container; STRIDE classifies threats
at each phase. One STRIDE walk per kill-chain phase over the relevant surface slice.

**Scope:** netcidr `main` as of 2026-06-17. Builds on the prior STRIDE-per-element report
(`docs/stride-report.md`, 9 elements walked, all classified). This run addresses the gap
called out in that report: *"STRIDE-per-element misses chained/interaction threats."*

**Prior state:** 1 Critical + 2 High + 4/5 Medium from the STRIDE run are remediated and
merged. One Medium remains open (ENG-103). This analysis confirms that finding and surfaces
one new finding (ENG-108).

---

## Phase Walk

### Phase 1 — Reconnaissance
*Adversary researches and profiles the target.*

Relevant surface: E1 (HTTP API public routes), E4 (MCP server), E8 (CLI — local only, low
relevance).

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S — Spoofing | Public routes are unauthenticated by design; no impersonation needed to enumerate | N/A — by design | Accepted |
| T — Tampering | Probe responses not attacker-controlled | N/A | Clear |
| R — Repudiation | Scan activity logged via `tracing` but no alerting on scan patterns | Logs exist; no anomaly detection | Gap (low) |
| I — Disclosure | Error messages echo input (accepted low); OpenAPI visible when `--enable-swagger` | Accepted | Accepted low |
| D — Denial-of-service | Lambda deployment disables rate limiter (`rate_limit_per_second: 0`); scanning costs attacker nothing | **ENG-103 open** | **Open** |
| E — Elevation | Recon alone grants no elevation | N/A | Clear |

**Chain break available at this phase?** Marginal. ENG-103 is the only candidate disruption
control and it is unresolved on the Lambda path.

---

### Phase 2 — Weaponization
*Adversary builds a weaponized payload on their own infrastructure.*

STRIDE is minimally applicable — this phase occurs entirely on the adversary's plane and is
not directly observable. Intel gathered during Phase 1 would target:

- ENG-103 (DoS via flooding — unmitigated on Lambda)
- PAT credential stuffing (peppered 256-bit hashing makes this very expensive — effectively clear)

**Chain break available at this phase?** Only via external threat intelligence on known
tooling. No current control wired.

---

### Phase 3 — Delivery
*Adversary transmits the payload to the target — network requests to E1 or E4.*

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S — Spoofing | IPAM routes require OIDC/PAT/bearer; non-IPAM public routes unauthenticated by design | E2 auth layer | Mitigated |
| T — Tampering | Malformed or injected payloads | `validation.rs` + parameterized SQL | Mitigated |
| R — Repudiation | Delivery attempts logged | `#[instrument]` on all handlers | Mitigated |
| I — Disclosure | Error path leakage | 5xx scrubbed; OTLP PII-redacted | Mitigated |
| D — Denial-of-service | Volumetric flooding of Lambda path | **ENG-103 open** | **Open** |
| E — Elevation | MCP HTTP on non-loopback (pre-fix) | Fixed: loopback gate + `--allow-public-bind` (ENG-100) | Fixed |

**Chain break available at this phase?** Yes for auth-exploit delivery. No for volumetric DoS
delivery on the Lambda path (ENG-103).

---

### Phase 4 — Exploitation
*The delivered payload triggers and exploits a vulnerability.*

After all STRIDE-report remediation, only one exploitable path remains:

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S — Spoofing | Forged OIDC/PAT identity | OIDC issuer/audience/alg pinning + `email_verified` + fail-closed JWKS; constant-time bearer compare | Fixed |
| T — Tampering | SQL injection, path injection, MCP URL injection | Parameterized SQL + percent-encoded MCP path segments (ENG-101) | Fixed |
| R — Repudiation | Unlogged privileged actions | All mutations logged | Mitigated |
| I — Disclosure | 5xx internals leakage | 5xx scrubbed | Fixed |
| D — Denial-of-service | Unbounded flooding of Lambda | **ENG-103 open** | **Open** |
| E — Elevation | Tenant boundary crossing, PAT role inflation | `tenant_id` trigger (ENG-106); PAT role clamped at creation | Fixed |

**Chain break available at this phase?** Yes for every category except D. ENG-103 remains the
only unmitigated path from delivery to a successful exploit.

---

### Phase 5 — Installation
*Adversary establishes durable persistence on the compromised host.*

In netcidr's context "installation" means establishing credentials or records that survive
past the current session. Two vectors:

**Vector A — Rogue CIDR records**
An authenticated attacker could create IPAM records to corrupt managed space.
Mitigated: `tenant_id` isolation (ENG-106) prevents cross-tenant writes; within-tenant
pollution requires the attacker to already be an authenticated tenant principal.

**Vector B — PAT bulk creation** ← *new finding*
An authenticated tenant can create PATs without any per-tenant rate or count limit,
producing durable multi-credential access that survives individual token revocations.

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S — Spoofing | Forged identity for PAT creation | PAT creation requires valid existing auth | Mitigated |
| T — Tampering | Rogue IPAM record injection | `tenant_id` trigger (ENG-106) | Fixed |
| R — Repudiation | PAT creation unlogged | PAT creation is a logged mutation | Mitigated |
| I — Disclosure | Tenant data cross-contamination | Per-tenant isolation (ENG-106) | Fixed |
| D — Denial-of-service | PAT table exhaustion via bulk creation | **No cap on active PATs per tenant** | **Open (ENG-108)** |
| E — Elevation | Bulk PATs → durable standing access surviving rotation | **No creation rate limit** | **Open (ENG-108)** |

**Chain break available at this phase?** Partial. Rogue-record vector is closed. PAT
bulk-creation vector (ENG-108) has no control wired.

---

### Phase 6 — Command & Control
*Adversary opens a remote control channel.*

netcidr is a target, not a compromised host, so this phase is relevant only if the
deployment environment (Lambda, EC2, or container) is itself compromised. At that point the
threat model moves to the AWS IAM and VPC egress plane, outside netcidr's application
controls. No application-layer finding at this phase.

---

### Phase 7 — Actions on Objectives
*Adversary acts to achieve their goal.*

| Objective | Attack path | STRIDE | Existing control |
|-----------|-------------|--------|-----------------|
| Exfiltrate network topology | Bulk CIDR list queries | I | Auth required for IPAM; pagination cap 100/1000 (ENG-104) |
| Corrupt IPAM records | Authenticated write to wrong tenant | T | `tenant_id` trigger (ENG-106) |
| Ransomware SQLite | Filesystem access post-exploitation | T / D | `0600` DB perms (ENG-105); Lambda uses Postgres only |
| DoS the service | Volumetric flooding via Lambda | D | ENG-103 open |
| Pivot via IPAM intel | Use topology data to plan next intrusion | — | No application control; operational mitigations only |

**Chain break available at this phase?** Yes for all high-value paths that require
authentication. DoS (ENG-103) remains the only unauthenticated path to an objective.

---

## Findings

### ENG-103 (pre-existing, open) — Lambda rate limiting disabled

| Field | Value |
|-------|-------|
| Severity | Medium |
| Kill chain phases | Reconnaissance, Delivery, Exploitation |
| STRIDE category | D — Denial-of-service |
| Surface element | E1 HTTP API (Lambda deployment) |
| Root cause | `rate_limit_per_second: 0` in Lambda config disables the existing rate-limit middleware |
| Mitigation | API Gateway throttling, or a header-based per-IP limiter in the Lambda handler |
| Status | **Open — pending deployment decision** |

This finding surfaces at three kill chain phases, making it the highest-leverage open item.
Breaking it at Reconnaissance (cheapest) would deny the attacker free scanning and raise the
cost of Phase 2 weaponization.

---

### ENG-108 (new) — PAT creation uncapped per tenant

| Field | Value |
|-------|-------|
| Severity | Medium |
| Kill chain phase | Phase 5 — Installation |
| STRIDE categories | D — Denial-of-service, E — Elevation-of-privilege |
| Surface element | E2 Auth (PAT sub-system) |
| Root cause | `POST /me/tokens` has no per-tenant active-count cap and no creation rate limit |
| Mitigation | Hard cap on active PATs per tenant (default 25, configurable); creation rate limit per tenant (default 10/hr, configurable); `429 Too Many Requests` + `Retry-After` on breach |
| Precedent | ENG-104 (list pagination cap), ENG-107 (auto-allocate count cap) |
| Linear ticket | ENG-108 |
| Status | **Open — backlog** |

---

## Kill Chain Status Summary

```
Phase 1   Reconnaissance       ⚠  ENG-103 (no disruption cost for attacker on Lambda)
Phase 2   Weaponization        –  Off-plane; no application control
Phase 3   Delivery             ⚠  ENG-103 (DoS delivery unblocked on Lambda)
Phase 4   Exploitation         ⚠  ENG-103 (only remaining exploitable path)
Phase 5   Installation         ⚠  ENG-108 (PAT bulk-creation uncapped)
Phase 6   C&C                  –  Out of scope (deployment plane)
Phase 7   Actions on Objectives ✓  All high-value paths require auth; DoS via ENG-103 only
```

Two open links remain in the chain. Closing ENG-103 breaks the chain at Phases 1, 3, and 4.
Closing ENG-108 breaks the chain at Phase 5. No other unmitigated link exists after all prior
STRIDE-report remediation.

---

## Composite Assessment

### Confirmed strengths (carried forward from STRIDE report)

Constant-time bearer compare; OIDC issuer/audience/alg pinning + `email_verified` +
fail-closed JWKS; peppered 256-bit PAT hashing with role clamping; parameterized SQL +
tenant-match triggers; enforced OTLP PII redaction; deployment validation that fail-closes
auth/public-bind/IPAM; 5xx error scrubbing; list pagination + audit clamp (ENG-104);
`0600` SQLite DB perms (ENG-105); `tenant_id` defense-in-depth (ENG-106); auto-allocate
count cap (ENG-107).

### What the composition adds over STRIDE-per-element

The kill chain outer loop surfaced ENG-108, which the per-element STRIDE walk did not reach:
Phase 5 (Installation) is not a natural stop in a surface-element decomposition, but is a
natural stop in a kill-chain walk. The composition also clarifies ENG-103's priority — it is
not merely one medium finding but the only unmitigated link across three sequential phases.

### Tally

| | Count |
|-|-------|
| Fixed since STRIDE report | 7 (1 Critical, 2 High, 4 Medium) |
| Open from STRIDE report | 1 Medium (ENG-103) |
| New from this run | 1 Medium (ENG-108) |
| Accepted / low | No change |

---

## Feedback on the FSM composition (for the author)

### What worked

- **The two FSMs are genuinely complementary.** STRIDE is exhaustive per-element;
  kill chain is exhaustive per-phase. Their blind spots are each other's strengths. Running
  them in composition closes both gaps.
- **The kill chain's `chain-broken` gate at every phase is the right design.** It makes
  the "defense need not be perfect everywhere, only once" principle structurally explicit
  rather than a post-hoc annotation.
- **Phase 5 (Installation) is where the new finding lived.** A pure STRIDE walk misses it
  because "PAT creation" is an E2 element behavior, not an interaction threat. The kill chain
  phase framing forced the question: *how does an attacker persist after gaining access?*

### Gaps in the composition

1. **No automated surface mapping.** Deciding which surface elements are relevant at each
   kill chain phase is still manual analyst work. A companion `surface-mapping.machine.rune`
   that assigns elements to phases would make the composition fully mechanical.
2. **Phase 2 (Weaponization) is a dead zone.** The kill chain FSM correctly notes it is
   off-plane, but the composition has no fallback for phases where the defender has no direct
   control. A `threat-intel` input arc would make this useful rather than a structural no-op.
3. **No severity scoring.** Both FSMs enumerate threats but neither scores them. Every
   finding tier in this report was assigned by the analyst. A scoring gate (DREAD-lite, or a
   likelihood × impact field) on each STRIDE edge would close this gap.
4. **The `defeated` state in the kill chain has no evidence trail.** When the chain breaks
   (e.g., at Delivery), there is no structured output recording *what* broke it or *which*
   control fired. The `writes incident-record` annotation is present but the record schema is
   undefined — useful to specify so the composition can produce machine-readable output.

---

*Generated 2026-06-17 from `kill-chain.machine.rune` × `stride.machine.rune` against netcidr `main`.
Open items: ENG-103 (Lambda rate limiting), ENG-108 (PAT creation cap).*
