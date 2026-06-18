# Lambda rate limiting via X-Forwarded-For; auth-specific throttling deferred

**Status:** Accepted
**Date:** 2026-06-18
**Issue:** [#259](https://github.com/wingnut128/netcidr/issues/259) (ENG-103)
**Related:** [[ADR-0002 — RBAC role config and per-handler extractors]](./0002-rbac-role-config-and-per-handler-extractors.md)

## Context

`netcidr serve` has per-IP rate limiting (tower-governor, default 20 req/s,
burst 50, applied as a global layer in `api.rs`). The default
`PeerIpKeyExtractor` reads the client IP from `ConnectInfo<SocketAddr>` — the
TCP peer address — which `lambda_http` does not provide. So the Lambda binary
set `rate_limit_per_second: 0` to avoid every request 500ing with "Unable To
Extract Key", leaving the Lambda deployment with **no application-level
throttling** (it fell entirely to out-of-band AWS controls).

Separately, even on `serve` there is no auth-specific throttling: OIDC
validation is CPU-bound (RSA signature verify) and a distributed source set
could force repeated verifications within per-IP limits.

## Decisions

1. **Key the limiter on `X-Forwarded-For` via `SmartIpKeyExtractor`.**
   tower-governor 0.8 ships `SmartIpKeyExtractor`, which derives the client IP
   from `X-Forwarded-For`, then `X-Real-IP`, then `Forwarded`, falling back to
   `ConnectInfo<SocketAddr>` and the socket address. The router now uses it
   unconditionally (`api.rs`). Under Lambda, API Gateway always sets
   `X-Forwarded-For`, so the limiter works without any TCP peer. Under
   `netcidr serve`, clients that send no forwarding header fall back to the
   connection peer IP exactly as before. No custom extractor code is needed.

2. **Enable the limiter under Lambda, tunable by env var.** `lambda.rs` no
   longer hardcodes `0`. It reads `NETCIDR_RATE_LIMIT` (default 20 req/s; `0`
   disables) and `NETCIDR_RATE_LIMIT_BURST` (default 50), so operators tune
   throttling per environment without a redeploy.

3. **Trust boundary: API Gateway only.** `X-Forwarded-For` is trustworthy
   *only* because API Gateway is a trusted proxy that overwrites it with the
   real client IP. The Lambda Function URL must **not** be exposed directly —
   a direct caller could spoof the header to land every request in a different
   bucket and evade throttling. This is documented in the README Lambda
   section and is the operative deployment constraint.

4. **Auth-specific throttling: explicitly accepted (deferred), not
   implemented.** Per the ENG-103 acceptance criteria, we record the decision
   to *accept* the residual risk rather than build per-account/per-token
   lockout now. Rationale:
   - The per-IP limiter (20 req/s default) now covers both `serve` and Lambda,
     bounding brute-force throughput from any single source.
   - Account lockout introduces its own DoS vector (an attacker locks out a
     victim by spamming their identifier) and state that does not fit the
     stateless Lambda model without an external store.
   - OIDC tokens are validated against cached JWKS; there is no password to
     brute-force, only signature verification, which the per-IP limit already
     throttles.

   A stricter limit scoped to auth/token-mint endpoints remains a clean
   follow-up if abuse is observed.

## Consequences

- The Lambda deployment now enforces application-level per-IP throttling
  instead of relying solely on AWS-side controls.
- `serve` behavior is unchanged for direct clients (peer-IP fallback) and now
  additionally honors a forwarding header when present — correct when `serve`
  itself runs behind a trusted reverse proxy.
- New tunable-to-extract-key 500s are possible only in the pathological case
  of a Lambda request with neither a forwarding header nor a socket address,
  which API Gateway never produces.
- Spoofable `X-Forwarded-For` is a real risk if the Function URL is exposed
  directly; mitigated by the documented "API Gateway only" constraint.

## Out of scope (follow-ups)

- Per-route / auth-endpoint-specific rate limits (tighter bucket for
  `/me/tokens`, OIDC validation paths).
- Distributed rate-limit state shared across Lambda concurrency (today each
  execution environment keeps its own in-memory governor state).
