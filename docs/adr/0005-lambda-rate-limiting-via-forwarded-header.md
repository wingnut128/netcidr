# Lambda rate limiting via X-Forwarded-For; auth-specific throttling deferred

**Status:** Accepted — decisions 1 and 3 amended 2026-10-01 (see below)
**Date:** 2026-06-18
**Issue:** [#259](https://github.com/wingnut128/netcidr/issues/259) (ENG-103)
**Related:** [[ADR-0002 — RBAC role config and per-handler extractors]](./0002-rbac-role-config-and-per-handler-extractors.md)

## Amendment (2026-10-01): trust exactly one address source

Decision 1 keyed the limiter on `SmartIpKeyExtractor`, which takes the
**leftmost** parseable `X-Forwarded-For` entry. That is only safe behind a
proxy that *overwrites* the header. The production deployment is CloudFront
in front of a public Lambda Function URL, not API Gateway: CloudFront
*appends* the viewer address to whatever `X-Forwarded-For` the client sent,
and the Function URL can be called directly. Either way the client chose
its own bucket on every request, so decision 3's trust boundary did not
hold.

Replacement:

1. **`client_ip_source`** (`NETCIDR_CLIENT_IP_SOURCE`, TOML, or
   `--client-ip-source`) names the single place a client address is
   believed: `peer` (TCP connection; the default for `serve`), `xff:N` (the
   Nth entry from the *right* of `X-Forwarded-For`, i.e. what the outermost
   of N trusted proxies saw; the Lambda default is `xff:1`), or
   `header:<name>` (a header a trusted proxy sets, e.g.
   `cloudfront-viewer-address`). Nothing else is consulted, and a request
   with no usable address falls into one shared bucket instead of erroring
   or choosing its own.
2. **IPv6 clients are keyed by /64.** A subscriber usually controls a whole
   /64, and CloudFront's unbracketed `IPv6:port` is ambiguous; both readings
   fall in the same /64.
3. **Origin secret.** With `NETCIDR_ORIGIN_SECRET` set (≥ 32 characters),
   every request must carry `X-Origin-Verify` with that value or gets 403.
   The fronting proxy adds it, so the origin URL is useless on its own. The
   check runs before the limiter, so rejected requests spend no budget.
   CloudFront origin access control (OAC) was rejected for Lambda origins:
   it replaces the viewer's `Authorization` header with a SigV4 signature
   (netcidr authenticates with `Authorization: Bearer`), and it requires
   every POST/PUT client to send `x-amz-content-sha256`.

Changing the `serve` default from "leftmost forwarding header, else peer"
to "peer" means a `serve` behind a reverse proxy must now set
`client_ip_source` explicitly, or all clients share the proxy's bucket.

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
