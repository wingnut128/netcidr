# TODO

Reference: `.context/prd-ipam-persistence.md`

---

## Phase 5: Free Space & Utilization Enhancements

- [x] Gap-walking algorithm: load active allocations sorted by network address, identify gaps
- [x] Aligned CIDR fitting: for each gap, compute largest aligned blocks that fit
- [x] Target prefix mode: given a /N, count how many fit in available space
- [x] Utilization rollup: allocated vs total IPs, breakdown by status (active/reserved/released)

## Cross-cutting / Deferred

- [ ] **Trait-contract test suite for backend parity** — Shared test suite run against `&dyn IpamStore` per backend (SQLite in-memory by default, Postgres via Docker). Not yet implemented as a reusable harness.
- [ ] Property-based tests for conflict detection (random CIDR pairs, no false negatives)
- [ ] Fuzz targets for CIDR inputs to allocation functions
- [ ] Migration upgrade path tests (v0 -> vN with sample data)
- [ ] JSON export/import (`ipam dump` / `ipam load`) — deferred to v2
- [ ] IPv6 IPAM implementation (schema supports it, code is IPv4-only for v1)
- [ ] Reservation TTL/expiry — deferred to v2
- [ ] MCP server remote backend option — add a configuration flag (e.g. `--api-url`) so the MCP server can proxy tool calls to a running `ipcalc serve` HTTP API instead of calling local library functions directly. Useful when the MCP server runs on a different host or when IPAM state must be shared across clients.
