# TODO

Reference: `.context/prd-ipam-persistence.md`

---

## Phase 5: Free Space & Utilization Enhancements

- [x] Gap-walking algorithm: load active allocations sorted by network address, identify gaps
- [x] Aligned CIDR fitting: for each gap, compute largest aligned blocks that fit
- [x] Target prefix mode: given a /N, count how many fit in available space
- [x] Utilization rollup: allocated vs total IPs, breakdown by status (active/reserved/released)

## Cross-cutting / Deferred

- [x] **Trait-contract test suite for backend parity** — Macro-based harness in `tests/ipam_store_contract.rs` generates 18 contract tests against any `IpamStore` impl. Currently runs against SQLite in-memory; reusable for Postgres.
- [x] Property-based tests (proptest):
  - CIDR tiling exactness: `range_to_cidrs(start, end)` output tiles `[start, end]` with zero gaps and zero overlaps
  - Gap completeness: gaps + allocations exactly cover the supernet address space
  - No overlap after arbitrary operations: random allocate/release sequences never produce overlapping active/reserved allocations, and `allocated + free == total` always holds
- [x] Migration upgrade path tests — 3 tests verify data survives re-migration (simple, complex state, schema version tracking)
- [ ] JSON export/import (`ipam dump` / `ipam load`) — deferred to v2
- [ ] IPv6 IPAM implementation (schema supports it, code is IPv4-only for v1)
- [ ] Reservation TTL/expiry — deferred to v2
- [ ] MCP server remote backend option — add a configuration flag (e.g. `--api-url`) so the MCP server can proxy tool calls to a running `ipcalc serve` HTTP API instead of calling local library functions directly. Useful when the MCP server runs on a different host or when IPAM state must be shared across clients.
