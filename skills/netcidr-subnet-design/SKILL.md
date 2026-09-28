---
name: netcidr-subnet-design
description: Use when planning or comparing IPv4/IPv6 subnet layouts with netcidr, including VPC/VNet allocation pools, mixed subnet sizes, tiers, availability zones, existing allocations, exclusions, and growth reserves.
---

# Subnet design with netcidr

Turn requirements into verified alternative address plans. Use netcidr for
calculations; choose layouts based on the user's priorities. Planning does not
create cloud subnets or reserve IPAM space.

## Establish the constraints

Extract the parent CIDR(s), allowed allocation pools, address family, required
subnet counts/sizes or host capacities, tier/purpose labels, AZ/region/site
distribution, existing allocations, exclusions, and growth goals. Distinguish
hard requirements from preferences and unknowns. Ask only questions that change
feasibility or the recommendation; offer explicitly conditional scenarios when
the user wants exploration. Use illustrative CIDRs only when labeled as such.

Do not infer an AZ count or equal tier distribution from a subnet total. Clarify
whether counts are global or per AZ and what terms such as “access” mean.
For cloud host-capacity requirements, verify current provider address
reservations and allowed prefix sizes against official documentation; netcidr's
generic usable-host count is not a provider capacity guarantee.

## Calculate candidates

Discover available tool schemas before calling them (MCP clients may prefix tool
names). These calculator tools are stateless and **do not avoid occupied space**:

| Tool | Use |
|---|---|
| `subnet_calc` | Normalize CIDRs; obtain network and last/broadcast address |
| `subnet_split` | Equal-sized children using `cidr`, `prefix`, `count`; omit count/max for capacity only |
| `subnet_vlsm` | Mixed sizes using `cidr`, `prefixes`; non-decreasing prefix lengths, repeats allowed |
| `subnet_split_tree` | Full hierarchy using `cidr`, `steps`; strictly increasing prefix lengths |
| `contains_check` | Check an address against `cidr`; check both endpoints for CIDR containment |
| `from_range` | Turn an inclusive free `start`–`end` range into aligned CIDRs |
| `summarize` | Aggregate CIDRs without treating gaps as allocated |

VLSM packs from the pool's network address. Sort labeled requests largest-first
and retain their labels when mapping results back to tiers/AZs. Each requested
prefix must be longer than its parent; a request equal to a free block uses that
whole block without splitting. Neither VLSM nor fixed splitting accepts arbitrary
exclusions. Read `ipam_list_allocations`/`ipam_free_blocks` when an existing IPAM
pool is relevant; otherwise subtract supplied occupied/reserved intervals and
use `from_range` on the residual ranges. Place requests only within verified free
blocks. Aggregate free capacity alone does not prove that a large subnet fits.

A tree fully expands every level, not just selected branches. For partial
occupancy, calculate grouping envelopes first and split selected children
separately. Estimate output size before generation; tools cap generated results
at 1,000,000 subnets/nodes. Prefer small, targeted calls over enormous trees.
If MCP tools are unavailable, use the installed CLI's `split --vlsm` / `--steps`
equivalents. If neither is available, label calls as proposed and calculations
as unverified rather than claiming execution.

## Compare and validate

Compare suitable compact, tier-first, or AZ/site-first layouts. Vary only what
helps resolve the user's priorities: contiguity, summarization, fragmentation,
per-group growth, or ease of expansion. State which assumptions each alternative
uses; there is no universally best split.

For every candidate verify alignment, containment inside both pool and parent,
pairwise non-overlap, exclusion avoidance, and requested counts/capacity. Account
separately for deployed/proposed leaf subnets, growth reserved inside grouping
envelopes, unassigned pool space, and parent space outside the pool. These buckets
must balance without counting envelopes and their children twice. An envelope
is a planning boundary, not another deployable overlapping subnet. CIDR adjacency
does not establish routing, public access, or security isolation.

Present assumptions, a scenario comparison, a recommendation tied to priorities,
and a CIDR/tier/AZ/status table with exact free/reserved ranges. If infeasible,
explain the constraint and offer changes without silently relaxing requirements.
Only call IPAM mutation tools when the user authorizes recording the design;
recheck current free space before writing.

Read [the worked example](references/scenarios.md) when a concrete MCP sequence
or growth-space accounting example would help. Its counts and tiers are examples,
not defaults.
