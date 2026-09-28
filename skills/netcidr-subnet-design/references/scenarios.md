# Worked comparison: twelve /24s

Illustrative inputs: VPC `10.20.0.0/16`, allocation pool `10.20.0.0/17`,
twelve `/24`s. AZ count and tier balance are unresolved. Offer conditional
choices: three AZs with one access, two private, and one database subnet per AZ;
or four AZs with one of each per AZ. Neither follows from the total alone.

The following comparison assumes the **three-AZ option** solely to hold demand
constant while comparing layouts. These are proposed MCP calls, not evidence
that the tools ran. All envelopes are planning boundaries.

## Capacity and compact placement

Call `subnet_calc({"cidr":"10.20.0.0/16"})` and
`subnet_calc({"cidr":"10.20.0.0/17"})`. Verify both pool endpoints lie in
the VPC using `contains_check`. Then:

```json
{"tool":"subnet_split","arguments":{"cidr":"10.20.0.0/17","prefix":24}}
```

Expected capacity: 128 `/24`s. Generate only twelve:

```json
{"tool":"subnet_vlsm","arguments":{"cidr":"10.20.0.0/17","prefixes":[24,24,24,24,24,24,24,24,24,24,24,24]}}
```

Expected: `10.20.0.0/24` through `10.20.11.0/24`; 3,072 allocated and
29,696 remaining addresses. Assign four consecutive subnets per AZ and label
them access/private/private/database. Free pool CIDRs are `10.20.12.0/22`,
`10.20.16.0/20`, `10.20.32.0/19`, and `10.20.64.0/18`.

## Tier-first envelopes

```json
{"tool":"subnet_vlsm","arguments":{"cidr":"10.20.0.0/17","prefixes":[21,22,22]}}
```

Map the returned envelopes in order to private `10.20.0.0/21`, access
`10.20.8.0/22`, and database `10.20.12.0/22`. Call `subnet_split` with
`prefix:24` and counts 6, 3, and 3 respectively. Assign two private and one
subnet of each other tier per AZ.

In-envelope growth reserves: `10.20.6.0/23`, `10.20.11.0/24`, and
`10.20.15.0/24` (four `/24` equivalents). Unassigned pool space:
`10.20.16.0/20`, `10.20.32.0/19`, `10.20.64.0/18` (112 equivalents).

## AZ-first envelopes with local growth

```json
{"tool":"subnet_vlsm","arguments":{"cidr":"10.20.0.0/17","prefixes":[21,21,21]}}
```

Assign `10.20.0.0/21`, `10.20.8.0/21`, and `10.20.16.0/21` to AZ A/B/C.
Split four `/24`s from each, labeling them access/private/private/database.
Reserves are `10.20.4.0/22`, `10.20.12.0/22`, and `10.20.20.0/22`.
Unassigned pool space is `10.20.24.0/21`, `10.20.32.0/19`, and `10.20.64.0/18`.

| Layout | Active /24s | Reserved /24 equivalents | Unassigned /24 equivalents | Trade-off |
|---|---:|---:|---:|---|
| Compact | 12 | 0 | 116 | Largest shared free region; little adjacent growth per group |
| Tier-first | 12 | 4 | 112 | Tier summaries and some tier growth; AZ ranges are dispersed |
| AZ-first | 12 | 12 | 104 | Contiguous AZ space with local growth; more space earmarked |

Each row totals 128. The other VPC half, `10.20.128.0/17`, remains outside
the allocation pool and is accounted for separately. Reserved space is still
unused; it becomes an actual IPAM reservation only through an authorized write.

To inspect one AZ's full possible hierarchy, call
`subnet_split_tree({"cidr":"10.20.0.0/21","steps":[22,24]})`.
It returns two `/22` children and eight `/24` leaves (10 nodes excluding root),
not just the four planned active subnets. Label their status separately.

## Existing allocations and mixed sizes

Given `10.40.0.0/20` with occupied `10.40.4.0/22`, the free blocks are
`10.40.0.0/22` and `10.40.8.0/21`. Confirm inventory and any other exclusions.
For a hypothetical request of two `/24`s and four `/26`s:

```json
{"tool":"subnet_vlsm","arguments":{"cidr":"10.40.0.0/22","prefixes":[24,24,26,26,26,26]}}
```

Expected placement: `10.40.0.0/24`, `10.40.1.0/24`, and four `/26`s covering
`10.40.2.0/24`. Remaining free space is `10.40.3.0/24` and `10.40.8.0/21`.
Running VLSM on the entire `/20` would ignore the occupied block. A request for
a `/21` must use the second free block; a `/20` cannot fit despite free space
elsewhere. Apply the same interval checks to IPv6 with exact integer arithmetic.
