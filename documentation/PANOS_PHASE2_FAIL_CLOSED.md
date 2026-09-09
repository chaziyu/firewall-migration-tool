# PAN-OS Phase 2 Fail-Closed Contract

Phase 2 hardens the PAN-OS source path against silent broadening. It is a safety
contract across source extraction, canonical IR, optimizer behavior, and target
generation; it is not a request to synthesize PAN-OS effective defaults when
source evidence is missing.

## Core invariants

1. **Explicit source semantics are distinct from missing semantics.**
   An explicit PAN-OS `any` member is preserved as `any`. A missing container,
   empty container, blank member, malformed value, or unresolved reference is
   never replaced with `any`.
2. **Missing action is never converted to Allow.**
   A Security Policy rule without an explicit supported action is withheld from
   canonical deployable policy output and remains visible in extraction
   inventory.
3. **Missing route destination is never converted to a default route.**
   `0.0.0.0/0` or `::/0` is canonicalized only when explicitly represented by
   the source configuration.
4. **Unsafe canonical objects remain unsafe after serialization.**
   `migration_status`, `requires_manual_review`, `review_reasons`, unresolved
   reference evidence, and source-action evidence survive IR JSON round trips.
5. **The optimizer does not repair unsafe rules.**
   Optimization routines must skip policies that are not safe for target
   generation. They must not turn incomplete or review-required source policy
   into broader canonical policy.
6. **Target generators enforce the safety boundary.**
   Security Policy and NAT objects that are not safe for target generation are
   omitted from target configuration and produce audit evidence instead.
7. **Withholding is not silent loss.**
   Rejected or partially normalized source objects still receive extraction
   inventory records and section accounting.

## Security Policy action fidelity

PAN-OS distinguishes the following Security Policy actions:

- `allow`
- `deny`
- `drop`
- `reset-client`
- `reset-server`
- `reset-both`

The canonical IR currently represents `drop` and `reset-*` using the
fail-closed `DENY` action while preserving the exact source action. Because the
operational behavior is not identical to plain `deny`, these variants must be
`PARTIALLY_NORMALIZED`, require manual review, and remain unsafe for automatic
target generation.

The source action is retained in `IRPolicy.source_action`; the review reason is
`source-action-variant`.

## Required Security Policy match dimensions

The PAN-OS parser requires non-empty source evidence for these dimensions
before creating canonical policy:

- `from`
- `to`
- `source`
- `destination`
- `application`
- `service`

A missing node, empty node, or blank member is treated as missing source
semantics. An explicit `any` member is valid source semantics and is preserved.

Unresolved references may remain in canonical source-facing fields for audit,
but they taint the policy with a review reason so
`safe_for_target_generation == False`.

## NAT safety

PAN-OS NAT extraction requires non-empty match semantics for:

- `from`
- `to`
- `source`
- `destination`
- `service`

Missing match dimensions do not become `any`. Ambiguous translation branches,
invalid translated-address values, unresolved translation references, and
other incomplete translation semantics require review. Such rules can remain
visible in canonical IR for analysis but are withheld by target generators.

## Static-route safety

Static-route destination is mandatory for canonical route creation. The parser
does not infer a default route from a missing destination.

For PAN-OS static routes, explicit numeric values are validated against the
vendor ranges:

| Field | Accepted range |
| --- | ---: |
| Administrative distance | 10-240 |
| Metric | 1-65535 |

An out-of-range value is a `PARSE_ERROR`. No boundary value is clamped and no
fallback value is synthesized. The exact source scalar is retained in route
source evidence as `pan_metric_source` or `pan_admin_distance_source`.

A PAN-OS static route can legitimately use an IP next hop, FQDN, next routing
instance, discard, or no next hop depending on source configuration. Phase 2
does not invent a blanket requirement for an IP next hop.

## Regression suite

`tests/test_palo_alto_safety.py` is the permanent Phase 2 regression suite. It
covers:

- missing, empty, and blank-member Security Policy dimensions;
- missing action;
- explicit wildcard preservation;
- unresolved policy references;
- `drop` and `reset-*` action tainting and target withholding;
- optimizer safety;
- IR JSON round-trip safety;
- missing NAT match fields;
- invalid and ambiguous NAT translation;
- missing versus explicit default-route destination;
- static-route metric and administrative-distance range boundaries.

Phase 2 tests are not expected-failure placeholders. Any failure represents a
regression in the fail-closed contract.

## Schema 1.50 update

The earlier fail-closed treatment of PAN-OS `drop` and `reset-*` as lossy
`DENY` projections is superseded by schema 1.50.  These actions are now
represented exactly in canonical IR.  Fail-closed behavior remains mandatory,
but is applied by target capability checks when a target cannot reproduce the
exact action.  The same parser/target boundary applies to canonical URL
category matches and list-valued security-profile assignments.
