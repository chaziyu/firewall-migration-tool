# Check Point Extraction Reference

## Scope

The `checkpoint` source path combines Check Point Management API/export evidence and Gaia configuration into source accounting plus canonical IR where portable semantics are exact.

**Executable authority:** `src/fwmigrate/parsers/checkpoint/`

The registry display name remains R80/R81-oriented. Newer official Check Point releases reviewed for documentation freshness are tracked separately in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml) and are not automatically declared validated.

## Source relationships

Management data is authoritative for management objects, package/layer relationships, gateway ownership, Security Zone/topology evidence, and other management-plane semantics. Gaia configuration is authoritative for persistent OS/interface configuration and related system state. Ambiguous Management/Gaia correlation must remain review-required rather than being joined by name alone.

## Safety invariants

- Pagination and collection completeness are validated before policy transformation.
- Domain/package/layer/VS scope is preserved.
- Inline/ordered layer semantics are not flattened when doing so could broaden access.
- NAT method and ordering evidence must be explicit; translated values alone do not prove hide/PAT semantics.
- Unsupported actions, identity/content/time dimensions, and unresolved dependencies taint target safety.
- Secret material is scrubbed at extraction boundaries.

## Support matrix

See [`support-matrix.md`](support-matrix.md).

## Historical detail

Detailed earlier R81 architecture/support snapshots and phase/fidelity plans are retained under `documentation/archive/2026/`. They are historical evidence, not the active authority.
