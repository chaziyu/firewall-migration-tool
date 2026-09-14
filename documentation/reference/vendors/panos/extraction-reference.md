# PAN-OS Extraction Reference

## Scope

The `palo_alto` source adapter accepts PAN-OS/Panorama XML configuration and produces `ExtractionResult` plus canonical `IRConfig` for proven portable semantics.

**Executable authority:** `src/fwmigrate/parsers/palo_alto/`

## Input contract

The registered source extension is generated in [`../../../generated/capabilities.md`](../../../generated/capabilities.md). XML API wrappers containing the configuration result are supported by the parser; arbitrary XML or PAN-OS `set` syntax must not be assumed equivalent to the XML export path.

## Version evidence

No single PAN-OS release is declared universally tested by documentation metadata unless repository validation records it. The newest official PAN-OS release reviewed for documentation freshness is tracked in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml), separately from tested versions.

## Extraction behavior

Portable coverage includes addresses/groups, services, schedules, zones, selected interface semantics, Security Policy, NAT, and static routing. PAN-specific constructs such as advanced policy dimensions, dynamic routing, external dynamic lists, security profile definitions, VPN-specific behavior, Panorama inheritance, and management-plane settings may be partial or source-only depending on exact semantics.

## Fail-closed rules

- Explicit `any` is distinct from missing/empty source semantics.
- Missing policy or NAT match dimensions are not synthesized as `any`.
- Missing actions are not synthesized as `allow`.
- Missing route destinations are not synthesized as a default route.
- Unresolved references retain evidence and taint generation safety.
- Optimizer behavior must not repair an unsafe source rule into a broader deployable rule.

## Support matrix

See [`support-matrix.md`](support-matrix.md).

## Historical detail

The previous detailed PAN-OS extraction reference and Phase 2 fail-closed plan are retained under `documentation/archive/2026/` for history. The current safety contract is maintained in [`../../../explanation/safety-model.md`](../../../explanation/safety-model.md).
