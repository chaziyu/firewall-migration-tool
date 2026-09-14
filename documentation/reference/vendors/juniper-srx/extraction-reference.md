# Juniper SRX Extraction Reference

## Scope

The `juniper_srx` source parser handles Junos SRX configuration in root-level `display set` form and supported hierarchical configuration.

**Executable authority:** `src/fwmigrate/parsers/juniper_srx/`

## Input contract

Registered extensions are generated in [`../../../generated/capabilities.md`](../../../generated/capabilities.md). Relative `display set` output captured from inside an `edit` hierarchy must not be treated as root-level configuration unless the parser can prove the missing hierarchy.

## Extraction behavior

Current handling includes system metadata, interfaces/VLANs, security zones, address books/sets, applications/application sets, security policy, static routing, firewall filters/forwarding evidence, NAT, VPN source models, and additional source-only Junos families.

Deactivated configuration, unsupported syntax, parse errors, access-denied placeholders, and vendor-specific behavior remain source-accounted rather than disappearing.

## Safety rules

- Multiple interface addresses or route next hops must not be collapsed arbitrarily.
- Routing-instance context must not be silently merged into root routing.
- Management-plane host-inbound behavior is not treated as ordinary transit policy.
- Secret-bearing commands are sanitized before persistence/reporting.

## Version evidence

The newest official Junos release reviewed for documentation freshness is tracked in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml). It is not a blanket parser-compatibility claim.

## Support matrix

See [`support-matrix.md`](support-matrix.md).
