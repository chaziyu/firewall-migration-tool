# FortiGate Extraction Reference

## Scope

The `fortigate` source parser handles FortiGate/FortiOS configuration files and produces `ExtractionResult` plus canonical `IRConfig` where semantics are portable.

**Executable authority:** `src/fwmigrate/parsers/fortigate/`

## Input contract

Registered extensions are generated in [`../../../generated/capabilities.md`](../../../generated/capabilities.md). For operational collection, prefer an unchanged `show full-configuration` snapshot.

## Version evidence

Repository implementation contains explicit FortiOS **7.4.6** audit/fix modules. The newest official Fortinet documentation reviewed for freshness is recorded separately in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml). A newer reviewed vendor release is not a claim that all of its syntax is tested.

## Extraction behavior

The parser normalizes portable semantics where they are proven and retains additional FortiOS settings as typed or structured source evidence when target-neutral behavior is incomplete. Key areas include firewall objects/services, interfaces, security policy, NAT, routing, authentication/identity, security-profile relationships, VPN-related source evidence, system settings, and source inventory for FortiOS-specific features.

FortiOS settings that influence behavior but lack exact portable semantics must make the affected item partial/source-only or otherwise review-required. Unknown or malformed values must not be converted into permissive defaults.

## NAT-specific behavior

- Central SNAT `orig-port`, `dst-port`, and `nat-port` use the FortiOS scalar `0` as an any-port sentinel. A scalar `0` is omitted from canonical port ranges, while the raw setting remains in NAT Rules `Additional Settings`; mixed, malformed, inverted, or out-of-range values require review.
- Policy-based IPsec policies with `natinbound` and/or `natoutbound` produce separate source and destination NAT evidence rows. They remain partial/manual-review and are withheld from target generation. `natip` becomes a static translated source only when it is one unambiguous IPv4 host; broad, multiple, malformed, or unresolved values remain source evidence.
- Matching same-VDOM Phase 2 policies are retained with `vpntunnel`, `id`, `name`, `phase1name`, and `use-natip` evidence. Missing references or conflicting `use-natip` values remain review findings.
- Advanced IP-pool and VIP features, including PBA, NAT46/NAT64, exclusions, full-cone behavior, filters, and load-balancing controls, are preserved and withheld or marked partial when exact target semantics are not proven.

## Safety boundaries

- Invalid network syntax is not repaired into `/0`, `/32`, or another usable prefix.
- Missing selectors are not replaced with `any`.
- Unsafe services/groups/routes and dependent rules are withheld when target generation would broaden behavior.
- Source-only attributes are evidence and are not target-generation instructions.
- Secret material is sanitized before reporting.

## Support matrix

See [`support-matrix.md`](support-matrix.md) for the maintained domain-level view.

## Historical detail

The previous detailed FortiGate reference is preserved at `documentation/archive/2026/legacy/fortigate-config-extraction-reference.md` for audit history. Use current code/tests and this maintained reference for current claims.
