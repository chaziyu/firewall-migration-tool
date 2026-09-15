# FortiGate Extraction Reference

## Scope

The `fortigate` source parser handles FortiGate/FortiOS configuration files and produces `ExtractionResult` plus canonical `IRConfig` where semantics are portable.

**Executable authority:** `src/fwmigrate/parsers/fortigate/`

FortiOS documentation is authoritative for FortiGate source syntax. Target-vendor references, including PAN-OS NAT CLI documentation, are used only when validating whether canonical IR can be generated safely for that target. They are not a substitute for FortiOS source-command validation.

## Input contract

Registered extensions are generated in [`../../../generated/capabilities.md`](../../../generated/capabilities.md). For operational collection, prefer an unchanged `show full-configuration` snapshot.

## Version evidence

Repository implementation contains explicit FortiOS **7.4.6** audit/fix modules. The newest official Fortinet documentation reviewed for freshness is recorded separately in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml). A newer reviewed vendor release is not a claim that all of its syntax is tested.

The FortiOS 7.4.6 source contracts used by the NAT extraction path include:

- `firewall_ip_746.py` for `firewall ippool` / `firewall ippool6` validation, defaults, and safety classification.
- `firewall_vip_746.py` for reviewed `firewall vip` top-level and nested-field accounting.
- `policy_nat_preservation_extensions.py` for scoped dependency preservation and review-gating of source-specific NAT/VIP behavior.

## Extraction behavior

The parser normalizes portable semantics where they are proven and retains additional FortiOS settings as typed or structured source evidence when target-neutral behavior is incomplete. Key areas include firewall objects/services, interfaces, security policy, NAT, routing, authentication/identity, security-profile relationships, VPN-related source evidence, system settings, and source inventory for FortiOS-specific features.

FortiOS settings that influence behavior but lack exact portable semantics must make the affected item partial/source-only or otherwise review-required. Unknown or malformed values must not be converted into permissive defaults.

## NAT-specific behavior

- `config firewall central-snat-map` is a FortiOS source construct. Its match, translation, protocol, address-family, port, pool, status, UUID, and comment fields are parsed from FortiOS syntax; target generation is evaluated separately.
- Central SNAT `orig-port`, `dst-port`, and `nat-port` use the FortiOS scalar `0` as an any-port sentinel. A scalar `0` is omitted from canonical port ranges, while the raw setting remains in NAT Rules `Additional Settings`; mixed, malformed, inverted, or out-of-range values require review.
- Central SNAT rules are normalized only when effective Central NAT mode can be proven from the supplied configuration. If `central-nat` / policy-based NGFW context is absent or ambiguous, the rule remains `PARTIALLY_NORMALIZED` and target generation is blocked.
- Basic IPv4 `firewall ippool` overload/range semantics are normalized when the source contract is valid. Fixed-port-range, port-block-allocation, CGN resource allocation, exclusions, `permit-any-host`, malformed values, and other target-specific behavior remain partial/manual-review rather than being flattened into a simple translated range.
- `firewall ippool6` is retained as IPv6 source inventory and remains `EXTRACT_ONLY` unless a target-specific path proves equivalent translation semantics. Successful parsing alone does not make an IPv6 pool generation-safe.
- Basic static `firewall vip` DNAT and port-forwarding fields are normalized when the behavior is representable. Advanced server/load-balancing, QUIC, SSL/proxy, GSLB, real-server, persistence, and source-specific filtering behavior remains partial/manual-review. Nested source commands remain available in the dedicated VIP nested-configuration inventory.
- `src-vip-filter` is a reviewed FortiOS 7.4.6 field. It is preserved as source evidence; enabling it remains review-gated because reverse-SNAT source filtering is not assumed portable.
- `firewall vipgrp` members are resolved within their source VDOM. Valid members retain their group and individual VIP references in derived NAT evidence. Unresolved members remain visible and taint affected output rather than being silently dropped.
- Policy-based IPsec policies with `natinbound` and/or `natoutbound` produce separate source and destination NAT evidence rows. They remain partial/manual-review and are withheld from target generation. `natip` becomes a static translated source only when it is one unambiguous IPv4 host; broad, multiple, malformed, or unresolved values remain source evidence.
- Matching same-VDOM Phase 2 policies are retained with `vpntunnel`, `id`, `name`, `phase1name`, and `use-natip` evidence. Missing references or conflicting `use-natip` values remain review findings.
- `config firewall ippool_grp` is typed as FortiGate source inventory. Ordered member names, unresolved same-VDOM members, explicit fields, and unknown settings are preserved. Policy `poolname` references can resolve to an IP pool group, but the group is not flattened into translated addresses; dependent NAT rules remain partial/manual-review and are withheld from target generation. A same-VDOM name collision between `firewall ippool` and `firewall ippool_grp` remains ambiguous and fails closed.
- Advanced IP-pool and VIP features, including PBA, NAT46/NAT64, exclusions, full-cone behavior, filters, and load-balancing controls, are preserved and withheld or marked partial when exact target semantics are not proven.

## Safety boundaries

- Invalid network syntax is not repaired into `/0`, `/32`, or another usable prefix.
- Missing selectors are not replaced with `any`.
- Unsafe services/groups/routes and dependent rules are withheld when target generation would broaden behavior.
- Source-only attributes are evidence and are not target-generation instructions.
- Preserved source evidence does not imply semantic portability or target-generation support.
- Secret material is sanitized before reporting.

## Support matrix

See [`support-matrix.md`](support-matrix.md) for the maintained domain-level view.

## Historical detail

The previous detailed FortiGate reference is preserved at `documentation/archive/2026/legacy/fortigate-config-extraction-reference.md` for audit history. Use current code/tests and this maintained reference for current claims.
