# Migration automation support

Implemented against the existing FortiGate-to-PAN-OS pipeline. Source models remain immutable.

## Source diagnostics and counts

- Malformed explicit primary interface addresses are reported once with affected configuration keys.
- Referenced interfaces absent from the source stay unresolved; Phase 1 entries do not create synthetic FGInterface objects.
- Mapping choices, dependent task groups, conflicts, excluded configuration items and issue groups have separate counts.
- Exclusions and unsupported features remain visible in conversion coverage and the downloaded report.

## Target setup

- Optional PAN-OS 11.1 command-version selection and PA-820 hardware selection are part of the signed design context.
- PA-820 proposals use data ports ethernet1/1 through ethernet1/12. MGT/HA roles are not inferred from source names.
- Referenced, addressed or explicitly managed physical interfaces receive bounded-pool proposals before interfaces with no detected consumers or settings.
- Existing allocations are reserved; out-of-pool overrides conflict. A shortage remains an explicit decision.
- Engineers can exclude interfaces after reviewing source usage suggestions. Excluding a referenced interface does not unblock its dependents.
- A unique compatible destination router can be proposed for a single VDOM. It stays pending until approval.
- Offline mode does not use destination XML. XML-configured interfaces do not establish complete chassis inventory.

## Interfaces and names

- SNMP interface indices are preserved as source-only metadata rather than blocking conversion.
- Explicitly enabled secondary IPv4 addresses can be rendered. Unknown activation, per-address administrative access and unsupported settings stay blocked.
- An existing management profile can be assigned explicitly. The engineer must verify its protocols and permitted IPs; no profile is created automatically.
- Explicit supported site-to-site IPsec interfaces receive stable tunnel.N proposals. Existing target identifiers and manual allocations are reserved.
- Special/remote-access tunnels stay outside this converter slice. Tunnel-dependent commands require an explicitly reviewed existing-target VPN prerequisite.
- Unnumbered static routes can use next-hop None only through a planned tunnel interface. Disabled routes, priority semantics and invalid distances retain their existing restrictions.
- Invalid or colliding object names receive deterministic bounded names. Group, policy, NAT and VPN references follow the allocated names without changing source names.
- Ambiguous source references remain blocked. Explicit service-name overrides retain their previous conflict checks.

## VPN and policies

- Non-secret crypto support includes single AES-128/256-CBC proposals paired with SHA256, SHA384 or SHA512. Proposal combinations are not broadened.
- Lifetimes use verified PAN-OS seconds or integral-hour representations. Missing lifetimes, DH, PFS and IKE version are separate reviewed target values; explicit source values cannot be overwritten through those controls.
- Phase 1 metadata unrelated to crypto does not block an otherwise supported crypto profile. Unknown semantics still block it.
- Gateways and Phase 2 selectors appear as structured manual-completion items. Multiple selectors retain their source identities under the Phase 1 tunnel.
- Gateway/tunnel executable generation and secret recovery are not implemented. Report-only VPN items cannot be made executable by changing their status; validation blocks them.
- One existing target protection-group assignment can apply to policies with the same source inspection settings. Decryption, protocol options, identity and Internet Service constraints are not removed by that assignment.
- Destination mode checks that an assigned protection group exists in the selected scope. Existing rulebase ordering still needs separate placement review.
- Supported service unions in SNAT are expanded into adjacent single-service rules, with bounded nesting/expansion. Other NAT blockers prevent expansion and rendering. Combined SNAT/DNAT, overlapping VIPs, unsupported translations and source ambiguity remain manual.
- Target conflicts on expanded NAT rules are tied to the exact generated rule, not every rule derived from the source policy.

## Approval and compatibility

- Settings and exact generated configuration are bound to the existing signed approval.
- Staged UI edits revoke the active artifact and prevent approval until applied. Changing settings after approval requires a fresh review.
- Preview, command download and bundle use the same approved RenderedMigration.
- New request/draft fields are additive. Existing CLI options and service overrides remain available. No database, dependency, source-model or deployment-protocol migration is required.

## Official references

- [PA-800 hardware ports](https://docs.paloaltonetworks.com/hardware/pa-800-hardware-reference/pa-800-firewall-overview/pa-800-front-panel)
- [PAN-OS 11.1 configuration hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy)
- [PAN-OS 11.1 IPsec cipher suites](https://docs.paloaltonetworks.com/compatibility-matrix/reference/supported-cipher-suites/cipher-suites-supported-in-pan-os-11-1/cipher-suites-supported-in-pan-os-11-1-ipsec)
- [IKE Phase 1 algorithms](https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/ipsec-vpn-basics/internet-key-exchange-ike-for-vpn/ike-phase-1)
- [Static routing through site-to-site VPN](https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/site-to-site-vpn-quick-configs/site-to-site-vpn-with-static-routing)
- [PAN-OS NAT first-match behavior](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)
