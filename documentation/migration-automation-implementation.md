# Migration automation support

Implemented against the existing FortiGate-to-PAN-OS pipeline. Source models remain immutable.

## Source diagnostics and counts

- Malformed explicit primary interface addresses are reported once with affected configuration keys.
- Referenced interfaces absent from the source stay unresolved; Phase 1 entries do not create synthetic FGInterface objects.
- Mapping choices, dependent task groups, conflicts, excluded configuration items and issue groups have separate counts.
- Exclusions and unsupported features remain visible in conversion coverage and the downloaded report.
- Download separates included items, supported items not selected for approval, unresolved prerequisites, unsupported conversion, source-data problems and target conflicts. These report categories do not change render permissions.
- Review all ready changes opens the existing explicit approval preview with configuration-family counts. A partial download can return to review even when it already contains commands.

## Verified effective values

- FortiOS 7.2.13 omitted policy action (deny) and VIP type (static-nat) are derived separately from explicit source state. Their source version and official references appear in draft findings and the artifact report.
- FortiOS 7.2.13 Phase 2 interface PFS (enable) and lifetime (43200 seconds) are also derived from the exact-version CLI reference, page 1939. These facts can complete crypto profiles; they do not establish gateway authentication or peer negotiation.
- Explicit values win. Missing or different firmware versions do not use these defaults. Other VPN and DHCP omissions remain reviewed choices unless their exact source-version semantics are verified. Conflicting target overrides cannot replace verified source values.
- Standalone VIP address objects require target ownership but not interface mappings. Their NAT rules and consuming policies retain their mapping and dependency checks.

## Target setup

- Optional PAN-OS 11.1 command-version selection and PA-820 hardware selection are part of the signed design context.
- PA-820 proposals use data ports ethernet1/1 through ethernet1/12. MGT/HA roles are not inferred from source names.
- Referenced, addressed or explicitly managed physical interfaces receive bounded-pool proposals before interfaces with no detected consumers or settings.
- Existing allocations are reserved; out-of-pool overrides conflict. A shortage remains an explicit decision.
- Engineers can exclude interfaces after reviewing source usage suggestions. Excluding a referenced interface does not unblock its dependents.
- A unique compatible destination router can be proposed for a single VDOM. It stays pending until approval.
- Offline mode does not use destination XML. XML-configured interfaces do not establish complete chassis inventory.
- Offline setup uses one ownership/interface/zone editor. Shared source zones are edited once; explicit member overrides remain visible.
- Unsupported interfaces show their blocking reason instead of a disabled blank input. Missing source interfaces require source correction, not an invented target port.
- Actionable mapping problems appear under Needs attention. Full conversion issues and manual work remain in Review conversion and the report.
- Guided/bulk mapping tools and YAML/JSON import/export controls remain available only in destination-aware mode. Backend and CLI interfaces are unchanged.

## Interfaces and names

- SNMP interface indices are preserved as source-only metadata rather than blocking conversion.
- Interface monitor-bandwidth is also preserved as source-only display metadata. remote-ip, src-check and unknown interface settings retain their semantic blockers.
- Explicitly enabled secondary IPv4 addresses can be rendered. Unknown activation, per-address administrative access and unsupported settings stay blocked.
- An existing management profile can be assigned explicitly. Alternatively, reviewed protocol groups can generate device-scoped management profiles after the engineer supplies permitted management CIDRs. A shared CIDR proposal can populate all groups. Existing per-interface profile assignments take precedence.
- Generated profiles explicitly enable or disable supported management services and are created before attachment. Interfaces depend on their profile's approval and validation. Destination-aware creation stays blocked because the current target extraction does not verify existing profile definitions and collisions.
- Interfaces with identical explicit management protocols are grouped within their VDOM. One reviewed existing-profile assignment updates that group's per-interface settings.
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
- An ssl-ssh-profile of no-inspection alone does not require an unrelated protection-group assignment. Other decryption modes still require their own implementation.
- Destination mode checks that an assigned protection group exists in the selected scope. Existing rulebase ordering still needs separate placement review.
- Scoped user/group mappings can populate security-rule source-user values after explicit confirmation of target identity prerequisites. Source identity names can be proposed in bulk; that action does not confirm identity services or approve rules. Identity-dependent NAT remains unsupported.
- Supported service unions in SNAT and VIP consumers expand into bounded, ordered single-service rules. Multiple VIP consumers retain their individual match contexts and require one consistent post-NAT zone. Other NAT blockers prevent expansion and rendering.
- Single TCP/UDP VIP port translations with explicit built-in ALL consumer services generate an original-port service and translated-port commands. Ranges, custom/post-translation service selectors and unsupported translations remain manual.
- SNAT and VIP rules in the same target scope are no longer blocked solely for coexisting. Independence requires the SNAT source to exclude the VIP mapped server and its destination to exclude both VIP external and mapped addresses. Unknown names, cycles and overlapping/combined flows stay blocked.
- VIP extintf and consumer policy zones/addresses do not prove independent NAT eligibility. extintf does not bind FortiGate DNAT to ingress, and VIP reverse-SNAT must also be considered. VIPs sharing an external address require distinct verified original protocol/port matches or remain blocked.
- Target conflicts on expanded NAT rules are tied to the exact generated rule, not every rule derived from the source policy.
- One isolated policy combining explicit overload-pool SNAT and a static VIP can render both translations in one NAT rule. This requires an explicit source subnet excluding the mapped server and identical verified matches. Translation egress dependencies remain separate from the original-packet destination interface. Multiple policies, PAT, identity matches and uncertain overlaps retain their blockers.
- Flat VIP-group destinations expand only when their membership and settings are supported. Coverage considers the group represented only when all member addresses, NAT rules and consuming policies are satisfied. Incomplete or unapproved groups remain visible.

## Approval and compatibility

- Settings and exact generated configuration are bound to the existing signed approval.
- Staged UI edits revoke the active artifact and prevent approval until applied. Changing settings after approval requires a fresh review.
- Preview, command download and bundle use the same approved RenderedMigration.
- Review counts distinguish approved items from remaining ready items. A successful approval closes its completed preview; a failed approval preserves the selection for recovery.
- Shared actions group repeated causes by source scope and actual prerequisite. Source correction, reviewed target choices, missing converters, dependencies and source-only evidence remain distinct. Counts can overlap and are not an automation percentage.
- New request/draft fields are additive. Existing CLI options and service overrides remain available. No database, dependency, source-model or deployment-protocol migration is required.

## Remaining conversion boundaries

- Malformed WAN1 primary IPv4 data and the missing Euronet-P1 source interface require a corrected source export. Secondary addresses and target names cannot repair those source facts.
- Full gateway/tunnel commands remain excluded until authentication, peer identity, compatible tunnel-level crypto and selectors have a verified implementation. The report retains non-secret completion structure.
- Decryption stays excluded where source inspection-profile definitions, certificates or an equivalent reviewed target design are unavailable. A protection-group name alone does not establish decryption equivalence.
- Custom all-protocol services, DHCP options, route priority/VRF differences and other operational families without a verified equivalent retain specific exceptions. Source-only metadata does not imply operational coverage.
- These changes automate supported proposals and shared choices. They do not make a partial offline export deployment-ready or verify destination hardware, licensing or live behavior.

## Validation on 2026-10-16

- Python: 1882 tests and 8 subtests passed; compileall and Ruff passed.
- Frontend: 91 tests, ESLint, TypeScript and production build passed.
- Browser: offline and destination-aware approval, failed-build recovery, preview/download/bundle integrity, bulk management proposals and mobile layout passed.
- Supplied FortiGate file: 7818 approved configuration items, 10029 commands and 2850 excluded plan items. The preview and downloaded command bytes matched. This replay did not select additional management-access or identity decisions.
- No live firewall, candidate acceptance, peer negotiation or full decryption equivalence was tested.

## Official references

- [PA-800 hardware ports](https://docs.paloaltonetworks.com/hardware/pa-800-hardware-reference/pa-800-firewall-overview/pa-800-front-panel)
- [PAN-OS 11.1 configuration hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy)
- [PAN-OS 11.1 IPsec cipher suites](https://docs.paloaltonetworks.com/compatibility-matrix/reference/supported-cipher-suites/cipher-suites-supported-in-pan-os-11-1/cipher-suites-supported-in-pan-os-11-1-ipsec)
- [IKE Phase 1 algorithms](https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/ipsec-vpn-basics/internet-key-exchange-ike-for-vpn/ike-phase-1)
- [Static routing through site-to-site VPN](https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/site-to-site-vpn-quick-configs/site-to-site-vpn-with-static-routing)
- [PAN-OS NAT first-match behavior](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)
- [FortiOS 7.2.13 policy defaults](https://docs2.fortinet.com/document/fortigate/7.2.13/cli-reference/333889629/config-firewall-policy)
- [FortiOS 7.2.13 CLI reference, VIP defaults](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/9b85aed5-fafc-11f0-8b43-d2943efe5b2f/FortiOS-7.2.13-CLI_Reference.pdf)
- [Fortinet VIP extintf versus srcintf-filter](https://community.fortinet.com/fortigate-3/technical-tip-firewall-vip-difference-in-srcintf-filter-and-extintf-137043)
