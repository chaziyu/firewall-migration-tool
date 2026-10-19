# Migration support matrix

Updated 2026-10-19. These are partial, directional migration workflows. A successful export is not a complete replacement firewall configuration.

## Version and execution boundaries

| Direction | Target syntax baseline | Destination comparison | Execution |
| --- | --- | --- | --- |
| FortiGate to PAN-OS | PAN-OS 11.1 | Native XML | Reviewed candidate push, separate validation and explicit commit |
| PAN-OS to FortiGate | FortiOS 7.4.6 | Native FortiGate configuration | Offline CLI export |
| FortiGate to Cisco ASA | ASA 9.20, routed context | Native ASA configuration and explicit completeness metadata | Offline CLI export |
| FortiGate to Juniper SRX | Junos 25.2R1, standalone | Native Junos configuration and explicit completeness metadata | Offline set export |
| FortiGate to Check Point | Management API 1.8.1; separate Gaia output | Native Management JSON and explicit completeness metadata | Offline API request specification and Clish export |

The browser accepts optional destination snapshots for every listed pair. Snapshots are sanitized by the native backend reporter. Completeness is an explicit operator declaration, checked against available collection evidence. A missing table does not prove absence. Snapshot comparison does not establish live device acceptance, licensing, hardware fit, or current candidate state.

Destination text, selected scope, version, mode, completeness declarations, mappings, operations and dependencies are bound to the design. Changes require a new review and approval. Proposal imports do not restore approval. Unsupported directions fail closed.

FortiGate to PAN-OS and PAN-OS to FortiGate have assisted mapping and guided review. The reverse pair prepares deterministic target proposals, derives a bounded documented PAN-OS 11.1 source-behavior subset, and groups remaining policy choices. ASA, SRX and Check Point require manual target mappings and choices. Discovery retains its existing availability flags and adds descriptive mapping, comparison, execution and activation limits. These descriptions do not authorize execution or enable unsupported capabilities.

## Source accounting

ASA, SRX and Check Point reviews and artifact reports include scoped source inventory accounting. Repeated source edits retain separate records. Unknown sections remain visible as manual work. Counts describe source records, not command counts.

- `MANUAL`: unrepresented source evidence or an item with its own blocker.
- `DEPENDENCY_BLOCKED`: an otherwise planned item cannot satisfy its dependencies or atomic group.
- `PENDING`: representable source evidence has not been selected for this artifact.
- `REUSED`: selected target evidence satisfies the item without creation commands.
- `RENDERED`: selected source evidence contributes to the export.

ASA and SRX artifact item rows use `NOT_APPROVED` for eligible but unselected work. Review-time eligibility stays unchanged. Selected reuse counts as satisfied work even when it emits zero commands. Reports retain omitted and blocked rows and source coverage.

The report always retains `export_is_complete_migration: false`. Source inventory is evidence accounting; it does not prove traffic equivalence. CLI output remains unapproved review material even when records are labeled rendered.

## FortiGate source NAT evidence

The FortiGate source pipeline preserves explicit policy `fixedport` and `port-preserve` controls. Central SNAT records preserve VDOM, order, edit identity, interfaces, addresses, pools, protocol, ports, state and unsupported evidence. Missing fields stay absent. Native preview exposes the typed central SNAT records; the source workbook retains inventory evidence.

Central SNAT extraction and derivation do not enable central SNAT conversion in ASA, SRX or Check Point. Unsupported port translation, allocation, identity NAT, ordering and return-path behavior remain manual.

## Pair-specific verified increments

### Cisco ASA

See [ASA usage and limits](fortigate_to_cisco_asa-migration.md).

- Existing IPv4 objects, services, physical interfaces, routes, weekly schedules and ordered ingress ACL coverage remains available.
- ASAv VLAN subinterfaces require an explicitly selected ASAv platform, confirmed capacity/availability, a mapped physical parent, a valid explicit tag and unique target interface ownership. Parent commands precede child commands. Existing target VLAN tags block creation; target VLAN replacement is unsupported.
- Exact destination address objects may be reused only when the native command evidence matches and carries no unsupported or NAT behavior. Conflicts block creation.
- A fixed one-host, one-address pool case emits static source NAT with `no-proxy-arp`. It requires explicit fixed-port preservation, routed-return confirmation and complete empty destination traffic evidence.
- This NAT case is limited to one active HTTPS policy between distinct source and destination hosts, destination interface `any`, one ingress, no central SNAT/VIPs, and full interface mapping.
- NAT, its mapped object, policy and every ingress ACL binding form one approval group. Explicit default denies prevent reverse initiation. A blocked or unapproved group emits no NAT traffic changes.
- PAT, broad pool allocation, VIP/DNAT and uncertain NAT order remain manual.
- Policies require explicit match, action, state, logging, disabled inspection/negation and supported NAT evidence. Missing fields block approval. NAT46/NAT64, inbound/outbound translation and unverified typed translation controls block ordinary ACL export. A blocked predecessor also blocks later rules on the same ingress.
- Existing destination object or manual NAT blocks traffic exports until independence can be proven. Complete NAT evidence is not proof of compatibility. Independent address and service objects remain exportable.
- Nested network and service groups use `group-object`. Groups and traffic render in stable dependency order; unresolved dependencies and cycles are rejected. Reused dependencies emit no creation commands.
- Preview, commands and bundle export reject expired or malformed approval expiry. Downloads do not renew approval. Already downloaded files cannot be revoked.

### Juniper SRX

- Existing IPv4 objects, services, physical topology, routes, schedules and ordered policies remain available within their explicit field checks.
- vSRX VLAN output requires explicit platform/capacity choices and a tagged-only physical parent with explicitly configured `0.0.0.0 0.0.0.0` source addressing. The parent must have no direct zone, policy or route membership. The export emits `vlan-tagging`, the child's explicit `vlan-id`, and its IPv4 address. Addressed untagged parents remain manual; no native VLAN is invented. Existing parent configuration conflicts block the child.
- The new fixed-pool case requires one source host, one active policy, builtin `all`/`ALL`, one translated IPv4 address, explicit fixed-port preservation, disabled pool proxy ARP and confirmed routed return traffic.
- The pool emits `port no-translation`. Pool, source NAT rule and policy share an atomic approval group. A target conflict on any member blocks the entire group.
- Interface PAT, shared pools, multiple policy allocation, central SNAT, VIP/DNAT and unverified topology remain manual.
- Destination-aware new policies are allowed only with all relevant families declared complete, no existing local/global/inherited policy rules, no destination NAT or routing-instance ambiguity, and verified or planned zone/topology dependencies. An explicit local default `deny-all` is allowed; other policy settings, inactive policy hierarchies and populated placement remain blocked. Exact policy reuse remains separate. Source order and target snapshot approval binding are preserved.

### Check Point

See [Check Point usage and limits](fortigate_to_checkpoint-migration.md).

- Explicit IPv4 ranges now produce `add-address-range`, alongside hosts, networks and TCP/UDP services. Invalid or IPv6 ranges remain blocked.
- The first advanced increment supports explicit IPv6 `ipprefix` host and network objects through API 1.8.1 `ipv6-address`, `subnet6` and `mask-length6` fields. IPv4/IPv6 names retain distinct scoped identities. Exact IPv6 objects can be reused by UID; dual-stack collisions and unsupported source controls block reuse. IPv6 policies, groups and NAT remain manual.
- Exact native Management hosts, networks, ranges and services may be reused by UID. Address reuse requires explicit automatic NAT disablement. Unknown settings and collisions block reuse and creation.
- New rule insertion requires an explicitly selected package, layer, gateways and a cleanup-only active Drop rulebase with explicit unrestricted matching and verified install-on scope. Native UIDs replace approved references; later created rules use response UID bindings.
- Existing target NAT, other access rules, ambiguous domain ownership and incomplete collection prevent policy creation.
- Management evidence cannot prove Gaia route safety. Gaia and Management remain separate planes.
- NAT, non-always schedules, interface-bound policies and inline layers remain manual. No publish, policy installation or API execution is added.
- Before approval, the browser shows selected operations plus required predecessor rules and object dependencies, request settings, placement and UID bindings. Confirmation is explicit. Failed file generation can retry the current approval without granting a new one. Target edits clear the preview, approval and executable files.

### PAN-OS to FortiGate

See [reverse migration usage and limits](PAN-OS-to-FortiGate-migration.md).

- Source upload opens a proposed conversion. Supported profile, zone, port/VLAN and single-router VRF placement proposals remain subject to engineer review. Ports require declared inventory or explicit eligible destination evidence.
- Verified local PAN-OS 11.1 effective values remain separate from explicit XML. Unknown fields use individual or reviewed bulk target choices. Unsupported policies retain manual findings without ineffective questions.
- Signed approval binds requested overrides, resolved mappings and provenance. Preview, download and bundle retain one approved command list. FortiGate execution remains unavailable.

- Multiple dynamic source NAT rules are accepted only when direct literal IPv4 source prefixes prove pairwise disjointness. Source order is preserved.
- Overlap, group/`any` ambiguity, no-NAT exceptions, combined DNAT and unsupported allocation remain blocked. Consuming policies retain dependencies on the complete NAT set.
- Existing isolated DNAT restrictions remain unchanged.

### FortiGate to PAN-OS

Existing destination-aware planning and deployment boundaries remain in place. Newly typed FortiGate port preservation controls stay blocked where their PAN-OS equivalence is unverified. This expansion does not add a deployment direction or bypass signed design approval.

## Remaining manual coverage

This increment does not claim VLAN support beyond the ASAv/vSRX cases above, general NAT conversion, Check Point NAT or time objects, advanced routing, VPN, identity/inspection profiles, broad IPv6 traffic migration, or hardware acceptance. Interface PAT, VIP/DNAT, schedules and other advanced families from the wider roadmap remain pending pair-specific equivalence verification. Unsupported evidence remains visible and affected dependencies remain blocked. Further cases need pair-specific native fixtures, semantic proof and regression tests before enabling output.

## Semantic references

- [FortiOS 7.4.6 CLI reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/cb8d6b09-b8b3-11ef-9411-ae1fcf29f169/FortiOS-7.4.6-CLI_Reference.pdf), including central SNAT and explicit policy port controls.
- [ASA 9.20 NAT guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html). `unidirectional` and `no-proxy-arp` are alternative static NAT options; the constrained implementation uses `no-proxy-arp` plus reviewed ACL isolation.
- [ASA 9.20 objects and groups](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-objects.html): object members and nested group members use different commands.
- [Junos security policy order](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/concept/policy-overview.html) and [global policy lookup](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-global-policies.html). The empty-target extension does not merge populated policy contexts or ignore global policies.
- Junos 25.2R1 selected CLI references under `documentation/official-cli-references-selected version/`, including source NAT pools and `port no-translation`.
- [ASA 9.20 VLAN subinterfaces](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/interface-vlan.html), plus [ASAv interface support](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/interface-basic-asav.html).
- [Junos VLAN tagging](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/vlan-tagging-edit-interfaces.html). The implemented vSRX case excludes mixed untagged/tagged routing.
- [Check Point Management API 1.8.1 address ranges](https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/add-address-range~v1.8.1) and its [versioned API schema](https://sc1.checkpoint.com/documents/latest/APIs/data/v1.8.1/dynamic/apis.json).
