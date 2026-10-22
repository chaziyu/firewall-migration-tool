# Migration support matrix

Updated 2026-10-22. These are partial, directional migration workflows. A successful export is not a complete replacement firewall configuration.

## Version and execution boundaries

| Direction | Target syntax baseline | Destination comparison | Execution |
| --- | --- | --- | --- |
| FortiGate to PAN-OS | PAN-OS 11.1 | Native XML | Reviewed candidate push, separate validation and explicit commit |
| PAN-OS to FortiGate | FortiOS 7.4.6 | Native FortiGate configuration | Offline CLI export |
| PAN-OS to Juniper SRX | Junos 25.2R1, standalone | Optional complete native Junos snapshot | Offline set export |
| PAN-OS to Cisco ASA | ASA 9.20, routed single context | Optional exact object comparison; existing-target traffic stays blocked | Bounded offline CLI export; reviewed ZIP download verified |
| FortiGate to Cisco ASA | ASA 9.20, routed context | Native ASA configuration and explicit completeness metadata | Offline CLI export |
| FortiGate to Juniper SRX | Junos 25.2R1, standalone | Native Junos configuration and explicit completeness metadata | Offline set export |
| FortiGate to Check Point | Management API 1.8.1; separate Gaia output | New package needs no snapshot. Existing-target comparison uses native Management JSON and completeness metadata | Offline API requests, new-package mgmt_cli commands and Clish export |
| PAN-OS to Check Point | Management API 1.8.1; separate Gaia output | Optional native Management snapshot for exact object reuse; existing-policy insertion and Gaia stay blocked | Offline API requests, response UID bindings, fresh-package mgmt_cli commands |
| PAN-OS to Cisco FTD | FMC REST API 7.7.0 (FMC-managed FTD) | Optional native FMC REST export bundle for exact object and security zone reuse; existing-policy insertion stays blocked | Offline API requests, response ID bindings, fresh-policy curl script and instructions |

The browser accepts optional destination snapshots for every listed pair. Snapshots are sanitized by the native backend reporter. Completeness is an explicit operator declaration, checked against available collection evidence. A missing table does not prove absence. Snapshot comparison does not establish live device acceptance, licensing, hardware fit, or current candidate state.

Destination text, selected scope, version, mode, completeness declarations, mappings, operations and dependencies are bound to the design. Changes require a new review and approval. Proposal imports do not restore approval. Unsupported directions fail closed.

FortiGate to PAN-OS and PAN-OS to FortiGate have assisted mapping and guided review. The reverse pair prepares deterministic target proposals, derives a bounded documented PAN-OS 11.1 source-behavior subset, and groups remaining policy choices. PAN-OS to SRX supports an offline set export and optional family-complete Junos snapshot comparison; policy, NAT and routing ambiguity stays blocked. Check Point proposes a new package without destination evidence; existing-policy insertion still requires target choices. FortiGate to SRX proposes new-device placement for review. ASA proposes recognized numbered ports and safe nameif values; security levels and traffic attestations remain explicit choices. Discovery retains its existing availability flags and adds descriptive mapping, comparison, execution and activation limits. These descriptions do not authorize execution or enable unsupported capabilities.

## Offline browser workflow

All nine pairs offer Source → Review conversion → Download for offline conversion. FortiGate to PAN-OS also retains its advanced destination and live candidate workflow. The other eight pairs have no deployment path.

- Source analysis opens the conversion review. No physical device selection or connection is required.
- Target software baselines remain visible. Editable target setup sits inside review details.
- Pair-owned proposals preserve engineer overrides. FortiGate SRX numbered ports use stable port-number placement; PAN-OS SRX proposes physical ports, logical units, source tags and zone names. These are offline conventions, not verified hardware allocation.
- ASA port/name proposals leave security levels unresolved. Empty-target, routing-completeness, capacity and return-routing attestations are never auto-confirmed.
- Eligible configuration appears in a paginated approval preview by default. Custom exclusions and dependency expansion remain visible. Approve and generate is the explicit action that signs the selection and builds the native files.
- Included, reused, excluded and blocked/manual counts remain visible after generation. An unselected item is not a completed conversion. Reuse-only output is distinct from excluded or blocked output.
- Check Point retains Management JSON, command shell, UID bindings and Gaia files. FTD retains FMC request specifications, curl script, ID bindings and application instructions.
- Source, scope, options, target evidence and selection changes revoke affected approval/artifacts. Superseded responses cannot restore them. A current approval survives generation failure for retry; expiry still requires approval again.

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

See [ASA usage and limits](guides/fortigate-to-cisco-asa-migration.md).

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

- New-device proposals allocate `ge-0/0/N` physical ports, source-tag-based VLAN units, root placement, and separate zones for interfaces outside explicit FortiGate zones. Existing engineer values are preserved. Proposals do not verify hardware, grant approval, or assume an uploaded destination is empty. Review port allocation and cabling before approval.
- IPv4 objects and groups preserve source UUID/color evidence without treating those presentation fields as unsupported matching behavior. Interface-bound addresses require proof that every direct or nested policy consumer uses the bound source interface. Unknown fields, ambiguous representations, cycles and unresolved references remain blocked.
- FortiOS 7.2.13 header evidence enables a bounded set of documented address, policy, interface and static-route defaults. Defaults remain in derived state; review settings carry each value, origin, version and official reference. Missing or other firmware versions do not receive these defaults. Explicit source values take precedence.
- Explicit services and address objects take precedence over built-in-name aliases. TCP/UDP ports, numeric IP protocols 1–254, and ICMP with explicit type/code are supported. A verified unrestricted IP service maps directly to policy `application any`; it needs no custom application. Unsupported selectors, explicit service TTLs and unknown settings remain blocked.
- Supported interface addressing is separate from manual administrative-access and discovery design. The export enables no host-inbound or administrative services. Source coverage remains manual for interfaces with these outstanding control-plane settings. Unsupported forwarding settings still block the interface itself.
- Static routes retain distance as Junos preference. Unknown or disabled state, unsupported priority, missing gateways, ambiguous destinations and unsupported interfaces remain blocked. Ordinary policy defaults do not bypass UTM/identity, NAT, policy-order, dependency or approval checks. UTM-only logging adds no session logs when security inspection is disabled.
- FQDN runtime/cache behavior, dynamic addresses, inspection profiles, VPN interfaces, advanced NAT and source ambiguities still require verified pair-specific design. Common Junos syntax does not prove feature availability or semantic equivalence across all SRX models.
- The reserved `FABRIC_DEVICE` address remains manual even when its configured subnet is `0.0.0.0/0`. That subnet is a placeholder for Security Fabric runtime membership; it must not become an unrestricted target address.
- vSRX VLAN output requires explicit platform/capacity choices and a tagged-only physical parent with explicitly configured `0.0.0.0 0.0.0.0` source addressing. The parent must have no direct zone, policy or route membership. The export emits `vlan-tagging`, the child's explicit `vlan-id`, and its IPv4 address. Addressed untagged parents remain manual; no native VLAN is invented. Existing parent configuration conflicts block the child.
- The new fixed-pool case requires one source host, one active policy, builtin `all`/`ALL`, one translated IPv4 address, explicit fixed-port preservation, disabled pool proxy ARP and confirmed routed return traffic.
- The pool emits `port no-translation`. Pool, source NAT rule and policy share an atomic approval group. A target conflict on any member blocks the entire group.
- Interface PAT, shared pools, multiple policy allocation, central SNAT, VIP/DNAT and unverified topology remain manual.
- Destination-aware new policies are allowed only with all relevant families declared complete, no existing local/global/inherited policy rules, no destination NAT or routing-instance ambiguity, and verified or planned zone/topology dependencies. An explicit local default `deny-all` is allowed; other policy settings, inactive policy hierarchies and populated placement remain blocked. Exact policy reuse remains separate. Source order and target snapshot approval binding are preserved.

### Check Point

See [Check Point usage and limits](guides/fortigate-to-checkpoint-migration.md).

- Explicit IPv4 ranges now produce `add-address-range`, alongside hosts, networks and TCP/UDP services. Invalid or IPv6 ranges remain blocked.
- The first advanced increment supports explicit IPv6 `ipprefix` host and network objects through API 1.8.1 `ipv6-address`, `subnet6` and `mask-length6` fields. IPv4/IPv6 names retain distinct scoped identities. Exact IPv6 objects can be reused by UID; dual-stack collisions and unsupported source controls block reuse. IPv6 policies, groups and NAT remain manual.
- Exact native Management hosts, networks, ranges and services may be reused by UID. Address reuse requires explicit automatic NAT disablement. Unknown settings and collisions block reuse and creation.
- New-target mode creates a separate package and Drop anchor without a destination snapshot. Domain and gateways are selected during manual application. Its additional Bash command file uses an existing API session and requires `mgmt_cli` and `jq`.
- Existing-target rule insertion requires an explicitly selected package, layer, gateways and a cleanup-only active Drop rulebase with explicit unrestricted matching and verified install-on scope. Native UIDs replace approved references; later created rules use response UID bindings.
- In existing-target comparison, target NAT, other access rules, ambiguous domain ownership and incomplete collection prevent policy creation.
- Management evidence cannot prove Gaia route safety. Gaia and Management remain separate planes.
- NAT, non-always schedules, interface-bound policies and inline layers remain manual. No publish, policy installation or API execution is added.
- Before approval, the browser shows selected operations plus required predecessor rules and object dependencies, request settings, placement and UID bindings. Confirmation is explicit. Failed file generation can retry the current approval without granting a new one. Target edits clear the preview, approval and executable files.

### PAN-OS to FortiGate

See [reverse migration usage and limits](guides/PAN-OS-to-FortiGate-migration.md).

- Source upload opens a proposed conversion. Supported profile, zone, port/VLAN and single-router VRF placement proposals remain subject to engineer review. Ports require declared inventory or explicit eligible destination evidence.
- Verified local PAN-OS 11.1 effective values remain separate from explicit XML. Unknown fields use individual or reviewed bulk target choices. Unsupported policies retain manual findings without ineffective questions.
- Signed approval binds requested overrides, resolved mappings and provenance. Preview, download and bundle retain one approved command list. FortiGate execution remains unavailable.

- Multiple dynamic source NAT rules are accepted only when direct literal IPv4 source prefixes prove pairwise disjointness. Source order is preserved.
- Overlap, group/`any` ambiguity, no-NAT exceptions, combined DNAT and unsupported allocation remain blocked. Consuming policies retain dependencies on every active or unknown-state NAT item.
- Explicitly disabled NAT rules remain visible as nonexecutable `inactive_nat` evidence. They do not participate in active overlap proofs or traffic dependencies. Disabled security policies do not sever the active predecessor chain.
- UUID attributes, organizational group tags and explicitly unrestricted HIP selectors do not block supported matching. Only exact inactive service-timeout overrides are accepted; active, incomplete and unknown overrides remain blocked.
- Verified standalone PAN-OS 11.1 predefined HTTP/HTTPS references generate explicit target services with version/reference provenance and normal approval dependencies. Custom objects and ambiguous references retain their source resolution.
- Nested IPv6 interface controls and unknown service containers remain preserved source evidence. Self-referential route gateways are blocked. See the [automation review and implementation plan](palo-alto-to-fortigate-automation-review.md).
- Existing isolated DNAT restrictions remain unchanged.

### PAN-OS to Check Point

- Requires one selected standalone VSYS and Check Point Management API 1.8.1 target baseline. Produces reviewed offline API request specification, response UID bindings, and fresh-package `mgmt_cli` commands. No live execution, login, publish, or policy installation is performed.
- Converts explicit IPv4 hosts, subnets, ranges (`add-host`, `add-network`, `add-address-range`), static address groups (`add-group`), and TCP/UDP services with explicit source/destination port ranges split into atomic services and service groups (`add-service-tcp`, `add-service-udp`, `add-service-group`).
- New-target mode creates a fresh policy package, access layer, and an explicit Drop cleanup rule anchor without requiring a target snapshot. Gateway installation targets (`install-on`) and management domain are reviewed during mapping.
- Unrestricted-zone L3/L4 policies (`from any`, `to any`, `application any`) with explicit allow/drop and unlogged defaults map to ordered Check Point access rules with position preserved via response UID bindings.
- Zone-constrained policies, active/unknown NAT, App-ID, named schedules, logging/inspection profiles, Gaia interface topology and Gaia static routes remain blocked manual items.
- Optional destination snapshots support exact native UID reuse for addresses and address groups with auto-rule NAT disabled; existing policy insertion and Gaia stay blocked.

### PAN-OS to Cisco FTD (FMC-managed)

- Requires one selected standalone VSYS and Cisco FMC REST API 7.7.0 target baseline. Produces reviewed offline API request specification (`cisco_fmc_operations.json`), response ID bindings (`cisco_fmc_bindings.json`), fresh-policy `curl` script (`cisco_fmc_curl.sh`), and application instructions (`ftd_application_instructions.txt`). No live execution, login, credential storage, or deployment is performed.
- Converts explicit IPv4 hosts, subnets, ranges (`/object/networks`, `/object/rangeobjects`), static address groups (`/object/networkgroups`), TCP/UDP port objects split into atomic single-port/range objects (`/object/protocolportobjects`) and grouped under port groups (`/object/portobjectgroups`), and security zones (`/object/securityzones`). Returned object IDs bind later requests using `{$response_binding:...}`.
- Target mode: New-target mode plans a fresh Access Control Policy container (`/policy/accesspolicies`) and default rule without requiring destination evidence. FMC domain UUID and policy container names are reviewed during target setup.
- Access Policies: Only explicit L3/L4 policies with verified universal rule type, unlogged Drop defaults (`intrazone-default` and `interzone-default`), and explicit allow/drop actions are representable. Policies preserve source rule order and map to `/policy/accesspolicies/{acp_id}/accessrules`.
- Fail-Closed Safety: FDM mode and device CLI target modes are unsupported and fail closed. Active/unknown NAT, App-ID, named schedules, logging/inspection profiles, device interface assignments, and FTD static routes remain blocked manual items.
- Target Snapshot Comparison: Optional native FMC REST export bundle comparison supports exact address, port object, and security zone ID reuse when names and types match. Conflicting target objects fail closed. Existing policy insertion stays blocked.

### FortiGate to PAN-OS

Existing destination-aware planning and deployment boundaries remain in place. Newly typed FortiGate port preservation controls stay blocked where their PAN-OS equivalence is unverified. This expansion does not add a deployment direction or bypass signed design approval.

## Remaining manual coverage

This increment does not claim VLAN support beyond the ASAv/vSRX cases above, general NAT conversion, Check Point NAT or time objects, advanced routing, VPN, identity/inspection profiles, broad IPv6 traffic migration, or hardware acceptance. Interface PAT, VIP/DNAT, schedules and other advanced families from the wider roadmap remain pending pair-specific equivalence verification. Unsupported evidence remains visible and affected dependencies remain blocked. Further cases need pair-specific native fixtures, semantic proof and regression tests before enabling output.

## Semantic references

- PAN-OS to ASA requires one selected standalone VSYS, explicit target ports/nameifs/security levels, confirmed new empty target state and complete connected/static routing evidence. Supported traffic uses explicit TCP/UDP rules without inspection or logging, documented PAN-OS 11.1 always behavior only when no named schedule is configured, explicit unlogged Drop defaults, bounded ACE expansion and whole-destination egress proof. Missing source ports, named schedules, active/unknown NAT, unsupported predecessors, FQDN/IPv6 and topology ambiguity remain blocked. Interfaces, security controls, routes, ACL rules, final denies, bindings and final activation form one atomic approval unit. No live operation or automatic save is implemented. Browser ZIP saving and byte equality were verified with synthetic policy and supplied LFSA inputs, including a 390px final-build check. Direct `.cfg` saving did not work in the in-app browser, including on an isolated diagnostic page; the ZIP contains the same native `.cfg`. Standalone-browser direct saving and live ASA acceptance remain unverified. See the implementation progress log.
- [ASA 9.20 access-rule order, implicit permits and security checks](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html).

- [FortiOS 7.2.13 CLI reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/9b85aed5-fafc-11f0-8b43-d2943efe5b2f/FortiOS-7.2.13-CLI_Reference.pdf), including the version-bound address, policy, interface, route and IP-service defaults retained in SRX review evidence.
- [Junos custom applications](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/application-edit-applications-srx.html) and [ICMP selectors](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/applications-edit-icmp-type.html), including numeric protocol and explicit ICMP type/code syntax.
- [FortiGate dynamic Fabric addresses](https://docs.fortinet.com/document/fortigate/7.2.4/administration-guide/146433/dynamic-policy-fabric-devices): configured placeholder subnets do not represent the runtime policy match set.
- [FortiOS 7.4.6 CLI reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/cb8d6b09-b8b3-11ef-9411-ae1fcf29f169/FortiOS-7.4.6-CLI_Reference.pdf), including central SNAT and explicit policy port controls.
- [ASA 9.20 NAT guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html). `unidirectional` and `no-proxy-arp` are alternative static NAT options; the constrained implementation uses `no-proxy-arp` plus reviewed ACL isolation.
- [ASA 9.20 objects and groups](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-objects.html): object members and nested group members use different commands.
- [Junos security policy order](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/concept/policy-overview.html) and [global policy lookup](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-global-policies.html). The empty-target extension does not merge populated policy contexts or ignore global policies.
- Junos 25.2R1 selected CLI references under `documentation/official-cli-references-selected version/`, including source NAT pools and `port no-translation`.
- [ASA 9.20 VLAN subinterfaces](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/interface-vlan.html), plus [ASAv interface support](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/interface-basic-asav.html).
- [Junos VLAN tagging](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/vlan-tagging-edit-interfaces.html). The implemented vSRX case excludes mixed untagged/tagged routing.
- [Check Point Management API 1.8.1 address ranges](https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/add-address-range~v1.8.1) and its [versioned API schema](https://sc1.checkpoint.com/documents/latest/APIs/data/v1.8.1/dynamic/apis.json).
- [Cisco Firepower Management Center REST API Configuration Guide, Version 7.7.0](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/api/fmc/fmc-rest-api-quick-start-770.html), including object containers, access rules, response UUID structures, and batch request contracts.
