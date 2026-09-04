# Palo Alto Networks Extraction Reference

The PAN-OS source adapter accepts XML configuration exports only. It also
accepts the standard API wrapper `response/result/config`; arbitrary XML and
PAN-OS `set` syntax are rejected. Extraction is scope-first and follows the
canonical flow `PAN-OS XML -> ExtractionResult -> IRConfig`.

## Safety and accounting contract

Every handled source object or rule receives one terminal extraction inventory
outcome. `NORMALIZED` is used only when all material configured semantics have
a canonical representation. Retained PAN-specific settings force
`PARTIALLY_NORMALIZED`; structured source-only constructs use `EXTRACT_ONLY`
or `VENDOR_EXTENSION`; intentionally unimplemented constructs use
`UNSUPPORTED`; malformed supported syntax uses `PARSE_ERROR`.

Source evidence is sanitized and retained in `source_attributes` or
`source_extra_settings`. Missing policy and NAT match fields are never replaced
with `any`; missing actions are never replaced with `allow`; missing route
destinations are never replaced with a default route. Scope-aware
`SourceSectionResult` summaries report source, parsed, and normalized terminal
outcomes.

## Supported canonical extraction

The extraction boundary is summarized below. `Structured` means that source
semantics are retained for review; it does not imply target generation
support.

| Domain | Parsed | Structured | Canonical projection |
|---|---|---|---|
| Addresses and groups | Yes | Yes | Yes / partial on unresolved or unsafe references |
| Services and schedules | Yes | Yes | Yes / partial on unsupported settings |
| Security rules | Yes | Yes | Yes when required match fields are present |
| IPv4 NAT | Yes | Yes | Yes / partial |
| NAT64 / NPTv6 | Yes | Yes | Partial; family semantics remain source evidence |
| Legacy Virtual Router routes | Yes | Yes | Yes / partial |
| Logical Router / VRF routes | Yes | Yes | Route subset; partial for non-portable settings |
| BGP, OSPF, OSPFv3, RIP | Yes | Yes | No; source-only dynamic-routing inventory |
| External Dynamic Lists | Yes | Yes | No; source-only |
| Region and Device-ID objects | Yes | Yes | No; PAN-specific source-only objects |
| Security profiles | Yes | Yes | Limited profile-group compatibility; definitions source-only |
| IKE / IPsec | Yes | Yes | No; source-only VPN inventory |
| Advanced policy families | Yes | Yes | No; source-only family inventory |
| Panorama templates / stacks | Yes | Yes | No; effective inheritance is not calculated |
| Management access | Yes | Yes | No; source-only management-plane inventory |

- Addresses: `ip-netmask`, `ip-range`, `ip-wildcard`, and `fqdn`, with scope,
  tags, descriptions, and collision-safe reference resolution.
- Address and service groups: static membership and supported dynamic address
  filters, with unresolved, ambiguous, unsafe, and cyclic membership retained.
- PAN-OS predefined services `service-http` and `service-https` are valid
  references in security rules, NAT rules, and service groups, including nested
  groups. They are safe terminal members and are not synthesized as configured
  `IRService` objects, so source service counts remain faithful. `any` and
  `application-default` are rule-context keywords and are not automatically
  treated as service-group predefined objects.
- TCP/UDP services, schedules whose windows fit the current canonical model,
  zones, safely representable Layer 3 interface identity, Security rules,
  PAN-OS NAT rules, and IPv4/IPv6 static routes.
- Security and NAT rules preserve scope, pre/local/post rulebase position,
  source index, stable source-rule ID, and exact source path.
  Security-rule source and destination references resolve configured address
  objects and groups first; valid literal IP/CIDR values and the explicit
  PAN-OS predefined region-code catalog are retained as policy references
  with classification evidence, while only genuinely unresolved values
  require review.
- NAT match parsing uses direct XML paths. Scalar service, `to-interface`,
  `nat-type`, disabled state, description, tags, group-tag, active-active
  binding, destination translated port, and source/destination translation
  modes are retained.
- NAT translated-address values are classified in this order: literal host,
  literal prefix, scoped address-object reference, valid IP range, then
  unresolved reference or invalid value. A configured `to-interface` is also
  projected to canonical `IRNATRule.source_to_interfaces`; `any` remains
  `['any']` rather than being treated as absent.
- Source NAT distinguishes `dynamic-ip-and-port`, `dynamic-ip`, `static-ip`,
  and interface-address behavior. Fallback, floating-IP, bi-directional, and
  unknown translation settings remain structured source evidence and require
  review where canonical semantics are incomplete.
- Destination and dynamic-destination translation retain address, port, DNS
  rewrite, and distribution settings.
- Static routes are discovered from both the device
  `network/virtual-router/entry` hierarchy and the actual
  `network/logical-router/entry/vrf/entry` hierarchy. Virtual-router or
  logical-router/VRF identity, address family, explicit metric and
  administrative distance, interface, IP/discard/FQDN/next-VR next hop, BFD,
  path monitor, route-table installation, and unknown fields are retained.
  Omitted metric remains absent. Destinations are processed first as literal
  IPv4/IPv6 prefixes, then as scoped PAN address references. Named `ip-netmask`
  objects can provide a normalized prefix while the original reference remains
  preserved for manual review.
- Layer 3 interfaces are associated with direct interface members of their
  PAN-OS virtual-router or logical-router/VRF. The visible routing-instance
  name and type are normalized into the interface IR, while virtual-router,
  logical-router, and VRF names remain source evidence. Unresolved members and
  conflicting assignments are audited and require manual review.
- Default Security rules deliberately remain outside canonical `IRPolicy`.
  Their implicit matching semantics cannot be represented without inventing
  ordinary `from`, `to`, source, destination, application, or service fields.

## Partially normalized areas

- Security-rule source semantics without complete portable fields: App-ID
  predefined references, source user, HIP, category, negation, SaaS selectors,
  inspection options, direct profiles, non-basic action variants, unknown
  fields, and unresolved references.
  Security Policy `<rule-type>` values are validated against the PAN-OS
  values `universal`, `interzone`, and `intrazone`. An explicitly configured
  value is retained as `pan_rule_type` in `IRPolicy.source_extra_settings`,
  with explicit presence and validity evidence. Because canonical `IRPolicy`
  does not model PAN-OS rule-type matching semantics, known values require
  targeted review reasons `rule-type-universal`, `rule-type-interzone`, or
  `rule-type-intrazone`; the parser does not rewrite `from_zone` or `to_zone`
  to approximate them. Unknown non-empty values are preserved and require
  `unsupported-rule-type`; an explicitly empty value is preserved and
  requires `invalid-rule-type`. An omitted `<rule-type>` remains absent from
  source value evidence and does not add a review reason; PAN-OS documents
  `universal` as the effective default, but extraction does not synthesize that
  default so explicit source configuration remains distinguishable.
  Modern `source-hip` and `destination-hip` fields are preserved as before;
  PAN-OS 9.1 `hip-profiles` is recognized as a legacy source HIP field,
  retained in source evidence, and mapped to effective source HIP only when
  modern `source-hip` is absent. Legacy `any` is not a review finding, while
  named legacy HIP profiles remain `PARTIALLY_NORMALIZED` with a specific
  legacy-HIP review reason.
- NAT interface-address, fallback, bi-directional static NAT, dynamic
  destination distribution, DNS rewrite, `nat-type`, `to-interface`, active-
  active binding, unknown fields, and unresolved references.
- Layer 3 interfaces with multiple IPv4 addresses, IPv6 entry attributes,
  DHCP client, PPPoE, link-state `auto`, MTU/speed/duplex, physical or Layer 3
  LLDP, Layer 3 NetFlow profiles, or unknown physical/Layer 3 settings.
  Layer 3 LLDP is retained as structured `pan_layer3_lldp` evidence and Layer 3
  NetFlow keeps its exact `pan_netflow_profile` name; both remain source-only
  until portable IR semantics are available. Physical LLDP remains sourced
  from the physical interface node and is retained separately when a Layer 3
  LLDP subtree is also configured.
- Zones with security-relevant settings, unknown fields, unresolved/conflicting
  interfaces, or multiple effective network types.
- Security profile definitions and profile groups with data-filtering,
  unexpected multiple members, unresolved references, or unknown fields. Every
  definition/group has an inventory record; all members remain in source
  evidence.
- Static routes with FQDN/next-VR next hops, BFD, path monitoring, route-table
  installation settings, unknown fields, or destination references. Address
  groups, FQDNs, ranges, and unresolved references are retained without being
  flattened or converted into invented prefixes. A route with a destination
  reference remains unsafe for automatic target generation.

## Extract-only and vendor-specific inventory

- Custom applications, application groups, application filters, and tags are
  conservative source inventory; filters are not expanded against an absent
  dynamic App-ID content database.
- Region objects and Device-ID/device-object configuration are retained as
  vendor-specific source inventory and are never reinterpreted as generic
  address objects.
- BGP, OSPF, OSPFv3, RIP, and redistribution configuration is structured
  source-only inventory under each virtual or logical router. Router IDs,
  ASNs, peer groups/peers, peer/local addressing, interfaces, authentication,
  BFD, timers, import/export policy, redistribution references, OSPF areas and
  interfaces, RIP interfaces, unknown fields, and routing-instance identity
  remain visible. Extraction does not calculate route convergence.
- Layer 2 Ethernet and aggregate Ethernet, Layer 2 subinterfaces,
  virtual-wire, tap, HA, and decrypt-mirror modes remain structured source-only
  inventory. Physical settings and mode-specific settings remain separate;
  non-Layer-3 modes are never projected into Layer-3 canonical fields.
- Default Security rules retain name, built-in/local/Panorama override state,
  action, disabled state, logging, description, tags/group-tag, profile group,
  direct profiles, options, ICMP-unreachable, and unknown evidence without
  fabricating ordinary rule match fields.
- Security Policy rule-level QoS marking is explicitly parsed from the
  confirmed `qos/marking` hierarchy. `ip-dscp` and `ip-precedence` values are
  retained as `pan_qos_ip_dscp` and `pan_qos_ip_precedence`, with the marking
  type, complete `qos` subtree, and complete `marking` subtree preserved in
  `source_extra_settings`. Unknown direct QoS or marking children are retained
  under targeted `pan_unknown_qos_fields` and
  `pan_unknown_qos_marking_fields` evidence. Because `IRPolicy` has no exact
  canonical packet-marking field, configured marking is
  `PARTIALLY_NORMALIZED` and requires the `qos-marking` review reason; unknown
  and conflicting branches receive additional targeted review reasons.
- Decryption, application-override, authentication, QoS, DoS, tunnel-inspect,
  SD-WAN, and network-packet-broker rules are parsed by the generic family
  handlers. Scope, pre/local/post provenance, source index, stable source-rule
  ID, common match/action fields, family-specific subtrees, and unknown fields
  are `EXTRACT_ONLY`; no family is forced into `IRPolicy`.
- PBF rules are parsed by the dedicated `PANPBFRuleExtractor`. PBF is not a
  generic flat `FAMILY_FIELDS` family: its nested selectors and action/forward
  structures remain structured source-only evidence.
- PBF ingress selectors follow the PAN-OS hierarchy: zones are extracted from
  `from/zone/member` and interfaces from `from/interface/member`. These remain
  separate source semantics. The complete `from` subtree and unknown nested
  children are retained as structured evidence. PBF action semantics are
  extracted from the nested `action` subtree: `forward`, `discard`, `no-pbf`,
  and the PAN-OS `forward-to-vsys` variant when present. Forwarding preserves
  the nested egress interface, IP-address/FQDN/none next-hop type and value,
  monitor profile/IP/disable behavior, and complete
  action, forward, next-hop, and monitor source subtrees. Unknown nested
  action, forward, next-hop, and monitor children remain visible in dedicated
  evidence fields. Rule-level symmetric-return settings and active-active
  device binding are also retained. PBF remains source-only: these fields are
  not converted into canonical `IRRoute` objects.
  Extraction quality is classified per rule: structurally valid understood
  rules use `EXTRACT_ONLY`; malformed or invalid known values use
  `PARSE_ERROR`; and structurally valid action or nexthop branches that the
  extractor cannot safely interpret use `UNSUPPORTED`. Preserved unknown
  optional fields keep the rule `EXTRACT_ONLY` with `requires_manual_review`
  and stable PBF review reasons such as `unknown-forward-fields` or
  `unknown-monitor-fields`. PBF does not use `NORMALIZED` because it has no
  canonical IR representation.
- VSYS network imports preserve interfaces, virtual routers, logical routers,
  VLANs, virtual wires, unknown import subtypes, and their VSYS association.
- Security profile definitions and profile groups with data-filtering,
  unexpected multiple members, unresolved references, or unknown fields are
  retained as source evidence. Every definition/group has an inventory record.
- IKE crypto profiles, IPsec crypto profiles, IKE gateways, and IPsec tunnels
  retain negotiation, selector, monitoring, and unknown settings as sanitized
  source-only VPN inventory. Both crypto-profile families are read from
  `network/ike/crypto-profiles` first, with the legacy `network/ipsec` IPsec
  profile path retained as a fallback. IKE version-specific crypto profiles
  and DPD, protocol-common NAT traversal/passive/fragmentation settings,
  named Phase-1 gateway references, tunnel monitoring, and proxy IDs remain
  source evidence. Secrets are represented only as presence or redacted
  evidence; PSK contents are never serialized.
- Panorama device-group parent relationships and managed VSYS membership are
  vendor-specific topology evidence. Parent inheritance is applied before
  final reference resolution; child shadowing wins and scoped canonical names
  remain unique. Managed VSYS identity is qualified by device serial, so two
  firewalls using `vsys1` cannot resolve each other's local objects or rules.
- Effective Panorama Security-policy ordering is derived without overwriting
  source provenance. Shared and ancestor pre-rules evaluate highest-to-lowest,
  local firewall rules follow, device-group post-rules evaluate
  lowest-to-highest, shared post-rules follow, and effective default rules are
  last. Derived layer, rank, scope chain, effective index, per-context ordering,
  and an explicit completeness flag are retained as source evidence. Missing
  parents or cycles make the derived order incomplete.

## Predefined App-ID references

Policy application references use a conservative classifier. Configured custom
applications, application groups, and application filters resolve through the
existing scoped hierarchy before predefined-name recognition, so local custom
evidence wins a same-name collision. A maintained high-confidence catalog of
common built-in names is classified as `PREDEFINED_REFERENCE`; unknown or
misspelled names remain unresolved. The classifier is not limited to the
original five-name set and never fabricates App-ID ports, category, risk,
technology, dependencies, or content-version metadata.

## Explicitly unsupported inventory

Unknown future families below `rulebase`, `pre-rulebase`, and `post-rulebase`
remain `UNSUPPORTED` per rule. Dynamic-routing protocols other than BGP, OSPF,
OSPFv3, and RIP, unknown interface families, unhandled network subtrees, and
other PAN-OS domains without dedicated handlers remain explicit unsupported or
residual inventory. Recognized-but-unimplemented areas include dynamic-routing
families such as IS-IS and multicast routing, advanced routing profiles not
reachable through the implemented protocol structures, VPN semantics beyond
source inventory, HA/system semantics, effective template inheritance, and
future policy families. Panorama missing-parent and cycle errors are reported
as review findings and are not installed into resolver traversal.

Portable target generation must consume canonical IR only and must withhold
objects whose migration status, review reasons, or extraction findings make
generation unsafe.

## PAN-OS management-access extraction (Phases 8-10)

### Residual and unknown-field protection

Dedicated handlers own unknown descendants inside source structures they
recognize; generic residual handling owns only unhandled sibling branches.
Handled management structures are not duplicated as residuals, while unknown
source data remains preserved for review without inferred canonical semantics.
Direct children of `deviceconfig/system` now have a residual safety net;
`hostname` and Phase 10-owned children are excluded because they already have
dedicated ownership. These residual records are source-only and
`UNSUPPORTED`.

PAN-OS does not expose a FortiGate-style `local-in-policy` rulebase. Traffic
terminating on the firewall is controlled through management-plane
configuration, principally:

- Interface Management Profiles at
  `network/profiles/interface-management-profile/entry[@name='...']`.
- Interface assignments at
  `network/interface/.../interface-management-profile`, which remain owned by
  interface extraction and are not correlated with profile definitions yet.
- Dedicated management-interface and device/system controls at
  `deviceconfig/system/ip-address`, `netmask`, `default-gateway`,
  `type`, `permitted-ip`, `service`, and the supported IPv6 controls.

The source-only extraction domain is `management_access`. Its stable inventory
kinds are `interface-management-profile`, `system-management-access`, and
`management-interface-access`. Valid records use `EXTRACT_ONLY`, preserve
scope, source paths, raw source subtrees, and Phase 8 unknown-field evidence.
Interface Management Profile definitions are extracted as source-only records.
Supported service fields are `http`, `https`, `ping`, `response-pages`,
`userid-service`, `userid-syslog-listener-ssl`,
`userid-syslog-listener-udp`, `ssh`, `telnet`, `snmp`, and `http-ocsp`.
Configured values use strict PAN-OS `yes`/`no` parsing, while explicit field
presence is retained separately from omission. Permitted IPv4 and IPv6 hosts
and networks are retained as ordered source literals; absent permitted-IP
entries remain an empty list and do not become `any`, `0.0.0.0/0`, or `::/0`.
The complete profile and permitted-IP subtrees, malformed values, and unknown
fields are retained for review. Valid definitions use `EXTRACT_ONLY`; malformed
known values use `PARSE_ERROR`. Interface Management Profile extraction remains
the Phase 9 behavior and is kept separate from the detailed Phase 10 system
records.

Phase 10 extracts dedicated MGT/system controls as source-only
`management-interface-access` or `system-management-access` records while
preserving the existing source paths and one-record-per-system-child topology.
System service fields are PAN-OS `disable-*` controls: `yes` means disabled and
`no` means not disabled by that explicit control. The direct disable map keeps
the original field names, while the derived enabled map uses `http`, `https`,
`telnet`, `ssh`, `ping` (from `disable-icmp`), `snmp`, `userid-service`,
`userid-syslog-listener-ssl`, `userid-syslog-listener-udp`, and `http-ocsp`.
Derived values are emitted only for explicitly configured valid fields; omitted
controls remain omitted. The full service subtree, presence, unknown fields,
and malformed literals are preserved.

System permitted IPs are inline IPv4/IPv6 host or network literals. Their source
order and optional descriptions are preserved separately from profile permitted
IPs. An empty container remains an empty list and never becomes `any`,
`0.0.0.0/0`, or `::/0`. Invalid values and missing entry names are retained and
classified as `PARSE_ERROR`; unknown optional fields remain source-preserved with
manual review. MGT IPv4 address, netmask, gateway, IPv6 address, gateway,
enable flag, and choice-based address/gateway types are retained without
canonicalization. A management gateway never creates an `IRRoute`.

The following system mappings are implemented:

| Source path | Structured source evidence | Canonical projection |
| --- | --- | --- |
| `deviceconfig/system/service/disable-http` | `pan_system_management_service_disable["disable-http"]`; derived `pan_system_management_services["http"]` | none |
| `deviceconfig/system/service/disable-https` | `pan_system_management_service_disable["disable-https"]`; derived `pan_system_management_services["https"]` | none |
| `deviceconfig/system/service/disable-telnet` | `pan_system_management_service_disable["disable-telnet"]`; derived `pan_system_management_services["telnet"]` | none |
| `deviceconfig/system/service/disable-ssh` | `pan_system_management_service_disable["disable-ssh"]`; derived `pan_system_management_services["ssh"]` | none |
| `deviceconfig/system/service/disable-icmp` | `pan_system_management_service_disable["disable-icmp"]`; derived `pan_system_management_services["ping"]` | none |
| `deviceconfig/system/service/disable-snmp` | `pan_system_management_service_disable["disable-snmp"]`; derived `pan_system_management_services["snmp"]` | none |
| `deviceconfig/system/service/disable-userid-service` | direct disable map; derived `userid-service` | none |
| `deviceconfig/system/service/disable-userid-syslog-listener-ssl` | direct disable map; derived `userid-syslog-listener-ssl` | none |
| `deviceconfig/system/service/disable-userid-syslog-listener-udp` | direct disable map; derived `userid-syslog-listener-udp` | none |
| `deviceconfig/system/service/disable-http-ocsp` | direct disable map; derived `http-ocsp` | none |
| `deviceconfig/system/permitted-ip/entry@name` | `pan_system_management_permitted_ips` | none |
| `deviceconfig/system/permitted-ip/entry/description` | `pan_system_management_permitted_ip_details` | none |
| `deviceconfig/system/ip-address`, `netmask`, `default-gateway` | dedicated `pan_system_management_*` fields | none; no `IRRoute` |
| `deviceconfig/system/type/<choice>` | `pan_system_management_type` (`static` or `dhcp-client`) | none |
| `deviceconfig/system/ipv6-address`, `ipv6-default-gateway` | dedicated IPv6 source fields | none; no `IRRoute` |
| `deviceconfig/system/ipv6-enable` | `pan_system_management_ipv6_enabled` | none |
| `deviceconfig/system/ipv6-type/<choice>` | `pan_system_management_ipv6_type` | none |
| `deviceconfig/system/ipv6-gw-type/<choice>` | `pan_system_management_ipv6_gateway_type` | none |

Malformed known syntax is `PARSE_ERROR`; unknown optional semantics remain
`EXTRACT_ONLY` with manual review. No fake Local-In Policy is created, and no
management record creates canonical policy, service, route, NAT, or PBF
objects. Interface/profile/effective-access correlation is implemented in
Phase 11.

### Phase 11: Interface Management Profile correlation

After network interface extraction completes for each device scope, the parser
correlates canonical `IRInterface` objects with same-scope
`interface-management-profile` inventory records. A unique non-`PARSE_ERROR`
profile projects only explicitly enabled service fields into the existing
`IRInterface.management_access` list, in stable service-catalog order. Omitted
fields remain omitted and are recorded through
`pan_effective_management_service_state_complete`; incomplete service state,
unknown profile semantics, and permitted source IP restrictions produce stable
manual-review reasons rather than being guessed or discarded.

Correlation evidence is mirrored to the matching `interfaces` inventory row,
including resolution status, profile provenance, effective service maps,
permitted IPs, and derived restricted/unrestricted source state. Unresolved,
ambiguous, and malformed profile references never populate canonical management
access. Profile records receive ordered assignment backreferences, and unused
valid profiles remain valid source-only records.

Dedicated `deviceconfig/system` MGT controls remain separate source-only
evidence. Phase 11 does not create a synthetic MGT interface, Local-In policy,
canonical policy/service/route/NAT object, or permitted-IP address object.

Management access is not a Security Policy, PBF rule, NAT rule, static route,
or canonical `IRPolicy`/`IRRoute` object. Phase 11 correlates interface
identity/address, the existing interface profile reference, and the profile
definition within the current device scope. Panorama templates remain
device/template-scoped source contexts; template-stack inheritance is not
resolved.

The hierarchy and semantics are based on Palo Alto Networks documentation for
[Interface Management Profiles](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/use-interface-management-profiles-to-restrict-access),
[Device > Setup > Interfaces](https://docs.paloaltonetworks.com/ngfw/help/10-2/device/device-setup-interfaces),
and the [PAN-OS CLI command hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy).

### Phase 13: conformance matrix

The final extraction regression matrix is implemented by
`tests/test_palo_alto_phase13_conformance.py` using
`tests/fixtures/palo_alto/phase13_conformance.xml` through the registered
`palo_alto` parser. It covers Security Policy rule-type/QoS, PBF, Interface
Management Profile correlation, dedicated MGT controls, static routing, NAT,
direct system residuals, source accounting, terminal ownership, and migration
safety aggregation.

The fixture intentionally includes one unsupported future system field, so
manual review is required and migration is incomplete by design. PBF and
dedicated management remain source-only; no new canonical model is introduced.
Malformed and parser-error matrices remain in the focused Phase 1–12 test
modules.
