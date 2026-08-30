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

- Addresses: `ip-netmask`, `ip-range`, `ip-wildcard`, and `fqdn`, with scope,
  tags, descriptions, and collision-safe reference resolution.
- Address and service groups: static membership and supported dynamic address
  filters, with unresolved, ambiguous, unsafe, and cyclic membership retained.
- TCP/UDP services, schedules whose windows fit the current canonical model,
  zones, safely representable Layer 3 interface identity, Security rules,
  PAN-OS NAT rules, and IPv4/IPv6 static routes.
- Security and NAT rules preserve scope, pre/local/post rulebase position,
  source index, stable source-rule ID, and exact source path.
- NAT match parsing uses direct XML paths. Scalar service, `to-interface`,
  `nat-type`, disabled state, description, tags, group-tag, active-active
  binding, destination translated port, and source/destination translation
  modes are retained.
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
  Omitted metric remains absent; a missing destination is a parse error.
- Default Security rules deliberately remain outside canonical `IRPolicy`.
  Their implicit matching semantics cannot be represented without inventing
  ordinary `from`, `to`, source, destination, application, or service fields.

## Partially normalized areas

- Security-rule source semantics without complete portable fields: App-ID
  predefined references, source user, HIP, category, negation, SaaS selectors,
  inspection options, direct profiles, non-basic action variants, unknown
  fields, and unresolved references.
- NAT interface-address, fallback, bi-directional static NAT, dynamic
  destination distribution, DNS rewrite, `nat-type`, `to-interface`, active-
  active binding, unknown fields, and unresolved references.
- Layer 3 interfaces with multiple IPv4 addresses, IPv6 entry attributes,
  DHCP client, PPPoE, link-state `auto`, MTU/speed/duplex/LLDP, or unknown
  physical/Layer 3 settings.
- Zones with security-relevant settings, unknown fields, unresolved/conflicting
  interfaces, or multiple effective network types.
- Security profile definitions and profile groups with data-filtering,
  unexpected multiple members, unresolved references, or unknown fields. Every
  definition/group has an inventory record; all members remain in source
  evidence.
- Static routes with FQDN/next-VR next hops, BFD, path monitoring, route-table
  installation settings, or unknown fields.

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
- Decryption, application-override, authentication, PBF, QoS, DoS,
  tunnel-inspect, SD-WAN, and network-packet-broker rules are parsed by
  independent family handlers. Scope, pre/local/post provenance, source index,
  stable source-rule ID, common match/action fields, family-specific subtrees,
  and unknown fields are `EXTRACT_ONLY`; no family is forced into `IRPolicy`.
- VSYS network imports preserve interfaces, virtual routers, logical routers,
  VLANs, virtual wires, unknown import subtypes, and their VSYS association.
- Security profile definitions and profile groups with data-filtering,
  unexpected multiple members, unresolved references, or unknown fields are
  retained as source evidence. Every definition/group has an inventory record.
- IKE crypto profiles, IPsec crypto profiles, IKE gateways, and IPsec tunnels
  retain negotiation, selector, monitoring, and unknown settings as sanitized
  source-only VPN inventory. Secrets are represented only as presence or
  redacted evidence.
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
