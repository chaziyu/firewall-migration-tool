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

- Addresses: `ip-netmask`, `ip-range`, `ip-wildcard`, and `fqdn`, with scope,
  tags, descriptions, and collision-safe reference resolution.
- Address and service groups: static membership and supported dynamic address
  filters, with unresolved, ambiguous, unsafe, and cyclic membership retained.
- TCP/UDP services, schedules whose windows fit the current canonical model,
  zones, Layer 3 interfaces, Security rules, PAN-OS NAT rules, and IPv4/IPv6
  static routes.
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
- Static routes are discovered only from the device `network/virtual-router`
  hierarchy. Virtual-router identity, address family, explicit metric and
  administrative distance, interface, IP/discard/FQDN/next-VR next hop, BFD,
  path monitor, route-table installation, and unknown fields are retained.
  Omitted metric remains absent.

## Partially normalized areas

- Security-rule source semantics without complete portable fields: App-ID
  predefined references, source user, HIP, category, negation, SaaS selectors,
  inspection options, direct profiles, non-basic action variants, unknown
  fields, and unresolved references.
- NAT interface-address, fallback, bi-directional static NAT, dynamic
  destination distribution, DNS rewrite, `nat-type`, `to-interface`, active-
  active binding, unknown fields, and unresolved references.
- Interfaces with multiple IPv4 addresses, IPv6 entry attributes, DHCP client,
  PPPoE, link-state `auto`, or unknown physical/Layer 3 settings.
- Zones with security-relevant settings, unknown fields, unresolved/conflicting
  interfaces, or multiple effective network types.
- Security profile groups with data-filtering, unexpected multiple members, or
  unknown fields. Every group has one inventory record; all members remain in
  source evidence.
- Static routes with FQDN/next-VR next hops, BFD, path monitoring, route-table
  installation settings, or unknown fields.

## Extract-only and vendor-specific inventory

- Custom applications, application groups, application filters, and tags are
  conservative source inventory; filters are not expanded against an absent
  dynamic App-ID content database.
- Default Security rules retain name, override presence, action, logging,
  description, tags/group-tag, profile-setting, option and ICMP-unreachable
  evidence without fabricating ordinary rule match fields.
- VSYS network imports preserve interfaces, virtual routers, logical routers,
  VLANs, virtual wires, unknown import subtypes, and their VSYS association.
- Panorama device-group parent relationships and managed VSYS membership are
  vendor-specific topology evidence. Parent inheritance is applied before
  final reference resolution; child shadowing wins and scoped canonical names
  remain unique.

## Explicitly unsupported inventory

Unhandled families below `rulebase`, `pre-rulebase`, and `post-rulebase` are
recorded per family/rule, including application-override, decryption,
authentication, tunnel-inspection, QoS, PBF, SD-WAN, DoS,
network-packet-broker, and future unknown families. Unhandled network subtrees
and interface modes are also visible rather than suppressed by their parent
containers. Panorama missing-parent and cycle errors are reported as review
findings and are not installed into resolver traversal.

Portable target generation must consume canonical IR only and must withhold
objects whose migration status, review reasons, or extraction findings make
generation unsafe.
