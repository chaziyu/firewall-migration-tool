# PAN-OS migration command verification

Reviewed 2026-10-15 against the repository's selected PAN-OS reference and the
[official PAN-OS 11.1 configuration hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy).
The [CLI Jump Start](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/cli-jump-start)
confirms explicit `vsys` prefixes for scoped configuration.

## Scope

- Syntax baseline: PAN-OS 11.1, standalone firewall, explicit VSYS ownership,
  legacy virtual routers, IPv4 only for executable interface conversion.
- Documentation verification is not device validation. No hardware or PAN-OS
  runtime was used. Other releases remain unverified; the selected reference's
  “11.1 & later” label is not a compatibility guarantee.
- No version switch is added: the current emitted subset has no verified
  release-dependent branch. Panorama templates and Advanced Routing Engine
  logical routers are outside this renderer's scope.
- Every rendered report records this distinction in `cli_compatibility`.

## Audited families

- Ethernet: device `network interface ethernet`, `layer3`, `ip`, and
  `layer3 units` with explicit tag and IP. VLAN IDs remain distinct from unit IDs.
- Loopback: device `network interface loopback units`; no Ethernet `layer3`
  segment. IPv4 masks must be /32, per the official
  [Layer 3 interface instructions](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/layer-3-interfaces/configure-layer-3-interfaces).
- Aggregate: device `network interface aggregate-ethernet`, Layer 3 and units;
  Ethernet `aggregate-group` members; explicit Layer 3 LACP enable/mode.
  Member hardware capacity, matching bandwidth, and peer settings need review.
- Ownership: VSYS `import network interface`; device `network virtual-router`
  membership. Interface creation precedes imports, zones and router membership.
- Zones: VSYS `zone ... network layer3` membership.
- Addresses: VSYS `address` ip-netmask, ip-range and fqdn; static address groups.
- Services: VSYS `service ... protocol tcp|udp` port/source-port; service groups.
- Schedules: recurring weekly/daily and non-recurring ranges.
- Security: VSYS rulebase match lists, application, schedule, action, negate,
  disabled, description and explicit logging leaves. Preserve source rule order.
- NAT: IPv4 rulebase match lists, service, to-interface, dynamic IP/port source
  translation and destination translation leaves. Preserve source NAT order.
- Routes: device legacy virtual-router IPv4 static routes, destination,
  interface, ip-address/discard next hop and admin-dist. FortiGate priority is
  not translated into a PAN-OS metric.
- DHCP: device interface server, explicit lease, pools, gateway, mask and DNS.

Regression tests assert exact ordered commands. Signed artifact and web tests
check approval, dependency exclusion and identical preview/download/bundle
content. Candidate validation and explicit commit remain separate operations.
