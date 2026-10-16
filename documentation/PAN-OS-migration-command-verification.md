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

## Limited VPN subset

- Only standalone, non-secret IKE and ESP IPsec crypto profiles are executable.
  Each profile requires a separate signed configuration approval.
- Input must be interface-based Phase 1/Phase 2. Policy-based namespaces remain
  recommendation-only. Phase 2 must reference Phase 1 in the same VDOM.
- Accept one explicit `aes128-sha256` or `aes256-sha256` proposal. These map to
  AES-CBC and SHA256. Multiple proposals stay manual to avoid creating algorithm
  combinations absent from the source.
- Require one explicit DH group in 14, 15, 16, 19, 20 or 21. Explicit disabled
  Phase 2 PFS maps to `no-pfs`. Missing PFS never implies disabled.
- Require explicit lifetime seconds from 180 through 65535. Byte lifetimes,
  unsupported proposals, preserved unknown settings and invalid names block output.
- Device-scoped names include source VDOM; collisions block all affected profiles.
  Existing target profiles need manual reuse review.
- Gateway peer identities, selectors, Phase 1/Phase 2 relationships and credentials
  remain visible in recommendations. No IKE gateway, tunnel, authentication,
  certificate or PSK command is emitted. Tunnel interfaces and dependent traffic
  remain blocked. Exporting profiles is always a partial VPN migration.

Full tunnel conversion needs a separately reviewed credential/reference contract.
Sanitized input intentionally cannot supply usable authentication material.

Regression tests assert exact ordered commands. Signed artifact and web tests
check approval, dependency exclusion and identical preview/download/bundle
content. Candidate validation and explicit commit remain separate operations.
