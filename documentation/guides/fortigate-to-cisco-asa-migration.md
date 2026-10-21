# FortiGate to Cisco ASA reviewed export

The pair produces an offline, reviewed Cisco ASA 9.20 configuration for one selected FortiGate VDOM, one security context, and routed firewall mode. It does not connect to or modify an ASA device.

## Supported subset

- IPv4 `ipmask` and `iprange` addresses, static address groups, explicit TCP/UDP destination-port services, and service groups.
- Explicit physical Ethernet interfaces with mapped ASA interface, `nameif`, security level, IPv4 address, and source up/down state.
- ASAv VLAN subinterfaces with explicit platform/capacity confirmation, a mapped physical parent, unique tag and target interface, explicit IPv4 address and source state. A child's approval includes its parent. Existing target tags block creation.
- Explicit IPv4 static routes with a mapped egress interface.
- Recurring weekly time ranges with a confirmed matching source and target time zone.
- Ordered extended ACL entries for explicit, supported FortiGate policy fields and source ingress interfaces. Rule combinations are expanded into ACEs. Disabled source policies produce inactive ACEs.
- A default-deny ACL entry per planned interface. An `access-group` binding is emitted only after complete destination binding evidence proves the target interface has no existing binding.

Unsupported or unknown source fields block the affected object, route, schedule, policy, or dependent output. A FortiGate destination-interface constraint other than `any` blocks the policy because the ASA ACL plan cannot represent that egress restriction. Unverified logging, reject behavior, identity/inspection features, unsupported services, and policy order without an explicit source ID remain manual.

## NAT and manual work

A constrained static source NAT case is enabled: one active HTTPS policy from one IPv4 host to a distinct IPv4 host, destination interface `any`, and a one-to-one pool containing one translated IPv4 address. Source fixed-port and port-preservation controls must be explicitly enabled, pool proxy ARP explicitly disabled, and routed return traffic explicitly confirmed. Central SNAT, VIPs and additional policies disqualify this case.

It requires complete empty destination NAT, access-rule and ACL-binding evidence, complete object evidence, and full interface mappings. The export uses `no-proxy-arp`. NAT, its mapped object, policy and default-deny bindings on every ingress interface form one atomic approval group. Reverse initiation is denied by those ACLs. Conflicts block the entire group. PAT, other pool allocation, DNAT/VIPs and uncertain ordering remain manual.

Schedules only emit weekly intervals with explicit matching time-zone choices. ASA time ranges use the appliance system clock; this export does not configure or validate the target clock or NTP state.

Optional browser destination uploads compare native ASA evidence with explicit context, version, mode and complete-family declarations. Exact address objects can be reused when their native command evidence matches without extra behavior. Destination text and metadata are bound to approval. Hardware fit, interface availability, routing adjacency, ARP behavior, licensing and device acceptance require separate review.

## Review and artifacts

The browser and API require current signed approval bound to the source, pair options, selected items, and dependencies. Mapping imports are proposals and do not create approval. Command preview and downloads are served from the same signed artifact bytes. The bundle contains `asa_config.cfg`, the migration report, mapping proposals, the target mapping, and a sanitized FortiGate source workbook.

The ASA artifact is not accepted by PAN-OS deployment transport. There is no ASA live execution, configuration commit, `write memory`, or automatic access-group replacement.

Reviews and artifact reports include scoped source coverage. Unknown source records remain manual work; rendered commands do not imply complete migration. See the [support matrix](../migration-support-matrix.md).

## Cisco references checked

- [ASA 9.20 basic interface configuration](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/interface-basic.html)
- [ASA 9.20 access rules and ACL binding](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html)
- [ASA 9.20 NAT behavior and ordering](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html)
- [ASA 9.20 firewall CLI guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config.pdf), including time-range commands.
