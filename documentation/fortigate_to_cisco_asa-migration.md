# FortiGate to Cisco ASA reviewed export

The pair produces an offline, reviewed Cisco ASA 9.20 configuration for one selected FortiGate VDOM, one security context, and routed firewall mode. It does not connect to or modify an ASA device.

## Supported subset

- IPv4 `ipmask` and `iprange` addresses, static address groups, explicit TCP/UDP destination-port services, and service groups.
- Explicit physical Ethernet interfaces with mapped ASA interface, `nameif`, security level, IPv4 address, and source up/down state.
- Explicit IPv4 static routes with a mapped egress interface.
- Recurring weekly time ranges with a confirmed matching source and target time zone.
- Ordered extended ACL entries for explicit, supported FortiGate policy fields and source ingress interfaces. Rule combinations are expanded into ACEs. Disabled source policies produce inactive ACEs.
- A default-deny ACL entry per planned interface. An `access-group` binding is emitted only after complete destination binding evidence proves the target interface has no existing binding.

Unsupported or unknown source fields block the affected object, route, schedule, policy, or dependent output. A FortiGate destination-interface constraint other than `any` blocks the policy because the ASA ACL plan cannot represent that egress restriction. Unverified logging, reject behavior, identity/inspection features, unsupported services, and policy order without an explicit source ID remain manual.

## NAT and manual work

No ASA NAT commands are enabled. FortiGate policy NAT, VIPs, and VIP groups remain blocked until source/target ordering, identity NAT interactions, real/mapped address behavior, directionality, return routing, and proxy ARP can be proven for the affected case. An ASA syntax example alone does not prove FortiGate equivalence.

Schedules only emit weekly intervals with explicit matching time-zone choices. ASA time ranges use the appliance system clock; this export does not configure or validate the target clock or NTP state.

Hardware fit, interface availability, existing target objects and bindings, routing adjacency, ARP behavior, licensing, and device acceptance require separate review. Destination-aware comparison is not exposed in this browser workflow yet.

## Review and artifacts

The browser and API require current signed approval bound to the source, pair options, selected items, and dependencies. Mapping imports are proposals and do not create approval. Command preview and downloads are served from the same signed artifact bytes. The bundle contains `asa_config.cfg`, the migration report, mapping proposals, the target mapping, and a sanitized FortiGate source workbook.

The ASA artifact is not accepted by PAN-OS deployment transport. There is no ASA live execution, configuration commit, `write memory`, or automatic access-group replacement.

## Cisco references checked

- [ASA 9.20 basic interface configuration](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/interface-basic.html)
- [ASA 9.20 access rules and ACL binding](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html)
- [ASA 9.20 NAT behavior and ordering](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html)
- [ASA 9.20 firewall CLI guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config.pdf), including time-range commands.
