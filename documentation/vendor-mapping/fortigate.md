# FortiGate → IR Mapping

Support describes current parser/extraction normalization. It does not by
itself guarantee target-generator support. Complex or vendor-specific values
remain in source evidence and may require review.

IR V2 storage uses canonical collections for portable intent. FortiOS-only
source rules, SD-WAN details, and other
nonportable semantics are stored under `vendor_extensions.fortios`; legacy
Python root properties remain compatibility projections.

Standalone FortiGate IPS sensor inventory, Internet Service inventory, and
global web-proxy settings are outside the extraction boundary. Their source
sections remain accounted for as `IGNORED_BY_POLICY`. References to those
objects from policies, routing, NAT, local-in, multicast, or SD-WAN rules are
preserved as source references and are resolved as external dependencies.

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | `firewall address` / `firewall address6` | `subnet` | `IRAddress` | `subnet` | Direct | Full | `transformer.py` |
| Address | `firewall address` / `firewall address6` | `start-ip`, `end-ip` | `IRAddress` | `ip_range_start`, `ip_range_end` | Direct | Full | `transformer.py` |
| Address | `firewall address` / `firewall address6` | `fqdn`, `wildcard-fqdn`, `type` | `IRAddress` | `fqdn`, `dynamic_filter`, `type` | Semantic | Partial | `transformer.py` |
| Address group | `firewall addrgrp` / `firewall addrgrp6` | `member`, `exclude-member` | `IRAddressGroup` | `members`, `exclude_members` | Direct | Full | `transformer.py` |
| Interface | `system interface` | `ip`, `allowaccess`, VLAN/aggregate fields | `IRInterface` | `ip`, `management_access`, `interface_type`, `members` | Semantic | Full | `transformer.py` |
| Zone | `system zone` | `interface`, `intrazone`, `tagging` | `IRZone` | `interfaces`, source intrazone/tag fields | Semantic | Full | `transformer.py` |
| Service | `firewall service custom` / `service group` | protocol and port-range fields, `member` | `IRService`, `IRServiceGroup` | `ports`, `members` | Semantic | Full | `parser.py`, `model.py` |
| Schedule | `firewall schedule recurring` / `onetime` / `group` | time and member fields | `IRSchedule`, `IRScheduleGroup` | canonical time boundaries and members | Semantic | Full | `transformer.py`, `extractor.py` |
| Security policy | `firewall policy` | `srcintf`, `dstintf`, `srcaddr`, `dstaddr`, `service`, `action`, `schedule` | `IRPolicy` | zones, `source`, `destination`, `service`, `action`, `schedule` | Semantic | Full | `transformer.py` |
| Security profiles | `firewall policy` | `profile-group`, `av-profile`, `webfilter-profile`, `ips-sensor`, `application-list`, `ssl-ssh-profile` | `IRPolicy`, `IRSecurityProfileGroup` | profile references and status fields | Semantic | Partial | `transformer.py`, `builders/security_profiles.py` |
| Users & Auth | `user local`, `user group`, `user ldap`, `user radius` | auth servers, groups, status | `IRUserGroup`, `IRUserLDAP`, `IRUserRADIUS`, etc. | unified user groups and auth server configs | Semantic | Full | `transformer.py`, `extractor.py` |
| Destination NAT | `firewall vip` / `firewall vip6` | `extip`, `mappedip`, `extport`, `mappedport`, `portforward` | `IRVirtualIP` | external/mapped addresses and ports | Semantic | Full | `firewall_vip_746.py`, `transformer.py` |
| NAT | `firewall ippool` / `firewall ippool6` | address range, port range, overload settings | `IRIPPool` | pool addresses, ranges, ports, runtime settings | Semantic | Partial | `firewall_ip_746.py`, `transformer.py` |
| Central NAT | `firewall central-snat-map` | source/destination/interface/service and translation fields | `IRNATRule` | canonical `nat_rules` with `source_origin=central-snat-map`; FortiOS-only details under `vendor_extensions.fortios` | Semantic | Partial | `transformer.py`, `extractor.py` |
| Routing | `router static` / `router static6` | destination, gateway, device, distance, priority | `IRRoute` | `destination`, `next_hop`, `interface`, metrics | Semantic | Full | `transformer.py` |
| Policy routing | `router policy` / `router policy6` | source/destination/interface/gateway criteria | `IRFortiGatePolicyRoute` | `vendor_extensions.fortios.policy_routes` match and forwarding fields | Semantic | Partial | `transformer.py` |
| VPN | `vpn ipsec phase1*` / `phase2*` | peer, interface, proposals, `phase1name`, selectors | `IRVPNTunnel`, `IRVPNPhase2` | tunnel, phase-2, and unresolved-reference fields | Semantic | Partial | `extractor.py`, `transformer.py` |
| SSL VPN | `vpn ssl settings`, `vpn ssl web portal` | ssl vpn pools, portals, rules | (FortiOS Extensions) | `vendor_extensions.fortios` | Semantic | Partial | `extractor.py`, `transformer.py` |
| SD-WAN & Traffic | `system sdwan`, `firewall shaper *` | sdwan members/rules, shaping profiles | (FortiOS Extensions) | `vendor_extensions.fortios` | Semantic | Partial | `extractor.py`, `transformer.py` |
| System & Core | `system global`, `system dns`, `vpn certificate *` | hostname, dns servers, certificates | (FortiOS Extensions) | `vendor_extensions.fortios` and system metadata | Evidence | Extract-only | `extractor.py` |
| Source accounting | unsupported or source-only sections | raw section and parse/residual data | `IRAuditEntry`, `IRFortiGateSourceRule` | status, review, and source evidence | Evidence | Extract-only | `extractor.py` |
