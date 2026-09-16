# Palo Alto → IR Mapping

Support describes current parser/extraction normalization. It does not by
itself guarantee target-generator support. Device-group, VSYS, and Panorama
scope must remain part of object identity and source context.

IR V2 storage uses canonical collections for portable intent. PAN-OS scope,
GlobalProtect, operational, SD-WAN, and other nonportable details are stored
under `vendor_extensions.panos`; legacy PAN root properties remain compatibility
projections.

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | `address` | `ip-netmask`, `ip-range`, `fqdn`, `description` | `IRAddress` | `subnet`, range fields, `fqdn`, `description` | Direct | Full | `parser.py` |
| Address group | `address-group` | `static`, `dynamic`, members, filter | `IRAddressGroup` | `members`, `is_dynamic`, `dynamic_filter` | Semantic | Full | `parser.py`, `completeness.py` |
| Service | `service` | protocol, source-port, port | `IRService`, `IRServicePort` | `ports`, protocol and port fields | Direct | Full | `parser.py` |
| Service group | `service-group` | member | `IRServiceGroup` | `members` | Direct | Full | `parser.py` |
| Interface | `network interface` | interface type, address, comment, virtual router | `IRInterface` | `interface_type`, `ip`, `description`, routing context | Semantic | Full | `interfaces.py` |
| Zone | `zone` | network/member, type | `IRZone` | `interfaces`, `zone_type` | Semantic | Full | `parser.py`, `completeness.py` |
| Security policy | `rulebase security rules` | from/to, source/destination, service, action, disabled | `IRPolicy` | zones, address/service references, `action`, `disabled` | Semantic | Full | `parser.py`, `policy_families.py` |
| Security profiles | `profiles` / `profile-group` | profile references and group members | `IRSecurityProfileGroup`, `IRPolicy` | profile references and review fields | Semantic | Partial | `security_profiles.py`, `security_profile_coverage.py` |
| NAT | `rulebase nat rules` | source/destination, service, source/destination translation | `IRNATRule` | match and translation fields | Semantic | Partial | `nat.py`, `policy_nat_coverage.py` |
| PBF | `rulebase pbf rules` | source/destination, application, service, forwarding/monitor | `IRPolicyBasedForwardingRule` | match, next hop, monitor, symmetric return | Semantic | Partial | `pbf.py` |
| Routing | `virtual-router routing-table ip static-route` | destination, interface, next hop, metric | `IRRoute` | destination, interface, next hop, metrics | Direct | Full | `routing.py` |
| VPN | `network ike/ipsec/vpn` | gateways, proposals, selectors, tunnel | `IRVPNTunnel`, `IRVPNPhase2` | tunnel and phase-2 fields | Semantic | Partial | `vpn.py` |
| Certificates | `shared` / device-group certificate entries | certificate identity, issuer, validity, usage | `IRCertificate` | certificate metadata and review fields | Semantic | Partial | `certificates.py` |
| GlobalProtect | `global-protect` | portal, gateway, client and network gateway settings | `IRRemoteAccessVPN` plus typed PAN extensions | portable remote-access VPN summary in `remote_access_vpns`; detailed portal/gateway records in `vendor_extensions.panos` | Semantic | Partial | `globalprotect.py` |
| Scope | `vsys`, device-group, Panorama managed device | scope and device identity | affected IR models | `source_context`, source IDs, provenance | Semantic | Full | `resolver.py`, `parser.py` |
| Source accounting | residual/unmodeled XML nodes | path and raw value evidence | `—` | `—` | Evidence | Extract-only | `residual.py`, `safe_completeness.py` |
