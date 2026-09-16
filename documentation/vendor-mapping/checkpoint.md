# Check Point → IR Mapping

Support describes current parser/extraction normalization for Check Point
management exports and Gaia data. Package, layer, domain, and UID scope must
remain explicit; names alone are not global identities.

IR V2 storage uses canonical collections for portable intent. Check Point
package, layer, domain, assignment, SIC, and management-only details are stored
under `vendor_extensions.checkpoint`; legacy root properties remain compatibility
projections.

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | Management object `host` / `network` | IPv4/IPv6 address or subnet | `IRAddress` | address type, family, and value fields | Direct | Full | `objects.py` |
| Address range | Management object `address-range` | first/last address | `IRAddress` | `ip_range_start`, `ip_range_end` | Direct | Full | `objects.py` |
| Address group | Management object `group` | member UIDs/names | `IRAddressGroup` | `members` and source UID fields | Semantic | Full | `objects.py`, `group_fidelity.py` |
| Service | Management object `service-tcp` / `service-udp` | protocol and port | `IRService`, `IRServicePort` | `ports`, protocol and port fields | Direct | Full | `services.py` |
| Service group | Management object `service-group` | members | `IRServiceGroup` | `members` | Direct | Full | `services.py` |
| Interface | Gaia gateway/interface data | interface, address, topology | `IRInterface` | interface identity, IP, checkpoint context | Semantic | Partial | `gaia.py`, `gateways.py` |
| Zone/context | gateway topology and interface assignments | gateway/domain scope and members | `IRZone` | `name`, `interfaces`, `source_context` | Semantic | Partial | `gateways.py`, `gaia.py` |
| Access policy | Access Control rulebase | source, destination, service, action, track, time | `IRPolicy`, `IRCheckpointAccessRule` | portable match/action plus package/layer/rule identity | Semantic | Partial | `access.py`, `rulebase.py` |
| Policy package | Access policy package | package UID, layers, installation targets | `IRCheckpointPolicyPackage` | `vendor_extensions.checkpoint.checkpoint_policy_packages` | Direct | Full | `extractor.py` |
| Access layer | Access Control layer | layer UID, parent layer/rule, rule order | `IRCheckpointAccessLayer` | `vendor_extensions.checkpoint.checkpoint_access_layers` | Direct | Full | `extractor.py`, `rulebase.py` |
| Domain/global assignment | Multi-Domain / global policy | domain UID, assignment, package mapping | `IRCheckpointDomain`, `IRCheckpointGlobalAssignment` | `vendor_extensions.checkpoint.checkpoint_domains` and `checkpoint_global_assignments` | Semantic | Partial | `extractor.py`, `gaia_scoped.py` |
| NAT | Management NAT rulebase | original/translated source, destination, service | `IRNATRule` | package context, match and translation fields | Semantic | Partial | `nat.py` |
| VPN | VPN community/gateway | members, topology, IKE/IPsec settings | `IRVPNCommunity`, `IRVPNGateway` | gateway membership and VPN settings | Semantic | Partial | `vpn.py` |
| Threat Prevention | Threat Prevention rule/profile | scope, destination, service, profile, action | `IRCheckpointThreatPreventionRule`, `IRCheckpointThreatPreventionProfile` | rule/profile fields and associations | Semantic | Partial | `threat_prevention.py`, `threat_profiles.py` |
| Certificates/SIC | certificates and SIC gateway metadata | certificate identity, fingerprint, SIC state | `IRCertificate`, `IRCheckpointSICMetadata` | certificate/SIC metadata and review fields | Semantic | Partial | `certificates.py`, `extractor.py` |
