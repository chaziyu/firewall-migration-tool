# Cisco ASA → IR Mapping

Support describes current parser/extraction normalization. It does not by
itself guarantee target-generator support. ASA names, interfaces, and ACL
references remain scoped where the source configuration requires it.

IR V2 storage uses canonical collections for portable ASA intent. The typed ASA
extension container is available for semantics that are not portable.

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | `object network` | `host`, `subnet`, `range`, `fqdn` | `IRAddress` | address type and value fields | Direct | Full | `parser.py`, `net_utils.py` |
| Address group | `object-group network` | `network-object`, `group-object` | `IRAddressGroup` | `members` | Direct | Full | `parser.py` |
| Service | `object service` | protocol, destination/source port | `IRService`, `IRServicePort` | `ports`, protocol and port fields | Direct | Full | `service_parser.py` |
| Service group | `object-group service` | `port-object`, `group-object` | `IRServiceGroup` | `members` | Semantic | Full | `service_parser.py` |
| Interface | `interface` | name, `nameif`, IP address, shutdown | `IRInterface` | `name`, `ip`, status and interface fields | Semantic | Full | `parser.py` |
| Zone | interface security context | `nameif` and interface membership | `IRZone` | `name`, `interfaces` | Semantic | Full | `parser.py` |
| Security policy | `access-list` | source/destination, service, protocol, action | `IRPolicy` | `source`, `destination`, `service`, `action` | Semantic | Full | `acl_parser.py`, `parser.py` |
| ACL object references | `access-list` | object and object-group names | `IRPolicy` | address/service references and unresolved-reference fields | Semantic | Full | `reference_validation.py` |
| NAT | `nat` | source/destination, interface, service, translated value | `IRNATRule` | match and translation fields | Semantic | Partial | `parser.py`, `extraction.py` |
| Routing | `route` | interface, network, gateway, metric | `IRRoute` | `interface`, `destination`, `next_hop`, metric | Direct | Full | `parser.py` |
| VPN evidence | `crypto`, `tunnel-group`, `ipsec` | IKE/IPsec and peer settings | `—` | `—` | Evidence | Extract-only | `parser.py`, `extraction.py` |
| Source accounting | unparsed or unsupported commands | command and source line | extraction result | residual and parse-error accounting | Evidence | Extract-only | `section_scanner.py`, `extraction.py` |
