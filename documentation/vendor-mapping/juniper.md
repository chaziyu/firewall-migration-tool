# Juniper SRX → IR Mapping

Support describes current parser/extraction normalization for Junos hierarchy
configuration. Logical-system and zone scope must remain part of source
context; unresolved references are retained for review.

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | `security address-book ... address` | `ip-prefix`, `dns-name`, `wildcard-address` | `IRAddress` | address type and value fields | Semantic | Full | `handlers/address_book.py` |
| Address group | `security address-book ... address-set` | `address`, `address-set` members | `IRAddressGroup` | `members`, source context | Direct | Full | `handlers/address_book.py` |
| Service/application | `applications application` | protocol, source/destination port, timeout | `IRService`, `IRServicePort` | `ports`, protocol, timeout fields | Semantic | Full | `handlers/applications.py`, `transformer.py` |
| Application set | `applications application-set` | application members | `IRApplicationGroup` | application group members | Semantic | Partial | `handlers/applications.py` |
| Interface | `interfaces` | unit, family address, VLAN/parent, disable | `IRInterface` | identity, address, type, parent, status | Semantic | Full | `handlers/interfaces.py`, `transformer.py` |
| Zone | `security zones security-zone` | interface members and host-inbound settings | `IRZone` | `name`, `interfaces`, source settings | Semantic | Full | `handlers/zones.py` |
| Security policy | `security policies` | from-zone/to-zone, match, then action | `IRPolicy` | zones, source/destination/service, action | Semantic | Full | `handlers/policies.py`, `transformer.py` |
| Source NAT | `security nat source` | rule-set context, match, pool/interface translation | `IRNATRule` | source match and source translation fields | Semantic | Partial | `handlers/nat.py`, `transformer.py` |
| Destination/static NAT | `security nat destination` / `static` | match and translated address | `IRNATRule` | destination match and translation fields | Semantic | Partial | `handlers/nat.py`, `transformer.py` |
| Static routing | `routing-options static route` | destination, next hop, interface, preference | `IRRoute` | destination, next hop, interface, metrics | Direct | Full | `handlers/routing.py`, `transformer.py` |
| Firewall filter | `firewall family ... filter` | term, from criteria, then action | `IRFirewallFilter` | filter terms and attachments | Semantic | Partial | `handlers/firewall_filters.py` |
| VPN | `security ike`, `security ipsec`, `security ipsec-vpn` | proposals, policies, gateways, tunnel | `IRVPNTunnel`, `IRVPNPhase2` | tunnel and phase-2 fields | Semantic | Partial | `handlers/vpn.py`, `transformer.py` |
| PKI | `security pki` | certificate identity and usage | `IRCertificate` | certificate metadata and references | Semantic | Partial | `handlers/pki.py`, `transformer.py` |
| Source accounting | unconsumed hierarchy commands | command path and candidate values | `—` | `—` | Evidence | Extract-only | `extraction.py`, `provenance.py` |
