# Cisco FTD → IR Mapping

Support describes current parser/extraction normalization for FDM and FMC
REST bundles. It does not by itself guarantee target-generator support.

IR V2 storage uses canonical collections for portable FTD intent. The typed FTD
extension container is available for semantics that are not portable.

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | FDM/FMC network objects | host, network, range, FQDN value | `IRAddress` | address type and value fields | Direct | Full | `fdm_bundle.py`, `fmc_bundle.py` |
| Address group | FDM/FMC network groups | member objects and nested groups | `IRAddressGroup` | `members` | Direct | Full | `fdm_bundle.py`, `fmc_bundle.py` |
| Service | FDM/FMC port objects | protocol and port/range | `IRService`, `IRServicePort` | `ports`, protocol and port fields | Direct | Full | `fdm_bundle.py`, `fmc_bundle.py` |
| Service group | FDM/FMC port groups | member objects | `IRServiceGroup` | `members` | Direct | Full | `fdm_bundle.py`, `fmc_bundle.py` |
| Interface | FDM/FMC interfaces | name, address, mode, zone membership | `IRInterface` | interface identity, IP, type and context | Semantic | Full | `parser.py`, `fdm_bundle.py`, `fmc_bundle.py` |
| Zone | FDM/FMC security zones | zone name and interface members | `IRZone` | `name`, `interfaces` | Direct | Full | `fdm_bundle.py`, `fmc_bundle.py` |
| Security policy | FDM/FMC access rules | source/destination, service, action, interface/zone | `IRPolicy` | match references and `action` | Semantic | Full | `fdm_bundle.py`, `fmc_bundle.py` |
| NAT | FDM/FMC NAT rules | original/translated source and destination, interfaces | `IRNATRule` | match and translation fields | Semantic | Partial | `fdm_bundle.py`, `fmc_bundle.py` |
| Routing | FDM/FMC static routes | destination, gateway, interface, metric | `IRRoute` | destination, next hop, interface, metrics | Direct | Full | `parser.py`, `fdm_bundle.py`, `fmc_bundle.py` |
| VPN | FDM/FMC VPN resources | peers, proposals, protected networks | source evidence or VPN IR | `IRVPNTunnel` / phase-2 fields where normalized | Semantic | Partial | `fdm_bundle.py`, `fmc_bundle.py` |
| Certificate | FDM/FMC certificate resources | identity, trust/usage, material presence | `IRCertificate` | certificate metadata and presence flags | Semantic | Partial | `fdm_bundle.py`, `fmc_bundle.py` |
| Source accounting | unsupported REST resources | endpoint, object ID, raw attributes | `—` | `—` | Evidence | Extract-only | `extractor.py`, `coverage.py` |
