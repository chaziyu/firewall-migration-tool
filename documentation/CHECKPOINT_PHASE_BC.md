# Check Point Phase B/C — VS-Aware Gaia Scope and Network Reconciliation

This change extends the existing Check Point R81 extraction architecture without replacing the established Gaia parser.

## Scope identity

`set virtual-system <VSID>` is parser state. The state changes only when another explicit `set virtual-system` command appears.

Gaia interfaces, routes, zones, and source-inventory records carry the virtual-system identifier in source provenance. Objects with the same source name in different VSIDs are not merged.

Management topology is correlated to Gaia interfaces only when the source identity is unambiguous. If multiple Gaia interfaces share a name across VSIDs and Management data has no explicit VSID, the topology evidence is retained and the affected records require review instead of selecting one interface by name.

Gaia `show configuration` remains authoritative for persistent OS addressing and interface state. Management gateway data remains authoritative for Check Point topology, Security Zone, and anti-spoofing relationships. Management IP values are retained as evidence and conflict indicators; they do not silently overwrite Gaia addressing.

## Canonical-boundary behavior

The current canonical DNS and NTP models are root-scoped. VS-specific DNS/domain/NTP commands therefore remain `PARTIALLY_NORMALIZED` source evidence and are not merged into the root canonical DNS/NTP record. Global/default-context DNS and NTP keep the existing canonical behavior.

VS-scoped interfaces remain represented in canonical IR with distinct `source_context` values, but are marked for review until target generators can preserve equivalent virtual-system scope.

## Ordered Gaia reconciliation

The scoped layer replays list-valued and delete-capable configuration in source order where last-write-wins would lose behavior:

- bonding members and member state;
- bridge members and fail-open membership;
- bonding/bridge setting removal;
- DHCP pools, DNS entries, reservations and delete operations;
- repeated DNS search suffixes;
- multiple NTP servers.

Quoted values are tokenized with `shlex` in the scoped reconciliation path.

## Interface behavior

Portable fields are projected where the current IR has an exact field, including MTU, comments, link speed metadata, duplex metadata and IPv6 autoconfiguration metadata. Platform-specific or behavior-changing values such as monitor mode, MAC override and auto-negotiation remain explicit source attributes and keep the interface review-required.

## Regression coverage

New tests cover:

- VS switching and re-entry;
- duplicate interface/route names in different VSIDs;
- Management/Gaia topology ambiguity and conflict detection;
- bonding and bridge member deletion;
- quoted interface comments;
- DNS family validation and repeated suffixes;
- DHCP repeated/delete state;
- timezone and multiple NTP servers;
- prevention of VS-specific DNS/NTP leakage into root canonical system settings.
