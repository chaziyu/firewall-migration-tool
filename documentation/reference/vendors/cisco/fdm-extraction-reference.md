# Cisco Secure Firewall / FDM REST Extraction Reference

## Scope

FDM-managed FTD is accepted only through the explicit offline bundle format
`cisco-fdm-rest-export-v1`. FDM bundles are parsed by the dedicated
`CiscoFDMBundleParser`; they are not treated as FMC bundles or ASA/LINA text.

## Bundle contract

The root object contains:

- `format`: exactly `cisco-fdm-rest-export-v1`
- `source`: `fdm-rest-api`
- `domain`: optional `id` and `name`
- `objects`: `hosts`, `networks`, `ranges`, `network_groups`, `services`,
  `service_groups`, `interfaces`, and `zones`
- `nat_rules`: ordered structured NAT rules

NAT rules carry explicit `id`, `sequence`, `type`, source/destination
references, translation modes, ports, `identity`, `patMethod`, `enabled`, and
source evidence. References use object UUIDs or names. Unresolved references
are retained as unsupported evidence and block generation; they are never
converted to `any`.

## Semantics

Hosts, networks, ranges, nested groups, services, interface/zone membership,
source and destination translation, PAT ports, identity NAT, and rule order
are normalized into the shared canonical IR. FDM-specific fields remain under
`source_attributes` when they are not vendor-neutral.

This is an offline parsing contract. The parser does not log in to FDM or
collect live data.
