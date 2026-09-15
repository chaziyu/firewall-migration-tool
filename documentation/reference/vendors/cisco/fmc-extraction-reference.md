# Cisco Secure Firewall / FMC REST Extraction Reference

## Scope

Cisco FTD policy extraction through FMC REST bundles is intentionally separate from ASA/LINA CLI parsing. Standalone FTD text is limited to management, interface, and route evidence; it is not an authoritative managed policy/NAT source and remains generation-blocked.

**Executable authority:** `src/fwmigrate/parsers/cisco_ftd/`

## Bundle contract

The parser accepts the project offline bundle contract using:

```json
{
  "format": "cisco-fmc-rest-export-v1",
  "source": "fmc-rest-api"
}
```

The bundle carries collected FMC REST response structures for referenced objects, Access Control Policy, and NAT policy data. Collectors must preserve pagination and referenced-object evidence.

## Semantics

ACP zones, network/object references, services, applications/users, enabled state, actions, logging, and supported NAT translation modes are normalized where the canonical model is exact. Unsupported action variants, policy references, PAT options, translated-port behavior, and FMC-only settings remain explicit and can require review.

An unresolved object UUID/name is never converted to `any`.

## Source versus target capability

`cisco_ftd` is a registered **source** parser. There is no registered `cisco_ftd` target generator. The existence of the `cisco_asa` target generator does not make FTD a same-vendor target format.

## Vendor reference freshness

The latest FMC REST API guide reviewed is recorded in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml). This is reference freshness, not automatic parser-version certification.
