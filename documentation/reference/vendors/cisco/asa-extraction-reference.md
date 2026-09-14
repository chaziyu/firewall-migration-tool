# Cisco ASA Extraction Reference

## Scope

The `cisco_asa` source parser handles offline Cisco ASA running configuration and produces `ExtractionResult` plus canonical `IRConfig` where portable semantics are proven.

**Executable authority:** `src/fwmigrate/parsers/cisco_asa/`

## Input contract

Registered extensions are generated in [`../../../generated/capabilities.md`](../../../generated/capabilities.md). Prefer complete `show running-config` output with terminal paging disabled.

## Current coverage

The parser contains structured handling for core ASA firewall configuration, including interfaces, objects/groups, ACL/policy semantics, NAT, routes, VPN/source evidence, management/system areas, MPF/class-map/policy-map constructs, and additional source-only feature families.

Coverage classification is maintained by the ASA extraction/coverage modules. Parsing a command does not mean its complete behavior is portable.

## Important boundaries

- Standard ACL destination-only semantics are not treated as equivalent to an extended transit security rule without attachment/consumer context.
- Legacy NAT exemption and ordered/fallback NAT behavior remain conservative when canonical IR cannot reproduce ordering exactly.
- Dynamic address-only NAT must remain distinct from PAT.
- MPF inspection/action behavior can be structured while remaining partial or source-only.
- Invalid or unresolved source values must not be widened into permissive behavior.

## Version evidence

The project does not claim universal compatibility with the newest ASA software merely because current Cisco command references were reviewed. Vendor reference freshness is recorded in [`../../../metadata/vendors.yml`](../../../metadata/vendors.yml).

## Support matrix

See [`support-matrix.md`](support-matrix.md), which separates ASA and FMC/FTD source behavior.
