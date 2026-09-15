# FortiGate Support Matrix

Status describes **source extraction**, while target generation is tracked separately.

| Domain | Extraction status | Canonical IR | Target generation | Notes |
|---|---|---|---|---|
| Addresses and address groups | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Broad | Conditional | Dynamic/vendor-specific selectors retain source evidence. |
| Services and service groups | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Broad | Conditional | Source-port/helper/proxy/application semantics can require review. |
| Interfaces and topology | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Broad | Conditional | Aggregate/redundant/VRF/vendor settings can remain partial. |
| Security policy | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Broad | Conditional | Dependency taint and unmodeled match/profile semantics can block output. |
| NAT / VIP / IP pools | `NORMALIZED` / `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Broad plus source-preserving extensions | Conditional | `central-snat-map`, `ippool`, `ippool6`, `ippool_grp`, `vip`, and `vipgrp` are FortiOS source constructs. Central SNAT port sentinels are preserved. Basic IPv4 SNAT/DNAT is normalized where semantics are proven; IP-pool groups remain typed inventory/correlation evidence and are not flattened into target translations. Central SNAT ambiguity, policy-based IPsec NAT, advanced pools/VIPs, unresolved VIP-group members, and IPv6 pool semantics remain review-gated or extract-only unless equivalent target semantics are proven. |
| Static routing | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Broad | Conditional | Named destinations and vendor options can require review. |
| SD-WAN | `EXTRACT_ONLY` | Source inventory | Withheld | Target selection/failover behavior is not inferred. |
| Security profiles | `EXTRACT_ONLY` / `PARTIALLY_NORMALIZED` | Selected references/models | Conditional | Engine-specific behavior is not assumed equivalent across vendors. |
| Identity/authentication | `EXTRACT_ONLY` / `PARTIALLY_NORMALIZED` | Selected models | Conditional | Secrets remain redacted and vendor behavior can be nonportable. |
| System/management settings | `NORMALIZED` / `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Selected models | Conditional | Hardware/platform-specific behavior remains review evidence. |

FortiGate currently has the broadest audited source coverage in the repository, but this table is not a claim of complete FortiOS feature parity.

FortiOS documentation is authoritative for FortiGate source extraction syntax and behavior. Target-vendor documentation, including PAN-OS NAT documentation, is used only to validate whether canonical IR can be emitted safely by that target generator; it is not evidence that a FortiOS source command was parsed correctly.

For current NAT details, see the [FortiGate extraction reference](extraction-reference.md). Generated capability pages are derived from executable registry/model data and are not hand-edited.
