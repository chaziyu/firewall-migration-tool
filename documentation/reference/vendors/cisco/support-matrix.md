# Cisco Support Matrix

| Source area | Parser | Extraction status | Canonical IR | Target generation | Notes |
|---|---|---|---|---|---|
| ASA interfaces / objects / groups | `cisco_asa` | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Vendor/platform details remain source evidence. |
| ASA ACL / security policy | `cisco_asa` | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Standard ACL consumer semantics require review. |
| ASA NAT | `cisco_asa` | `NORMALIZED` / `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Broad | Conditional | Ordered exemptions/fallback behavior is not guessed. |
| ASA routes | `cisco_asa` | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Unsafe source values are withheld. |
| ASA MPF / inspection | `cisco_asa` | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Limited | Conditional/withheld | Inspection-engine behavior is not assumed portable. |
| FMC ACP | `cisco_ftd` | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional to registered targets | Uses offline REST bundle. |
| FMC manual/auto NAT | `cisco_ftd` | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Translation evidence must be explicit. |
| FMC referenced objects | `cisco_ftd` | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Unresolved UUID/name blocks safe generation. |
| FTD as target | — | `NOT_APPLICABLE` | — | Not registered | No `cisco_ftd` target generator exists. |
