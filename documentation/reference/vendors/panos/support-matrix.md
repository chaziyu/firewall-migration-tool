# PAN-OS Support Matrix

| Domain | Extraction status | Canonical IR | Target generation | Notes |
|---|---|---|---|---|
| Addresses and groups | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Scoped, unresolved, cyclic, or PAN-specific semantics require review. |
| Services and schedules | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Only semantics represented by current IR are portable. |
| Security Policy | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | App-ID, identity/HIP, profile, rule-type, and other PAN-specific dimensions can taint rules. |
| IPv4 NAT | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Complex translation/fallback/interface behavior can remain partial. |
| NAT64 / NPTv6 | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Limited | Withheld/conditional | Address-family semantics are preserved without inventing equivalence. |
| Static routes | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Virtual/logical router context and advanced next-hop behavior can require review. |
| Dynamic routing | `EXTRACT_ONLY` | No portable routing protocol model | Withheld | Source inventory only. |
| Security profiles | `EXTRACT_ONLY` / `PARTIALLY_NORMALIZED` | Selected references/models | Conditional | Engine-specific definitions are not treated as target-equivalent. |
| IKE/IPsec | `EXTRACT_ONLY` / partial | Limited | Conditional/withheld | Cryptographic/topology fidelity requires target review. |
| Panorama template/inheritance | `EXTRACT_ONLY` | No effective inheritance synthesis | Withheld | Effective configuration is not invented. |
