# Juniper SRX Support Matrix

| Domain | Extraction status | Canonical IR | Target generation | Notes |
|---|---|---|---|---|
| System/version/DNS/time zone | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Selected models | Conditional | Unmodeled system settings remain evidence. |
| Interfaces / VLANs | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Multiple addresses and vendor attributes can require review. |
| Security zones | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Host-inbound/screen behavior is source-oriented. |
| Address books / sets | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Scope, cycles, and specialized forms can require review. |
| Applications / sets | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Services/groups | Conditional | Multi-term/vendor semantics can remain partial. |
| Security policies | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Exclusions and nonportable action details require review. |
| Static routes | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | ECMP, reject/discard, routing-instance and install behavior can be partial. |
| Firewall filters / forwarding | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Selected filter/PBR models | Conditional | Stateless filter semantics are not invented as security policy. |
| NAT | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Broad | Conditional | Only exact translation semantics are portable. |
| IKE/IPsec VPN | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Limited | Conditional/withheld | Crypto/topology fidelity requires review. |
