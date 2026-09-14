# Check Point Support Matrix

| Domain | Extraction status | Canonical IR | Target generation | Main limitation |
|---|---|---|---|---|
| Hosts, networks, ranges, ordinary groups | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Yes | Conditional | Specialized object semantics remain source-only. |
| Policy packages / layers | `NORMALIZED` / `PARTIALLY_NORMALIZED` | Metadata + policy context | Conditional | Ordered and Inline Layers are not flattened unsafely. |
| Access rules | `PARTIALLY_NORMALIZED` | Yes where exact | Conditional | Unsupported dimensions/actions/dependencies withhold rules. |
| NAT | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Broad | Conditional | Automatic/manual ordering and identity barriers require fidelity evidence. |
| Gaia interfaces/routes | `PARTIALLY_NORMALIZED` | Yes | Conditional | VS/platform/topology details can be nonportable. |
| VPN | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Limited | Conditional/withheld | Community/crypto/topology behavior requires review. |
| Identity/authentication | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Selected models | Conditional | Credentials excluded; vendor-specific identity behavior retained. |
| Threat Prevention / HTTPS Inspection | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Selected evidence | Withheld/conditional | Engine behavior is not target-equivalent. |
| ClusterXL / performance | `PARTIALLY_NORMALIZED` / `EXTRACT_ONLY` | Source evidence | Withheld/conditional | Runtime evidence is not persistent target configuration. |
| Multi-Domain scope | `PARTIALLY_NORMALIZED` / `UNSUPPORTED` | Scoped evidence | Conditional/withheld | Effective global/local ordering and cross-domain leakage are not guessed. |
