# Firewall Migration Tool Documentation

This directory uses one canonical IR reference and one standardized mapping
file per source vendor. Machine-readable vendor reference schemas may also be
kept under `reference-schema/` when they are derived from official vendor
documentation and are clearly separated from implementation-support claims.

## Documentation layout

```text
documentation/
├── README.md
├── ir-model.md
├── ir-schema-v2-plan.md
└── vendor-mapping/
    ├── fortigate.md
    ├── palo-alto.md
    ├── cisco-asa.md
    ├── cisco-ftd.md
    ├── checkpoint.md
    └── juniper.md
```

| File | Purpose |
|---|---|
| [`ir-model.md`](ir-model.md) | Current executable canonical IR model, fields, relationships, safety flags, and serialization behavior. |
| [`ir-schema-v2-plan.md`](ir-schema-v2-plan.md) | Historical IR V2 design rationale and generic/vendor-extension boundary. |
| [`vendor-mapping/fortigate.md`](vendor-mapping/fortigate.md) | FortiGate configuration to canonical IR mapping. |
| [`vendor-mapping/palo-alto.md`](vendor-mapping/palo-alto.md) | Palo Alto configuration to canonical IR mapping. |
| [`vendor-mapping/cisco-asa.md`](vendor-mapping/cisco-asa.md) | Cisco ASA configuration to canonical IR mapping. |
| [`vendor-mapping/cisco-ftd.md`](vendor-mapping/cisco-ftd.md) | Cisco FTD configuration to canonical IR mapping. |
| [`vendor-mapping/checkpoint.md`](vendor-mapping/checkpoint.md) | Check Point configuration to canonical IR mapping. |
| [`vendor-mapping/juniper.md`](vendor-mapping/juniper.md) | Juniper SRX configuration to canonical IR mapping. |

## Vendor mapping table

Every vendor file uses this structure:

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | `...` | `...` | `IRAddress` | `...` | Direct / Semantic | Full / Partial / Unsupported | `...` |

Keep vendor-specific findings, support notes, and parser references in that
vendor's mapping file. Do not create separate audit, findings, phase, NAT, or
fix-plan documents for the same vendor.

Reference schemas are source-document inventories for parser design and coverage.
They must not be used to claim current parser support. Keep source syntax metadata
separate from IR semantic mappings so extraction fidelity can be audited
independently from normalization.

## Authority

- Executable source code and regression tests define implementation behavior.
- Official vendor documentation defines vendor behavior.
- `ir-schema-v2-plan.md` records the implemented V2 contract's design rationale.
- Reference schemas derived from official documentation describe documented source syntax, not runtime availability or parser support.
- Vendor mapping documents describe implemented mappings and must not claim support without parser, IR, generator, or test evidence.

The architecture remains:

```text
vendor source -> ExtractionResult -> IR V2 -> Excel
```

When the IR changes, update the executable models, serialization/migrations,
affected tests, and `ir-model.md` together. When a vendor parser changes, update
only its mapping file unless the canonical IR contract also changes.
