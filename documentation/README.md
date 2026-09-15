# Firewall Migration Tool Documentation

This directory uses one canonical IR reference and one standardized mapping
file per source vendor.

## Documentation layout

```text
documentation/
├── README.md
├── ir-model.md
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

## Authority

- Executable source code and regression tests define implementation behavior.
- Official vendor documentation defines vendor behavior.
- These documents describe the implemented mapping and must not claim support
  without parser, IR, generator, or test evidence.

The architecture remains:

```text
source config -> source parser -> ExtractionResult + canonical IR
             -> validation / optimization -> target generator
```

When the IR changes, update the executable models, serialization/migrations,
affected tests, and `ir-model.md` together. When a vendor parser changes,
update only its mapping file unless the canonical IR contract also changes.
