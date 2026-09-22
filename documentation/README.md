# Firewall Migration Tool Documentation

This directory contains source-reporting architecture notes, retained vendor
references, and historical conversion material.

## Current architecture

The supported path is:

```text
Vendor source → VendorConfig → DerivedViews → validation → vendor preview / Excel
```

Source reporting does not depend on canonical IR. Configuration conversion is
temporarily unavailable. The reserved future boundary is documented in
[`src/fwmigrate/conversion/README.md`](../src/fwmigrate/conversion/README.md):

```text
source-native model → pair-specific mapper → target-native model
→ target validator → target renderer
```

Planned examples are `cisco_asa_to_fortigate`, `juniper_srx_to_fortigate`,
`cisco_ftd_to_fortigate`, and `checkpoint_to_fortigate`. They are not
implemented.

## Directory Layout

```text
documentation/
├── ir-model.md               # Canonical IR V2 model, fields, and serialization
├── vendor-mapping/           # Standardized IR mappings per vendor
├── official-cli-references/  # Official vendor syntax references (Source of Truth)
├── generated/                # Automatically generated docs
└── metadata/                 # Documentation metadata and configuration
```

## Vendor Mappings

All vendor-specific findings, support notes, and parser references must be kept in their respective `vendor-mapping/<vendor>.md` file. **Do not create separate audit, findings, NAT, or fix-plan documents per vendor.**

Every mapping file must use this standardized table structure:

| Domain | Vendor config | Vendor field | IR model | IR field | Mapping | Support | Parser |
|---|---|---|---|---|---|---|---|
| Address | `...` | `...` | `IRAddress` | `...` | Direct / Semantic | Full / Partial / Unsupported | `...` |

## Sources of Truth (Authority)

The source-reporting architecture is vendor-native. Retained IR and mapping
files are historical/conversion references only.

- **Implementation**: Executable source code and regression tests define actual behavior.
- **Vendor Syntax**: `official-cli-references/` (derived from official docs) define source syntax, *not* parser support.
- **Mapping Docs**: `vendor-mapping/` describe implemented mappings. They must not claim support without backing code/tests.

**When updating:**
- **Source-reporting changes**: Update the affected vendor source model, derived views, validation, preview, Excel, and tests together.
- **Historical IR changes**: Keep them separate from source-reporting changes.
