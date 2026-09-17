# Firewall Migration Tool Documentation

This directory contains the canonical IR documentation, vendor mappings, and reference materials for the parser.

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

The extraction architecture is:
`vendor source -> ExtractionResult -> IR V2 -> Excel`

- **Implementation**: Executable source code and regression tests define actual behavior.
- **Vendor Syntax**: `official-cli-references/` (derived from official docs) define source syntax, *not* parser support.
- **Mapping Docs**: `vendor-mapping/` describe implemented mappings. They must not claim support without backing code/tests.

**When updating:**
- **IR changes**: Update executable models, tests, and `ir-model.md` together.
- **Vendor parser changes**: Update only the specific vendor's mapping file (unless canonical IR contract changes).
