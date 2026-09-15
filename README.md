# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

A Python 3.10+ multi-vendor firewall configuration extraction and migration platform.

The current development priority is reliable, auditable extraction:

```text
Vendor configuration
        ↓
ExtractionResult
        ↓
Canonical IR V2 + vendor extensions
        ↓
Validation and coverage accounting
        ↓
Excel report
```

Target configuration generation remains available, but extraction correctness and completeness are the primary validation milestone.

## Supported source vendors

- Fortinet FortiGate
- Palo Alto Networks PAN-OS / Panorama
- Cisco ASA
- Cisco Firepower Threat Defense
- Check Point R80/R81
- Juniper SRX / Junos

Run the live plugin registry to see currently registered parsers and generators:

```bash
fwmigrate vendors
```

## Common extraction pipeline

All source vendors are being standardized around the same lifecycle:

```text
Raw source
  ↓
1. Input detection / format adapter
  ↓
2. Source normalization
  ↓
3. Parse / tokenize / load
  ↓
4. Vendor source model
  ↓
5. Context / scope / inheritance resolution
  ↓
6. Reference and dependency resolution
  ↓
7. Source inventory and coverage accounting
  ↓
8. Transform to IR V2
     ├─ canonical generic IR
     └─ typed vendor extensions
  ↓
9. Semantic validation
  ↓
10. Extraction safety and completeness evaluation
  ↓
11. Finalize ExtractionResult
  ↓
12. Excel export
```

`extract()` is the authoritative parser entry point. Source syntax may differ by vendor, but every parser must produce the same extraction contract and must not silently discard configuration.

Each source item should be accounted for as one of:

- `NORMALIZED`
- `PARTIALLY_NORMALIZED`
- `VENDOR_EXTENSION`
- `EXTRACT_ONLY`
- `UNSUPPORTED`
- `PARSE_ERROR`

## IR direction

The canonical IR is being refined so portable firewall intent stays vendor-neutral while vendor-only semantics remain preserved in typed extensions.

Use these documents as the source of truth:

- [Planned IR V2 contract](documentation/ir-schema-v2-plan.md)
- [Currently implemented IR](documentation/ir-model.md)
- [Documentation index](documentation/README.md)

Vendor-specific extraction coverage is maintained separately:

- [FortiGate](documentation/vendor-mapping/fortigate.md)
- [Palo Alto](documentation/vendor-mapping/palo-alto.md)
- [Cisco ASA](documentation/vendor-mapping/cisco-asa.md)
- [Cisco FTD](documentation/vendor-mapping/cisco-ftd.md)
- [Check Point](documentation/vendor-mapping/checkpoint.md)
- [Juniper](documentation/vendor-mapping/juniper.md)

## Safety principles

The project follows a fail-closed extraction model:

- **No silent loss:** source configuration must be normalized or explicitly accounted for.
- **No unsafe guessing:** malformed, ambiguous, unsupported, or unresolved semantics must not be broadened into permissive values.
- **Preserve evidence:** source-only and vendor-specific semantics remain available for review.
- **Protect secrets:** passwords, usable PSKs, private keys, tokens, and equivalent credentials must not appear in normal outputs.
- **Review generated output:** target configuration generation still requires human and vendor validation.

Detailed repository rules are in [AGENTS.md](AGENTS.md).

## Installation

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Basic usage

Start the web application:

```bash
fwmigrate serve --port 5000
```

Or use the desktop launcher:

```bash
fwmigrate app --port 5000
```

Run a file-based migration when target generation is required:

```bash
fwmigrate migrate \
  --input /path/to/source.conf \
  --output ./output \
  --source-vendor fortigate \
  --target-vendor palo_alto
```

FortiGate live collection is also available:

```bash
fwmigrate-live-fortigate \
  --host 192.0.2.10 \
  --username admin \
  --verify-host-key \
  --output fortigate_source_inventory.xlsx
```

## Development and testing

```bash
python -m compileall -q src tests
python -m py_compile scripts/*.py scripts/docs/*.py
python -m pytest -q
```

CI runs the test suite on supported Python versions.

## Current focus

The near-term goal is not to maximize target-generation features. It is to prove that supported firewall configurations can be extracted deterministically into IR V2 and Excel with complete source accounting.

A successful extraction should make it clear:

- what was found in the source,
- what was normalized,
- what remains vendor-specific,
- what requires manual review,
- what could not be parsed or supported,
- and which references or dependencies remain unresolved.

Once extraction completeness is stable across all six vendors, target-generation work can build on a much safer foundation.

## Known limitations

- Vendor feature coverage is not complete.
- Some settings are intentionally source-only or partially normalized.
- Cisco FTD currently has no dedicated target generator.
- Live source collection is currently FortiGate-only.
- Runtime-learned state may not exist in offline configuration backups.
- Hardware-, cluster-, identity-, and platform-specific behavior can require manual review.

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).

Copyright © 2025 GSW Systems.  
Modified in 2026 by Cha Zi Yu.

This project is derived from [gswsystems/fortigate-palo-migration](https://github.com/gswsystems/fortigate-palo-migration) and remains distributed under AGPL-3.0.
