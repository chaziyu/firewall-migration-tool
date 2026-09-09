# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)
![Package](https://img.shields.io/badge/package-0.2.0-blue.svg)
![IR Schema](https://img.shields.io/badge/IR%20schema-1.51-purple.svg)

A Python-based multi-vendor firewall extraction, inventory, migration, and target-generation platform.

The project uses a vendor-neutral Intermediate Representation (IR) to decouple source parsing from target generation. Source adapters preserve migration-relevant evidence through canonical IR and `ExtractionResult` accounting where implemented, so unsupported or non-portable semantics remain visible instead of silently disappearing.

> **Project status**
>
> Source and target coverage varies by vendor and feature. FortiGate currently has the broadest audited extraction coverage. Generated configurations must be reviewed and validated before deployment.

## Key capabilities

- Multi-vendor source parsing through a plugin registry.
- Vendor-neutral canonical IR for portable firewall semantics.
- Source-accounting and extraction coverage for audited parser paths.
- Native configuration and Terraform target generation.
- Excel source inventory and migration reports.
- Optional rule/object optimization.
- Web, CLI, and desktop entry points.
- Fail-closed handling when required migration semantics are unresolved.

## Architecture

```text
Source configuration
        |
        v
   Source adapter
        |
        +------> ExtractionResult / source accounting
        |         (where implemented)
        v
   Canonical IR
        |
        +------> Excel source inventory
        |
        v
 Validation / optional optimization
        |
        v
   Target generator
      /       \
     v         v
 Native      Terraform
        \     /
         v   v
   Reports / packages
```

The architecture follows an M×N model: source and target vendors are decoupled through IR. Do not treat this as a guarantee of equal feature coverage across every vendor pair.

## Supported vendors

Current registration on `main`:

| Vendor | Source adapter | Target generator | Notes |
|---|---:|---:|---|
| Fortinet FortiGate / FortiOS | Yes | Yes | Most extensively audited source path |
| Palo Alto Networks PAN-OS / Panorama | Yes | Yes | XML source and PAN-OS/Panorama scope handling |
| Cisco ASA | Yes | Yes | Offline running configuration; extraction coverage is partial in some areas |
| Cisco Secure Firewall Threat Defense (FTD) | Yes | No | Management/device configuration extraction only on `main`; FMC policy/NAT API extraction is not implemented |
| Check Point R80/R81 | Yes | Yes | JSON/API/Gaia-oriented extraction with source accounting |
| Juniper SRX / Junos OS | Yes | Yes | Root-level `display set` source syntax |

Run the registry command for the current runtime view:

```bash
fwmigrate vendors
```

### Target formats

| Target | Formats |
|---|---|
| Palo Alto Networks | `xml`, `terraform` |
| Fortinet FortiGate | `cli`, `terraform` |
| Cisco ASA | `cli`, `terraform` |
| Check Point | `cli`, `terraform` |
| Juniper SRX / Junos OS | `set`, `cli`, `terraform` |

## Safety model

Firewall migration is security-sensitive. The core rules are:

1. **Zero silent loss** — migration-relevant source configuration must be accounted for.
2. **No permissive fallback** — malformed or unresolved input must not silently become `any`, `/0`, `/32`, `allow`, or another broader semantic.
3. **Preserve source evidence** — non-portable or unsupported values should remain visible for review.
4. **Do not invent topology** — zones, interfaces, routes, or other relationships must come from explicit evidence.
5. **Do not expose secrets** — passwords, usable PSKs, private keys, tokens, and similar credentials must not be written to normal IR, reports, or Excel output.
6. **Withhold unsafe output** — target generation should omit or flag objects whose required semantics cannot be represented safely.

Extraction accounting can classify source data as:

```text
NORMALIZED
PARTIALLY_NORMALIZED
EXTRACT_ONLY
VENDOR_EXTENSION
UNSUPPORTED
IGNORED_BY_POLICY
PARSE_ERROR
```

Detailed rules are defined in [`AGENTS.md`](AGENTS.md), [`documentation/IR_DATA_STRUCTURE.md`](documentation/IR_DATA_STRUCTURE.md), and [`documentation/EXTRACTION_DATA_MODEL.md`](documentation/EXTRACTION_DATA_MODEL.md).

## Versions

- Package: `0.2.0`
- Python: `>=3.10`
- Canonical IR schema: `1.51`

Serialized `IRConfig` carries its own `schema_version`. IR schema compatibility is independent from the package version and source firewall software version.

## Installation

### Requirements

- Python 3.10+
- Git
- Additional platform/vendor requirements only for the workflows you use

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
python -m pip install -e .
```

Development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Available optional extras currently include `cisco` and `reports`:

```bash
python -m pip install -e ".[dev,cisco,reports]"
```

## Usage

### List registered vendors

```bash
fwmigrate vendors
```

### Start the web interface

```bash
fwmigrate serve --port 5000
```

Open `http://localhost:5000`.

On Windows, `run_migration.bat` starts the web interface on port 5000.

### Launch the desktop application

```bash
fwmigrate app
```

### Run a migration

```bash
fwmigrate migrate \
  --input examples/example_fortigate.conf \
  --output ./output \
  --source-vendor fortigate \
  --target-vendor palo_alto \
  --format terraform \
  --report ./output/migration_report.md
```

Explicit zone mapping can be provided with:

```bash
--zone-map path/to/zone_map.yaml
```

Explicit mapping is authoritative. The migration pipeline must not infer permissive trust/untrust mappings when source evidence is insufficient.

## Outputs

Depending on the workflow and vendor, the application can produce:

- target-native configuration;
- Terraform configuration;
- source inventory Excel workbook;
- `migration_report.md`;
- `migration_report.html`;
- migration packages from the web workflow.

Source inventory is intended to represent the extracted source before optional optimizer pruning.

## Optimization

The optimizer supports analysis such as:

- unused-object detection;
- duplicate-object analysis;
- shadowed-rule detection;
- optional unused-object pruning;
- selected structural rule corrections.

Optimization is separate from source extraction and accounting.

## Documentation

| Document | Purpose |
|---|---|
| [`documentation/IR_DATA_STRUCTURE.md`](documentation/IR_DATA_STRUCTURE.md) | Canonical IR contract and schema evolution |
| [`documentation/EXTRACTION_DATA_MODEL.md`](documentation/EXTRACTION_DATA_MODEL.md) | Extraction accounting and zero-silent-loss model |
| [`documentation/User Manual.md`](documentation/User%20Manual.md) | Operational usage guidance |
| [`documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md`](documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md) | FortiGate extraction reference |
| [`documentation/PALO_ALTO_EXTRACTION_REFERENCE.md`](documentation/PALO_ALTO_EXTRACTION_REFERENCE.md) | PAN-OS extraction reference |
| [`documentation/CHECKPOINT_EXTRACTION.md`](documentation/CHECKPOINT_EXTRACTION.md) | Check Point extraction reference |
| [`documentation/JUNIPER_SRX_CONFIG_EXTRACTION_REFERENCE.md`](documentation/JUNIPER_SRX_CONFIG_EXTRACTION_REFERENCE.md) | Juniper SRX extraction reference |
| [`documentation/LIVE_SOURCE_EXTRACTION.md`](documentation/LIVE_SOURCE_EXTRACTION.md) | Live-source workflow guidance |
| [`AGENTS.md`](AGENTS.md) | Engineering, architecture, and migration-safety rules |

## Testing

Run the test suite with:

```bash
python -m pytest -q
```

For parser and generator changes, prefer semantic assertions over checks that only verify non-empty output. Do not hard-code a test-pass count in documentation because it becomes stale as the suite changes.

## Windows executable

A PyInstaller specification is included:

```text
Firewall Migration Tool.spec
```

Build locally with:

```powershell
# Install the runtime/build dependencies into the environment being packaged.
python -m pip install -r requirements.txt

# Use a fresh ignored work path; this avoids stale or read-only PyInstaller output.
python -m PyInstaller `
  --noconfirm `
  --workpath .codex-tmp\pyinstaller-build `
  --distpath dist `
  "Firewall Migration Tool.spec"
```

If the environment has no `pip`, install with uv instead:

```powershell
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
& .venv\Scripts\python.exe -m PyInstaller `
  --noconfirm `
  --workpath .codex-tmp\pyinstaller-build `
  --distpath dist `
  "Firewall Migration Tool.spec"
```

Successful builds are written to `dist/`. A prebuilt executable is not part of the current `main` tree.

## Repository structure

```text
src/fwmigrate/
├── extraction/              # ExtractionResult/source accounting
├── ir/                      # Canonical IR and schema versioning
├── parsers/                 # Source-vendor adapters
│   ├── fortigate/
│   ├── palo_alto/
│   ├── cisco_asa/
│   ├── cisco_ftd/
│   ├── checkpoint/
│   └── juniper_srx/
├── generators/              # Target-vendor generators
│   ├── fortigate/
│   ├── palo_alto/
│   ├── cisco_asa/
│   ├── checkpoint/
│   └── juniper_srx/
├── core/                    # Registry, optimizer, shared logic
├── report/                  # Excel and migration reports
├── engine/                  # Terraform/diagnostics support
├── templates/               # Web UI templates
├── static/                  # Web UI assets
├── main.py                  # CLI/desktop entry points
└── web.py                   # Flask web application
```

## Known limitations

This tool is an engineering aid, not a guarantee of semantic equivalence.

- Vendor feature parity varies.
- Some extracted data is intentionally source-only or partially normalized.
- Cisco Secure Firewall Threat Defense on `main` does not include FMC policy/NAT API extraction.
- Runtime-learned values may not exist in offline configuration backups.
- Hardware-, cluster-, and platform-specific settings may require manual work.
- Unresolved canonical semantics should cause affected target output to be withheld rather than broadened.
- Every generated configuration must be reviewed and validated before deployment.

## License and attribution

This repository is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](LICENSE).

Copyright © 2025 GSW Systems.  
Modified in 2026 by Cha Zi Yu.

This project is a derivative work adapted from [`gswsystems/fortigate-palo-migration`](https://github.com/gswsystems/fortigate-palo-migration) and remains distributed under AGPL-3.0.
