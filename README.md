# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

A Python 3.10+ platform for multi-vendor firewall extraction, inventory, migration, and target configuration generation.

The tool decouples source parsing from target generation through a vendor-neutral Intermediate Representation (IR). Migration-relevant source data is normalized where possible and explicitly accounted for when it cannot be represented safely.

> **Status:** Vendor and feature coverage varies. FortiGate currently has the broadest audited extraction coverage. Generated configurations must be reviewed and validated before deployment.

## Capabilities

- Multi-vendor source parsing through a plugin registry.
- Vendor-neutral canonical IR for portable firewall semantics.
- Extraction/source-accounting support for audited parser paths.
- Native configuration and Terraform generation.
- Excel source inventory and Markdown/HTML migration reports.
- Optional rule and object optimization.
- CLI, web, and desktop workflows.
- Live FortiGate collection over SSH.

## Architecture

```text
source config
    -> source adapter
    -> ExtractionResult + canonical IR
    -> validation / optional optimization
    -> target generator
    -> native config / Terraform / reports
```

This is an M×N architecture: source and target vendors are separated by the canonical IR. Support for a vendor does not imply equal feature coverage for every migration pair.

## Supported vendors

| Vendor | Source | Target | Notes |
|---|---:|---:|---|
| Fortinet FortiGate / FortiOS | Yes | Yes | Broadest audited source coverage |
| Palo Alto Networks PAN-OS / Panorama | Yes | Yes | XML source with PAN-OS/Panorama scope handling |
| Cisco ASA | Yes | Yes | Offline configuration parsing; some extraction areas remain partial |
| Cisco Secure Firewall Threat Defense (FTD) | Yes | No | Management/device configuration extraction only; FMC policy/NAT API extraction is not implemented on `main` |
| Check Point R80/R81 | Yes | Yes | JSON/API/Gaia-oriented extraction |
| Juniper SRX / Junos OS | Yes | Yes | Root-level `display set` source syntax |

Target formats currently registered:

| Target | Formats |
|---|---|
| Palo Alto Networks | `xml`, `terraform` |
| Fortinet FortiGate | `cli`, `terraform` |
| Cisco ASA | `cli`, `terraform` |
| Check Point | `cli`, `terraform` |
| Juniper SRX / Junos OS | `set`, `cli`, `terraform` |

Use the runtime registry as the authoritative view:

```bash
fwmigrate vendors
```

## Safety model

Firewall migration is security-sensitive. The project follows four core rules:

1. **No silent loss:** migration-relevant source data must be normalized or explicitly accounted for.
2. **Fail closed:** unresolved input must not silently become broader semantics such as `any`, `/0`, `/32`, `allow`, or fabricated topology.
3. **Preserve evidence:** unsupported or non-portable source semantics should remain visible for review.
4. **Protect secrets:** passwords, usable PSKs, private keys, tokens, and similar credentials must not be exposed in normal outputs.

Detailed engineering rules are in [`AGENTS.md`](AGENTS.md), [`documentation/IR_DATA_STRUCTURE.md`](documentation/IR_DATA_STRUCTURE.md), and [`documentation/EXTRACTION_DATA_MODEL.md`](documentation/EXTRACTION_DATA_MODEL.md).

## Installation

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
python -m pip install -e .
```

Development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Optional extras defined by `pyproject.toml`:

```bash
python -m pip install -e ".[cisco]"
python -m pip install -e ".[reports]"
```

For development with both optional extras:

```bash
python -m pip install -e ".[dev,cisco,reports]"
```

## Usage

### Web interface

```bash
fwmigrate serve --port 5000
```

Open `http://localhost:5000`. On Windows, `run_migration.bat` starts the same web workflow on port 5000.

### Desktop application

```bash
fwmigrate app
```

The desktop launcher uses `pywebview` when available and otherwise opens the local web application in the default browser.

### CLI migration

```bash
fwmigrate migrate \
  --input /path/to/source.conf \
  --output ./output \
  --source-vendor fortigate \
  --target-vendor palo_alto \
  --format terraform \
  --report ./output/migration_report.md
```

Optional zone mapping:

```bash
--zone-map /path/to/zone_map.yaml
```

Explicit mappings are authoritative. The migration pipeline must not invent permissive zone relationships when the source configuration does not provide enough evidence.

### Live FortiGate inventory

Install the report dependency, then collect a FortiGate configuration over SSH and export source inventory to Excel:

```bash
fwmigrate-live-fortigate \
  --host 192.0.2.10 \
  --username admin \
  --verify-host-key \
  --output fortigate_source_inventory.xlsx
```

The command prompts for the password instead of accepting it as a command-line argument.

See [`documentation/LIVE_SOURCE_EXTRACTION.md`](documentation/LIVE_SOURCE_EXTRACTION.md) for the live-source workflow.

## Outputs

Depending on the selected source, target, and workflow, outputs can include:

- target-native configuration;
- Terraform configuration;
- Excel source inventory;
- Markdown and HTML migration reports;
- migration packages produced by the web workflow.

Source inventory represents extracted source data before optional optimizer pruning.

## Optimization

Optional optimization includes unused-object analysis, duplicate-object analysis, shadowed-rule detection, unused-object pruning, and selected structural rule corrections.

Optimization is separate from source extraction/accounting and should not be treated as evidence that source data was successfully normalized.

## Development and testing

CI installs `.[dev]`, compiles the Python sources/scripts, and runs the test suite on Python 3.11, 3.12, and 3.13.

```bash
python -m compileall -q src tests
python -m py_compile scripts/*.py
python -m pytest -q
```

There is currently no configured Ruff, Black, mypy, or pre-commit gate.

For parser and generator changes, prefer semantic assertions over checks that only verify non-empty output.

## Windows executable

`Firewall Migration Tool.spec` defines the PyInstaller build and intentionally bundles the tracked Terraform runtime asset under `bin/`.

```powershell
python -m pip install -r requirements.txt
python -m PyInstaller `
  --noconfirm `
  --workpath .codex-tmp\pyinstaller-build `
  --distpath dist `
  "Firewall Migration Tool.spec"
```

Build output is written to `dist/`. A prebuilt executable is not part of the current `main` tree.

## Documentation

| Document | Purpose |
|---|---|
| [`documentation/User Manual.md`](documentation/User%20Manual.md) | Operational usage |
| [`documentation/IR_DATA_STRUCTURE.md`](documentation/IR_DATA_STRUCTURE.md) | Canonical IR and schema evolution |
| [`documentation/EXTRACTION_DATA_MODEL.md`](documentation/EXTRACTION_DATA_MODEL.md) | Extraction accounting and zero-silent-loss model |
| [`documentation/LIVE_SOURCE_EXTRACTION.md`](documentation/LIVE_SOURCE_EXTRACTION.md) | Live-source collection |
| [`documentation/`](documentation/) | Vendor-specific extraction/reference documents |
| [`AGENTS.md`](AGENTS.md) | Engineering and repository guidance |

## Known limitations

- Vendor feature parity varies, and some extracted data is intentionally source-only or partially normalized.
- Cisco FTD support on `main` does not include FMC policy/NAT API extraction or a target generator.
- Offline backups may not contain runtime-learned state.
- Hardware-, cluster-, and platform-specific settings may require manual work.
- Unsafe or unresolved canonical semantics should cause affected output to be withheld rather than broadened.
- Every generated configuration must be reviewed and validated before deployment.

## License and attribution

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](LICENSE).

Copyright © 2025 GSW Systems.  
Modified in 2026 by Cha Zi Yu.

This project is a derivative work adapted from [`gswsystems/fortigate-palo-migration`](https://github.com/gswsystems/fortigate-palo-migration) and remains distributed under AGPL-3.0.
