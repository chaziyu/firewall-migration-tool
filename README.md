# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

A Python 3.10+ platform for multi-vendor firewall extraction, source inventory, migration analysis, and target configuration generation.

## Key highlights

| Highlight | Current implementation |
|---|---|
| Canonical IR | Registered source parsers produce `ExtractionResult` and the vendor-neutral `IRConfig`; target generators consume the IR, not parser-specific models. |
| M×N architecture | `source config → source parser → IR → validation/normalization/optional optimization → target generator`. Adding a source or target does not require direct source-to-target converters. |
| Source coverage | Six built-in source parsers: FortiGate, Palo Alto, Cisco ASA, Cisco FTD, Check Point, and Juniper SRX. |
| Target coverage | Five built-in target generators: Palo Alto, FortiGate, Cisco ASA/Firepower, Check Point, and Juniper SRX. Cisco FTD currently has no target generator. |
| Fail-closed safety | Parse errors, unsupported semantics, unresolved references, and unsafe topology are retained for review or block generation; they are not silently widened into permissive values. |
| Source accounting | Extraction keeps source inventory, commands, unsupported items, and provenance so recognized data is not silently dropped. |
| Analysis and outputs | The CLI and web UI support migration previews, capability analysis, optional unused-object pruning, native configuration, Terraform, Markdown/HTML reports, and Excel source inventory. |
| Live collection | The integrated web/desktop workflow and `fwmigrate-live-fortigate` support complete FortiGate configuration collection over SSH. |

The runtime plugin registry is the source of truth for registered parsers and generators. Parser recognition is broader than safe target generation, so every generated artifact still requires review and vendor validation before deployment.

## Architecture

```text
source configuration
        │
        ▼
registered source parser
        │
        ▼
ExtractionResult + canonical IRConfig
        │
        ▼
safety analysis → normalization → optional optimization → validation/capability analysis
        │
        ▼
registered target generator
        │
        ▼
native configuration / Terraform / reports / source inventory
```

## Documentation

The documentation follows one canonical IR reference and one standardized mapping file per source vendor:

- [Documentation index](documentation/README.md)
- [Current canonical IR model](documentation/ir-model.md)
- [FortiGate mapping](documentation/vendor-mapping/fortigate.md)
- [Palo Alto mapping](documentation/vendor-mapping/palo-alto.md)
- [Cisco ASA mapping](documentation/vendor-mapping/cisco-asa.md)
- [Cisco FTD mapping](documentation/vendor-mapping/cisco-ftd.md)
- [Check Point mapping](documentation/vendor-mapping/checkpoint.md)
- [Juniper mapping](documentation/vendor-mapping/juniper.md)

The runtime registry and executable models are authoritative for code-derived capability facts. Vendor mappings describe source-to-IR coverage and semantic limits; they are not complete feature-parity claims.


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

Optional extras currently defined by `pyproject.toml` are `cisco` and `reports`.

## Usage

List the current registered source and target plugins:

```bash
fwmigrate vendors
```

Run a file-based migration:

```bash
fwmigrate migrate \
  --input /path/to/source.conf \
  --output ./output \
  --source-vendor fortigate \
  --target-vendor palo_alto \
  --format terraform \
  --report ./output/migration_report.md
```

`--report` writes the Markdown report and an HTML sidecar with the same base name. Use `--optimize` to enable unused-object analysis and pruning. A zone-map YAML file can be supplied with `--zone-map` when interface-to-zone context needs to be provided.

Start the web application with preview, migration, reporting, Excel inventory, and Terraform preparation workflows:

```bash
fwmigrate serve --port 5000
```

Open `http://localhost:5000`. The desktop launcher uses the same integrated workflow:

```bash
fwmigrate app --port 5000
```

If `pywebview` is not installed, the desktop command falls back to the default browser.

Collect a FortiGate configuration over SSH and write parser-backed source inventory Excel:

```bash
fwmigrate-live-fortigate \
  --host 192.0.2.10 \
  --username admin \
  --verify-host-key \
  --output fortigate_source_inventory.xlsx
```

The command prompts for the password, requires a complete collection, and prints the resulting source SHA-256.

## Built-in plugins

### Source parsers

| Vendor ID | Display name | Common input formats |
|---|---|---|
| `fortigate` | Fortinet FortiGate | `.conf`, `.cfg`, `.txt` |
| `palo_alto` | Palo Alto Networks (PAN-OS / Panorama) | `.xml`, `.json`, `.txt` |
| `cisco_asa` | Cisco ASA | `.cfg`, `.txt`, `.conf` |
| `cisco_ftd` | Cisco Firepower Threat Defense | `.cfg`, `.txt`, `.conf`, `.json` |
| `checkpoint` | Check Point R80/R81 (JSON Dump / API) | `.json`, `.txt`, `.cfg` |
| `juniper_srx` | Juniper SRX (Junos root-level display set) | `.set`, `.txt`, `.conf` |

### Target generators

| Vendor ID | Display name | Formats |
|---|---|---|
| `palo_alto` | Palo Alto Networks (PAN-OS / Panorama) | XML, Terraform |
| `fortigate` | Fortinet FortiGate (FortiOS CLI / Terraform) | CLI, Terraform |
| `cisco_asa` | Cisco ASA / Firepower | CLI, Terraform |
| `checkpoint` | Check Point Quantum / CloudGuard | CLI, Terraform |
| `juniper_srx` | Juniper SRX / JunOS | set, CLI, Terraform |

Aliases such as `fortinet`, `fg`, `panos`, `asa`, `ftd`, `check_point`, `srx`, and `junos` are registered where supported. Run `fwmigrate vendors` to inspect the live registry.

## Safety model

The project follows these core rules:

1. **No silent loss:** migration-relevant source data must be normalized or explicitly accounted for.
2. **Fail closed:** missing, malformed, ambiguous, or unresolved semantics must not become broader values such as `any`, `allow`, `/0`, `/32`, or fabricated topology.
3. **Preserve evidence:** unsupported and non-portable source semantics remain available for review.
4. **Protect secrets:** passwords, usable PSKs, private keys, tokens, and equivalent credentials must not be exposed in normal outputs.
5. **Review before deployment:** generated configuration and Terraform plans require human and vendor validation.

Detailed repository rules are in [`AGENTS.md`](AGENTS.md).

## Development and testing

```bash
python -m compileall -q src tests
python -m py_compile scripts/*.py scripts/docs/*.py
python -m pytest -q
```

CI runs the full test suite on Python 3.11, 3.12, and 3.13.

## Windows executable

`Firewall Migration Tool.spec` defines the PyInstaller build and intentionally bundles the tracked Terraform runtime asset under `bin/`. Follow the repository-specific build instructions before changing packaging behavior.

## Known limitations

- Vendor feature parity varies; some extracted data is intentionally source-only or partially normalized.
- Cisco FTD/FMC is a registered source path but there is no `cisco_ftd` target generator.
- Live source collection is currently FortiGate-only.
- Offline backups may not include runtime-learned state.
- Hardware-, cluster-, identity-, and platform-specific settings can require manual work.
- Target generation safety is narrower than parser recognition.

## License and attribution

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](LICENSE).

Copyright © 2025 GSW Systems.  
Modified in 2026 by Cha Zi Yu.

This project is a derivative work adapted from [`gswsystems/fortigate-palo-migration`](https://github.com/gswsystems/fortigate-palo-migration) and remains distributed under AGPL-3.0.
