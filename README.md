# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

A Python 3.10+ platform for multi-vendor firewall extraction, source inventory, migration, and target configuration generation.

The project separates source parsing from target generation through a vendor-neutral Intermediate Representation (IR):

```text
source config
    -> source adapter
    -> ExtractionResult + canonical IR
    -> validation / optional optimization
    -> target generator
    -> native config / Terraform / reports
```

> **Safety:** Vendor and feature coverage varies. Generated configuration must be reviewed and validated before deployment. Unsupported or unresolved semantics are retained for review and should be withheld rather than silently broadened.

## Documentation

Start at [`documentation/README.md`](documentation/README.md).

Key references:

- [User guide](documentation/how-to/user-guide.md)
- [Architecture](documentation/explanation/architecture.md)
- [Safety model](documentation/explanation/safety-model.md)
- [Canonical IR reference](documentation/reference/ir/ir-schema.md)
- [Extraction model](documentation/reference/ir/extraction-model.md)
- [Generated runtime capabilities](documentation/generated/capabilities.md)
- [Vendor-version verification metadata](documentation/metadata/vendors.yml)

The runtime registry and executable schema are authoritative for code-derived capability facts. Vendor support matrices describe semantic limits and must not be interpreted as complete feature parity.

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

Start the web application:

```bash
fwmigrate serve --port 5000
```

Start the desktop launcher:

```bash
fwmigrate app
```

Example migration:

```bash
fwmigrate migrate \
  --input /path/to/source.conf \
  --output ./output \
  --source-vendor fortigate \
  --target-vendor palo_alto \
  --format terraform \
  --report ./output/migration_report.md
```

Live FortiGate source inventory:

```bash
fwmigrate-live-fortigate \
  --host 192.0.2.10 \
  --username admin \
  --verify-host-key \
  --output fortigate_source_inventory.xlsx
```

See the [user guide](documentation/how-to/user-guide.md) for workflow details.

## Safety model

The project follows these core rules:

1. **No silent loss:** migration-relevant source data must be normalized or explicitly accounted for.
2. **Fail closed:** missing, malformed, ambiguous, or unresolved semantics must not become broader values such as `any`, `allow`, `/0`, `/32`, or fabricated topology.
3. **Preserve evidence:** unsupported and non-portable source semantics remain available for review.
4. **Protect secrets:** passwords, usable PSKs, private keys, tokens, and equivalent credentials must not be exposed in normal outputs.

Detailed rules are in [`AGENTS.md`](AGENTS.md) and the [safety model](documentation/explanation/safety-model.md).

## Development and testing

```bash
python -m compileall -q src tests
python -m py_compile scripts/*.py scripts/docs/*.py
python scripts/docs/validate_docs.py
python scripts/docs/generate_docs.py --check
python -m pytest -q
```

CI runs the full test suite on Python 3.11, 3.12, and 3.13. Documentation consistency checks run in CI as well.

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
