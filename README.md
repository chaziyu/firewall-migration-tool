# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

A Python 3.10+ multi-vendor firewall configuration extraction and migration platform.

The core goal of this project is **reliable, auditable extraction** of firewall intent into a vendor-neutral intermediate representation (IR) before converting it into target configurations or reports.

## Supported source vendors

- Fortinet FortiGate
- Palo Alto Networks PAN-OS / Panorama
- Cisco ASA
- Cisco Firepower Threat Defense (FTD)
- Check Point R80/R81
- Juniper SRX / Junos

## Documentation & Architecture

- **[Documentation Index](documentation/README.md)**: Details on the canonical IR model and vendor-specific mappings.
- **[AGENTS.md](AGENTS.md)**: Core architectural rules, extraction pipeline steps, and safety principles (fail-closed, no silent loss).

## Installation

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
python -m pip install -e .
```

## Basic Usage

Start the web application:

```bash
python -m fwmigrate.main serve --port 5000
```

## Development and Testing

Before submitting changes, ensure all validations pass:

```bash
python -m compileall -q src tests
python -m py_compile scripts/*.py scripts/docs/*.py
python -m pytest -q
```

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).

Copyright © 2025 GSW Systems.  
Modified in 2026 by Cha Zi Yu.

This project is derived from [gswsystems/fortigate-palo-migration](https://github.com/gswsystems/fortigate-palo-migration) and remains distributed under AGPL-3.0.
