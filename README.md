# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

A Python 3.10+ multi-vendor firewall configuration extraction and reporting platform.

The current product is **reliable, auditable vendor-native extraction**:

```text
Vendor source → VendorConfig → DerivedViews → validation → vendor preview / Excel
```

Configuration conversion is temporarily unavailable. The future boundary is
reserved in [`src/fwmigrate/conversion/`](src/fwmigrate/conversion/README.md)
for pair-specific converters; no converter or replacement IR is implemented.

## Supported source vendors

- Fortinet FortiGate
- Palo Alto Networks PAN-OS / Panorama
- Cisco ASA
- Cisco Firepower Threat Defense (FTD)
- Check Point R80/R81
- Juniper SRX / Junos

## Architecture

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
python -m pytest -q
```
