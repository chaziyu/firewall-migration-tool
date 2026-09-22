# Firewall Migration Tool

![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

Vendor-native firewall configuration extraction, validation, preview, and Excel reporting for Python 3.10+.

> **Project status**
>
> This branch focuses on **source extraction and reporting**.
>
> Cross-vendor configuration conversion is currently unavailable while the conversion architecture is being redesigned around pair-specific converters.

## Overview

Firewall Migration Tool analyzes firewall configuration sources while preserving vendor-specific source semantics.

The current source-reporting pipeline is:

```text
Vendor Source
→ Vendor Parser / Source Adapter
→ Vendor Source Config
→ Relationships / Transforms
→ Vendor DerivedViews
→ Validation
→ Web Preview / Excel
```

The architecture prioritizes:

```text
correctness
→ source preservation
→ clear semantics
→ traceability
→ maintainability
```

Source configuration is not forced through a vendor-neutral firewall model for reporting.

A missing source-model field means that the value was **not explicitly configured in the authoritative source**. Vendor defaults are not silently inserted into source models.

Unsupported or partially understood configuration is preserved where practical rather than silently discarded.

## Current Capabilities

The current branch supports:

- Vendor-native firewall configuration extraction.
- Source inventory and unsupported-source accounting.
- Vendor-specific relationship and topology resolution.
- Read-only derived views.
- Validation without silently repairing source configuration.
- Web-based source configuration preview.
- Vendor-specific Excel reporting.
- Secret sanitization for reportable source evidence.
- Multiple source formats where supported by the vendor implementation.

Cross-vendor configuration generation is not currently available.

## Supported Source Vendors

| Vendor | Vendor ID | Accepted Input | Notes |
|---|---|---|---|
| Fortinet FortiGate | `fortigate` | `.conf`, `.cfg`, `.txt` | FortiGate CLI configuration |
| Cisco ASA | `cisco_asa` | `.cfg`, `.txt`, `.conf` | ASA command-oriented configuration |
| Cisco Firepower Threat Defense | `cisco_ftd` | `.cfg`, `.txt`, `.conf`, `.json` | FMC/FDM bundles and FTD CLI/text evidence |
| Juniper SRX / Junos | `juniper_srx` | `.set`, `.txt`, `.conf` | Junos configuration sources |
| Check Point R80/R81 | `checkpoint` | `.json`, `.txt`, `.cfg` | Management export/API-style data and Gaia CLI sources |
| Palo Alto Networks PAN-OS / Panorama | `palo_alto` | `.xml` | XML configuration only |

### Cisco FTD

FTD supports multiple source planes:

```text
FMC API / export
FDM API / export
FTD CLI / device evidence
```

These inputs are not treated as equivalent.

CLI-only extraction does not manufacture FMC/FDM-managed policy data that is not present in the authoritative input.

Examples include:

```text
Access Control Policy rules
managed NAT policy
managed objects
other FMC/FDM-only policy state
```

### PAN-OS

PAN-OS source reporting currently accepts XML configuration.

PAN-OS CLI `set` format is not currently supported.

### Check Point

Check Point reporting keeps source scope information distinct where available, including:

```text
Management API
domain
package
layer
gateway
Gaia / gateway CLI
```

Failed or incomplete collection evidence is not interpreted as an empty configuration.

## Installation

Clone the repository and switch to the refactor branch:

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
git switch codex/refactor
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Upgrade pip and install the project:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Usage

### List Registered Source Vendors

```bash
fwmigrate vendors
```

Equivalent module invocation:

```bash
python -m fwmigrate.main vendors
```

### Start the Web Application

```bash
fwmigrate serve --port 5000
```

Then open:

```text
http://localhost:5000
```

Equivalent module invocation:

```bash
python -m fwmigrate.main serve --port 5000
```

The web application currently supports the source-reporting workflow:

```text
upload source configuration
→ select source vendor
→ parse and analyze
→ review source preview and validation
→ export vendor-native Excel report
```

## Conversion Status

Cross-vendor configuration conversion is currently disabled.

The existing `migrate` CLI command is retained as a compatibility boundary but does not perform conversion.

Future conversion is intended to use directional, pair-specific pipelines:

```text
VendorSourceConfig
→ VendorDerivedViews
→ pair-specific converter
→ TargetVendorConfig
→ target validation
→ target renderer
```

The reserved conversion boundary is located at:

[`src/fwmigrate/conversion/`](src/fwmigrate/conversion/)

See:

[`src/fwmigrate/conversion/README.md`](src/fwmigrate/conversion/README.md)

No pair-specific converter is currently implemented.

The source-reporting architecture does not use a vendor-neutral migration IR.

## Architecture

Each vendor owns its source semantics and reporting pipeline.

Shared infrastructure handles orchestration and presentation contracts without requiring vendors to expose a common firewall data model.

```text
Tokenizer / Scanner
    syntax and lexical structure only

Parser / Source Adapter
    vendor structure and explicit source data

Command Evaluator
    source command semantics

Vendor Source Config
    explicit vendor source state

Relationships
    references, memberships, bindings and topology

Transforms
    vendor-specific semantic normalization and genuine derived values

DerivedViews
    read-only derived representation

Validation
    detect and report only

Web Preview / Excel
    presentation only
```

Validation and derived processing must not silently mutate or repair source configuration.

Shared source-reporting code treats vendor analysis results as opaque.

It does not require every vendor to expose a common representation for:

```text
addresses
services
policies
NAT
interfaces
zones
routes
VPNs
```

For detailed architecture and development rules, see:

[`AGENTS.md`](AGENTS.md)

## Source Value Semantics

The extraction pipeline keeps these concepts distinct:

```text
explicit source value
derived value
effective value
vendor default
unknown value
unsupported source value
```

A missing source-model field does not automatically mean:

```text
disabled
false
empty
zero
inherit
any
vendor default
```

Only explicitly configured source values belong in authoritative source state.

Effective values should only be exposed when vendor-specific logic actually calculates them.

## Source Preservation

Useful source configuration should be preserved even when the tool does not fully understand its semantics.

Depending on the vendor, this may include:

```text
raw_extra
unsupported commands
source attributes
source metadata
source inventory
additional settings
source appendix sheets
collection evidence
```

When behavior is unclear, the preferred handling is:

```text
preserve source
→ classify as unknown / unsupported / source-only
→ report the limitation
→ do not guess
```

## Validation

Validation detects and reports problems.

Validation does not silently repair source configuration.

Examples include:

```text
broken references
duplicate names
invalid memberships
unresolved interfaces
policy binding problems
topology issues
unsupported constructs
ambiguous source data
collection incompleteness
derived transformation issues
```

Validation output should distinguish between:

```text
source configuration issue
unsupported extraction
unknown interpretation
derived-view limitation
collection/input limitation
```

## Excel Reporting

Excel is a presentation layer.

Each vendor owns its Excel schema and exporter.

Vendor Excel reports may contain:

```text
explicit source fields
genuine derived fields
validation findings
source inventory
unsupported/source-only evidence
additional settings
source appendix information
```

Excel reporting should not drive source-model design.

The reporting layer should not introduce:

```text
vendor-neutral IR fields
target-vendor fields
fake effective values
redundant normalized duplicates
unsupported inferred values
```

## Security and Sensitive Configuration

Firewall configurations may contain sensitive authentication material.

The reporting pipeline must not expose actual secrets such as:

```text
passwords
pre-shared keys
private keys
API keys
tokens
authentication credentials
secret strings
sensitive SNMP community values
```

Safe metadata may be reported instead:

```text
Password Configured = Yes
PSK Configured = Yes
Credential Present = Yes
```

Secret handling applies to:

```text
source extraction
source inventory
unsupported/raw evidence
validation messages
web preview
Excel
logs
```

Configuration files and generated reports should still be treated as sensitive operational data.

## Project Structure

Key areas of the current architecture:

```text
src/fwmigrate/
├── extraction/
│   └── Shared extraction evidence and accounting utilities
│
├── source_reporting/
│   └── Shared source-report dispatch and presentation utilities
│
├── vendors/
│   └── Vendor-owned extraction and reporting implementations
│
├── conversion/
│   └── Reserved future pair-specific conversion boundary
│
├── web.py
│   └── Shared web host and source-report dispatch
│
└── main.py
    └── CLI entry point
```

Vendor-specific logic belongs inside the corresponding vendor package.

Examples include:

```text
parsing
source models
relationships
transforms
DerivedViews
validation
preview serialization
Excel export
```

## Development

The `codex/refactor` branch is focused on **source architecture stabilization**.

The intended source-reporting direction is:

```text
source
→ VendorConfig
→ relationships / transforms
→ VendorDerivedViews
→ validation
→ preview / Excel
```

Development should preserve vendor-native source semantics and avoid recreating the previous shared migration architecture.

Do not reintroduce for source reporting:

```text
vendor-neutral source IR
common firewall object hierarchy
generic migration schema used for Excel
cross-vendor normalized policy model
target-vendor concepts inside source models
shared semantic Excel exporter
```

The future `conversion/` boundary should remain separate from source extraction and reporting until individual conversion pairs are implemented.

Current branch-specific priorities are documented in:

[`Refactor Plan.md`](Refactor%20Plan.md)

## Testing

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Compile source and tests:

```bash
python -m compileall -q src tests
```

Run the test suite:

```bash
python -m pytest -q
```

The source-reporting path should be tested end-to-end:

```text
source
→ parser / source adapter
→ VendorConfig
→ DerivedViews
→ validation
→ web preview / Excel
```

Important regression areas include:

```text
nested configuration
contexts
domains
VSYS
logical systems
unknown fields
unsupported fields
reference resolution
interface topology
policy ordering
NAT ordering
source provenance
collection completeness
Excel compatibility
secret redaction
web preview
Excel download
```

Cross-vendor conversion tests should remain separate from source extraction tests.

## Documentation

Repository architecture and implementation guidance:

- [`AGENTS.md`](AGENTS.md) — architecture rules and development constraints.
- [`Refactor Plan.md`](Refactor%20Plan.md) — current source-architecture stabilization priorities.
- [`src/fwmigrate/conversion/README.md`](src/fwmigrate/conversion/README.md) — reserved future conversion architecture.

Official vendor documentation should be used as the primary semantic reference when implementing or validating vendor behavior.

When implementation behavior is uncertain:

```text
preserve source
→ mark unknown / unsupported
→ report the limitation
→ do not guess
```