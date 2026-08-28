# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)
![Package](https://img.shields.io/badge/package-0.2.0-blue.svg)
![IR Schema](https://img.shields.io/badge/IR%20schema-1.2-purple.svg)

A Python-based multi-vendor firewall extraction, inventory, migration, and target-generation platform.

The project uses a vendor-neutral Intermediate Representation (IR) to separate source parsing from target generation. FortiGate file extraction additionally uses an `ExtractionResult` accounting layer so source configuration can be classified instead of silently disappearing.

> **Project status**
>
> The architecture supports multiple source and target plugins, but feature depth is not identical across every vendor pair. FortiGate extraction is currently the most deeply audited path. Migration output should always be reviewed before deployment.

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modified in 2026 by Cha Zi Yu**  
**License:** GNU Affero General Public License v3.0 (AGPL-3.0)

> **Acknowledgments**
>
> This project is a derivative work adapted from the
> [gswsystems/fortigate-palo-migration](https://github.com/gswsystems/fortigate-palo-migration)
> repository by GSW Systems and is distributed under the AGPL-3.0 license.

---

## Documentation

The authoritative architecture and extraction references are:

- [IR Data Structure](documentation/IR_DATA_STRUCTURE.md) — canonical vendor-neutral IR contract and schema evolution.
- [Extraction Data Model](documentation/EXTRACTION_DATA_MODEL.md) — source accounting, coverage statuses, zero-silent-loss rules, and Excel extraction behavior.
- [Project Detail](documentation/Project%20Detail.md) — implementation and project-level details.
- [User Manual](documentation/User%20Manual.md) — operational usage guidance.
- [AGENTS.md](AGENTS.md) — repository engineering rules and migration-safety invariants.

---

## Architecture

```text
Source configuration file
             |
             v
      Vendor source adapter
             |
             +-----------------------------+
             |                             |
             | FortiGate file extraction   | Other/current IR-only paths
             v                             v
      ExtractionResult                Canonical IR
        |       |
        |       +--> source inventory / unsupported / coverage
        |
        +--> Canonical IR
                 |
                 +--> Excel source inventory
                 |    (before optimizer pruning)
                 |
                 +--> validation / optimizer
                 |
                 v
          Target generator
                 |
        +--------+---------+
        |                  |
        v                  v
 Native / CLI / XML     Terraform
        |
        +--> migration reports / packages
```

### Separation of responsibilities

- **Tokenizer/parser/source models** understand source-vendor syntax.
- **ExtractionResult** answers what existed in the source and what happened to it during extraction.
- **Canonical IR (`IRConfig`)** represents portable or intentionally retained migration semantics.
- **Optimizer** performs optional rule/object analysis after source inventory is captured.
- **Target generators** consume IR and produce target-specific artifacts.
- **Excel** is an extraction/inventory output and must not reinterpret raw vendor syntax as target semantics.

---

## Safety and fidelity rules

The project follows these core rules:

1. **Zero silent loss** — migration-relevant source configuration must be accounted for.
2. **No permissive fallback** — uncertain input must never become `any`, `/0`, `/32`, `allow`, or another broader valid semantic merely to keep processing.
3. **Normalize only portable semantics** — vendor-specific information can remain extract-only or source metadata.
4. **Preserve source evidence** — useful non-secret values that cannot be normalized remain available for inventory/manual review.
5. **Do not invent zones** — canonical trust/untrust zones are not inferred from interface names, aliases, descriptions, or FortiGate interface roles.
6. **Do not expose secrets** — passwords, usable PSKs, private keys, tokens, and similar credentials are not written to ordinary IR or Excel exports.
7. **Withhold unsafe target output** — generators should omit or flag rules/routes whose required canonical semantics are unresolved rather than broaden them.

### Extraction statuses

FortiGate source sections can be classified as:

```text
NORMALIZED
PARTIALLY_NORMALIZED
EXTRACT_ONLY
VENDOR_EXTENSION
UNSUPPORTED
IGNORED_BY_POLICY
PARSE_ERROR
```

`NORMALIZED` means the source semantics are represented in canonical IR. It does not mean every source-vendor feature has a one-to-one implementation on every target.

---

## IR schema versioning

Serialized canonical IR carries a root-level schema version:

```json
{
  "schema_version": "1.2"
}
```

The current schema is:

```text
IR_SCHEMA_VERSION = 1.2
```

Schema version is independent from source firewall software version, parser version, and application package version. Unsupported or incompatible declared IR versions must be rejected or explicitly migrated rather than guessed.

---

## Vendor plugins

Built-in source and target adapters are registered for:

| Vendor | Source adapter | Target generator |
|---|---:|---:|
| Fortinet FortiGate | Yes | Yes |
| Palo Alto Networks PAN-OS / Panorama | Yes | Yes |
| Cisco ASA / Firepower | Yes | Yes |
| Check Point | Yes | Yes |
| Juniper SRX / JunOS | Yes | Yes |

The M×N architecture means source and target adapters are decoupled through IR. It does **not** imply equal semantic coverage for every feature on every source-target pair.

Run:

```bash
fwmigrate vendors
```

to list the currently registered vendors and advertised target formats.

### Check Point R81 extraction safety

Check Point `checkpoint-export-v1` and Gaia inputs produce canonical IR plus
`ExtractionResult` source accounting. Automatic generation is deliberately
withheld for mixed zone/address OR conditions, mixed service/application OR
conditions, unsupported actions, translated-service NAT, nonportable match
objects, incomplete pagination, and ambiguous domain/package/layer scope.
Dual-stack source objects, time groups, and group-with-exclusion objects remain
visible for review without being treated as universally target-safe.

`scripts/export_checkpoint_bundle.py` is a live, paginated `mgmt_cli` collector.
Already-collected JSON response files can be assembled offline with
`fwmigrate.parsers.checkpoint.bundle_builder.build_checkpoint_bundle`.

### Current target formats

Examples from the built-in generators include:

- **Palo Alto Networks:** XML, Terraform
- **FortiGate:** CLI, Terraform
- **Cisco ASA / Firepower:** CLI, Terraform
- **Check Point:** CLI / `mgmt_cli` script, Terraform
- **Juniper SRX:** JunOS `set` / CLI, Terraform

---

## FortiGate extraction coverage

FortiGate is currently the most extensively audited source parser.

```text
FortiGate CLI backup
→ tokenizer
→ parser
→ FortiGate source models
→ ExtractionResult
→ canonical IR
→ Excel inventory
→ optional optimizer
→ target generation
```

Current typed handling covers major areas including:

- system settings and DNS;
- interfaces and explicit system zones;
- DHCP inventory;
- IPv4/IPv6 addresses, address groups, and wildcard FQDNs;
- service categories, services, and service groups;
- recurring and one-time schedules;
- firewall policies and source-policy metadata;
- IP pools;
- virtual IPs, real servers, and VIP groups;
- NAT structures;
- IPsec VPN inventory;
- certificates and SSH keys;
- static routes;
- SD-WAN;
- Internet services;
- FortiClient EMS / ZTNA provider inventory;
- IPS sensors and entries;
- LDAP, SAML, local users, and user groups;
- SSL VPN settings, portals, rules, and host checks;
- DoS policies/anomalies;
- firewall sniffer inventory;
- authentication schemes/rules;
- session helpers and session-TTL overrides;
- traffic shapers;
- proxy addresses and global web-proxy settings.

Some of these are deliberately `EXTRACT_ONLY` or `PARTIALLY_NORMALIZED` because the source semantics are useful for inventory but are not safely portable across vendors.

Additional FortiGate security-profile and routing families can be retained as structured source-only inventory rather than being forced into canonical IR.

---

## Interface and zone behavior

Interface role and canonical zone are separate concepts.

```text
FortiGate:
    set role wan

Possible IR:
    role = "wan"
    zone = null
```

`IRInterface.zone` is assigned only from explicit evidence such as:

- caller-provided `zone_mapping`;
- configured FortiGate `system zone` membership;
- explicit SD-WAN zone membership.

The transformer does not create `trust`, `untrust`, or `dmz` solely from interface names or source roles.

Unresolved interface references remain preserved on policies through fields such as:

```text
source_from_interfaces
source_to_interfaces
```

Target generators must not turn missing canonical zones into `any`.

---

## Static routes

FortiGate static routes preserve routing semantics separately.

```text
FortiGate set distance
→ IR administrative_distance

FortiGate set priority
→ IR priority

FortiGate set blackhole
→ IR blackhole

FortiGate set sdwan-zone
→ IR SD-WAN route association
```

Administrative distance is not treated as a generic route metric.

A valid FortiGate default route is represented as:

```text
0.0.0.0/0
```

including the FortiGate case where `set dst` is omitted.

Malformed route, interface, or address netmasks are not repaired into valid `/0` or `/32` prefixes. Source evidence is preserved and the affected object is marked for manual review / parse failure.

---

## Excel inventory

The web file-upload path can export a source inventory workbook independently of target generation.

For FortiGate file uploads, the workbook uses authoritative `ExtractionResult` evidence and is generated **before optimizer pruning**.

Representative sheets include:

- Summary
- System Settings / DNS Settings
- Interfaces / Interface Source Settings
- DHCP inventory
- Zones
- Addresses / Address Groups
- Proxy and Web Proxy inventory
- Services and Service Groups
- Session Helpers / Session TTL Overrides
- Schedules / Traffic Shapers
- Policies
- ZTNA Providers
- IP Pools
- Virtual IPs / VIP Real Servers / VIP Groups
- NAT Rules
- VPN / SSL VPN inventory
- Certificates / SSH Keys
- Routes
- Routing Protocol source inventory
- SD-WAN
- Internet Services
- IPS Sensors / Entries
- Security Profile source inventory
- LDAP / SAML / Local Users / User Groups
- DoS / Firewall Sniffer / Authentication inventory
- Warnings
- Unsupported
- Extraction Coverage

Exact sheet availability depends on the extracted data and current implementation.

### Extraction Coverage

For FortiGate file extraction, the coverage sheet records source-section evidence such as source, parsed, and normalized counts, status, parser handler, source line range when available, and notes.

Count equality alone is not considered proof of semantic completeness when parse errors, unresolved semantics, or retained unmodeled route settings exist.

---

## Installation

### Requirements

- Python 3.10+
- Git
- Platform-specific requirements for live-device or Terraform workflows you choose to use

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
python -m pip install -e .
```

Development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Optional vendor extras are defined in `pyproject.toml`.

---

## Usage

### List registered vendors

```bash
fwmigrate vendors
```

### Start the web interface

```bash
fwmigrate serve --port 5000
```

Open:

```text
http://localhost:5000
```

On Windows, `run_migration.bat` starts the web server on port 5000.

### Launch the desktop application

```bash
fwmigrate app
```

A Windows standalone executable is present at:

```text
dist/Firewall Migration Tool.exe
```

### CLI migration example

```bash
fwmigrate migrate   --input examples/example_fortigate.conf   --output ./output   --source-vendor fortigate   --target-vendor palo_alto   --format terraform   --report ./output/migration_report.md
```

### Explicit zone mapping

```bash
--zone-map path/to/zone_map.yaml
```

Explicit zone mapping is authoritative input. The transformer does not fall back to trust/untrust naming heuristics when no mapping exists.

---

## Web outputs

### Excel extraction

Source configuration can be downloaded as a vendor-neutral/source-accounting workbook. FortiGate file uploads use the authoritative extraction model and retain source coverage/unsupported evidence.

### Migration package

The web migration workflow can package:

- target-native / Terraform artifacts;
- `migration_report.md`;
- `migration_report.html`;
- source inventory Excel workbook.

Source inventory is produced before optional optimizer pruning.

---

## Optimization

The optimizer supports analysis such as:

- unused-object detection;
- duplicate-object analysis;
- shadowed-rule detection;
- optional unused-object pruning;
- implemented structural rule corrections.

Optimization is separate from extraction. Source Excel inventory should represent the extracted source before optional pruning.

---

## Testing

Run locally with:

```bash
pytest -q
```

or:

```bash
python -m pytest -q
```

This README intentionally does not hard-code a test-pass count because that number becomes stale as tests are added.

Extraction regressions should cover parser → source model → IR → Excel, source-section coverage, malformed input, secret redaction, no silent loss, and safe withholding of unresolved target semantics.

---

## Building the Windows executable

The repository contains:

```text
Firewall Migration Tool.spec
```

With PyInstaller installed:

```bash
python -m pip install pyinstaller
pyinstaller "Firewall Migration Tool.spec"
```

Build output is expected under `dist/`.

---

## Known limitations and review requirements

This tool is an engineering aid, not an automatic guarantee of semantic equivalence.

Important limitations include:

- vendor feature parity varies;
- extraction-only data may not have target-generation support;
- some security-profile families remain source inventory instead of portable policy models;
- runtime-learned values such as some DHCP/PPPoE gateways may not exist in backup files;
- unresolved canonical zones cause affected rules to be withheld rather than widened;
- malformed network syntax is preserved and flagged rather than repaired;
- hardware/cluster/platform-specific settings may be unsupported or intentionally ignored;
- target configuration must be reviewed and validated before deployment.

---

## Repository structure

```text
src/fwmigrate/
├── extraction/              # ExtractionResult/source accounting models
├── ir/                      # Canonical IR and schema versioning
├── parsers/                 # Source-vendor adapters
│   ├── fortigate/
│   ├── palo_alto/
│   ├── cisco_asa/
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

---

## Development principles

When adding or modifying source extraction:

```text
source syntax
→ source model
→ ExtractionResult / canonical IR
→ Excel
→ target generation
```

For every migration-relevant source field, decide explicitly whether it is:

```text
NORMALIZED
PARTIALLY_NORMALIZED
EXTRACT_ONLY
VENDOR_EXTENSION
UNSUPPORTED
IGNORED_BY_POLICY
PARSE_ERROR
```

Do not force every vendor field into canonical IR. Preserve useful source-only semantics separately and require manual review when portability is uncertain.

---

## License

This repository is licensed under the GNU Affero General Public License v3.0.

See [LICENSE](LICENSE) for the full license text.
