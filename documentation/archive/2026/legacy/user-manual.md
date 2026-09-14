# Firewall Migration Tool — User Manual

This guide describes the current file-conversion, source-inventory, CLI, and
reviewed Terraform deployment workflows. Parser support is source-accounted:
individual objects can be `NORMALIZED`, `PARTIALLY_NORMALIZED`, `EXTRACT_ONLY`,
`UNSUPPORTED`, or `PARSE_ERROR`. A supported vendor does not mean every
vendor-specific setting is safe to generate.

## Contents

1. [Supported platforms](#1-supported-platforms)
2. [Launch](#2-launch)
3. [Prepare a source export](#3-prepare-a-source-export)
4. [Offline file conversion](#4-offline-file-conversion)
5. [Live source extraction](#5-live-source-extraction)
6. [Live deployment](#6-live-deployment)
7. [CLI](#7-cli)
8. [Output and review](#8-output-and-review)
9. [Troubleshooting](#9-troubleshooting)

## 1. Supported platforms

| Source capability | Input extensions / bundle | Target formats |
|---|---|---|
| Fortinet FortiGate | `.conf`, `.cfg`, `.txt` | `cli`, `terraform` |
| Palo Alto PAN-OS / Panorama | `.xml` | `xml`, `terraform` |
| Cisco ASA | `.cfg`, `.txt`, `.conf` | `cli`, `terraform` |
| Cisco FTD / FMC export | `.json` FMC REST bundle, plus supported text forms | `cli`, `terraform` through the Cisco target |
| Check Point R80/R81 | `.json`, `.txt`, `.cfg` | `cli`, `terraform` |
| Juniper SRX / Junos | `.set`, `.txt`, `.conf` | `set`, `cli`, `terraform` |

Run `fwmigrate vendors` for the registered list. The vendor reference documents
describe the semantic limits for [FortiGate](FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md),
[PAN-OS](PALO_ALTO_EXTRACTION_REFERENCE.md),
[Cisco FMC](CISCO_FMC_EXTRACTION.md),
[Check Point](CHECKPOINT_SUPPORT_MATRIX.md), and
[Juniper SRX](JUNIPER_SRX_CONFIG_EXTRACTION_REFERENCE.md).

## 2. Launch

Install the project and development/report dependencies:

```powershell
python -m pip install -e ".[dev]"
```

Then use one of these entry points:

```powershell
fwmigrate serve --port 5000   # web UI, including FortiGate live extraction
fwmigrate app                 # native desktop UI
```

On Windows, `run_migration.bat` starts the web UI. The built executable, when
present, is under `dist/`.

## 3. Prepare a source export

- **FortiGate:** `show full-configuration`.
- **PAN-OS / Panorama:** export the XML running configuration.
- **Cisco ASA:** `show running-config` with paging disabled.
- **Cisco FTD / FMC:** assemble the offline bundle documented in
  [CISCO_FMC_EXTRACTION.md](CISCO_FMC_EXTRACTION.md), using
  `format: "cisco-fmc-rest-export-v1"` and `source: "fmc-rest-api"`.
- **Check Point:** provide the JSON management export/bundle; Gaia command
  collection is separate source evidence.
- **Juniper SRX:** `show configuration | display set | no-more`, or provide
  hierarchical configuration. Both forms are normalized by the parser.

Keep the original export unchanged. The upload API accepts UTF-8 and rejects a
decode failure instead of silently dropping bytes.

## 4. Offline file conversion

1. Open **Convert Config File**.
2. Select the source and target vendors.
3. Upload the source export.
4. Optionally enable **Optimize** for unused-object pruning and rule/object
   analysis.
5. Download the migration package.

The source is parsed into `ExtractionResult` and canonical `IRConfig` before
optimization. Source inventory is generated from the pre-optimization result;
target generation consumes canonical IR and applies fail-closed safety checks.

Use **Extract to Excel** when you only need the source inventory. It does not
require a target vendor and does not run target conversion or optimizer pruning.

## 5. Live source extraction

Live source extraction is currently **FortiGate-only** and is available under
**Extract to Excel → Input Method: Live Firewall**.

1. Enter the FortiGate host, SSH port, username, and password.
2. Optionally enable known-host verification.
3. Run **Test Connection**, then **Pull Configuration**.
4. After a complete snapshot, download the source inventory workbook.

The collector runs `get system status` and `show full-configuration` over a
non-PTY SSH channel. The raw snapshot is held temporarily in server memory;
credentials are not stored in the snapshot. Collection completeness does not
mean that every source semantic is migration-ready.

See [LIVE_SOURCE_EXTRACTION.md](LIVE_SOURCE_EXTRACTION.md) for the collection
contract and CLI collector.

## 6. Live deployment

The **Live migration** tab currently supports **PAN-OS targets**.

1. Upload the source configuration in the file workflow.
2. Enter the PAN-OS management host, HTTPS port, and API key or credentials.
3. Run the connection diagnostics.
4. Prepare the Terraform session and run a dry-run plan.
5. Review the plan and audit output, then explicitly approve the session.
6. Start the apply only after review.

Rollback runs Terraform destroy for resources tracked by that session. It is not
a full device snapshot restore. Treat apply and rollback as high-impact
operations and keep the target firewall's own backup/recovery process in place.

## 7. CLI

List the current plugin registry:

```powershell
fwmigrate vendors
```

Convert a Cisco ASA export to PAN-OS Terraform:

```powershell
fwmigrate migrate `
  --input backup/cisco_asa.cfg `
  --source-vendor cisco_asa `
  --target-vendor palo_alto `
  --format terraform `
  --output .\output_palo_alto `
  --report .\output_palo_alto\migration_report.md
```

The `migrate` command also accepts `--zone-map` and `--optimize`. Its format
choices are `xml`, `set`, `terraform`, and `cli`. `serve` and `app` accept
`--port`.

## 8. Output and review

The web conversion package contains:

```text
migration_<source>_to_<target>.zip
├── migration_report.md
├── migration_report.html
├── source_inventory_<vendor>.xlsx
├── target native artifacts
└── terraform/                 # when Terraform artifacts are generated
```

The CLI writes artifacts to the requested output directory and writes both
Markdown and HTML reports when `--report` is supplied.

Before using generated configuration:

- review the migration report and source-inventory workbook;
- resolve all `requires_manual_review` and blocking findings;
- confirm that unsupported or extract-only source data has an approved manual
  treatment;
- run the target platform's validation/commit checks in a controlled window.

Credentials, PSKs, private keys, and similar secrets are redacted from source
inventory and audit output. Do not add real secrets to examples, tickets, or
generated documentation.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `No module named fwmigrate` | Run `python -m pip install -e ".[dev]"`. |
| Upload stops at decode | Save the source export as valid UTF-8 and upload again. |
| Vendor is unavailable | Run `fwmigrate vendors`; check the source extension/bundle. |
| Objects are withheld | Read the report’s blocking reasons and source review evidence; do not broaden missing values manually. |
| Live deployment cannot plan | Run diagnostics, verify Terraform/provider access, and check PAN-OS connectivity/authentication. |
| Live collection is incomplete | Review SSH errors, permissions, pager markers, and collector warnings. |
