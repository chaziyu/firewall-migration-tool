# User Guide

## 1. Install

For development and reporting workflows:

```bash
python -m pip install -e ".[dev]"
```

## 2. Check registered vendors

Run:

```bash
fwmigrate vendors
```

The committed registry-derived table is also available in [`../generated/capabilities.md`](../generated/capabilities.md).

Source and target registration are separate. For example, `cisco_ftd` is a registered source parser but is **not** a registered FTD target generator. Do not interpret a source parser as a same-vendor target capability.

## 3. Start the application

```bash
fwmigrate serve --port 5000
```

For the desktop launcher:

```bash
fwmigrate app
```

On Windows, `run_migration.bat` starts the web workflow.

## 4. Prepare a source export

Use a complete, unchanged source export where possible:

- **FortiGate**: `show full-configuration`.
- **PAN-OS / Panorama**: exported XML running configuration.
- **Cisco ASA**: `show running-config` with paging disabled.
- **Cisco FTD / FMC**: use the offline FMC REST bundle described in [`../reference/vendors/cisco/fmc-extraction-reference.md`](../reference/vendors/cisco/fmc-extraction-reference.md) for policy/NAT migration. FTD text is limited management/interface/route evidence and is generation-blocked for full policy migration.
- **Check Point**: supported management JSON/API bundle and/or Gaia configuration evidence as documented in the vendor reference.
- **Juniper SRX**: root-level `show configuration | display set | no-more` or supported hierarchical configuration.

Do not modify the source export to hide parse errors. Source-accounting findings are part of the migration review.

## 5. Offline conversion

1. Select source and target vendors.
2. Upload the source configuration.
3. Optionally enable optimization.
4. Generate and download the migration package.
5. Review the migration report and source inventory before using target artifacts.

The source is extracted to `ExtractionResult` and canonical `IRConfig` before target generation. Unsupported or incomplete source semantics can make generation unsafe even when the vendor itself is registered.

## 6. Source inventory only

Use **Extract to Excel** when the requirement is source inventory rather than target conversion. Source inventory is produced from extraction/accounting data and should represent source state before optional optimizer pruning.

## 7. Live FortiGate extraction

Live source acquisition is currently FortiGate-only. Follow [`live-fortigate-extraction.md`](live-fortigate-extraction.md).

## 8. CLI migration

Example:

```bash
fwmigrate migrate \
  --input backup/cisco_asa.cfg \
  --source-vendor cisco_asa \
  --target-vendor palo_alto \
  --format terraform \
  --output ./output_palo_alto \
  --report ./output_palo_alto/migration_report.md
```

Use `fwmigrate vendors` to verify the current registry rather than relying on copied tables in old documentation.

## 9. Review before deployment

Before applying generated configuration:

- review migration and source-inventory findings;
- resolve blocking reasons and manual-review items;
- confirm treatment of `EXTRACT_ONLY`, `VENDOR_EXTENSION`, `UNSUPPORTED`, and parse-error evidence;
- validate output with the target platform's own commit/check mechanisms;
- retain the target platform's normal backup and recovery process.

Generated output is not a substitute for target-platform validation.
