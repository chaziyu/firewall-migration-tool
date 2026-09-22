# IR dependency inventory

Status: Phase 1 baseline. This inventory records the current boundary before removing
IR from shared extraction contracts. Existing worktree changes are intentionally preserved.

## Runtime classification

- Source reporting: `src/fwmigrate/source_reporting/`, vendor `source_report.py` modules,
  and `/api/preview` plus `/api/extract/excel` in `src/fwmigrate/web.py`.
- Legacy conversion: `src/fwmigrate/application/pipeline.py`,
  `src/fwmigrate/application/models.py`, `src/fwmigrate/generators/`, vendor-to-IR
  transformers, and migration-only parser adapters.
- Shared extraction contract: `src/fwmigrate/extraction/models.py`,
  `src/fwmigrate/extraction/finalize.py`, and `src/fwmigrate/core/base_parser.py`.
- Web/API conversion: `/api/migrate` in `src/fwmigrate/web.py`; it intentionally remains
  on `MigrationPipeline` until a separate conversion result contract exists.
- CLI and application entry points: `src/fwmigrate/main.py` and
  `src/fwmigrate/application/`.
- Presentation: `src/fwmigrate/report/`; `IRExcelExporter` is conversion/source-inventory
  legacy code, while vendor-native Excel exporters are under vendor packages.

## High-risk shared references

- `ExtractionResult.canonical_ir` is still required by legacy parser transformers,
  finalization, sanitization, and migration tests.
- `BaseSourceParser.parse()` remains a legacy compatibility projection, but no longer
  advertises `IRConfig` in its shared type contract.
- `finalize_extraction()` synchronizes IR safety fields and cannot be changed until the
  conversion-only result is separated.
- `MigrationPipeline` and target generators depend on the legacy IR path.
- `IRExcelExporter` is still used by `/api/migrate` for the optional migration inventory.

## Native source-reporting status

- FortiGate, Cisco ASA, Cisco FTD, Juniper SRX, and Check Point reporters already return
  vendor-native result objects.
- PAN-OS native reporting now returns only `PaloAltoSourceResult.config`, derived views,
  and validation. The legacy adapter remains available only for conversion callers.
- Shared source-reporting modules do not import `fwmigrate.ir`.

## Test classification

- Source-reporting contracts: `tests/architecture/test_source_reporting_contract.py`.
- Native vendor reporting: `tests/parsers/*/test_source_report.py` and
  `tests/vendors/*/test_source_reporting.py`.
- Web source reporting: `tests/test_web_source_reporting.py`.
- Legacy conversion and IR compatibility: `tests/ir/`, migration pipeline tests,
  parser contract baselines, and FortiGate migration regression tests.

## Phase 2/3 checklist

- [x] Remove PAN-OS legacy extraction from native analysis results.
- [x] Keep PAN-OS legacy adapter available for conversion callers.
- [x] Remove the shared `BaseSourceParser.parse()` return-type dependency on `IRConfig`.
- [x] Disable `/api/migrate` and Terraform preparation with HTTP 503.
- [x] Disable the CLI migration command with the same message.
- [x] Remove target-generator registrations from builtin startup registration.
- [x] Replace `MigrationPipeline` with an explicit unavailable compatibility shell.
- [ ] Remove vendor-to-IR transformers after all legacy imports and tests are migrated.
- [ ] Remove the IR core and generic target generators after runtime references reach zero.
- [ ] Introduce a conversion-only extraction result before removing `canonical_ir`.
- [ ] Move generation safety fields out of the source-only contract.
- [ ] Migrate `BaseSourceParser.parse()` callers.
- [ ] Update conversion tests before deleting the shared IR field.
- [ ] Run full architecture, vendor, web, and migration test suites.
