# Universal Multi-Vendor Firewall Migration Platform

**Document status:** Current architecture summary. Executable source and
registered plugin metadata are authoritative when this document drifts.

## 1. Architecture

The project uses an M×N source-parser / canonical-IR / target-generator design:

```text
source file or approved source snapshot
        -> source parser / extractor
        -> ExtractionResult + canonical IRConfig
        -> validation and optional optimizer
        -> target generator
        -> native config, Terraform, reports, and source inventory
```

Parsers do not contain target-vendor conversion logic. Generators consume
`IRConfig`; source-only and unsupported semantics remain in extraction evidence
and are not silently broadened.

## 2. Current repository map

```text
src/fwmigrate/
├── core/          # parser/generator interfaces, registry, optimizer
├── extraction/    # ExtractionResult and source-accounting models
├── ir/            # canonical Pydantic IR, JSON I/O, migrations, versioning
├── parsers/       # FortiGate, PAN-OS, Cisco ASA/FTD, Check Point, Juniper
├── generators/    # native and Terraform target generators
├── collectors/    # read-only FortiGate live SSH collection
├── deployment/    # deployment/rollback boundaries and snapshots
├── engine/        # Terraform runner, diagnostics, binary management
├── report/        # migration reports and Excel source inventory
├── templates/     # web UI templates
└── static/        # web UI JavaScript and CSS

documentation/     # current IR, extraction, vendor, and operations docs
tests/             # sanitized fixtures, vendor regressions, safety, integration
scripts/           # offline Check Point bundle export helper
```

The main entry points are `fwmigrate.main` for CLI commands,
`fwmigrate.web` for the web/API application, and `fwmigrate.web_live` for the
same application with FortiGate live-source routes enabled.

## 3. Registered capabilities

The registry currently exposes these source parsers:

| Source ID | Input extensions / contract |
|---|---|
| `fortigate` | `.conf`, `.cfg`, `.txt` |
| `palo_alto` | `.xml` |
| `cisco_asa` | `.cfg`, `.txt`, `.conf` |
| `cisco_ftd` | `.cfg`, `.txt`, `.conf`, `.json` FMC REST-export bundle |
| `checkpoint` | `.json`, `.txt`, `.cfg` |
| `juniper_srx` | `.set`, `.txt`, `.conf` |

Registered target generators expose:

| Target ID | Formats |
|---|---|
| `palo_alto` | `xml`, `terraform` |
| `fortigate` | `cli`, `terraform` |
| `cisco_asa` | `cli`, `terraform` |
| `checkpoint` | `cli`, `terraform` |
| `juniper_srx` | `set`, `cli`, `terraform` |

This table describes plugin capabilities, not a promise that every source
feature is portable. See the vendor reference and support-matrix documents for
feature-level status.

## 4. Canonical IR and extraction boundary

The production model is `fwmigrate.ir.core.IRConfig`. The executable IR schema
is currently `1.65`; serialization and migrations are owned by
`src/fwmigrate/ir/io.py`, `migrations.py`, and `version.py`.

`IRConfigV2` is a separate validator/model path. It is not the production
serialized migration contract.

`ExtractionResult` currently carries:

- `canonical_ir`
- `source_sections` and `coverage`
- `inventory_items`, `unsupported_items`, and `dependencies`
- `requires_manual_review`, `migration_complete`, `generation_safe`, and
  ordered `blocking_reasons`

Extraction status is source accounting. A parsed object can still be partial,
extract-only, unsupported, or unsafe for generation. Target generators enforce
the generation-safety boundary and must not consume source-only attributes as
portable semantics.

## 5. Web and deployment workflows

The web application provides:

- `/api/preview` for source preview and optimization findings;
- `/api/migrate` for a multi-vendor migration ZIP containing target artifacts,
  Markdown/HTML reports, and the source-inventory workbook;
- `/api/extract/excel` for source inventory without a target;
- Terraform prepare, plan, approve, apply-stream, and destroy-stream routes for
  the reviewed live-deployment workflow.

Live source extraction is FortiGate-only over SSH. Live deployment currently
supports PAN-OS targets. The deployment UI requires a dry-run plan and explicit
approval before apply; rollback destroys resources tracked by that Terraform
session and is not a full device snapshot restore.

## 6. Validation

Use the repository’s current validation commands after shared IR, parser,
generator, reporting, or deployment changes:

```powershell
python -m pytest -q
python -m compileall -q src tests
Get-ChildItem scripts -Filter *.py | ForEach-Object { python -m py_compile $_.FullName }
```

Focused vendor tests are useful first, but a focused pass is not a full-suite
claim. Keep sanitized fixtures under `tests/fixtures/` and preserve the
zero-silent-loss and fail-closed safety rules.
