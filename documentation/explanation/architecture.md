# Architecture

## Purpose

Firewall Migration Tool uses an M×N architecture so source parsing and target generation remain independent.

```text
source configuration / approved source snapshot
        -> source parser / extractor
        -> ExtractionResult + canonical IRConfig
        -> validation
        -> mandatory target-independent normalization
        -> optional safe optimization
        -> final safety validation
        -> target generator
        -> native config / Terraform / reports
```

Parsers must not contain target-vendor conversion logic. Generators consume canonical `IRConfig`, not parser-specific source models.

## Main boundaries

| Area | Responsibility | Executable authority |
|---|---|---|
| Registry | Source/target/deployer registration | `src/fwmigrate/core/registry.py` |
| Extraction | Source accounting, coverage, residual/unsupported evidence | `src/fwmigrate/extraction/` |
| Canonical IR | Portable migration contract | `src/fwmigrate/ir/` |
| Source adapters | Vendor parsing and source semantics | `src/fwmigrate/parsers/` |
| Target generators | Native/Terraform target output | `src/fwmigrate/generators/` |
| Collection | Read-only source acquisition | `src/fwmigrate/collectors/` |
| Deployment | Reviewed deployment/rollback boundaries | `src/fwmigrate/deployment/` and `src/fwmigrate/engine/` |
| Reporting | Migration reports and source inventory | `src/fwmigrate/report/` |

The current registry-derived source and target list is generated in [`../generated/capabilities.md`](../generated/capabilities.md).

## Canonical IR versus extraction evidence

IRConfig represents vendor-neutral firewall intent that can participate in cross-vendor migration. ExtractionResult records what existed in the source and whether it was normalized, partially normalized, source-only, unsupported, ignored by policy, or invalid.

The canonical IR has one aggregate root in ir.config.IRConfig. Its supporting
models are split by domain across common, metadata, provenance, network,
address, service, policy, nat, routing, vpn, and security_profiles. ir.core
remains a compatibility re-export layer for older imports.

A source feature does not become portable merely because it was parsed. Vendor-specific or incomplete semantics remain source evidence and can block target generation.

See [`../reference/ir/ir-schema.md`](../reference/ir/ir-schema.md) and [`../reference/ir/extraction-model.md`](../reference/ir/extraction-model.md).

## Interfaces

The main user-facing entry points are:

- `fwmigrate` CLI from `src/fwmigrate/main.py`;
- `fwmigrate serve` for the web application;
- `fwmigrate app` for the desktop launcher;
- `fwmigrate-live-fortigate` for FortiGate live inventory collection.

Live source extraction is currently FortiGate-only. Target deployment support is narrower than offline generation and must remain behind plan/review/approval safeguards.

## Migration orchestration

Offline CLI and web migrations use `MigrationPipeline` as the shared orchestration boundary. Interface adapters decode input and collect request options; the pipeline owns extraction, normalization, optional optimization, safety checks, and target generation.

| Component | Responsibility |
|---|---|
| CLI/web adapter | Decode input, build `MigrationRequest`, write or package results |
| `MigrationPipeline` | Run the migration stages in one consistent order |
| Parser/extractor | Produce `ExtractionResult` and canonical `IRConfig` |
| `IRNormalizer` | Apply mandatory vendor-neutral semantic normalization and report changes |
| `RuleOptimizer` | Optionally analyze and prune unused objects |
| Safety evaluator | Block generation when source or final IR is unsafe |
| Generator | Produce target `MigrationArtifact` objects from canonical IR |

The migration path is:

```text
source input
  -> parser/extractor
  -> ExtractionResult + source IR
  -> source safety check
  -> mandatory IRNormalizer normalization
  -> optional optimization/pruning
  -> final safety check
  -> target generator
  -> MigrationArtifact objects and reports
```

The pipeline does not contain Flask or Click behavior, parsers do not contain target-vendor logic, generators do not parse source configuration, and optimization does not repair required semantics. Existing generator capability checks remain active at the final target boundary.

## Design invariants

The architecture depends on these invariants:

1. zero silent loss for migration-relevant source data;
2. fail closed when source semantics are missing, malformed, ambiguous, or unresolved;
3. preserve source provenance and unsupported evidence;
4. protect secrets in reports, fixtures, logs, and generated documentation;
5. keep source extraction independent from target generation.

See [`safety-model.md`](safety-model.md) for the normative safety rules.
