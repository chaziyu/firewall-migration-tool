# Architecture

## Purpose

Firewall Migration Tool uses an M×N architecture so source parsing and target generation remain independent.

```text
source configuration / approved source snapshot
        -> source parser / extractor
        -> ExtractionResult + canonical IRConfig
        -> validation and optional optimization
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

`IRConfig` represents vendor-neutral firewall intent that can participate in cross-vendor migration. `ExtractionResult` records what existed in the source and whether it was normalized, partially normalized, source-only, unsupported, ignored by policy, or invalid.

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

Offline migration entry points use `MigrationPipeline` from
`src/fwmigrate/application/`. The CLI and Web layers are interface adapters:
they read input, validate interface-specific fields, construct a
`MigrationRequest`, call the pipeline, and format `MigrationResult` for disk,
ZIP, HTTP, or report output. Future Desktop/API migration entry points should
use the same boundary.

| Component | Responsibility |
|---|---|
| `MigrationPipeline` | Migration use-case orchestration |
| Parser and extractor | Source-native configuration to `ExtractionResult` and canonical `IRConfig` |
| Validators | Read-only integrity and safety checks over `IRConfig` |
| Capability analyzer | Early target-support evidence; generators remain defense in depth |
| `RuleNormalizer` | Mandatory target-independent semantic normalization |
| `RuleOptimizer` | Optional safe pruning and other improvements |
| Safety evaluator | Central extraction and pre-generation decision |
| Generator | Canonical IR to target `MigrationArtifact`; retains target-specific capability and safety checks |

The processing order is:

```text
source input
    -> parser / extractor
    -> ExtractionResult + canonical IR
    -> source safety and IR validation
    -> mandatory normalization
    -> optional optimization
    -> final validation and target capability analysis
    -> final safety check immediately before generation
    -> target generator
    -> MigrationArtifact
    -> report or interface output
```

Parsers remain source-native and must not contain target conversion logic.
Generators must not parse source configuration. `MigrationPipeline` must not
depend on Flask or Click, and new user-facing migration entry points must not
bypass it. This refactor keeps the existing production IR; it does not use
`IRConfigV2`. Optimization is not responsible for repairing required
semantics, and generator-specific safety checks remain defense in depth.
The evaluator preserves blocking reasons and manual-review state without
mutating the extraction result or canonical IR. Blocked migrations return no
deployable artifacts; diagnostic reports may be produced by an interface only
when they are explicitly marked non-deployable.

## Design invariants

The architecture depends on these invariants:

1. zero silent loss for migration-relevant source data;
2. fail closed when source semantics are missing, malformed, ambiguous, or unresolved;
3. preserve source provenance and unsupported evidence;
4. protect secrets in reports, fixtures, logs, and generated documentation;
5. keep source extraction independent from target generation.

See [`safety-model.md`](safety-model.md) for the normative safety rules.
