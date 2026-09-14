# Extraction Model Reference

## Authority

The executable extraction contract is defined primarily in `src/fwmigrate/extraction/models.py` and the vendor extractors under `src/fwmigrate/parsers/`.

The exact executable status vocabulary is generated in [`../../generated/extraction-statuses.md`](../../generated/extraction-statuses.md).

## Purpose

`ExtractionResult` answers a different question from canonical IR:

- IR asks what vendor-neutral intent can participate in migration.
- Extraction asks what was present in the source, what was understood, what reached IR, what remained source-only, and what could not be safely represented.

This separation provides source accounting for reports, Excel inventory, parser QA, pre-checks, and regression testing.

## Zero-silent-loss invariant

Migration-relevant source data must be classified. A parser may be incomplete, but it must not be silently incomplete.

Coverage counts do not by themselves prove semantic completeness. Manual-review state, parse errors, unresolved dependencies, and unmodeled settings remain part of the result.

## Generation boundary

`ExtractionResult` and canonical `IRConfig` are related but not interchangeable. Source-only evidence is not automatically portable. Target generators must use canonical semantics plus their capability/safety checks and must not broaden missing or unresolved values.

## Historical detail

The previous long-form extraction-model document is retained at `documentation/archive/2026/legacy/extraction-data-model.md`. It contains useful historical design detail, but current code and this maintained reference define the active authority model.
