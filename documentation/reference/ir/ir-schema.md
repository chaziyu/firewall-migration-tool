# Canonical IR Schema Reference

## Authority

The executable canonical contract is defined by:

- `src/fwmigrate/ir/config.py` and the domain modules under `src/fwmigrate/ir/`;
- `src/fwmigrate/ir/core.py` for legacy compatibility exports;
- `src/fwmigrate/ir/version.py`;
- `src/fwmigrate/ir/io.py`;
- `src/fwmigrate/ir/migrations.py` and versioned migration modules.

The current schema version is generated into [`../../generated/capabilities.md`](../../generated/capabilities.md). Do not hard-code a second authoritative schema version in this document.

## Purpose

`IRConfig` is the vendor-neutral contract between source extraction and target generation. It represents portable firewall intent, not source-vendor CLI syntax.

```text
source parser -> ExtractionResult -> IRConfig -> validation -> normalization -> optional optimization -> target generator
```

Source semantics that cannot be represented safely in IR remain extraction evidence instead of being forced into a misleading common field.

## Contract rules

- Serialized IR MUST carry its schema version.
- Schema migrations MUST be explicit.
- Source-only compatibility fields MUST NOT be consumed as portable target semantics unless the IR contract explicitly defines that meaning.
- Unsafe/review-required objects MUST retain safety evidence across serialization.
- A schema change that alters the serialized contract requires the corresponding migration/version/test updates.

## Current versus proposed design

Only executable models and serialization code define the current serialized contract. Design proposals are not fields until implemented and covered by tests.

A historical detailed design snapshot is preserved under `documentation/archive/2026/legacy/ir-data-structure.md` for context; it is not more authoritative than executable code.
