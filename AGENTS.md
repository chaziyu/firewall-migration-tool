# AGENTS.md

## Core Pipeline

All source extraction MUST follow this pipeline:

```text
Raw Source
→ Input Adapter / Normalization
→ Vendor Parser / Loader
→ Vendor Source Model
→ Scope / Context / Inheritance Resolution
→ Reference / Dependency Resolution
→ Source Inventory + Coverage Accounting
→ IR V2 Transformation
   ├── Canonical vendor-neutral IR
   └── Typed vendor extensions
→ Semantic Validation
→ Extraction Safety / Finalization
→ ExtractionResult
→ Reporting / Target Generation
```

Do not create alternate source-to-report or source-to-target paths.

`extract()` is the authoritative parser API.

`parse()` is compatibility only and MUST return or project `extract(...).canonical_ir`.

## IR Rules

Canonical IR MUST contain only portable cross-vendor semantics.

Vendor-specific semantics MUST go into typed `vendor_extensions` unless a portable equivalent is proven.

Source-only evidence, unsupported data, parse failures, unresolved dependencies, and extraction accounting belong in `ExtractionResult`, not in canonical IR merely for convenience.

Do not force unlike vendor concepts into one generic model.

Do not add new vendor-specific fields to canonical IR.

If portability is uncertain, preserve the source semantics and keep them vendor-specific.

## Extraction Rules

Zero silent loss.

Every meaningful source item MUST end in an explicit state such as:

```text
NORMALIZED
PARTIALLY_NORMALIZED
VENDOR_EXTENSION
EXTRACT_ONLY
UNSUPPORTED
IGNORED_BY_POLICY
PARSE_ERROR
```

Unknown, malformed, unresolved, or unsupported semantics MUST fail closed.

Never silently convert uncertainty into values such as:

```text
any
allow
0.0.0.0/0
::/0
enabled
fabricated objects
fabricated interfaces or zones
```

Preserve source context, ordering, inheritance, references, provenance, and vendor-only behavior when required for correctness.

## Vendor Parser Rules

Vendor syntax handling remains vendor-specific.

Do not force FortiOS CLI, Junos hierarchy, PAN-OS XML, Cisco CLI, and Check Point management/Gaia syntax through one generic grammar.

Parsers MAY use different internal implementations but MUST converge on the same `ExtractionResult` and IR V2 contracts.

Official vendor documentation is authoritative for source syntax and semantics.

Implementation and regression tests are authoritative for what the repository currently supports.

Do not guess undocumented semantics.

## Runtime Mutation

Do not monkey patch classes, functions, modules, parser entry points, registries, or model methods at runtime.

Do not rebind imported functions to change behavior after import.

Behavior changes MUST be implemented through explicit code paths, typed extension points, subclassing/composition, or the existing plugin/registry interfaces.

Tests may use temporary patching/mocking only when scoped to the test and automatically restored afterward.

If existing production code relies on monkey patching, replace it with an explicit implementation rather than adding more runtime mutation.

## Change Rules

Before changing parser or IR semantics:

1. Inspect the existing parser, source model, transformer, consumers, and tests.
2. Trace all readers and writers of fields being changed.
3. Check the relevant vendor mapping and official CLI/API reference.
4. Make the smallest change that preserves current supported behavior.
5. Add or update tests for semantics, coverage, dependencies, and safety.

Do not combine semantic changes with unrelated architecture cleanup.

Do not remove source/vendor-specific data until equivalent information is preserved in canonical IR, typed vendor extensions, or `ExtractionResult`.

## Compatibility

Serialized IR compatibility MUST be preserved through the IR loader.

When changing serialized IR:

- update the model;
- update migration/compatibility handling;
- update round-trip tests;
- update affected vendor tests.

Do not introduce a new IR schema version unless the current V2 contract cannot safely represent the required change.

## Secrets

Never expose usable passwords, PSKs, private keys, tokens, API keys, or customer secrets in:

```text
IR output
ExtractionResult
reports
logs
fixtures
tests
generated artifacts
```

Preserve only safe presence/status metadata where required.

## Required Validation

Run focused tests first.

For shared, IR, extraction, or semantic changes, run:

```bash
python -m pytest -q
python -m compileall -q src tests
python -m py_compile scripts/*.py scripts/docs/*.py
python scripts/docs/validate_docs.py
python scripts/docs/generate_docs.py --check
```

Do not claim validation passed unless the commands were actually run successfully.
