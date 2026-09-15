# AGENTS.md

## Scope

Firewall Migration Tool is a Python 3.10+ multi-vendor firewall extraction and migration platform.

Current engineering priority:

```text
vendor source -> ExtractionResult -> IR V2 -> Excel
```

Target generation remains supported, but parser, extraction, IR, source-accounting, and Excel correctness take priority.

Do not add direct source-to-target converters. Parsers must not contain target-vendor generation logic. Excel/reporting must not parse vendor source independently.

## Required Source Extraction Pipeline

All built-in vendors must converge on the same lifecycle:

```text
1. Input detection / format adapter
2. Source normalization
3. Parse / tokenize / load
4. Vendor source model
5. Context / scope / inheritance resolution
6. Reference and dependency resolution
7. Source inventory and coverage accounting
8. Transform to IR V2
   - canonical generic IR
   - typed vendor extensions
9. Semantic validation
10. Extraction safety / completeness evaluation
11. Finalize ExtractionResult
12. Excel / reporting
```

Rules:

- `extract()` is the authoritative source-parser entry point.
- `parse()` is compatibility only and should project `extract(...).canonical_ir`.
- Vendor syntax handling may differ internally, but all vendors must return the same `ExtractionResult` contract.
- Every meaningful source item must be accounted for. Nothing may disappear silently.
- Source items should end in an explicit state such as normalized, partially normalized, vendor extension, extract-only, unsupported, ignored-by-policy, or parse error.
- Vendor-specific semantics belong in typed vendor extensions or source evidence unless they are genuinely portable canonical concepts.
- Excel/reporting consumes `ExtractionResult` and IR only. Do not add a separate vendor-to-Excel parser path.

## Read Before Changing Semantics

- `documentation/ir-schema-v2-plan.md` — planned IR V2 target contract and generic/vendor-extension boundary.
- `documentation/ir-model.md` — currently implemented IR schema.
- `documentation/vendor-mapping/<vendor>.md` — maintained source-to-IR mapping and coverage notes.
- Relevant official vendor documentation — authority for vendor syntax and semantics.
- Implementation and regression tests — authority for what the repository currently supports.

If the planned IR document conflicts with proven vendor semantics or safe implementation behavior, do not guess. Preserve the source semantics and report the discrepancy.

If serialized IR changes, update models, compatibility/migration handling, tests, and schema version together.

## Important Areas

- `src/fwmigrate/ir/` — canonical IR and vendor-extension models.
- `src/fwmigrate/extraction/` — `ExtractionResult`, coverage, inventory, unsupported/residual accounting, safety finalization.
- `src/fwmigrate/parsers/` — vendor adapters, source models, resolvers, transformers, and extractors.
- `src/fwmigrate/report/` — Excel and report generation from extraction/IR data.
- `src/fwmigrate/core/` — shared parser interfaces, registry, and cross-vendor logic.
- `src/fwmigrate/application/` — application pipeline orchestration.
- `src/fwmigrate/generators/` — target generators; secondary to the current extraction-first milestone.
- `tests/fixtures/` — sanitized source fixtures.
- `documentation/` — maintained architecture, IR, and vendor-mapping documentation.

Plugin registration is import-driven. Built-in vendor packages register with `PluginRegistry`. Do not hard-code vendor routing in shared CLI/UI/application code.

## Extraction and IR Rules

- **Zero silent loss:** recognized or migration-relevant source data must be normalized or explicitly accounted for.
- **Fail closed:** unresolved, malformed, ambiguous, or unsupported semantics must not become broader values such as `any`, `allow`, `/0`, `/32`, fabricated interfaces/zones, or enabled rules.
- Preserve source context, ordering, inheritance, provenance, unresolved references, and vendor-only behavior when needed for auditability.
- Keep canonical IR vendor-neutral. Do not place a vendor field in the generic core merely because only one parser currently uses it.
- Do not force unlike concepts into one generic model. Use vendor extensions when portability is not proven.
- Do not let a generic normalizer guess intent from names or other weak heuristics unless that behavior is explicit, audited, and separately tested.
- Do not remove source-only/vendor-specific models until equivalent extraction evidence is preserved elsewhere.

## Excel and Reporting Rules

Excel is the primary near-term verification output.

It should make extraction behavior auditable by exposing, where relevant:

- canonical objects and rules
- vendor-extension data
- source context/provenance
- extraction/migration status
- review reasons
- unresolved dependencies
- unsupported items
- parse errors
- source versus normalized/accounted counts

A reviewer should be able to trace important Excel output back to the source configuration.

Never expose passwords, usable PSKs, private keys, tokens, API keys, or real customer secrets in reports, fixtures, logs, or generated artifacts.

## Testing Expectations

- Parser changes: add/update sanitized fixtures and assert source-model behavior, canonical IR, vendor extensions, dependencies, coverage, and safety accounting.
- A parser test is incomplete if it only proves that parsing did not crash.
- A successful parse with silently dropped source data is a failure.
- IR changes: test legacy payload compatibility, serialization round-trip, aliases/migrations, and all affected vendors.
- Reporting changes: test both canonical data and extraction/accounting output; preserve secret redaction.
- Shared extraction changes: run affected vendor suites and the full suite because they cross vendor boundaries.
- Generator changes, when required: consume canonical IR and preserve fail-closed behavior; do not depend on parser-private models.

Run focused tests first, then full validation for shared or semantic changes:

```bash
python -m pytest -q
python -m compileall -q src tests
python -m py_compile scripts/*.py scripts/docs/*.py
python scripts/docs/validate_docs.py
python scripts/docs/generate_docs.py --check
```

CI currently runs the full test suite on Python 3.11, 3.12, and 3.13. Do not invent additional lint/type-check gates that are not configured.

## Documentation Rules

- Official vendor documentation and release notes are authoritative for vendor behavior.
- Code and regression tests are authoritative for implementation claims.
- `documentation/ir-schema-v2-plan.md` describes the planned target contract; do not present unimplemented V2 behavior as current implementation.
- `documentation/ir-model.md` describes the currently implemented IR until V2 migration is complete.
- Keep vendor-specific mapping and support notes in `documentation/vendor-mapping/`.
- Do not create new phase/fix-plan documents as long-term authority. Historical plans belong in archive/history only.
- Do not manually edit generated documentation under `documentation/generated/`.

## Repository Hygiene

Keep changes focused. Do not mix unrelated refactoring with parser, IR, extraction, or reporting fixes.

Do not refactor solely to reduce file count. Split or merge modules only when it clarifies pipeline ownership, removes obsolete patch layering, or reduces duplicated logic without changing semantics.

Do not contact real firewalls from ordinary automated tests. Only sanitized fixtures under `tests/fixtures/` should contain representative source configuration.
