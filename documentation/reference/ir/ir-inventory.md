# Canonical IR inventory

This is the Phase 0 contract record for the current executable model. The
authoritative field inventory remains `IRConfig.model_fields` in
`src/fwmigrate/ir/core.py`; this document records where the former V2 ideas
live without creating a second schema.

| V2 concept | Current production contract | Decision |
|---|---|---|
| schema version | `IRConfig.schema_version`, `ir/version.py`, `ir/io.py`, migrations | already supported |
| generation safety | `generation_safe`, `generation_blocking_reasons`, `requires_manual_review` | already supported |
| source identity | `IRMetadata` plus object `source_*`, `source_context`, `source_attributes` fields | already supported |
| provenance/status | object `migration_status`, `review_reasons`, `parse_error`, and extraction coverage | already supported |
| native source evidence | `ExtractionResult.inventory_items`, `source_sections`, and sanitized source attributes | already supported |
| unsupported configuration | `ExtractionResult.unsupported_items` and source-only IR collections | already supported |
| dependencies | `ExtractionResult.dependencies` and typed unresolved-reference fields | already supported |
| manual review | extraction safety plus object review flags | already supported |
| target capability requirements | target capability modules and generator safety checks | target analysis, not canonical IR |
| `NativeModel` raw bag | vendor parser models and extraction evidence | experimental/unused as canonical data |
| `IRConfigV2` component hierarchy | no production consumer remains | obsolete; removed |

Representative serialization coverage is in
`tests/test_ir_canonical_contract.py`. It round-trips addresses, services,
policies, NAT, routes, VPN, security profiles, unsupported evidence, and
safety state through the production `IRConfig`/`ExtractionResult` contract.
