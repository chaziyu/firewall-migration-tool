# FortiOS 7.4.6 Reference Schema

Machine-readable source schema derived from the official **FortiOS 7.4.6 CLI Reference** (document `01-746-912654-20241212`, December 12, 2024).

This schema is intended for parser/refactor work and AI-assisted implementation. It describes FortiOS source syntax; it is **not** a claim that the current parser implements every documented section.

## Layout

- `index.yaml` — source metadata, coverage counts, and domain-to-file index.
- `schema-format.yaml` — Phase 0 metadata contract for evidence, enriched fields, semantic separation, nested nodes, defaults, ranges, references, and migration relevance.
- `schema/*.yaml` — all documented top-level `config` sections, nested `config` blocks, entry keys, and `set` value types.
- `ir-v2-mapping.yaml` — only mappings supported by the planned IR V2 contract and/or the maintained FortiGate mapping document. Unlisted sections remain unmapped until semantics are verified.

## Schema conventions

Each top-level section records:

- `path` — FortiOS path without the leading `config`.
- `mode` — `singleton` or `table`.
- `key` — `edit <...>` identifier for table sections.
- `fields` — documented `set` fields and their source value type.
- `nested` — recursively nested `config` blocks.
- `model_dependent` — the reference explicitly documents model/feature variability for the section.
- `read_only` — the reference describes the section as read-only.

Compact scalar field values such as `integer`, `string`, `ipv4-address`, or `enum` remain valid and mean source type only. Existing `!sensitive` suffixes remain valid compatibility shorthand.

When a field is reviewed in a later phase, it may be upgraded in place to the structured form defined by `schema-format.yaml`. That form can capture documented options, ranges, length limits, defaults, descriptions, read-only/model-dependent data, nested provenance, and explicitly documented conditions. It also keeps migration-tool semantics under a separate `semantic` block.

## Evidence rules

Use only these evidence statuses:

- `documented` — explicitly supported by the FortiOS 7.4.6 CLI Reference.
- `project_semantic` — migration-tool interpretation or classification, not a Fortinet documentation claim.
- `needs_review` — available evidence is insufficient to establish the claim safely.

Enriched source facts should identify the Fortinet document and config path. Semantic claims must carry their own evidence so they cannot be mistaken for Fortinet documentation.

## Required handling rules

1. Parse/preserve source syntax before IR mapping.
2. Do not treat absence from this 7.4.6 schema as a parse error. Fortinet explicitly documents model, hardware, and feature-dependent availability and notes that the CLI reference may not include every command.
3. Unknown fields inside known sections must be preserved as source evidence.
4. Do not materialize documented defaults as explicit source commands.
5. Do not infer references merely because a field is a `string` or `{user}`.
6. Keep canonical IR mapping separate from this source schema.
7. Sensitive values remain accounted for but must be redacted outside protected internal source handling.
8. Preserve unusual reference syntax; use `needs_review` instead of silently correcting it.
9. Enrich only the config family active in the current phase. Do not bulk-convert unrelated schema files.

## Phase 0 compatibility decision

Phase 0 does **not** rewrite existing `schema/*.yaml` files. The current compact representation remains valid. Later phases should enrich only the configs and fields they actually verify against the official reference.

The existing source-type vocabulary is therefore preserved as-is in Phase 0. Its full controlled vocabulary should be audited only when the reviewed schema is mature enough to do so without inventing or dropping source syntax.

## Coverage snapshot

The schema contains 595 documented top-level `config` sections, 1,232 config nodes including nested blocks, and 11,667 documented `set` fields across 42 CLI domains.

The source extraction deliberately preserves the reference's terminology. Where the PDF/refined source itself contains unusual tokenization, this schema does not silently invent corrected CLI syntax.
