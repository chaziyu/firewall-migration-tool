# FortiOS 7.4.6 Reference Schema

Machine-readable source schema derived from the official **FortiOS 7.4.6 CLI Reference** (document `01-746-912654-20241212`, December 12, 2024).

This schema is intended for parser/refactor work and AI-assisted implementation. It describes FortiOS source syntax; it is **not** a claim that the current parser implements every documented section.

## Layout

- `index.yaml` — source metadata, coverage counts, and domain-to-file index.
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

Compact scalar field values such as `integer`, `string`, `ipv4-address`, or `enum` are source syntax types. `password!sensitive` marks source values that must never be exposed in reports/logs. `identifier-list` and `option-list` represent list syntax. `opaque-user` is Fortinet's `{user}` source type and must not be semantically guessed.

## Required handling rules

1. Parse/preserve source syntax before IR mapping.
2. Do not treat absence from this 7.4.6 schema as a parse error. Fortinet explicitly documents model, hardware, and feature-dependent availability and notes that the CLI reference may not include every command.
3. Unknown fields inside known sections must be preserved as source evidence.
4. Do not materialize documented defaults as explicit source commands.
5. Do not infer references merely because a field is a `string` or `{user}`.
6. Keep canonical IR mapping separate from this source schema.
7. Sensitive values remain accounted for but must be redacted outside protected internal source handling.

## Coverage snapshot

The schema contains 595 documented top-level `config` sections, 1,232 config nodes including nested blocks, and 11,667 documented `set` fields across 42 CLI domains.

The source extraction deliberately preserves the reference's terminology. Where the PDF/refined source itself contains unusual tokenization, this schema does not silently invent corrected CLI syntax.
