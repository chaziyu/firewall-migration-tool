# PAN-OS / Panorama reference schema

This directory is the source-side schema baseline for the Palo Alto Networks parser.

It is intentionally separate from the executable parser and from canonical IR mapping.

## Scope

- XML/XPath structure
- list/singleton/container shape
- entry identity
- field type/cardinality
- references
- shared/device-group/vsys/template/template-stack/device scope
- inheritance and override behavior
- pre/local/post rule ownership and ordering
- sensitive/read-only/default metadata
- migration relevance
- custom-handler flags
- evidence provenance

## Version profile

The checked-in schema uses a **PAN-OS 11.1+ XML/API baseline** because the available official PAN-OS XML API
documentation describes that branch as “11.1 & Later”. PAN-OS XML structure varies by release and feature.
`index.yaml` therefore records this as a compatibility profile rather than claiming every path is invariant across
all releases.

## Evidence policy

`documented` means Palo Alto Networks documentation explicitly supports the claim.
`repository_observed` means the current repository parser/fixtures exercise the path or structure.
`project_semantic` is a migration-tool interpretation.
`needs_review` is used where the official uploaded reference was not available in the active project-file index and
the claim should be rechecked against the intended version-specific reference before parser refactoring.

## Refactor boundary

No PAN-OS Python parser, extractor, source model, transformer, IR model, or exporter is changed by this schema work.

Future target:

PAN XML → XML loader → PAN source tree/model → YAML schema registry → scope/inheritance resolver →
reference resolver → semantic handlers → PAN source model → IR transformer → accounting/validation → ExtractionResult
