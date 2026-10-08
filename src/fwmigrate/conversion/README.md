# Pair-specific migration architecture

This package contains directional migration planning. It is separate from source extraction and reporting and must not introduce a vendor-neutral firewall IR.

Current implemented pair:

```text
FortiGate → Palo Alto PAN-OS
```

Current flow:

```text
FortiGate VendorConfig / DerivedViews
→ Pair-specific Requirements
→ Target Evidence / Engineer Decisions
→ Deterministic Design Session
→ PANMigrationPlan
→ Target Validation / Object Reuse
→ Dependency-aware CREATE / CONFIGURE / REUSE / BLOCK disposition
→ Validation
→ RenderedMigration
```

A `MigrationPlan` is not a target `VendorConfig` and is not a complete PAN-OS configuration. It contains pair-specific planned items, source provenance, review status, and findings required to produce a reviewed migration artifact.

Package responsibilities:

```text
planning/          deterministic source-to-plan mappings
design/            deterministic reviewed design session
review/            engineer-facing review context and evidence
target/            target evidence, reuse, validation, and disposition
recommendations/   pair-specific guidance only
rendering/         PAN-OS set-command paths and rendering
application/       workflow-facing application services
```

Import implementation modules from these grouped packages directly. Do not add top-level compatibility shim modules that duplicate `planning/`, `rendering/`, `review/`, `target/`, or `recommendations/`.

Do not add generic source/target models, shared cross-vendor mapping tables, a `TargetVendorConfig` abstraction, or a vendor-neutral migration IR. Unimplemented migration pairs must fail closed.
