# Pair-specific migration architecture

This package contains directional migration planning. It is separate from source extraction and reporting and must not introduce a vendor-neutral firewall IR.

Implemented directional pairs:

```text
FortiGate → Palo Alto PAN-OS
FortiGate → Juniper SRX (reviewed offline export)
FortiGate → Cisco ASA (reviewed offline export)
FortiGate → Check Point (Management API request specification and separate Gaia file)
Palo Alto PAN-OS → FortiGate (reviewed CLI export only)
```

FMC-managed Cisco FTD is not registered for export while exact supported FMC
request schemas remain unverified. FDM and FTD CLI/device output are separate
products and are not interchangeable with the FMC workflow.

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
rendering/         pair-specific target CLI rendering
application/       workflow-facing application services
```

Import implementation modules from these grouped packages directly. Do not add top-level compatibility shim modules that duplicate `planning/`, `rendering/`, `review/`, `target/`, or `recommendations/`.

Do not add generic source/target models, shared cross-vendor mapping tables, a `TargetVendorConfig` abstraction, or a vendor-neutral migration IR. Unimplemented migration pairs must fail closed.

The reverse pair has its own `FGMigrationPlan`, options, target evidence,
deterministic approval, application facade, and FortiOS renderer under
`palo_alto_to_fortigate/`. It consumes the existing native PAN-OS analysis directly.
It does not call the forward converter or construct a target source-model object.
Its signed `fg_migration_artifact_v1` envelopes are rejected by PAN-OS deployment.
See [coverage and usage](../../../documentation/PAN-OS-to-FortiGate-migration.md).

The Check Point pair is owned by `fortigate_to_checkpoint/`. It emits only
version-pinned Management API request templates and a separate reviewed Gaia
static-route file. UID dependencies are response bindings. It has no live
Management API client, no target comparison, and no PAN-OS deployment path.
See [Check Point coverage and usage](../../../documentation/fortigate_to_checkpoint-migration.md).
