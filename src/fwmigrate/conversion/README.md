# Pair-specific migration architecture

This package contains directional migration planning. It is separate from source extraction and reporting and must not introduce a vendor-neutral firewall IR.

Implemented directional pairs:

```text
FortiGate → Palo Alto PAN-OS
FortiGate → Juniper SRX (reviewed offline export)
FortiGate → Cisco ASA (reviewed offline export)
FortiGate → Check Point (Management API request specification and separate Gaia file)
Palo Alto PAN-OS → FortiGate (reviewed CLI export only)
Palo Alto PAN-OS → Juniper SRX (reviewed offline export)
Palo Alto PAN-OS → Cisco ASA (reviewed offline export)
Palo Alto PAN-OS → Check Point (reviewed offline Management API request specification)
Palo Alto PAN-OS → Cisco FTD (reviewed offline FMC REST API request specification)
```

These are partial, directional implementations. Only FortiGate → PAN-OS supports
reviewed live candidate operations, available only in local mode. The other
eight pairs export offline artifacts. FMC-managed Cisco FTD targets the bounded
FMC REST API 7.7.0 request schemas; it does not execute requests or deploy to a
device. FDM and FTD CLI/device output remain separate products.

Use the [migration support matrix](../../../documentation/migration-support-matrix.md)
for current versions, feature subsets, destination-comparison limits and manual
activation requirements. `builtin.py` registers implemented planners and public
workflow metadata; `/api/migration/pairs` exposes that metadata. This architecture
guide is not an independent capability policy.

Current flow:

```text
Source VendorConfig / DerivedViews
→ Pair-specific Requirements
→ Target Evidence / Engineer Decisions
→ Deterministic Design Session
→ Pair-specific MigrationPlan
→ Target Validation / Object Reuse
→ Dependency-aware CREATE / CONFIGURE / REUSE / BLOCK disposition
→ Validation
→ RenderedMigration
```

A pair-specific migration plan is not a target `VendorConfig` or a complete target configuration. It contains pair-owned planned items, source provenance, review status, and findings required to produce a reviewed migration artifact. Source reporting remains independent of conversion, and pair implementations do not import other pair implementations.

Package responsibilities:

```text
planning/          deterministic source-to-plan mappings
design/            deterministic reviewed design session
review/            engineer-facing review context and evidence
target/            target evidence, reuse, validation, and disposition
recommendations/   pair-specific guidance only
rendering/         pair-specific target CLI or API request rendering
application/       workflow-facing application services
```

Import implementation modules from these grouped packages directly. Do not add top-level compatibility shim modules that duplicate `planning/`, `rendering/`, `review/`, `target/`, or `recommendations/`.

Do not add generic source/target models, shared cross-vendor mapping tables, a `TargetVendorConfig` abstraction, or a vendor-neutral migration IR. Unimplemented migration pairs must fail closed.

The reverse pair has its own `FGMigrationPlan`, options, target evidence,
deterministic approval, application facade, and FortiOS renderer under
`palo_alto_to_fortigate/`. It consumes the existing native PAN-OS analysis directly.
It does not call the forward converter or construct a target source-model object.
Its signed `fg_migration_artifact_v1` envelopes are rejected by PAN-OS deployment.
See [coverage and usage](../../../documentation/guides/PAN-OS-to-FortiGate-migration.md).

The Check Point pair is owned by `fortigate_to_checkpoint/`. It emits only
version-pinned Management API request templates and a separate reviewed Gaia
static-route file. UID dependencies are response bindings. Optional existing
Management snapshots support exact object reuse by UID and cleanup-only Drop
rulebase insertion. Management evidence does not verify Gaia routes. It has no
live Management API client or PAN-OS deployment path.
See [Check Point coverage and usage](../../../documentation/guides/fortigate-to-checkpoint-migration.md).
