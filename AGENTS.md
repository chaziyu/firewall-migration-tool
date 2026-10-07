# AGENTS.md

This repository uses **vendor-native extraction/reporting** plus **pair-specific migration planning**.

## Pipelines

Source reporting:

```text
Vendor Source
→ Parser / Adapter
→ VendorConfig
→ Relationships / Transforms
→ DerivedViews
→ Validation
→ Preview / Excel
```

Collection:

```text
Device / Manager
→ Collector
→ Sanitized Vendor Source
→ Source Reporting
```

Migration:

```text
VendorConfig
→ DerivedViews
→ Pair-specific Requirements
→ Target Evidence / Engineer Decisions
→ Deterministic Design Session
→ MigrationPlan
→ Target Validation / Reuse Classification
→ Dependency-aware Render Disposition
→ Renderer
```

Current migration pair:

```text
FortiGate → Palo Alto PAN-OS
```

Deployment:

```text
RenderedMigration
→ Candidate Push
→ Candidate Validation
→ Explicit Commit
```

Do not introduce a vendor-neutral firewall IR.

## Core rules

`VendorConfig` represents **explicit source state only**.

A missing field means:

```text
not explicitly configured
```

Never silently treat absence as:

```text
default
false
disabled
empty
zero
inherit
any
```

Keep distinct:

```text
explicit source
derived value
effective/default value
operational value
unknown / unsupported value
```

When unclear:

```text
preserve source
→ mark unknown / unsupported
→ report it
→ do not guess
```

## Responsibility boundaries

```text
Tokenizer / Scanner   syntax only
Parser / Adapter      source structure only
Command Evaluator     command semantics
VendorConfig          explicit source state
Relationships         references / bindings / topology
Transforms            vendor semantics / derivation
DerivedViews          read-only derived state
Validation            detect/report only
Preview / Excel       presentation only
Collection            acquisition only
Conversion            pair-specific planning only
Deployment            reviewed artifact execution only
```

Do not move semantics into parsers, validation, web code, or Excel for convenience.

After extraction, do not mutate `VendorConfig`.

Do not silently:

```text
fill defaults
repair references
insert inferred source objects
rewrite source values
delete unsupported evidence
```

## Source preservation

Preserve useful unsupported data through existing mechanisms such as:

```text
raw_extra
unsupported commands
source metadata
Source Inventory
Additional Settings
source appendix sheets
collection evidence
```

Do not add source-model fields only to satisfy Excel or migration output.

## Shared code

Shared infrastructure may handle:

```text
vendor registration
source-report dispatch
collection contracts
migration planner contracts
web orchestration
```

The React frontend is a presentation and workflow client. Do not move vendor parsing, source semantics, migration planning, validation semantics, or target rendering into frontend code.

The Tauri desktop shell owns native lifecycle, loopback-sidecar startup, and desktop transport controls. It must not duplicate Python domain logic.

Vendor semantic models remain vendor-owned.

Do not create shared semantic models for:

```text
addresses
services
policies
NAT
interfaces
zones
routes
VPNs
```

Source reporting must not depend on conversion.

## Vendor rules

Use the matching reference under:

```text
documentation/official-cli-references-selected version/
```

Use official vendor documentation as semantic authority.

### FortiGate
Preserve VDOMs, nested config, `set/append/unset`, ordering, topology, and `raw_extra`.

```text
Tokenizer
→ Parser
→ Command Evaluator
→ FGConfig
→ Relationships / Transforms
→ DerivedViews
→ Validation
→ Excel
```

Do not move FortiGate semantics into the parser.

### Cisco ASA
Preserve command/ACL/NAT order, contexts, bindings, `nameif`, inactive state, and explicit `no`.

### Cisco FTD
Keep FMC, FDM, and CLI/device evidence distinct. Preserve UUIDs, domains, ownership, overrides, ordering, and completeness.

### Juniper SRX
Preserve hierarchy, logical systems, routing instances, groups, inheritance, address-book scope, and inactive state.

### Check Point
Keep Management API and Gaia distinct. Preserve UID, domain, package, layer, section, inline-layer, gateway/cluster scope, and completeness.

### PAN-OS
Current source input is XML. Preserve VSYS/shared/device-group/device scope and rule order. Do not assume source `set` input support.

## Migration planning

`src/fwmigrate/conversion/` contains directional pair-specific planners.

Current pair:

```text
fortigate → palo_alto
```

Do not introduce:

```text
vendor-neutral IR
shared source/target firewall model
generic migration schema
generic cross-vendor mappings
TargetVendorConfig abstraction
```

Unimplemented pairs must fail closed.

Use the canonical pair-specific package boundaries:

```text
planning/
design/
review/
target/
recommendations/
rendering/
application/
```

Do not recreate top-level compatibility shim modules that duplicate those packages.

## Migration decisions

Target-specific information that cannot be derived safely requires an explicit decision.

Modes:

```text
AUTO
SUGGESTED
REQUIRED
UNSUPPORTED
```

Review states:

```text
PENDING
CONFIRMED
```

Only `AUTO` or `CONFIRMED` decisions may become planner input.

A suggestion is not confirmation.

Do not guess target:

```text
VSYS
virtual router
interface
zone
ownership
```

Decision identity must preserve source scope such as VDOM.

## Rendering and deployment

Rendering is target-aware and must preserve the reviewed plan plus its validated disposition.

```text
CREATE      render creation commands
CONFIGURE   render only explicitly approved additive target changes
REUSE       satisfy the item without rendering creation commands
BLOCK       render nothing for the item
```

`CONFIGURE` requires explicit engineer approval. `REUSE` is not equivalent to creation. Blocked dependencies must propagate through the plan before rendering.

Command preview, download, bundle, and deployment must use the same `RenderedMigration`.

Preserve:

```text
artifact identity
command count
command SHA-256
```

Deployment accepts reviewed rendered artifacts, not arbitrary command lists.

Default behavior:

```text
push candidate
→ validate candidate
→ no automatic commit
```

Commit must remain explicit.

## Collection

Collection is acquisition only.

Collectors may connect, read, sanitize, and report completeness.

States:

```text
SUCCESS
PARTIAL
FAILED
```

Never treat failed/unsupported collection parts as empty configuration.

Snapshots are sanitized source envelopes, not semantic models.

## Secrets

Never export, preview, log, or persist actual:

```text
passwords
password hashes
PSKs
private keys
API keys
tokens
shared secrets
sensitive credentials
```

Safe metadata such as `Password Configured = Yes` is allowed.

Apply redaction everywhere, including raw evidence, collection, reports, migration, deployment, and logs.

## Before editing

Inspect:

```text
current branch
actual paths
models
symbols
callers
tests
current pipeline
```

Then:

```text
make the smallest coherent change
preserve existing architecture
reuse existing logic
avoid unrelated refactoring
do not guess APIs
prefer package-relative imports
```

Current repository code and tests are authoritative.

## Testing

Test the affected real path.

Source:

```text
source
→ VendorConfig
→ DerivedViews
→ validation
→ preview / Excel
```

Migration:

```text
FortiGate
→ FGConfig / DerivedViews
→ requirements
→ target evidence / decisions
→ deterministic design review
→ MigrationPlan
→ target validation / reuse classification
→ dependency-aware render disposition
→ validation
→ RenderedMigration
```

Deployment:

```text
RenderedMigration
→ candidate
→ validation
→ explicit commit
```

Protect regressions in scope, ordering, references, topology, unsupported data, completeness, mapping decisions, artifact integrity, secret redaction, preview, Excel, migration bundle, and deployment.

Run applicable:

```text
Python:
python -m compileall -q src tests
python -m pytest -q

Frontend:
cd src/frontend
npm test
npm run lint
npm run build

Desktop:
cargo check --locked --manifest-path src/frontend/src-tauri/Cargo.toml
cargo test --locked --lib --manifest-path src/frontend/src-tauri/Cargo.toml
python scripts/check_desktop_release_version.py
```

For Docker, release dependency, or packaging changes, run the corresponding build/smoke path or rely on CI when the local environment cannot reproduce it.

Do not claim tests or CI passed unless they actually ran.

## Priority

```text
correctness
→ source preservation
→ explicit semantics
→ traceability
→ safety
→ maintainability
```