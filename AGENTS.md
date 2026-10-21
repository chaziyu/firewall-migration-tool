# AGENTS.md

This repository uses **vendor-native extraction/reporting** plus **pair-specific migration planning**.

## Runtime and packaging

- The application uses a React/Vite browser frontend and Flask backend, plus the `fwmigrate` CLI.
- `src/fwmigrate/main.py` defines CLI commands. `src/fwmigrate/web.py` composes the Flask application.
- `src/fwmigrate/web_api/` owns HTTP routes. `src/fwmigrate/web_support/` owns transport, artifact, and frontend-serving helpers.
- Flask serves `src/frontend/dist/`. Build it with `npm ci` and `npm run build` from `src/frontend` before using the Flask browser URL. Without the build, `/` returns HTTP 503.
- `Start Local.bat` runs Flask on `127.0.0.1:5000` and Vite on `127.0.0.1:5173`. Vite proxies API requests to Flask.
- Hosted web execution uses Gunicorn. Collection and deployment run on the backend machine and need network access from that machine.
- Tauri desktop packaging and Docker deployment files have been removed. Do not assume Rust/Cargo, desktop sidecars, container builds, or desktop installers are available.
- Frontend CI uses Node.js 24. Python compatibility CI covers 3.11–3.14. The constrained dependency job uses Python 3.12 and `requirements/constraints-python312.txt`.

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

Implemented migration pairs (partial, directional support):

```text
FortiGate → Palo Alto PAN-OS
PAN-OS → FortiGate
PAN-OS → Juniper SRX
PAN-OS → Cisco ASA
PAN-OS → Check Point
PAN-OS → Cisco FTD
FortiGate → Cisco ASA
FortiGate → Juniper SRX
FortiGate → Check Point
```

Only FortiGate → PAN-OS supports reviewed live candidate operations. The other
eight pairs export offline artifacts. See `documentation/migration-support-matrix.md`
and workflow discovery metadata for mapping, comparison and activation limits.

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

Implemented pair packages:

```text
fortigate → palo_alto
palo_alto → fortigate
palo_alto → juniper_srx
palo_alto → cisco_asa
palo_alto → checkpoint
palo_alto → cisco_ftd
fortigate → cisco_asa
fortigate → juniper_srx
fortigate → checkpoint
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

Saving or updating a proposal is not engineer approval. Web executable
artifacts require a current signed design approval bound to the
selected mappings, configuration items, target scope, operations, and
dependencies. CLI migration planning remains available without design approval;
it does not enable web deployment.

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

`CONFIGURE` requires explicit engineer approval. `REUSE` is not equivalent to creation. Render only approved items whose dependencies are satisfied; blocked dependencies must propagate through the plan before rendering. Unapproved or dependency-blocked items produce no commands, and unsupported migration coverage remains visible as manual work.

Command preview, download, bundle, and deployment must use the same `RenderedMigration`.

Preserve:

```text
artifact identity
command count
command SHA-256
```

Deployment accepts reviewed rendered artifacts, not arbitrary command lists.

Candidate preparation must verify the target serial, the approved sanitized
destination `baseline_sha256`, and a clean candidate before pushing. Candidate
validation and explicit commit are separate operations. Do not imply exclusive
device locking; application checks do not prevent another administrator from
changing the candidate between checks.

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

When `.codegraph/` exists, use `codegraph_explore` (or `codegraph explore`)
before repository searches or broad source reads to locate symbols and trace
callers. Use direct reads for configuration, documentation, tests, and context
the graph does not provide. Do not create or regenerate the index unless asked.

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

Collection regression:

```text
collector
→ sanitized source
→ source reporting
```

Migration:

```text
FortiGate
→ FGConfig / DerivedViews
→ requirements
→ target evidence / decisions
→ deterministic design session
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
ruff check src tests
python -m pytest -q

Frontend:
cd src/frontend
npm ci
npm test
npm run lint
npm run build

```

For release dependency or packaging changes, run the corresponding build/smoke path or rely on CI when the local environment cannot reproduce it.

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
