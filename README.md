# Firewall Migration Tool

![Python](https://img.shields.io/badge/python-3.11%2B-green.svg)

Vendor-native firewall configuration extraction, validation, reporting, live collection, and pair-specific migration planning for Python 3.11+.

> **Project status**
>
> Source extraction and reporting are implemented across multiple firewall vendors.
>
> FortiGate → Palo Alto PAN-OS migration planning is implemented for a supported subset of configuration, including reviewed target mappings, PAN-OS `set` command generation, migration artifacts, and optional candidate deployment.
>
> Other migration pairs are not implemented.

Website: https://firewall-migration-tool.onrender.com/

## Overview

Firewall Migration Tool analyzes firewall configuration while preserving vendor-specific source semantics.

Source reporting:

```text
Vendor Source
→ Parser / Source Adapter
→ VendorConfig
→ Relationships / Transforms
→ DerivedViews
→ Validation
→ Web Preview / Excel
```

Live collection:

```text
Device / Manager
→ Collector
→ Sanitized Vendor Source
→ Source Reporting
```

Migration planning:

```text
VendorConfig
→ DerivedViews
→ Pair-specific Requirements
→ Target Evidence / Engineer Decisions
→ Deterministic Design Session
→ Pair-specific MigrationPlan
→ Target Validation / Reuse Classification
→ Dependency-aware CREATE / CONFIGURE / REUSE / BLOCK disposition
→ Deterministic Target Renderer
```

Deployment:

```text
RenderedMigration
→ Candidate Push
→ Candidate Validation
→ Explicit Commit
```

The architecture prioritizes:

```text
correctness
→ source preservation
→ explicit semantics
→ traceability
→ safety
→ maintainability
```

Source reporting does not force vendor configuration through a vendor-neutral firewall model.

A missing source-model field means that the value was **not explicitly configured in the authoritative source**. Vendor defaults are not silently inserted.

Unsupported or partially understood source configuration is preserved where practical rather than silently discarded.

## Current Capabilities

- Vendor-native firewall configuration extraction.
- Source inventory and unsupported-source accounting.
- Vendor-specific relationship and topology resolution.
- Read-only derived views.
- Validation without silently repairing source configuration.
- Web-based source configuration preview.
- Vendor-specific Excel reporting.
- Secret sanitization for reportable source evidence.
- Live source collection for supported vendors.
- Sanitized collection snapshots.
- FortiGate → Palo Alto migration planning.
- Explicit migration mapping and decision review.
- PAN-OS `set` command generation.
- Migration reports and downloadable migration bundles.
- Optional PAN-OS candidate deployment and validation.

## Runtime Targets

The repository provides a browser application with a React frontend and Flask API, plus the `fwmigrate` CLI:

| Runtime | Backend | Where operations run |
|---|---|---|
| Local web | Flask + Vite during development, or Flask serving the built frontend | Local machine |
| Hosted web | Gunicorn → Flask serving the built frontend | Hosted web server |
| CLI | Python `fwmigrate` entry point | Machine running the command |

Tauri desktop packaging and Docker deployment files have been removed. The Windows launcher starts the browser development workflow; it does not build a desktop executable.

Web collection and PAN-OS deployment originate from the backend machine and require network reachability from that environment.

## Supported Source Vendors

| Vendor | Vendor ID | Accepted Input | Notes |
|---|---|---|---|
| Fortinet FortiGate | `fortigate` | `.conf`, `.cfg`, `.txt` | FortiGate CLI configuration |
| Cisco ASA | `cisco_asa` | `.cfg`, `.txt`, `.conf` | ASA command-oriented configuration |
| Cisco Firepower Threat Defense | `cisco_ftd` | `.cfg`, `.txt`, `.conf`, `.json` | FMC/FDM bundles and FTD CLI/device evidence |
| Juniper SRX / Junos | `juniper_srx` | `.set`, `.txt`, `.conf` | Junos configuration sources |
| Check Point R80/R81 | `checkpoint` | `.json`, `.txt`, `.cfg` | Management/API-style data and Gaia CLI sources |
| Palo Alto Networks PAN-OS / Panorama | `palo_alto` | `.xml` | XML configuration only |

### Cisco FTD

FTD supports multiple source planes:

```text
FMC API / export
FDM API / export
FTD CLI / device evidence
```

These inputs are not treated as equivalent.

CLI-only extraction does not manufacture FMC/FDM-managed state that is absent from the authoritative input.

### PAN-OS

PAN-OS source reporting currently accepts XML configuration.

PAN-OS CLI `set` format is not currently supported as source input.

PAN-OS `set` commands are used as migration output for the implemented FortiGate → Palo Alto migration pair.

### Check Point

Check Point reporting preserves source scope where available, including:

```text
Management API
domain
package
layer
gateway / cluster
Gaia / gateway CLI
```

Failed or incomplete collection evidence is not interpreted as an empty configuration.

## Installation

Clone the repository:

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Upgrade pip and install the project:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

### Reproducible Python 3.12 Builds

Dependency responsibilities are split deliberately:

```text
pyproject.toml
→ compatible source dependency ranges

requirements/constraints-python312.txt
→ resolved Python 3.12 versions for hosted installs and constrained dependency tests

src/frontend/package-lock.json
→ resolved frontend dependency graph
```

The Python constraints file is used for reproducible Python 3.12 installs and the CI `release-dependencies` job. The Python 3.11/3.12/3.13/3.14 compatibility test matrix installs from the declared ranges so supported-version compatibility is still exercised.

For a reproducible production-style install:

```bash
python -m pip install --constraint requirements/constraints-python312.txt -e ".[collection,deployment]"
python -m pip check
```

Review and regenerate the constraints file when dependencies are intentionally updated; do not silently edit individual pins merely to suppress a vulnerability scanner.


## Usage

### List Registered Source Vendors

```bash
fwmigrate vendors
```

Equivalent module invocation:

```bash
python -m fwmigrate.main vendors
```

### Start the Web Application

Build the frontend first. Use Node.js 24, matching frontend CI, and npm:

```bash
cd src/frontend
npm ci
npm run build
cd ../..
```

Start Flask from the repository root with the Python environment activated:

```bash
fwmigrate serve --port 5000
```

Then open:

```text
http://localhost:5000
```

Equivalent module invocation:

```bash
python -m fwmigrate.main serve --port 5000
```

For Windows development, run [`Start Local.bat`](./Start%20Local.bat). It needs
Python 3.11 or newer, Node.js, and npm. The script starts the local backend at
`http://127.0.0.1:5000` and the Vite development frontend at
`http://127.0.0.1:5173` and opens the frontend in the browser. It creates `.venv`
and installs collection/deployment dependencies when that environment is absent.
It also runs `npm ci` when Vite is absent. An existing Python environment must
already have the application dependencies installed.

For manual frontend development, keep Flask running on port 5000 and run
`npm run dev` from `src/frontend`. Vite proxies API requests to Flask. Without
`src/frontend/dist/index.html`, Flask's `/` route returns HTTP 503; use the Vite
URL during development or build the frontend before opening Flask's URL.

### Hosted Web Deployment

Build the frontend with Node.js 24 and install the Python application using Python 3.12 on the web host:

```bash
cd src/frontend
npm ci
npm run build
cd ../..
python -m pip install --constraint requirements/constraints-python312.txt -e ".[collection,deployment]"
```

Run Gunicorn from the repository root with `src` on `PYTHONPATH`:

```bash
PYTHONPATH=src gunicorn --bind=0.0.0.0:5000 --workers=1 --threads=4 --timeout=120 "fwmigrate.web:create_app()"
```

Set `FWMIGRATE_FRONTEND_DIST_DIR` to `src/frontend/dist` if the host does not use the default frontend build path. Configure `FWMIGRATE_WEB_USERNAME` and a strong `FWMIGRATE_WEB_PASSWORD`, and set `FWMIGRATE_REQUIRE_WEB_AUTH=1` for hosted use. Remote live collection and deployment are disabled by default. Enable `FWMIGRATE_ALLOW_REMOTE_COLLECTION=1` or `FWMIGRATE_ALLOW_REMOTE_DEPLOYMENT=1` only on an authenticated service with an appropriate network perimeter. Terminate HTTPS before Flask.

Set `FWMIGRATE_WORKSPACE_SIGNING_KEY` to a stable random secret of at least 32 bytes. Keep credentials and signing keys in the host's secret manager. SSH collection and deployment use operating-system known-hosts configuration and strict host-key checking.

## Live Collection

Live collection is available for supported vendors including ASA, Juniper SRX, FMC, and Check Point.

Install collection dependencies:

```bash
python -m pip install -e ".[collection]"
```

Collectors acquire vendor-native source data and record collection completeness.

Collection states are:

```text
SUCCESS
PARTIAL
FAILED
```

Partial or failed collection is not interpreted as an empty configuration.

SSH collection verifies device host keys against the operating system's known-hosts configuration.

FMC and Check Point HTTPS certificate verification is enabled by default.

Successful collection can produce a secret-sanitized snapshot for later preview and Excel reporting.

Collection snapshots are acquisition envelopes, not normalized firewall models.

## FortiGate → Palo Alto Migration

The currently implemented migration pair is:

```text
FortiGate
→ Palo Alto PAN-OS
```

Plan a migration from the CLI:

```bash
fwmigrate migrate \
  --input fortigate.conf \
  --output output \
  --format set
```

Use `--zone-map mapping.yaml` when target VSYS, virtual-router, interface, or zone mappings are required.

For destination evidence and intent, the CLI also accepts:

```bash
fwmigrate migrate --input fortigate.conf --output output --format set \
  --target-config target-pan-os.xml --target-device 012345678901 \
  --target-intent target-intent.yaml --automation-mode REVIEW_ONLY
```

`--target-config` supplies PAN-OS XML evidence. If the XML contains multiple
devices, select one with `--target-device`; that option requires
`--target-config`. `--target-intent` supplies engineer target-intent YAML.
`--automation-mode` accepts `REVIEW_ONLY`, `STRICT_VERIFIED`,
`VERIFIED_AND_DERIVED`, or `ENGINEER_INTENT`. Only `--format set` is currently
implemented; `xml` and `cli` are rejected. CLI planning and file export do not
provide web deployment approval.

Migration planning is directional and pair-specific:

```text
FortiGate source
→ FGConfig / DerivedViews
→ Mapping Requirements
→ Target Evidence / Engineer Decisions
→ Deterministic Design Session
→ PANMigrationPlan
→ Target Validation / Reuse Classification
→ Dependency-aware CREATE / CONFIGURE / REUSE / BLOCK disposition
→ PAN-OS Set Renderer
```

A `MigrationPlan` is not a complete target firewall configuration.

The migration report keeps supported, partial, manual-review, blocked, and unsupported items visible rather than silently dropping them.

Target-specific information that cannot be derived safely requires an explicit mapping or decision.

Suggestions are not treated as confirmed engineer decisions.

Guided review queues surface actionable mappings, unresolved prerequisites,
conflicts, and unsupported work. Updating a proposal saves a draft; it is not
engineer approval, even after validation. Approval binds the selected mappings
and configuration items, their target scope and operations, and their
dependencies to the reviewed design. Unapproved items and items blocked by
unresolved dependencies produce no commands. Unsupported coverage remains
visible as manual work, so partial approval is not a complete migration.

Unimplemented migration pairs fail closed.

## Migration Artifacts

Rendering is deterministic for a given reviewed migration plan.

The following surfaces must use the same rendered migration artifact:

```text
command preview
.set download
migration bundle
deployment
```

The migration report records artifact integrity information including:

```text
command count
command SHA-256
```

CLI `deploy` and `commit` are disabled because they do not carry signed design approval and artifact-bound candidate sessions. Use the web workflow for live deployment. CLI migration planning and file export remain available.

Web executable artifact generation requires a current signed approval from `/api/migration/design/prepare` → `/api/migration/design/approve`. Raw mappings and unsigned decision documents are proposal inputs: they cannot issue executable artifacts. The compatibility interface-confirmation, decision-approval, automation, and rule APIs preserve editable proposals and imports; their outputs still require deterministic design approval. Approvals expire after 24 hours, matching the browser workspace lifetime, and require renewed engineer review. Partial approvals render only approved groups with satisfied dependencies; unapproved or dependency-blocked items produce no commands. IPv6 and mixed-family policy matches remain visible as unsupported evidence and render no security rules.

Web candidate preparation requires a signed `READY` artifact and an explicit serial and baseline fingerprint in the approved destination XML evidence. A device name or hostname alone cannot establish serial identity. Before pushing, the SSH workflow checks the live serial, verifies the approved `baseline_sha256` against the live sanitized PAN-OS configuration, and requires `show config diff` to be empty. Destination drift requires refreshed evidence and renewed approval. After the push, the workflow fingerprints the complete XML candidate from `show config candidate` without exporting its contents. Revalidation and explicit commit check the same live serial and candidate fingerprint. Drift, validation failure, unknown commit state, session expiry, and server restart require another candidate preparation. `READY_NO_CHANGES` artifacts are downloadable but cannot deploy.

These guards apply to the web workflow; CLI deployment and commit are disabled. Device-native configuration locking is not enforced: another administrator can still change the candidate between the final fingerprint check and commit. Coordinate administrator access during candidate preparation and commit. The baseline fingerprint identifies approved sanitized destination evidence; the rendered command SHA-256 identifies the commands to apply; the post-push candidate SHA-256 identifies the candidate configuration checked during validation and commit. They serve distinct purposes.

This provides the intended flow:

```text
one reviewed plan
→ one RenderedMigration
→ one command digest
→ preview / download / bundle / deployment
```

## Candidate Deployment

PAN-OS SSH deployment uses the optional deployment dependency:

```bash
python -m pip install -e ".[deployment]"
```

Use Live migration in the web application after approving the design and reviewing the plan. The application shows candidate deployment eligibility and any missing destination evidence.

```text
verify signed migration artifact
→ verify destination serial and reviewed baseline
→ push candidate commands
→ validate candidate
→ stop
→ explicit commit of the validated candidate
```

Deployment does **not** automatically commit. CLI `deploy` and `commit` fail without connecting to a device; use the reviewed application workflow instead.

## Architecture

Each vendor owns its source semantics.

Shared infrastructure handles orchestration and contracts without requiring vendors to expose a common firewall object model.

```text
Tokenizer / Scanner
    syntax and lexical structure only

Parser / Source Adapter
    vendor structure and explicit source data

Command Evaluator
    vendor command semantics where applicable

VendorConfig
    authoritative explicit source state

Relationships
    references, memberships, bindings and topology

Transforms
    vendor-specific semantics and genuine derivation

DerivedViews
    read-only derived state

Validation
    detect and report only

Web Preview / Excel
    presentation only

Collection
    vendor-native acquisition only

Conversion
    pair-specific migration planning and rendering

Deployment
    reviewed rendered-artifact execution
```

Validation and derived processing must not silently mutate or repair source configuration.

Shared source-reporting code treats vendor analysis results as opaque.

It does not require a common semantic representation for:

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

There is no vendor-neutral migration IR.

Detailed architecture and development rules are defined in:

[`AGENTS.md`](AGENTS.md)

## Source Semantics

The source pipeline keeps these concepts distinct:

```text
explicit source value
derived value
effective value
vendor default
unknown value
unsupported source value
```

A missing source-model field does not automatically mean:

```text
disabled
false
empty
zero
inherit
any
vendor default
```

Effective values are exposed only when vendor-specific logic actually calculates them.

When behavior is unclear:

```text
preserve source
→ classify as unknown / unsupported / source-only
→ report the limitation
→ do not guess
```

## Source Preservation

Useful source configuration should be preserved even when the tool does not fully understand its semantics.

Depending on the vendor, this may include:

```text
raw_extra
unsupported commands
source attributes
source metadata
Source Inventory
Additional Settings
source appendix sheets
collection evidence
```

Excel and migration output must not drive source-model design.

## Validation

Validation detects and reports problems.

It does not silently repair source configuration.

Examples include:

```text
broken references
duplicate names
invalid memberships
unresolved interfaces
policy binding problems
topology issues
unsupported constructs
ambiguous source data
collection incompleteness
derived transformation issues
```

Validation should distinguish source problems from extraction, interpretation, derivation, or collection limitations.

## Excel Reporting

Excel is a presentation layer.

Each vendor owns its Excel schema and exporter.

Reports may contain:

```text
explicit source fields
genuine derived fields
validation findings
source inventory
unsupported/source-only evidence
additional settings
source appendix information
```

Excel reporting should not introduce:

```text
vendor-neutral IR fields
target-vendor fields
fake effective values
redundant normalized duplicates
unsupported inferred values
```

## Security

Firewall configurations may contain sensitive authentication material.

For customer configuration handling, the web application applies a bounded request-size limit, keeps multipart upload streams in memory, sanitizes vendor-native evidence before parsing/reporting, marks API responses `no-store`, and adds restrictive browser security headers. PAN-OS XML containing DTD or entity declarations is rejected before parsing. Sanitized configuration still contains sensitive operational topology and must be handled as customer-confidential data.


The application must not expose actual:

```text
passwords
password hashes
pre-shared keys
private keys
API keys
tokens
credentials
shared secrets
sensitive SNMP community values
```

Safe metadata may be reported instead:

```text
Password Configured = Yes
PSK Configured = Yes
Credential Present = Yes
Private Key Present = Yes
```

Secret handling applies across:

```text
source extraction
raw / unsupported evidence
source inventory
live collection
collection snapshots
validation
web preview
Excel
migration decisions
migration reports
rendered artifacts
deployment responses and errors
logs
```

Configuration files, generated reports, and migration artifacts should still be treated as sensitive operational data.

## Project Structure

Key areas:

```text
src/
├── fwmigrate/
│   ├── collection/       Vendor-native live source acquisition
│   ├── extraction/       Shared extraction evidence and accounting utilities
│   ├── source_reporting/ Source-report orchestration and presentation contracts
│   ├── vendors/          Vendor-owned extraction and reporting implementations
│   ├── conversion/       Pair-specific migration planning and rendering
│   ├── deployment/       Reviewed target artifact deployment
│   ├── web.py            Flask composition, auth, security, and route registration
│   ├── web_api/          Source, migration, and deployment HTTP route modules
│   ├── web_support/      Web transport, reporting, frontend, and artifact helpers
│   └── main.py           CLI entry point
│
└── frontend/
    ├── src/               React presentation and workflow client
    └── dist/              Generated frontend build served by Flask

requirements/              Reproducible Python build constraints
scripts/                   FortiGate FAST Excel benchmark
Start Local.bat            Windows browser development launcher
```

The React frontend is a presentation and workflow client. It must not become a vendor-semantics or migration-planning layer.

Vendor-specific logic belongs inside the corresponding vendor package.

Examples include:

```text
parsing
source models
relationships
transforms
DerivedViews
validation
preview serialization
Excel export
```

Pair-specific target semantics belong in the corresponding conversion package, not in source models.

## Development

Before changing behavior, inspect the current code, models, symbols, callers, tests, and pipeline.

Prefer the smallest coherent change.

Do not reintroduce:

```text
vendor-neutral source IR
common firewall object hierarchy
generic cross-vendor migration schema
target-vendor concepts inside source models
shared semantic Excel models
generic migration mapping framework
```

Source reporting must remain independent of conversion.

Migration must remain directional and pair-specific.

Validation must detect and report rather than silently repair source state.

## Testing

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Compile source and tests:

```bash
python -m compileall -q src tests
```

Run the Python test suite:

```bash
python -m pytest -q
```

Run Python linting:

```bash
ruff check src tests
```

For frontend changes:

```bash
cd src/frontend
npm ci
npm test
npm run lint
npm run build
```

For deployment/release dependency changes, also validate the constrained Python 3.12 dependency set used by hosted deployment builds.

Run only the checks relevant to the affected area locally, while CI remains the authoritative full repository matrix.

Source-reporting path:

```text
source
→ parser / adapter
→ VendorConfig
→ DerivedViews
→ validation
→ web preview / Excel
```

Collection path:

```text
collector
→ sanitized source
→ source-reporting pipeline
```

Migration path:

```text
FortiGate
→ FGConfig / DerivedViews
→ requirements
→ target evidence / decisions
→ deterministic design session
→ MigrationPlan
→ target validation / object reuse
→ dependency-aware render disposition
→ validation
→ RenderedMigration
```

Deployment path:

```text
RenderedMigration
→ candidate push
→ candidate validation
→ explicit commit
```

Important regression areas include:

```text
nested configuration
contexts / domains / VDOM / VSYS / logical systems
unknown and unsupported fields
reference resolution
interface topology
policy ordering
NAT ordering
source provenance
collection completeness
snapshot sanitization
decision scope
mapping confirmation
source-digest mismatch
partial migration
target object reuse
CREATE / CONFIGURE / REUSE / BLOCK disposition
dependency-propagated render blockers
command count / SHA-256 consistency
preview / download / bundle consistency
deployment artifact verification
explicit commit separation
credential and secret redaction
web preview
Excel compatibility
Excel download
```

Source-reporting, collection, conversion, and deployment tests should remain separated according to their architectural boundaries.

## Documentation

Repository architecture and implementation guidance:

- [`AGENTS.md`](AGENTS.md) — architecture rules and development constraints.
- [`src/fwmigrate/conversion/README.md`](src/fwmigrate/conversion/README.md) — pair-specific migration architecture.
- `documentation/official-cli-references-selected version/` — selected official vendor configuration references.

Official vendor documentation is the primary semantic reference when implementing or validating vendor behavior.

When implementation behavior is uncertain:

```text
preserve source
→ mark unknown / unsupported
→ report the limitation
→ do not guess
```
