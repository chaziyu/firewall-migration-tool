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
→ Engineer Decisions / Mappings
→ Pair-specific MigrationPlan
→ Validation
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

The repository supports two independent runtime targets that share the same React frontend, Flask API contract, and `fwmigrate` application logic:

| Target | Runtime | Docker required? | Where backend operations run |
|---|---|---|---|
| Web / Render | Browser → Gunicorn → Flask | Yes for the current production container deployment | Render/container host |
| Windows desktop | React → Tauri → local PyInstaller Flask sidecar | **No** | User workstation |

The Tauri desktop application does **not** start Docker, require Docker Desktop, or communicate through a Docker container. Its Python backend is packaged as a sidecar executable and binds only to `127.0.0.1` using a per-launch authentication token.

This distinction matters for network access: desktop collection and PAN-OS deployment originate from the user's workstation, while web/Render collection and deployment originate from the hosted container and therefore require network reachability from that environment.

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
→ resolved Python 3.12 versions for Docker/Render and Tauri/PyInstaller builds

src/frontend/package-lock.json
→ resolved frontend dependency graph
```

The Python constraints file is used only by artifact-producing Python 3.12 paths. The Python 3.11/3.12/3.13 compatibility test matrix continues to install from the declared ranges so supported-version compatibility is still exercised.

For a reproducible production-style install:

```bash
python -m pip install --constraint requirements/constraints-python312.txt -e ".[ai,collection,deployment]"
python -m pip check
```

Review and regenerate the constraints file when dependencies are intentionally updated; do not silently edit individual pins merely to suppress a vulnerability scanner.

For the optional Groq migration advisor:

```powershell
python -m pip install -e ".[ai]"
if (-not (Test-Path .env.local)) { Copy-Item .env.example .env.local }
```

Set `GROQ_API_KEY` and `FWMIGRATE_AI_ENABLED=1` in `.env.local`. Groq uses the 20B model for simple decisions and 120B for ownership, dependency, high-candidate, coupled, and repair work. Request batches, byte size, AI-context candidate count, completion tokens, reasoning effort, reasoning format, retry delay, and the complex-candidate threshold are bounded in `.env.example`. Candidate reduction is deterministic and affects only the AI request: the full target candidate inventory is preserved for review. If a candidate cutoff would split equally supported candidates, the decision remains manual instead of being truncated arbitrarily. Rate-limit retries honor a provider `Retry-After` value when it is within the configured retry-delay ceiling. Set `FWMIGRATE_AI_LOCAL_URL` to use local Qwen first, with Groq available for capability escalation and fallback. The advisor resolves deterministic decisions before requesting advice and proposes only existing, unambiguous target candidates. An engineer must approve proposals before they affect the plan. The review page's synthetic **Test advisor** checks both the provider contract and a production-shaped request; `/api/migration/ai/status` returns configuration metadata without credentials. Set `FWMIGRATE_AI_LOCAL_RESPONSE_MODE=JSON_ONLY` if the local server rejects strict JSON schema requests. `FWMIGRATE_AI_GROQ_MODEL`, `FWMIGRATE_AI_MODEL`, and `FWMIGRATE_GROQ_MODEL` remain supported as fallback settings. `FWMIGRATE_AI_GUARD_MODEL` is reserved for free-text evidence; the current advisor context excludes descriptions and comments. Exported sanitized AI audit JSONL can be evaluated with `python tools/evaluate_ai_advisor.py <audit.jsonl>`; the report includes agreement, abstention, safety, engineer-outcome, request-efficiency, provider/model, target-field, and candidate-count metrics.

### Desktop Application

The desktop build is a native Tauri application. Tauri owns the window and lifecycle, while the existing Flask application runs locally as a PyInstaller sidecar:

```text
React
→ Tauri
→ authenticated 127.0.0.1 Flask sidecar
→ fwmigrate application / domain logic
```

**Docker is not part of the desktop runtime.** A user can run the packaged desktop application without Docker Desktop installed.

Windows build prerequisites are Rust, Node.js, Python, PyInstaller, and the normal Tauri Windows system dependencies. The desktop build uses the reviewed Python 3.12 constraints file:

```powershell
python -m pip install --constraint requirements/constraints-python312.txt -e ".[ai,collection,deployment]" "pyinstaller>=6.0"
python -m pip check

cd src/frontend
npm ci
npm run build
cd ../..

python desktop/build_tauri_sidecar.py

cd src/frontend
cargo install tauri-cli --version "^2" --locked
cargo tauri build
```

Typical build outputs are under:

```text
src/frontend/src-tauri/target/release/
src/frontend/src-tauri/target/release/bundle/nsis/
src/frontend/src-tauri/target/release/bundle/msi/
```

The existing pywebview/PyInstaller package remains available during the Tauri migration:

```powershell
pyinstaller "Firewall Migration Tool.spec"
```

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

### Docker / Render Web Deployment

Docker is used for the hosted web application, including the current Render deployment. It is separate from the Tauri desktop runtime; the Docker image does not host or launch the Tauri application.

The Docker image installs Python dependencies through `requirements/constraints-python312.txt`, so the deployed Python dependency set matches the reviewed Python 3.12 build constraints.

Build and run the production web image:

```bash
docker build -t firewall-migration-tool .
docker run --detach --name fwmigrate --publish 5000:5000 --env-file /etc/fwmigrate/fwmigrate.env --mount type=bind,src=/etc/fwmigrate/known_hosts,dst=/home/fwmigrate/.ssh/known_hosts,readonly firewall-migration-tool
```

On Windows, double-click [`Start Docker.bat`](./Start%20Docker.bat) to build the image, choose a local web password, start it on port `5000`, wait for its health check, and open the web application. Sign in as `fwmigrate` with that password. If that container is already running, the launcher reuses it; stop and remove it before rerunning to rebuild from current files.

The environment file supplies server settings and secrets at runtime. Hosted Docker/web deployments require HTTP Basic authentication. Set `FWMIGRATE_WEB_PASSWORD` to a strong runtime secret; `FWMIGRATE_WEB_USERNAME` defaults to `fwmigrate`. The unauthenticated `/healthz` endpoint is reserved for container health checks. Remote live collection is disabled by default even when the web application is reachable; set `FWMIGRATE_ALLOW_REMOTE_COLLECTION=1` only when the deployment is intentionally protected by the web authentication/access perimeter. The local Windows Docker launcher enables collection explicitly while publishing port 5000 on loopback only. For a company AI endpoint, set `FWMIGRATE_AI_ENABLED=1` and `FWMIGRATE_AI_LOCAL_URL` to its reachable HTTPS URL; `localhost` inside the container refers to the container itself. Do not bake secrets into the image.

The container listens on port `5000` and runs as the non-root `fwmigrate` user. SSH collection and deployment use strict host-key checking, so mount the company's trusted `known_hosts` file at `/home/fwmigrate/.ssh/known_hosts`. Allow outbound access from the container to firewall management interfaces, FMC/Check Point APIs as used, and the company AI endpoint.

Workflow state belongs to each browser profile in native IndexedDB. It contains sanitized vendor-native evidence, previews, decisions, advisory AI state, and signed rendered artifacts. Connection usernames and passwords stay in React memory. **New workspace** clears local workflow data and resets the UI. Workspaces expire after 24 hours of inactivity; profiles on a shared computer share local browser storage.

Set `FWMIGRATE_WORKSPACE_SIGNING_KEY` to a stable random secret of at least 32 bytes in the runtime environment file. Use the same key for every server handling the workspace. This keeps browser-held artifacts and AI designs valid across restarts. Without this setting, a temporary key is generated and existing signed artifacts must be rebuilt after restart. Key rotation also requires rebuilding signed artifacts. Never bake the key into the image or expose it to the browser.

Source preview, Excel, migration review, planning, and AI approval reconstruct analysis from request-carried source evidence. The backend retains no preview, source, rendered artifact, or AI workflow cache. API clients must send `source` (sanitized native evidence or collection snapshot), optional `target_source`, decisions, and target device; opaque preview IDs are no longer accepted. `/api/migrate` returns a signed `artifact` envelope. Export and deployment requests carry that envelope. Bundle export also carries the matching source. AI actions carry the signed `design_session`; audit export is local to the current browser workspace.

Gunicorn still uses one worker for candidate deployment coordination. Only transient target host/port, artifact identity/count/hash, validation job/time, and session nonce remain server-side. Same-target operations serialize; different targets can run concurrently. A restart invalidates candidate sessions and requires another prepare/validate step. Commit remains explicit. Multiple deployment workers or replicas require shared candidate coordination before they are supported.

The source-reporting workflow is:

```text
upload source configuration
→ select source vendor
→ parse and analyze
→ review preview and validation
→ export vendor-native Excel report
```

For FortiGate input, the web application additionally supports:

```text
analyze source
→ plan migration
→ review target mappings
→ confirm decisions
→ review migration plan
→ generate PAN-OS commands
→ download migration artifacts
→ optionally push candidate configuration
```

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

Migration planning is directional and pair-specific:

```text
FortiGate source
→ FGConfig / DerivedViews
→ Mapping Requirements
→ Engineer Decisions
→ PANMigrationPlan
→ Plan Validation
→ PAN-OS Set Renderer
```

A `MigrationPlan` is not a complete target firewall configuration.

The migration report keeps supported, partial, manual-review, blocked, and unsupported items visible rather than silently dropping them.

Target-specific information that cannot be derived safely requires an explicit mapping or decision.

Suggestions are not treated as confirmed engineer decisions.

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

CLI deployment verifies that the supplied `.set` file matches its adjacent `migration_report.json` before sending commands to the target firewall.

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

Deploy a generated `.set` file:

```bash
fwmigrate deploy \
  output/palo_alto_config.set \
  --host <firewall-host> \
  --username <username>
```

The password is prompted securely.

Default deployment behavior is:

```text
verify migration artifact
→ connect
→ push candidate commands
→ validate candidate
→ stop
```

Deployment does **not** automatically commit.

Commit is an explicit separate operation:

```bash
fwmigrate commit \
  --host <firewall-host> \
  --username <username>
```

Review generated commands and migration findings before deployment.

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
src/fwmigrate/
├── collection/
│   └── Vendor-native live source acquisition
│
├── extraction/
│   └── Shared extraction evidence and accounting utilities
│
├── source_reporting/
│   └── Source-report orchestration and presentation contracts
│
├── vendors/
│   └── Vendor-owned extraction and reporting implementations
│
├── conversion/
│   └── Pair-specific migration planning and rendering
│
├── deployment/
│   └── Reviewed target artifact deployment
│
├── web.py
├── web_live.py
│   └── Web application orchestration
│
└── main.py
    └── CLI entry point
```

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

Run the test suite:

```bash
python -m pytest -q
```

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
→ decisions
→ MigrationPlan
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
render blockers
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
