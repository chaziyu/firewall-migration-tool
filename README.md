# Firewall Migration Tool

![Python](https://img.shields.io/badge/python-3.11%2B-green.svg)

Vendor-native firewall configuration extraction, validation, reporting, live collection, and pair-specific migration planning for Python 3.11+.

> **Project status**
>
> Source extraction and reporting are implemented across multiple firewall vendors (FortiGate, Cisco ASA, Cisco FTD, Juniper SRX, Check Point, and Palo Alto PAN-OS).
>
> Pair-specific migration planning is implemented across **nine directional pairs**:
> - **FortiGate → Palo Alto PAN-OS** supports reviewed target mappings, PAN-OS `set` generation, and reviewed live candidate push, validation, and explicit commit.
> - **Eight offline export pairs** support engineer review, dependency-aware disposition, and downloadable configuration or API artifacts:
>   - **Palo Alto PAN-OS → FortiGate** (FortiOS 7.4.6 `.conf` CLI export)
>   - **Palo Alto PAN-OS → Juniper SRX** (Junos 25.2R1 `.set` export)
>   - **Palo Alto PAN-OS → Cisco ASA** (ASA 9.20 routed single-context `.cfg` export)
>   - **Palo Alto PAN-OS → Check Point** (Management API 1.8.1 JSON request specs + Gaia Clish routes)
>   - **Palo Alto PAN-OS → Cisco FTD** (FMC REST API 7.7.0 JSON request specs + curl script)
>   - **FortiGate → Cisco ASA** (ASA 9.20 `.cfg` export)
>   - **FortiGate → Juniper SRX** (Junos 25.2R1 `.set` export)
>   - **FortiGate → Check Point** (Management API 1.8.1 JSON request specs + Gaia Clish routes)
>
> Only FortiGate → PAN-OS supports live candidate operations; all other pairs export offline reviewed artifacts. For exact version baselines, limits, and operational rules, see the [Migration Support Matrix](documentation/migration-support-matrix.md).

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
- FortiGate → Palo Alto migration planning with optional live candidate deployment.
- PAN-OS → FortiGate reviewed FortiOS 7.4.6 `.conf` CLI export.
- PAN-OS → Juniper SRX standalone Junos 25.2R1 `set` export.
- PAN-OS → Cisco ASA 9.20 routed single-context `.cfg` export.
- PAN-OS → Check Point Management API 1.8.1 request specs and Gaia Clish routes.
- PAN-OS → Cisco FTD FMC REST API 7.7.0 request specs and curl execution script.
- FortiGate → Juniper SRX and Cisco ASA reviewed offline exports.
- FortiGate → Check Point Management API request specifications and separate Gaia static-route files.
- Explicit migration mapping and decision review across all 9 pairs.
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
PYTHONPATH=src gunicorn --config=gunicorn.conf.py --bind=0.0.0.0:5000 --timeout=120 "fwmigrate.web:create_app({'WEB_MODE': 'public'})"
```

API POST requests default to 30 requests per 60-second window per IP and at most 2 active processing requests. Configure positive integers with `FWMIGRATE_API_RATE_LIMIT_PER_MINUTE=30` and `FWMIGRATE_MAX_CONCURRENT_REQUESTS=2`. The supplied Gunicorn configuration uses one worker and four threads, and rejects startup or worker-count changes that request another count. Sessions, target-operation locks, rate limits, and concurrency controls are process-local. Run exactly one application instance. Custom launchers that bypass this configuration are not guarded. Multiple instances, overlapping process generations, and zero-downtime replacement require a different coordination design; avoid overlap in this setup.

Set `FWMIGRATE_FRONTEND_DIST_DIR` to `src/frontend/dist` if the host does not use the default frontend build path. Public mode requires no application login. It accepts configuration uploads, snapshot imports, previews, Excel reports, and migration downloads. All live collection and candidate inspection, preparation, validation, and commit endpoints return HTTP 403, including requests forwarded by a loopback proxy. The old `FWMIGRATE_ALLOW_REMOTE_COLLECTION` and `FWMIGRATE_ALLOW_REMOTE_DEPLOYMENT` flags cannot enable device access. Existing optional Basic authentication settings remain supported for private installations.

`create_app()` defaults to public mode. `Start Local.bat` and `fwmigrate serve` enable local mode when bound to `127.0.0.1`, `localhost`, or `::1`; other bind addresses use public mode. Live device access requires local mode, a loopback client address, and a loopback hostname. Keep local mode bound to loopback and do not publish it through a reverse proxy or tunnel. For a custom WSGI launcher, set `FWMIGRATE_WEB_MODE=local` only for a loopback-only service.

Terminate HTTPS before Flask and enforce HTTPS at the edge. Preserve the original Host header. In public mode, configure `FWMIGRATE_TRUSTED_PROXY_FOR` for the number of trusted proxies supplying `X-Forwarded-For`, and `FWMIGRATE_TRUSTED_PROXY_PROTO` separately for `X-Forwarded-Proto`. Both default to zero. Enable them only when the backend cannot be reached directly and the trusted proxies overwrite or correctly append these headers. An incorrect count can trust client-supplied values. Configure Gunicorn's trusted scheme-header peers consistently with the actual proxy addresses. Forwarded host, port, and prefix headers are not used by the application. Proxy trust is rejected in local mode.

HTTPS responses include `Strict-Transport-Security: max-age=31536000`. HSTS does not protect the first HTTP request; verify edge HTTPS enforcement before publishing. Loopback HTTP and local Vite access remain supported.

Allowed hostnames default to `localhost`, `127.0.0.1`, and `::1`. Render's deployment-provided `RENDER_EXTERNAL_HOSTNAME` is also accepted. For custom domains or hosts without Render metadata, set `FWMIGRATE_ALLOWED_HOSTS` to a comma-separated list of exact hostnames without schemes or ports. API writes must have the same Origin as the backend URL; only local mode also permits the Vite development origins `http://127.0.0.1:5173` and `http://localhost:5173`. Browser requests with an untrusted or null Origin are rejected. API clients without Origin remain supported; an explicit cross-site Fetch Metadata header is rejected when Origin is absent.

Set `FWMIGRATE_WORKSPACE_SIGNING_KEY` to a stable random secret of at least 32 bytes. It preserves artifact signatures across restarts, but candidate sessions are always invalidated by restart. Without it, signed artifacts also expire on restart. Keep credentials and signing keys in the host's secret manager. SSH collection and deployment use operating-system known-hosts configuration and strict host-key checking.

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

FMC and Check Point HTTPS certificate verification is required. Requests that explicitly set `verify_tls=false` are rejected; omitted values and `true` remain accepted. For private certificate authorities, set `REQUESTS_CA_BUNDLE` on the backend to a PEM bundle containing the required trusted CAs. Browser requests cannot select server CA-file paths.

FMC sessions are closed locally after use. Server-side token revocation is not implemented: its API contract has not been verified for the supported FMC version. Do not assume local closure revokes a token. Cisco documents access tokens as valid for 30 minutes; keep API account permissions limited.

Successful collection can produce a secret-sanitized snapshot for later preview and Excel reporting.

Collection snapshots are acquisition envelopes, not normalized firewall models.

## Migration Planning & Supported Pairs

The tool supports **nine directional migration pairs**. Only FortiGate → Palo Alto PAN-OS supports live candidate operations; all other eight pairs export reviewed offline configuration or API artifacts.

| Source Vendor | Target Vendor | Target Baseline | Output Format | Execution Mode | Guide / Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FortiGate** | **Palo Alto PAN-OS** | 11.1 | `.set` commands | Reviewed Candidate Push & Commit | [Workflow below](#fortigate--palo-alto-migration-flow) |
| **PAN-OS** | **FortiGate** | FortiOS 7.4.6 | CLI (`.conf`) | Offline Reviewed CLI | [PAN-OS to FortiGate](documentation/guides/PAN-OS-to-FortiGate-migration.md) |
| **PAN-OS** | **Juniper SRX** | Junos 25.2R1 standalone | Set (`.set`) | Offline Reviewed Set | [Multi-Target Guide](documentation/guides/PAN-OS-multi-target-migration.md) |
| **PAN-OS** | **Cisco ASA** | ASA 9.20 routed single-context | CLI (`.cfg`) | Offline Reviewed CLI | [Multi-Target Guide](documentation/guides/PAN-OS-multi-target-migration.md) |
| **PAN-OS** | **Check Point** | Management API 1.8.1 | JSON + `.sh` | Offline API Specs + Clish | [Multi-Target Guide](documentation/guides/PAN-OS-multi-target-migration.md) |
| **PAN-OS** | **Cisco FTD** | FMC REST API 7.7.0 | JSON + `.sh` | Offline REST Specs + curl | [Multi-Target Guide](documentation/guides/PAN-OS-multi-target-migration.md) |
| **FortiGate** | **Cisco ASA** | ASA 9.20 routed single-context | CLI (`.cfg`) | Offline Reviewed CLI | [FortiGate to ASA](documentation/guides/fortigate-to-cisco-asa-migration.md) |
| **FortiGate** | **Juniper SRX** | Junos 25.2R1 standalone | Set (`.set`) | Offline Reviewed Set | [Support Matrix](documentation/migration-support-matrix.md#juniper-srx) |
| **FortiGate** | **Check Point** | Management API 1.8.1 | JSON + `.clish`| Offline API Specs + Clish | [FortiGate to Check Point](documentation/guides/fortigate-to-checkpoint-migration.md) |

For comprehensive feature coverage, CLI commands, and operational boundaries across all targets, see the [Migration Support Matrix](documentation/migration-support-matrix.md) and [Documentation Hub](documentation/README.md).

### FortiGate → Palo Alto Migration Flow

Plan a migration from the CLI:

```bash
fwmigrate migrate \
  --input fortigate.conf \
  --output output \
  --format set
```

Use `--zone-map mapping.yaml` when target VSYS, virtual-router, interface, or zone mappings are required.
Explicit interface-to-zone mappings also plan the corresponding target zones,
so policies and NAT rules can reference them. Missing mappings remain unresolved;
the CLI does not invent target placements.

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

The CLI prints the count of unplanned source items and the report path alongside
mapping and validation findings. Review these manual-work requirements even when
target mappings are complete. IPv4 IP-pool definitions without a corresponding
translated-address NAT plan remain visible; they are not exported as standalone
PAN-OS pools.
CLI and web migration review also account for preserved native source sections
outside the modeled feature families. These records remain manual work with
their source scope and hierarchy; raw setting values are not copied into
migration coverage. Programmatic callers can supply `source_inventory` to the
pair-specific pipeline; `coverage.inventory_available` records whether that
evidence was supplied.

Central-SNAT entries remain manual work. In a VDOM with a central-SNAT table or
preserved central/NGFW mode controls, policy NAT and VIP conversion require a
separate mode/order review. This includes explicit disable/unset controls: the
pair does not yet verify these source-mode semantics and does not infer an
activation state or default from them.

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

The browser defaults to offline `.set` export. Upload one FortiGate configuration,
review automatic proposals for physical target ports, review conversion
coverage, then approve and download the commands and report. PAN-OS XML is not
required. VSYS and virtual-router proposals require engineer confirmation.
Explicit physical/ethernet source interfaces receive deterministic, distinct
`ethernet1/N` proposals across VDOMs. Existing engineer allocations are preserved;
generated names do not verify hardware port availability or cabling. Missing or
unsupported source interface types are not treated as physical ports.
VLAN subinterface identifiers are editable independently of their VLAN tags.

Offline readiness describes the approved export only. Destination collisions,
hardware compatibility, capacity and licensing remain unverified. `CREATE`
describes the proposed design; it does not establish that an object is absent
from a firewall. Unsupported or blocked source configuration remains visible
and prevents a complete export. Independent supported objects can still export.

Select the advanced destination-aware workflow to supply destination XML and
check reuse. Changing workflow mode revokes the previous approval and artifact.
Offline artifacts cannot prepare, validate or commit a live candidate. Live
execution requires a newly approved destination-aware design and the existing
serial, sanitized baseline, clean candidate and explicit commit checks.

## FortiGate → Check Point Migration

The Check Point workflow is an offline, engineer-reviewed export. It does not
connect to Management or Gaia, publish a package, install policy, or save Gaia
configuration. See [Check Point coverage and usage](documentation/guides/fortigate-to-checkpoint-migration.md)
for the verified subset, CLI command, manual checks, and limitations.

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

Web candidate preparation requires a signed `READY` artifact and an explicit serial and baseline fingerprint in the approved destination XML evidence. A device name or hostname alone cannot establish serial identity. Before pushing, the SSH workflow checks the live serial, verifies the approved `baseline_sha256` against the live sanitized PAN-OS configuration, and requires `show config diff` to be empty. Destination drift requires refreshed evidence and renewed approval. After the push, the workflow fingerprints the complete XML candidate from `show config candidate` without exporting its contents. Revalidation and explicit commit check the same live serial and candidate fingerprint. Drift, validation failure, unknown commit state, session expiry, and server restart require read-only inspection and operator reconciliation before fresh preparation. `READY_NO_CHANGES` artifacts are downloadable but cannot deploy.

These guards apply to the web workflow; CLI deployment and commit are disabled. Device-native configuration locking is not enforced: another administrator can still change the candidate between the final fingerprint check and commit. Coordinate administrator access during candidate preparation and commit. The baseline fingerprint identifies approved sanitized destination evidence; the rendered command SHA-256 identifies the commands to apply; the post-push candidate SHA-256 identifies the candidate configuration checked during validation and commit. They serve distinct purposes.

This provides the intended flow:

```text
one reviewed plan
→ one RenderedMigration
→ one command digest
→ preview / download / bundle / deployment
```

## Guided migration workspace

Open **Plan migration** after loading a FortiGate configuration. The workspace follows
**Source → Target setup → Review conversion → Download**.
Navigation does not approve or change the design.

1. Upload a FortiGate configuration. Offline conversion opens **Target setup**
   automatically. For destination checks, open **Source** and select the advanced
   destination-aware migration intent. Evidence starts as an **Architecture template**; explicitly choose
   **Destination configuration** only for XML from the intended firewall. Destination
   mode needs the selected device, real serial and reviewed baseline before candidate
   preparation. XML cannot verify hardware capacity or licensing.
2. Review VDOM ownership (VSYS and virtual router), then review proposed parent ports in the
   interface table. Derived VLANs and proposed zones remain editable. **Apply mappings**
   validates nonempty edits in one request; approval remains separate. Blank edits stay
   unresolved. Detailed editors and mapping files remain under Advanced tools.
3. Expand unresolved choices and manual work when needed. Each task shows one
   instruction; technical reasons and affected identities remain expandable. Placement actions apply only to editable
   decisions. Unsupported inspection, source ambiguity and other manual work remain
   excluded even after mappings are supplied. Affected counts are deduplicated within
   each task; tasks may overlap.
4. In **Review conversion**, check coverage by configuration family. Choose
   **Review ready items** or select specific changes, review the exact values,
   operations, scope and expanded prerequisites, then **Approve selected changes**.
   A failed draft request retains the previous view and staged edits as read-only
   evidence; Retry submits the same intended update. Failed generation after approval
   can be retried without approving again. Revalidate to change an approved selection
   or renew an expired approval.
5. Check export status separately from candidate eligibility. **Partial export**
   excludes blocked and manual work and cannot deploy. Supporting configuration
   without traffic rules is called out explicitly. **No changes needed** can produce
   a bundle without an artificial command or candidate push. Preview, `.set`, bundle
   and deployment use the same reviewed commands and SHA-256.

Migration work stays in memory for the current page session. Refreshing clears it.

**Target version, hardware and conversion scope** contains optional reviewed settings.
Selecting PA-820 bounds physical proposals to its 12 data ports; referenced, addressed or
explicitly managed interfaces receive proposals first. Exclusions retain source evidence and keep dependents
blocked. Target XML lists configured ports, not complete hardware inventory.

The converter proposes supported site-to-site tunnel identifiers and valid object names,
rewrites planned references, and separates source defects from mapping choices. Missing VPN
parameters can be proposed by group. Existing management/protection profiles require an
explicit assignment; decryption and identity matching remain separate checks. Supported
SNAT service unions expand into adjacent rules only after other NAT blockers are resolved.
Gateway authentication and incomplete VPN semantics remain manual; no placeholder secrets
are emitted. See [automation support and limits](documentation/architecture/migration-automation.md).

### Candidate recovery

Preparation performs preflight, pushes commands and validates automatically. Successful
validation permits explicit commit; revalidation is optional. The password clears
after every operation and must be re-entered for inspection, revalidation or commit.

Partial push, validation failure, candidate drift, expired/lost session, server
restart and interrupted or ambiguous commit disable execution. Use **Inspect candidate
(read-only)** with a current approved destination artifact to check live serial,
reviewed baseline and candidate cleanliness. Known attempted/accepted counts are
shown; an interrupted response does not prove that nothing was written. Inspection
never creates a validated session or commits, rolls back, discards or replays commands.

Reconcile dirty or unknown candidate state with the operator; changes may include
another administrator's work. Only a verified clean reviewed baseline permits fresh
preparation. Renew evidence and approval after destination drift or artifact expiry.
Commit uncertainty also requires checking device jobs and running state with the
operator; the application cannot recover its process-local session after restart.
The one-worker deployment baseline and device locking limitations still apply.

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


All API POST endpoints share one IP rate bucket and a non-blocking processing semaphore, acquired before body parsing and released during teardown, including failures. Rejected requests return HTTP 429 with `rate_limit_exceeded` or `server_busy` and `Retry-After`; retry manually, especially for deployment operations. Frontend and API GET requests are unaffected. IP tracking expires after 60 seconds and is capped at 4096 entries; while full, new IPs are rejected until an entry expires rather than evicting active limits.

Controls use `request.remote_addr` and ignore forwarded headers. Behind a proxy, clients may share a bucket. Verify Render's trusted proxy chain before adding forwarded-IP handling. Public mode blocks live device operations independently of proxy client addresses. Unexpected errors return fixed messages without exception tracebacks; only explicitly safe validation messages are public. Deployment failure responses retain status, identity, counts, and validation classifications while replacing untrusted transport/device failure text.

Application upload streams stay in memory, but upstream request buffering, temporary storage, request/proxy logging, and log retention must be verified separately on the host. Before hosted rollout, use synthetic configurations to check 3–6 concurrent preview, Excel, and migration requests, peak RAM, latency, 429 responses, recovery, and absence of secrets in application and proxy logs. Local tests do not establish these hosting guarantees.

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

Repository architecture, documentation hub, and operational guidance:

- [`documentation/README.md`](documentation/README.md) — central documentation index and navigation sitemap.
- [`documentation/migration-support-matrix.md`](documentation/migration-support-matrix.md) — authoritative cross-vendor capability matrix and version limits.
- [`documentation/guides/`](documentation/guides/) — pair-specific and multi-target operational migration manuals.
- [`documentation/architecture/`](documentation/architecture/) — core automation DAG engine and reporting workbook architecture.
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
