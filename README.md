# Firewall Migration Tool

![Python](https://img.shields.io/badge/python-3.14%2B-green.svg)
![Node.js](https://img.shields.io/badge/node-24.22.1%2B-green.svg)

Vendor-native firewall configuration extraction, validation, Excel reporting, live collection, and deterministic pair-specific migration planning for Python 3.14+.

Website: https://firewall-migration-tool.onrender.com/

---

## Overview

Firewall Migration Tool analyzes firewall configurations while preserving vendor-specific source semantics—without forcing configurations through a vendor-neutral intermediate firewall model.

```text
Source reporting:  Vendor Source → Parser / Adapter → VendorConfig → Relationships / Transforms → DerivedViews → Validation → Web Preview / Excel
Live collection:   Device / Manager → Collector → Sanitized Vendor Source → Source Reporting
Migration plan:    VendorConfig → DerivedViews → Pair Requirements → Target Evidence / Decisions → Design Session → MigrationPlan → Reuse / Disposition → Renderer
```

### Key Capabilities

- **Vendor-native extraction & validation**: Preserves explicit source state (missing fields are never silently defaulted), resolves vendor-specific topology/references, and keeps unsupported configuration visible.
- **Excel & web reporting**: Interactive web source preview and vendor-native Excel exports (`fast` and `full` profiles).
- **Live source collection (`local` mode)**: Acquires sanitized configuration snapshots from Cisco ASA, Juniper SRX, Cisco FTD (FMC), and Check Point with explicit completeness states (`SUCCESS`, `PARTIAL`, `FAILED`).
- **Pair-specific migration exports**: Deterministic, dependency-aware planning across **9 directional pairs** using `CREATE`, `CONFIGURE`, `REUSE`, and `BLOCK` dispositions, HMAC-signed web review approvals, and offline reviewed artifact bundles (`deployment_available=False` across all pairs).
- **Secret redaction**: Strips passwords, hashes, PSKs, private keys, API tokens, and sensitive SNMP communities across previews, snapshots, workbooks, reports, and logs.

---

## Supported Vendors & Migration Pairs

### Source Reporting & Live Collection (6 Vendors)

| Vendor | Vendor ID | Accepted Input | Live Collection (`local` mode) | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Fortinet FortiGate** | `fortigate` | `.conf`, `.cfg`, `.txt` | — | FortiOS CLI configuration |
| **Cisco ASA** | `cisco_asa` | `.cfg`, `.txt`, `.conf` | SSH | Command-oriented configuration |
| **Cisco FTD** | `cisco_ftd` | `.cfg`, `.txt`, `.conf`, `.json` | FMC REST API | Keeps FMC, FDM, and CLI evidence distinct |
| **Juniper SRX** | `juniper_srx` | `.set`, `.txt`, `.conf` | SSH | Junos configuration sources |
| **Check Point R81** | `checkpoint` | `.json`, `.txt`, `.cfg` | Management API | Preserves Management API and Gaia scope |
| **Palo Alto PAN-OS** | `palo_alto` | `.xml` | — | XML only (`set` source input is unsupported) |

### Directional Migration Pairs (9 Offline Reviewed Exports)

| Source Vendor | Target Vendor | Target Baseline | Format | Documentation |
| :--- | :--- | :--- | :--- | :--- |
| **FortiGate** | **Palo Alto PAN-OS** | PAN-OS 11.1 | `.set` | [FortiGate → PAN-OS](documentation/migration-support-matrix.md#fortigate-to-palo-alto-pan-os) |
| **PAN-OS** | **FortiGate** | FortiOS 7.4.6 | `.conf` (`cli`) | [PAN-OS → FortiGate](documentation/migration-support-matrix.md#palo-alto-pan-os-to-fortigate) |
| **PAN-OS** | **Juniper SRX** | Junos 25.2R1 standalone | `.set` | [PAN-OS → Juniper SRX](documentation/migration-support-matrix.md#palo-alto-pan-os-to-juniper-srx) |
| **PAN-OS** | **Cisco ASA** | ASA 9.20 routed single-context | `.cfg` | [PAN-OS → Cisco ASA](documentation/migration-support-matrix.md#palo-alto-pan-os-to-cisco-asa) |
| **PAN-OS** | **Check Point** | R81 Management API 1.8.1 + Gaia | `.json` + `.sh` + `.clish` | [PAN-OS → Check Point](documentation/migration-support-matrix.md#palo-alto-pan-os-to-check-point) |
| **PAN-OS** | **Cisco FTD** | FMC REST API 7.7.0 | `.json` + `.sh` + `.txt` | [PAN-OS → Cisco FTD](documentation/migration-support-matrix.md#palo-alto-pan-os-to-cisco-ftd) |
| **FortiGate** | **Cisco ASA** | ASA 9.20 routed single-context | `.cfg` | [FortiGate → Cisco ASA](documentation/migration-support-matrix.md#fortigate-to-cisco-asa) |
| **FortiGate** | **Juniper SRX** | Junos 25.2R1 standalone | `.set` | [FortiGate → Juniper SRX](documentation/migration-support-matrix.md#fortigate-to-juniper-srx) |
| **FortiGate** | **Check Point** | R81 Management API 1.8.1 + Gaia | `.json` + `.sh` + `.clish` | [FortiGate → Check Point](documentation/migration-support-matrix.md#fortigate-to-check-point) |

All pairs generate **reviewed offline artifacts** (`deployment_available=False`). See the [Migration Support Matrix](documentation/migration-support-matrix.md) for supported object subsets, NAT/routing limits, destination snapshot rules, and manual application steps.

---

## Quickstart & Installation

### Prerequisites

- **Python**: `>=3.14` (matching `.python-version`)
- **Node.js**: `>=24.22.1` (matching `.node-version`)

### Windows Local Development Launcher

[`Start Local.bat`](Start%20Local.bat) creates `.venv` if absent, builds `src/frontend/dist` if missing, starts Flask on `http://127.0.0.1:5000`, and opens the browser:

```bat
"Start Local.bat"
```

### Windows Desktop App & Installer

[`Build Desktop App.bat`](Build%20Desktop%20App.bat) packages [`scripts/desktop_launcher.py`](scripts/desktop_launcher.py) (Flask + `pywebview` + bundled frontend) as a standalone Windows desktop app:

```bat
"Build Desktop App.bat"            :: Builds portable .exe + installer (if Inno Setup 6 is installed)
"Build Desktop App.bat" portable   :: Builds only dist\FirewallMigrationTool.exe (--onefile)
"Build Desktop App.bat" installer  :: Builds --onedir bundle + dist\FirewallMigrationTool-Setup-<version>.exe
```

- **Inno Setup requirement**: Installer builds use [Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`) and [`scripts/installer/FirewallMigrationTool.iss`](scripts/installer/FirewallMigrationTool.iss). Version is read from `pyproject.toml`.
- **Upgrading**: Run the new `FirewallMigrationTool-Setup-<version>.exe` directly over an existing installation—it upgrades in-place, closes any running instance, clears stale `_internal` files, and updates the Windows Apps & features entry.

### Manual Setup

```bash
git clone https://github.com/chaziyu/firewall-migration-tool.git
cd firewall-migration-tool

python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[collection,dev]"

# Build the React frontend (served by Flask; `/` returns HTTP 503 without dist/)
cd src/frontend && npm ci && npm run build && cd ../..

# Start the local web application
fwmigrate serve --port 5000
```

---

## Usage (Web & CLI)

### Web Workspace

Start with `fwmigrate serve --port 5000` (or `Start Local.bat` during frontend development) and open `http://127.0.0.1:5000`:

- **Configuration Report**: Upload a source file or sanitized snapshot to inspect parsed objects, validation findings, and download an Excel workbook (`fast` default for most vendors; `full` default for PAN-OS).
- **Live Collection (`local` mode only)**: Connect via SSH (strict `known_hosts` verification) or HTTPS (strict TLS verification; set `REQUESTS_CA_BUNDLE` for private CAs) to capture sanitized snapshots.
- **Plan Migration**: Follow the 4-stage workflow (**Source → Target setup → Review conversion → Download**) to inspect coverage, resolve mappings, explicitly **Approve** (HMAC-signed 24h envelope), and download reviewed outputs + `migration_report.json` + ZIP bundle.

### CLI (`fwmigrate`)

```bash
# Discover registered source vendors
fwmigrate vendors

# Export FortiGate -> PAN-OS (.set)
fwmigrate migrate \
  --source-vendor fortigate --target-vendor palo_alto \
  --input fortigate.conf --output out --format set \
  --zone-map mapping.yaml

# Export PAN-OS -> FortiGate (.conf)
fwmigrate migrate \
  --source-vendor palo_alto --target-vendor fortigate \
  --input panos.xml --output out --format cli \
  --zone-map mapping.yaml

# Export PAN-OS -> Cisco ASA (.cfg) / Juniper SRX (.set) / Check Point or FTD (.json)
fwmigrate migrate \
  --source-vendor palo_alto --target-vendor cisco_asa \
  --input panos.xml --output out --format cfg
```

Key options:
- `--source-vendor` / `--target-vendor`: Defaults to `fortigate` → `palo_alto` (unimplemented pairs fail closed).
- `--format`: Target format (`set` for PAN-OS/SRX, `cli` for FortiGate, `cfg` for Cisco ASA, `json` for Check Point/Cisco FTD).
- `--zone-map`: Pair-specific YAML mapping file.
- `--target-config`: Optional vendor-native destination snapshot/configuration for reuse comparison.
- `--target-device`, `--target-intent`, `--automation-mode`: Supported for `fortigate` → `palo_alto` only (`REVIEW_ONLY`, `STRICT_VERIFIED`, `VERIFIED_AND_DERIVED`, `ENGINEER_INTENT`).

> CLI planning does not require web design approval and outputs unapproved review material. `fwmigrate deploy` and `fwmigrate commit` remain disabled.

---

## Hosted Web Deployment & Configuration

Build the frontend and run Gunicorn with the single-worker config ([`gunicorn.conf.py`](gunicorn.conf.py), `workers = 1`, `threads = 4`, because sessions, rate limits, and concurrency semaphores are process-local):

```bash
cd src/frontend && npm ci && npm run build && cd ../..
PYTHONPATH=src gunicorn --config=gunicorn.conf.py --bind=0.0.0.0:5000 --timeout=120 "fwmigrate.web:create_app({'WEB_MODE': 'public'})"
```

- **`public` vs. `local` mode**: `create_app()` defaults to `public`, blocking live collection endpoints with HTTP 403. `local` mode requires loopback binding, loopback client address, and loopback `Host` header—never expose `local` mode behind a public proxy or tunnel.
- **Security controls**: Memory-only multipart uploads, XXE/DTD rejection on PAN-OS XML, restrictive CSP/security headers, `Origin`/`Sec-Fetch-Site` checks, IP rate limiting, and bounded request/export concurrency.

### Environment Variables

Starter template: [`.env.example`](.env.example).

| Variable | Default | Description |
| :--- | :--- | :--- |
| `FWMIGRATE_WEB_MODE` | `public` | `public` blocks live device endpoints; `local` permits loopback-only collection. |
| `FWMIGRATE_WORKSPACE_SIGNING_KEY` | Ephemeral 32B | Stable >=32-byte secret preserving signed approval validity across restarts. |
| `FWMIGRATE_ALLOWED_HOSTS` | Loopback + `RENDER_EXTERNAL_HOSTNAME` | Comma-separated exact hostnames (no schemes/ports) accepted in `Host` headers. |
| `FWMIGRATE_TRUSTED_PROXY_FOR` | `0` | Trusted proxy count for `X-Forwarded-For` (`public` mode only). |
| `FWMIGRATE_TRUSTED_PROXY_PROTO` | `0` | Trusted proxy count for `X-Forwarded-Proto` (`public` mode only). |
| `FWMIGRATE_API_RATE_LIMIT_PER_MINUTE` | `30` | Max API POST requests per minute per IP (HTTP 429 `rate_limit_exceeded`). |
| `FWMIGRATE_MAX_CONCURRENT_REQUESTS` | `2` | Max concurrent active API POST requests (HTTP 429 `server_busy`). |
| `FWMIGRATE_MAX_CONCURRENT_EXPORTS` | `2` | Max concurrent Excel workbook generations/streams (HTTP 429 `export_busy`). |
| `FWMIGRATE_FRONTEND_DIST_DIR` | `src/frontend/dist` | Override directory for the built React frontend. |
| `FWMIGRATE_REQUIRE_WEB_AUTH` | `false` | Require `FWMIGRATE_WEB_PASSWORD` at startup (`1`/`true`/`yes`/`on`). |
| `FWMIGRATE_WEB_USERNAME` | `fwmigrate` | HTTP Basic Auth username when `FWMIGRATE_WEB_PASSWORD` is configured. |
| `FWMIGRATE_WEB_PASSWORD` | Unset | Enables HTTP Basic Auth across web routes when set. |
| `REQUESTS_CA_BUNDLE` | System / certifi | PEM CA bundle path for private CAs during FMC and Check Point HTTPS collection. |

---

## Project Structure & Testing

```text
src/
├── fwmigrate/
│   ├── collection/       Live source acquisition & snapshot sanitization
│   ├── extraction/       Shared extraction evidence and accounting utilities
│   ├── source_reporting/ Source-report orchestration and contracts
│   ├── vendors/          Vendor-owned parsing, models, transforms, validation, Excel
│   ├── conversion/       Directional pair-specific migration planners and renderers
│   ├── web.py            Flask app factory, auth, security headers, route registration
│   ├── web_api/          Source, migration pair, and conversion HTTP route modules
│   ├── web_support/      Request controls, artifact signing, public errors, frontend serving
│   └── main.py           CLI entry point (`fwmigrate`)
└── frontend/             React/Vite presentation client (`src/` and built `dist/`)
documentation/
├── migration-support-matrix.md                Authoritative pair capabilities, limits, and CLI usage
└── official-cli-references-selected version/  Pinned official vendor CLI/API syntax references
scripts/                  Desktop launcher (`desktop_launcher.py`), Inno Setup script (`installer/`), benchmarks, and Playwright scripts (`browser/`)
tests/                    Domain-mirrored test suites (`architecture/`, `collection/`, `conversion/`, `source_reporting/`, `vendors/`, `web/`, `fixtures/`)
AGENTS.md                 Mandatory architecture boundaries and contributor rules
```

### Running Checks

```bash
# Python compile, lint, and tests
python -m compileall -q src tests scripts
ruff check src tests scripts
python -m pytest -q

# Frontend tests, lint, and production build
cd src/frontend
npm ci
npm test
npm run lint
npm run build
```

See [`AGENTS.md`](AGENTS.md) and [`src/fwmigrate/conversion/README.md`](src/fwmigrate/conversion/README.md) for architectural constraints and contributor guidelines.
