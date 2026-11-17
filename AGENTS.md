# AGENTS.md

This repository uses **vendor-native extraction/reporting** plus **pair-specific migration planning**.

## Runtime, layout, and packaging

- **Stack**: React/Vite frontend (`src/frontend/`) + Flask backend (`src/fwmigrate/web.py`) + `fwmigrate` CLI (`src/fwmigrate/main.py`).
- **Web layers**: `src/fwmigrate/web_api/` owns HTTP routes; `src/fwmigrate/web_support/` owns transport, artifact signing, request controls, public errors, reporting, and frontend serving.
- **Core packages**: `vendors/<vendor>/` (vendor-owned extraction/reporting), `source_reporting/` & `extraction/` (shared reporting contracts), `collection/` (acquisition & snapshots), `conversion/<pair>/` (pair-specific migration).
- **Tests**: Mirror `src/fwmigrate/` under `tests/architecture/`, `tests/collection/`, `tests/source_reporting/`, `tests/vendors/<vendor>/`, `tests/conversion/<pair>/`, `tests/web/`, and `tests/fixtures/`. Standalone Playwright scripts live under `scripts/browser/`.
- **Frontend build**: Flask serves `src/frontend/dist/`. Run `npm ci && npm run build` in `src/frontend` before opening Flask's URL (`/` returns HTTP 503 without it).
- **Local dev**: `Start Local.bat` runs Flask on `127.0.0.1:5000` and Vite on `127.0.0.1:5173` (proxying API calls to Flask).
- **Hosting & access**: Hosted web uses single-worker Gunicorn (`gunicorn.conf.py`, `WEB_MODE=public` default). Live collection runs on the backend machine, requires `WEB_MODE=local` + loopback client/host, and is blocked (`403`) in `public` mode. API POST concurrency (`MAX_CONCURRENT_REQUESTS`) and workbook streams (`MAX_CONCURRENT_EXPORTS`) are process-local.
- **Removed packaging**: Tauri desktop packaging, Docker deployment files, and live device deployment (`deployment/`) have been removed. Do not assume Rust/Cargo, desktop sidecars, container builds, desktop installers, or live deployment transports exist.
- **Versions & CI**: Frontend CI and Render use the Node.js 24 baseline in `.node-version` (`package.json` enforces `>=24.22.1 <25`). Python CI covers 3.11–3.14; the constrained dependency job uses Python 3.12 + `requirements/constraints-python312.txt`.

## Pipelines

- **Source reporting**: `Vendor Source → Parser / Adapter → VendorConfig → Relationships / Transforms → DerivedViews → Validation → Preview / Excel`
- **Collection**: `Device / Manager → Collector → Sanitized Vendor Source → Source Reporting`
- **Migration**: `VendorConfig → DerivedViews → Pair-specific Requirements → Target Evidence / Engineer Decisions → Deterministic Design Session → MigrationPlan → Target Validation / Reuse Classification → Dependency-aware Render Disposition → Renderer`

Implemented migration pairs (partial, directional offline exports; `deployment_available=False`; **no vendor-neutral firewall IR**):
`fortigate → palo_alto`, `palo_alto → fortigate`, `palo_alto → juniper_srx`, `palo_alto → cisco_asa`, `palo_alto → checkpoint`, `palo_alto → cisco_ftd`, `fortigate → cisco_asa`, `fortigate → juniper_srx`, `fortigate → checkpoint`. See `documentation/migration-support-matrix.md` and `src/fwmigrate/conversion/builtin.py` for mapping, comparison, and activation limits.

## Core semantic rules

- `VendorConfig` represents **explicit source state only**. A missing field means **not explicitly configured**—never silently treat absence as `default`, `false`, `disabled`, `empty`, `zero`, `inherit`, or `any`.
- Keep distinct: **explicit source**, **derived value**, **effective/default value**, **operational value**, and **unknown / unsupported value**.
- When unclear: `preserve source → mark unknown / unsupported → report it → do not guess`.

## Responsibility boundaries

| Layer | Responsibility |
|---|---|
| `Tokenizer / Scanner` | Syntax only |
| `Parser / Adapter` | Source structure only |
| `Command Evaluator` | Command semantics |
| `VendorConfig` | Authoritative explicit source state (immutable after extraction) |
| `Relationships` | References, bindings, and topology |
| `Transforms` | Vendor semantics and genuine derivation |
| `DerivedViews` | Read-only derived state |
| `Validation` | Detect and report only |
| `Preview / Excel` | Presentation only |
| `Collection` | Acquisition only |
| `Conversion` | Pair-specific planning and rendering only |

- Do not move semantics into parsers, validation, web code, or Excel for convenience.
- After extraction, do not mutate `VendorConfig`. Do not silently fill defaults, repair references, insert inferred source objects, rewrite source values, or delete unsupported evidence.

## Source preservation and shared code

- **Source preservation**: Preserve useful unsupported data via `raw_extra`, unsupported commands, source metadata, `Source Inventory`, `Additional Settings`, source appendix sheets, and collection evidence. Do not add source-model fields solely to satisfy Excel or migration output.
- **Allowed shared infrastructure**: Vendor registration, source-report dispatch, collection contracts, migration planner contracts, and web orchestration.
- **Frontend boundary**: The React frontend is strictly a presentation and workflow client—never move vendor parsing, source semantics, migration planning, validation semantics, or target rendering into frontend code.
- **No shared semantic models**: Vendor semantic models stay vendor-owned. Never create shared semantic models for `addresses`, `services`, `policies`, `NAT`, `interfaces`, `zones`, `routes`, or `VPNs`. Source reporting must not depend on conversion.

## Vendor rules

Use official vendor documentation under `documentation/official-cli-references-selected version/` as semantic authority.

- **FortiGate**: `Tokenizer → Parser → Command Evaluator → FGConfig → Relationships / Transforms → DerivedViews → Validation → Excel`. Preserve VDOMs, nested config, `set/append/unset`, ordering, topology, and `raw_extra`. Do not move semantics into the parser.
- **Cisco ASA**: Preserve command/ACL/NAT order, contexts, bindings, `nameif`, inactive state, and explicit `no`.
- **Cisco FTD**: Keep FMC, FDM, and CLI/device evidence distinct. Preserve UUIDs, domains, ownership, overrides, ordering, and completeness.
- **Juniper SRX**: Preserve hierarchy, logical systems, routing instances, groups, inheritance, address-book scope, and inactive state.
- **Check Point**: Keep Management API and Gaia distinct. Preserve UID, domain, package, layer, section, inline-layer, gateway/cluster scope, and completeness.
- **PAN-OS**: Current source input is XML only (do not assume source `set` input support). Preserve VSYS/shared/device-group/device scope and rule order.

## Migration planning and decisions

- `src/fwmigrate/conversion/` holds directional pair-specific planners. Do not introduce a `vendor-neutral IR`, shared source/target firewall model, generic migration schema, generic cross-vendor mappings, or a `TargetVendorConfig` abstraction. Unimplemented pairs must fail closed.
- **Canonical pair package boundaries**: Subpackages `planning/`, `design/`, `review/`, `target/`, `rendering/`, `application/`, and optional `recommendations/`, alongside pair-root domain modules (`models.py`, `options.py`, `planner.py`, `plan_dependencies.py`, `requirements.py`, and optional `validation.py` / `decisions.py`). Do not recreate top-level compatibility shim modules that duplicate those subpackages.
- **Decisions**: Modes are `AUTO`, `SUGGESTED`, `REQUIRED`, `UNSUPPORTED`; review states are `PENDING`, `CONFIRMED`. Only `AUTO` or `CONFIRMED` decisions may become planner input. A suggestion is not confirmation.
- **Approvals**: Saving/updating a proposal is not engineer approval. Web executable artifacts require a current signed design approval bound to selected mappings, configuration items, target scope, operations, and dependencies. CLI planning works without design approval and exports unapproved review material.
- Never guess target `VSYS`, `virtual router`, `interface`, `zone`, or `ownership`. Decision identity must preserve source scope (e.g., VDOM).

## Rendering, collection, and secrets

- **Render dispositions**: `CREATE` (render creation commands), `CONFIGURE` (render only explicitly approved additive target changes), `REUSE` (satisfy without creation commands; not equivalent to creation), `BLOCK` (render nothing). `CONFIGURE` requires explicit engineer approval. Render only approved items with satisfied dependencies; propagate blocked dependencies before rendering. Unsupported coverage stays visible as manual work.
- **Artifact integrity**: Command preview, download, and bundle must consume the exact same `RenderedMigration` (preserving artifact identity, command count, and command SHA-256).
- **Collection**: Acquisition only (`SUCCESS`, `PARTIAL`, `FAILED`). Never treat failed/unsupported parts as empty configuration. Snapshots are sanitized source envelopes, not semantic models.
- **Secrets**: Never export, preview, log, or persist actual passwords, password hashes, PSKs, private keys, API keys, tokens, shared secrets, or sensitive credentials anywhere (raw evidence, collection, reports, migration, logs). Safe presence metadata (e.g., `Password Configured = Yes`) is allowed.

## Before editing

- When `.codegraph/` exists, use `codegraph_explore` (or `codegraph explore`) before broad searches or reads to locate symbols and trace callers. Use direct reads for config, docs, tests, and non-graph context. Do not create or regenerate the index unless asked.
- Inspect: current branch, actual paths, models, symbols, callers, tests, and current pipeline.
- Apply changes cleanly: smallest coherent change, preserve existing architecture, reuse existing logic, avoid unrelated refactoring, do not guess APIs, prefer package-relative imports. Current repository code and tests are authoritative.

## Testing and verification

Test the affected real path across architectural boundaries:
- **Source**: `source → VendorConfig → DerivedViews → validation → preview / Excel`
- **Collection**: `collector → sanitized source → source reporting`
- **Migration**: `source → Source VendorConfig / DerivedViews → requirements → target evidence / decisions → deterministic design session → MigrationPlan → target validation / reuse classification → dependency-aware render disposition → validation → RenderedMigration`

Testing conventions:
- Protect regressions in scope, ordering, references, topology, unsupported data, completeness, mapping decisions, artifact integrity, secret redaction, preview, Excel, and migration bundle.
- Use dependency injection hooks in tests rather than monkeypatching external libraries or global registries: `connection_factory` on SSH collectors, and `SOURCE_COLLECTOR_REGISTRY` on Flask `app.config`.
- Run targeted `pytest` files during iteration, then run applicable full checks before reporting completion (never claim tests or CI passed unless they actually ran):

```bash
# Python
python -m compileall -q src tests scripts
ruff check src tests scripts
python -m pytest -q

# Frontend
cd src/frontend
npm ci
npm test
npm run lint
npm run build
```

For release dependency or packaging changes, validate the constrained Python 3.12 set (`requirements/constraints-python312.txt`) or rely on CI when local reproduction is unavailable.

## Priority

`correctness → source preservation → explicit semantics → traceability → safety → maintainability`
