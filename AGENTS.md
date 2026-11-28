# AGENTS.md

## Runtime, layout, and packaging

- **Stack & layout**: React/Vite (`src/frontend/`) + Flask (`src/fwmigrate/web.py`) + CLI (`src/fwmigrate/main.py`). Under `src/fwmigrate/`: `web_api/` (routes), `web_support/` (transport, signing, controls, errors, frontend serving), `vendors/<vendor>/`, `source_reporting/`, `extraction/`, `collection/`, and `conversion/<pair>/`.
- **Tests**: `tests/` (`architecture/`, `source_reporting/`, `vendors/<vendor>/`, `web/`, `fixtures/`); Playwright scripts in `scripts/browser/`.
- **Local dev & build**: Flask serves `src/frontend/dist/` (`/` returns `503` if missing; build with `npm ci && npm run build` in `src/frontend`). `Start Local.bat` builds `dist/` if needed and runs Flask on `127.0.0.1:5000`.
- **Desktop packaging**: `Build Desktop App.bat [all|portable|installer]` packages `scripts/desktop_launcher.py` (`pywebview` + Flask + `dist/`) via PyInstaller and/or Inno Setup (`scripts/installer/FirewallMigrationTool.iss`).
- **Hosting & access**: Single-worker Gunicorn (`gunicorn.conf.py`, `WEB_MODE=public` default); `MAX_CONCURRENT_REQUESTS` and `MAX_CONCURRENT_EXPORTS` are process-local. Live collection requires `WEB_MODE=local` + loopback (`403` in `public`).
- **Runtimes**: Node 24 (`.node-version`) and Python 3.14 (`.python-version`).


## Core semantic rules

- **Report Pipeline**: `Vendor Source → Parser / Adapter → VendorConfig → Relationships / Transforms → DerivedViews → Validation → Preview / Excel`
- **Source preservation**: Preserve useful unsupported data via `raw_extra`
- **Secrets**: Never expose or persist sensitive credentials; safe presence metadata (e.g., `Password Configured = Yes`) is allowed.
- **Migration pairs**: Do not modify implemented migration pairs without prior review (deferred to a later phase).
- **Frontend boundary**: The React frontend is strictly a presentation 
- **CodeGraph**: When `.codegraph/` exists, use `codegraph_explore` (or `codegraph explore`) before broad searches. 

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

- Keep semantics out of parsers, validation, web code, and Excel.
- After extraction, never mutate `VendorConfig`, fill defaults, repair references, insert inferred objects, rewrite source values, or delete unsupported evidence.


## Vendor rules

Use official vendor documentation under `documentation/official-cli-references-selected version/` as semantic authority.

- **FortiGate**: Source input is `.conf` / `.cfg` only.
- **PAN-OS**: Source input is XML only.

## Frontend styling

Follow `src/frontend/STYLE_GUIDE.md` for all React/CSS changes:
- Use only design tokens defined in `src/frontend/src/styles/tokens.css` and `themes.css` (enforced by `src/frontend/tests/designSystem.test.mjs`).
- Do not append new feature styles to `src/frontend/src/App.css`; colocate new styles in `*.module.css` or feature-scoped CSS files and reuse primitives from `src/components/common/` and `src/styles/primitives.css`.

## Testing and verification

- **End-to-end path**: Test the affected real path across boundaries (`source → VendorConfig → DerivedViews → validation → preview / Excel`).
- **Regression focus**: Scope, ordering, references, topology, unsupported data, completeness, secret redaction, artifact integrity, and preview/Excel/bundle outputs.
- **Test isolation**: Prefer dependency injection hooks (e.g., `SOURCE_COLLECTOR_REGISTRY` on Flask `app.config`) over monkeypatching external libraries or global registries.
- **Verification**: Run targeted `pytest` files while iterating, then applicable full checks before finishing (only report checks that actually ran):

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

- **Packaging/dependencies**: Validate with `python -m pip install -e ".[dev,collection]"` and `python -m pip check` on Python 3.14 (or via CI).