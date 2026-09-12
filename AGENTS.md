# AGENTS.md

## Scope

Firewall Migration Tool is a Python 3.10+ multi-vendor firewall extraction and migration platform.

Preserve the M×N architecture:

```text
source config -> source parser -> ExtractionResult + canonical IR -> validation/optimization -> target generator
```

Do not add direct source-to-target converters. Parsers must not contain target-vendor logic, and generators must consume canonical IR rather than parser-specific models.

## Read Before Changing Semantics

- `documentation/IR_DATA_STRUCTURE.md` — canonical IR contract and schema-version rules.
- `documentation/EXTRACTION_DATA_MODEL.md` — source accounting and zero-silent-loss rules.
- Relevant vendor extraction/reference document under `documentation/` for vendor-specific work.
- Implementation and tests — documentation alone is not proof that a feature is implemented.

If serialized IR changes, update the executable models, IR documentation, affected tests/serialization, and `schema_version` according to the documented versioning rules.

## Important Areas

- `src/fwmigrate/ir/` — canonical Pydantic IR.
- `src/fwmigrate/extraction/` — `ExtractionResult`, coverage, residual/unsupported accounting.
- `src/fwmigrate/parsers/` — source-vendor adapters and source models.
- `src/fwmigrate/generators/` — native/Terraform target generators.
- `src/fwmigrate/core/` — plugin registry, optimizer, base interfaces, shared logic.
- `src/fwmigrate/engine/` and `src/fwmigrate/deployment/` — Terraform/runtime and deployment support.
- `src/fwmigrate/report/` — Excel and migration reports.
- `src/fwmigrate/main.py` — Click CLI; `serve` and `app` launch `web_live.py`.
- `tests/fixtures/` — sanitized committed source fixtures.

Plugin registration is import-driven. `fwmigrate.parsers` and `fwmigrate.generators` import built-in vendor packages, and those packages register with `PluginRegistry`. When adding a parser or generator, update the corresponding package `__init__.py`; do not hard-code vendor routing in shared UI/CLI code.

## Setup, Run, and Validate

CI/development install:

```bash
python -m pip install -e ".[dev]"
```

Optional extras currently defined by `pyproject.toml` are only `cisco` and `reports`:

```bash
python -m pip install -e ".[dev,cisco,reports]"
```

Useful entry points:

```bash
fwmigrate vendors
fwmigrate serve --port 5000
fwmigrate app
```

`run_migration.bat` is the Windows web launcher.

Run focused tests first, then the full CI checks for shared or migration-semantic changes:

```bash
python -m pytest -q
python -m compileall -q src tests
python -m py_compile scripts/*.py
```

CI runs the full test suite on Python 3.11, 3.12, and 3.13. There is no configured Ruff/Black/mypy/pre-commit gate; do not invent or claim a lint/format command that the repository does not define.

For Windows executable packaging, follow the PyInstaller command in `README.md`. `Firewall Migration Tool.spec` intentionally bundles the tracked `bin/terraform.exe`; do not remove or replace that binary as generic cleanup.

## Migration Safety Rules

- **Zero silent loss:** migration-relevant source data must be normalized or explicitly accounted for as partial, extract-only, vendor-specific, unsupported, ignored-by-policy, or parse-error data.
- **Fail closed:** unresolved or malformed semantics must not silently become broader values such as `any`, `allow`, `/0`, `/32`, an enabled rule, or a fabricated object/zone/interface.
- Preserve unresolved references and source provenance when needed for review/audit.
- Keep vendor-specific semantics in vendor adapters or extraction/vendor-extension data unless they are genuinely portable IR concepts.
- Source inventory/Excel output must come from parser extraction (`ExtractionResult` + canonical IR), not a separate vendor-to-Excel parsing path.
- Never expose passwords, usable PSKs, private keys, tokens, API keys, or real customer configuration in logs, reports, fixtures, API responses, or generated artifacts.
- Treat live deployment as high impact. Do not bypass Terraform plan/review/approval safeguards or contact real firewalls from ordinary automated tests.

## Testing Expectations

- Parser changes: add/update sanitized fixtures and assert canonical IR plus extraction/accounting behavior. A successful parse with silently dropped source data is a failure.
- Generator changes: assert target semantics and capability/fail-closed behavior, not only non-empty output or incidental whitespace.
- IR/core/registry changes: run affected vendor tests and the full suite because they cross vendor boundaries.
- Reporting changes: test both normalized IR data and extraction/residual coverage where relevant; keep secret-redaction behavior intact.
- Deployment/Terraform changes: validate generated Terraform where applicable, but never run an automatic real `apply` in normal tests.

## Repository Hygiene

`.gitignore` excludes customer-style `*.conf`, `*.xml`, `*.xlsx`, Terraform state, generated outputs, logs, and temporary files. Only sanitized fixtures under `tests/fixtures/` are intentionally exempted for supported fixture extensions.

Keep changes focused. Do not mix unrelated refactors with parser/generator fixes, especially in shared IR, registry, or migration-safety code.
