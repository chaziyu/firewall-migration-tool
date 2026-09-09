# AGENTS.md

## Purpose

Firewall Migration Tool is a Python and Terraform platform for extracting,
inventorying, migrating, and generating enterprise firewall configuration
across multiple vendors.

Supported vendor families include FortiGate/FortiOS, PAN-OS/Panorama,
Cisco ASA, Check Point R80/R81, and Juniper SRX/JunOS.

The project uses an M × N architecture through a vendor-neutral Intermediate
Representation (IR):

```text
Source configuration
        |
        v
   Source parser
        |
        +------> ExtractionResult / source accounting
        |
        v
   Canonical IR
        |
        v
 Validation / optimization
        |
        v
 Target generator
     /       \
    v         v
Native      Terraform
              |
              v
       Deployment engine
```

Do not implement direct source-to-target converters.

---

## Repository Architecture

- `src/fwmigrate/parsers/` — source-vendor parsing and source models.
- `src/fwmigrate/extraction/` — extraction/accounting models.
- `src/fwmigrate/ir/` — canonical vendor-neutral IR.
- `src/fwmigrate/generators/` — target-native and Terraform generation.
- `src/fwmigrate/core/` — registry, optimizer, and shared logic.
- `src/fwmigrate/engine/` — Terraform and migration runtime.
- `src/fwmigrate/report/` — Excel and migration reports.
- `src/fwmigrate/web.py` — web/API orchestration.
- `src/fwmigrate/main.py` — CLI/desktop entry points.
- `tests/` — parser, IR, generator, integration, and safety tests.

Prefer vendor discovery through `PluginRegistry`. Vendor-specific behavior
belongs inside parser, generator, or deployer plugins rather than large
vendor-specific `if/elif` chains in shared orchestration.

---

## Sources of Truth

Before changing parser, IR, extraction, Excel, generator, optimizer, validator,
or deployment behavior, use this hierarchy:

1. `documentation/IR_DATA_STRUCTURE.md`
   - intended portable cross-vendor semantics;
   - canonical schema and schema-version rules.
2. `documentation/EXTRACTION_DATA_MODEL.md`
   - complete source-accounting behavior;
   - extraction statuses and zero-silent-loss rules.
3. `src/fwmigrate/ir/`
   - executable Pydantic IR implementation.
4. Vendor parser models under `src/fwmigrate/parsers/`
   - vendor-specific syntax before normalization.
5. Tests
   - executable evidence of implemented behavior.

Do not treat documentation, a class, or a stub alone as proof that a feature is
implemented. Verify code paths and tests.

If documentation and implementation disagree, determine which is outdated,
then update the appropriate source and tests. Do not silently choose one.

---

## Core Engineering Rules

### 1. Preserve the M × N architecture

Source parsers must not contain target-vendor generation logic.
Target generators must consume canonical IR, not source-vendor parser models.

Preferred:

```text
Vendor source -> IR -> Vendor target
```

Do not add dedicated FortiGate→PAN-OS, PAN-OS→Juniper, or similar converters.

### 2. IR is the canonical migration contract

Canonical IR represents portable firewall intent, not vendor CLI, XML, JSON,
API payloads, or Terraform syntax.

Do not force vendor-specific semantics into IR when doing so would distort their
meaning. Preserve such data through extraction-only structures, vendor
extensions, or unsupported/residual records.

Serialized IR must carry `IRConfig.schema_version`.

- backward-compatible additive serialized change -> minor schema increment;
- breaking serialized change -> major schema increment.

Do not infer IR compatibility from application or firewall software versions.

### 3. Zero silent loss

Every migration-relevant source element must be represented or explicitly
accounted for as one of:

- `NORMALIZED`
- `PARTIALLY_NORMALIZED`
- `EXTRACT_ONLY`
- `VENDOR_EXTENSION`
- `UNSUPPORTED`
- `IGNORED_BY_POLICY`
- `PARSE_ERROR`

Parsing success alone is insufficient. Relevant source configuration must not
disappear silently.

### 4. Fail closed

Never silently broaden access or fabricate valid values to keep processing.

Forbidden examples include:

- specific source/destination/service -> `any`;
- deny/drop -> allow;
- disabled rule -> enabled rule;
- scoped zone -> unrestricted zone;
- restricted NAT -> unrestricted translation;
- malformed network -> `/0` or `/32` fallback;
- unresolved reference -> default object or permissive value.

When semantics cannot be translated safely:

1. preserve source evidence where safe;
2. emit a warning/error or compatibility result;
3. withhold, disable, or quarantine unsafe target output when necessary;
4. require manual review.

"Generated successfully" must not imply semantic equivalence when behavior was
omitted or approximated.

### 5. Preserve reference integrity

Validate migration-relevant references before generation, including:

- policy -> addresses, services, zones/interfaces, profiles;
- NAT -> objects, interfaces, pools;
- VPN Phase 2 -> Phase 1/tunnel;
- routes -> interfaces/VRFs;
- group memberships and other object relationships.

Unresolved references must remain explicit and must not silently become `any`
or another permissive value.

Prefer typed models over unstructured dictionaries for migration-relevant
semantics.

### 6. Preserve distinct semantics

Do not collapse different source concepts merely because they look similar.
For example, vendor administrative distance must not be mapped into a generic
route metric.

Preserve source provenance such as IDs, names, scopes, paths, and source
section references where useful for audit and troubleshooting.

---

## Parser and Extraction Work

Before modifying a source parser:

1. Read the relevant parts of `EXTRACTION_DATA_MODEL.md`.
2. Read the relevant parts of `IR_DATA_STRUCTURE.md`.
3. Inspect the executable IR and nearby parser models.
4. Classify affected source fields/sections by extraction status.
5. Add or update semantic and extraction-coverage tests.
6. Confirm no migration-relevant configuration is silently discarded.

A parser must:

- parse source syntax without target-vendor assumptions;
- preserve useful source identifiers and provenance;
- normalize portable semantics into IR;
- preserve or report non-portable semantics;
- expose malformed input and unresolved references;
- never convert malformed input into an apparently valid empty configuration.

For FortiGate work, both IR and extraction documentation are mandatory
references. Do not force every FortiGate setting into canonical IR.

---

## Excel / Reporting Rules

Excel is source inventory and review output, not a separate parsing path.

Preferred flow:

```text
Config -> Parser -> ExtractionResult + Canonical IR -> Excel exporter
```

Rules:

- do not create independent vendor-to-Excel parsers;
- normalized worksheets should come from canonical IR where practical;
- unsupported, residual, vendor-specific, and coverage data should come from
  `ExtractionResult`;
- generate source inventory before migration-only optimizer pruning when the
  workbook represents the original source;
- never export passwords, usable PSKs, private keys, tokens, or credentials in
  plaintext.

---

## Target Generator Rules

Target generators should:

- consume IR only;
- produce deterministic output;
- validate target capability limitations;
- preserve policy ordering where semantically relevant;
- use stable object names;
- report unsupported or approximated mappings;
- withhold unsafe output rather than weaken policy restrictions.

Keep native and Terraform generation logically separate where practical.

---

## Terraform and Live Deployment Safety

Treat deployment as a destructive/high-impact operation.

Normal lifecycle:

```text
generate
  -> terraform init
  -> terraform validate
  -> terraform plan
  -> human review / approval
  -> terraform apply
  -> post-deployment validation
```

Do not bypass plan/review/approval safeguards.

Do not:

- automatically apply Terraform from ordinary tests;
- connect to or modify real firewalls during ordinary automated tests;
- hard-code credentials, tokens, passwords, API keys, or device secrets;
- expose secrets in logs, exceptions, Terraform output, reports, API responses,
  Excel files, or fixtures.

Sensitive Terraform variables must remain marked sensitive where applicable.

Deployment orchestration should remain vendor-neutral through the plugin
registry. Vendor-specific credentials, validation, diagnostics, and deployment
behavior belong in deployer/plugin implementations.

---

## Testing

Development setup:

```bash
pip install -e ".[dev]"
```

Optional vendor/report integrations:

```bash
pip install -e ".[dev,cisco,checkpoint,juniper,reports]"
```

Run focused tests first, then the full suite when practical:

```bash
pytest path/to/relevant_test.py -v
pytest tests/ -v
```

Changes to IR, parsers, generators, normalization, extraction, or deployment
behavior must include or update relevant tests.

Prefer semantic assertions over existence checks.

Weak:

```python
assert artifacts
```

Better:

```python
assert generated_policy.action == expected_action
assert generated_policy.sources == expected_sources
```

Where practical, test:

```text
source fixture -> parser -> expected IR/extraction
IR fixture -> generator -> expected target semantics
```

Use round-trip semantic comparison when the target parser supports it.

---

## Adding a Vendor

A new vendor should normally provide, as applicable:

1. source parser and registration;
2. live API client;
3. target generator;
4. Terraform generator/deployer;
5. fixtures and semantic tests;
6. compatibility coverage;
7. documentation.

Adding a vendor must not require converters from every existing vendor. The IR
exists to keep implementation growth approximately M + N instead of M × N.

---

## Change Checklists

### IR schema change

- [ ] Update executable IR/Pydantic models.
- [ ] Update `documentation/IR_DATA_STRUCTURE.md`.
- [ ] Review affected source parsers and normalization.
- [ ] Review target and Terraform generators/deployers.
- [ ] Review Excel/report serialization.
- [ ] Update semantic tests and fixtures.
- [ ] Apply the correct `schema_version` increment.
- [ ] Preserve backward compatibility where practical.
- [ ] Do not silently change the meaning of an existing field.

### Extraction/accounting change

- [ ] Update `documentation/EXTRACTION_DATA_MODEL.md` when semantics change.
- [ ] Update section/coverage classification.
- [ ] Update residual/unsupported handling.
- [ ] Update Excel extraction coverage tests where relevant.
- [ ] Verify zero silent loss for covered fixtures.

### Bug fix

1. Add or identify a reproducing test.
2. Make the smallest architecture-consistent fix.
3. Run targeted tests.
4. Run broader/full tests when practical.
5. Avoid unrelated refactoring.

---

## Security and Test Data

Treat uploaded firewall configurations as sensitive. They may contain internal
addresses, topology, VPN details, usernames, policy, API endpoints, and
credentials.

- do not unnecessarily log raw configuration;
- never commit real customer configurations or credentials;
- use sanitized synthetic fixtures;
- preserve useful evidence only after secret-safe sanitization.

---

## Documentation

Keep detailed design material under `documentation/`.

Update documentation when changing:

- IR schemas;
- extraction/accounting semantics;
- supported or unsupported vendor features;
- migration semantics;
- public CLI/API behavior;
- live API support;
- Terraform/deployment behavior.

Documentation must reflect functional implementation and test coverage.

---

## Definition of Done

A change is complete when all applicable conditions hold:

- architecture boundaries remain intact;
- relevant semantic tests pass;
- parser changes satisfy zero silent loss;
- extraction coverage is updated where parser behavior changes;
- unsupported, partial, extract-only, vendor-specific, and parse-error states
  are explicit;
- unresolved references remain explicit and fail closed;
- no policy, NAT, route, VPN, topology, or object semantics are fabricated or
  silently broadened;
- secrets are not exposed;
- IR and extraction documentation stay synchronized with executable models;
- Excel remains based on canonical IR plus `ExtractionResult`;
- generated Terraform validates where applicable;
- live deployment changes preserve plan/review/approval safeguards.

For parser work, "done" means **zero silent loss**, not 100% automatic migration
support. Unsupported features are acceptable only when they are identified,
preserved or reported as required, and visible to the operator.
