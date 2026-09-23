# AGENTS.md

This repository uses **vendor-native firewall extraction and reporting**.

```text
Vendor Source
→ Parser / Source Adapter
→ VendorConfig
→ Relationships / Transforms
→ DerivedViews
→ Validation
→ Preview / Excel
```

Cross-vendor conversion is not implemented yet.

For vendor-specific command and configuration coverage, use the matching selected reference in `documentation/official-cli-references-selected version/`:

- FortiGate: `FortiGate Selected CLI References.md`
- Cisco ASA: `Cisco_ASA_Selected_Configuration_References.md`
- Cisco FTD: `Cisco_FTD_Selected_Configuration_References.md`
- Juniper SRX: `Juniper_Selected_CLI_References.md`
- Check Point R81: `Check_Point_R81_Selected_CLI_and_Management_API_References.md`
- PAN-OS: `Palo_Alto_Selected_CLI_References.md`

Use these files to check the selected extraction coverage for that vendor. They do not make vendor defaults explicit source configuration.

## Core invariants

### 1. Preserve source truth

`VendorConfig` represents **explicit source state**.

A missing field means:

```text
not explicitly configured
```

Do not silently interpret missing values as:

```text
vendor default
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
unknown value
unsupported/source-only value
```

Only expose `Effective ...` fields when current vendor logic actually calculates them.

When uncertain:

```text
preserve source
→ mark unknown / unsupported
→ report it
→ do not guess
```

### 2. Respect layer boundaries

```text
Tokenizer / Scanner   syntax only
Parser / Adapter      explicit source structure
Command Evaluator     vendor command semantics
VendorConfig          authoritative source state
Relationships         references / bindings / topology
Transforms            vendor semantics / derivation
DerivedViews          read-only derived state
Validation            detect and report only
Preview / Excel       presentation only
```

Do not move semantics into parsers, validation, web, or Excel for convenience.

### 3. Never mutate source downstream

After extraction, treat `VendorConfig` as read-only.

Relationships, transforms, validation, preview, and Excel must not:

```text
fill defaults
repair references
insert inferred objects
rename objects
rewrite values
delete unsupported data
silently fix configuration
```

Derived information belongs in relationships, transforms, or `DerivedViews`.

Existing violations are technical debt, not patterns to copy.

### 4. Preserve unsupported data

Keep useful unsupported or partially understood source evidence through existing mechanisms such as:

```text
raw_extra
unsupported commands
source metadata
Source Inventory
Additional Settings
source appendix sheets
collection evidence
```

Do not add fake source-model fields only to satisfy reports.

## Shared code

Shared `source_reporting/` and web code may know:

```text
vendor ID
display name
supported extensions
analyze_source()
build_preview()
export_excel()
```

Vendor results are otherwise opaque.

Do not create shared firewall semantic models.

Excel is presentation only and must not drive source-model design.

## Vendor-specific rules

**FortiGate**
- Use `fortigate-extract` as the responsibility-boundary reference.
- Prefer `FortiGate Selected CLI References.md`.
- Do not copy FortiGate syntax/models into other vendors.

**Cisco ASA**
- Preserve command, ACL and NAT ordering, modes, contexts, `nameif`, and explicit `no`.
- Resolve relationships outside parsing.

**Cisco FTD**
- Keep FMC, FDM, and CLI/device evidence distinct.
- CLI evidence must not manufacture FMC/FDM-managed policy.
- Preserve source-plane provenance and completeness.

**Juniper SRX**
- Preserve hierarchy, logical systems, groups, inheritance, routing-instance scope, and provenance.
- Calculate effective state without rewriting source state.

**Check Point**
- Preserve UID, domain, package, layer, gateway/cluster scope, and collection completeness.
- Failed/incomplete collection does not mean empty configuration.

**PAN-OS**
- Current source input is XML.
- Do not assume CLI `set` support.
- Preserve VSYS/shared/device-group/device scope.

## Terminology

Prefer source-oriented terms:

```text
EXTRACTED
PARTIAL
SOURCE_ONLY
UNSUPPORTED
UNKNOWN
PARSE_ERROR
collection incomplete
```

Avoid migration-era terms such as `NORMALIZED`, `migration safe`, or `target compatible` in source-reporting code.

## Conversion

`src/fwmigrate/conversion/` is a reserved future boundary:

```text
VendorSourceConfig
→ VendorDerivedViews
→ pair-specific converter
→ TargetVendorConfig
→ target validation
→ target renderer
```

Do not implement conversion unless explicitly requested.

Do not reintroduce:

```text
vendor-neutral IR
shared firewall object model
generic migration framework
shared cross-vendor mappings
target generators
Terraform
SQLite / .fgreport
target concepts in source models
```

Source reporting must not depend on `conversion/`.

## Secrets

Never export, preview, log, or preserve actual secrets in reportable evidence:

```text
passwords
PSKs
private keys
API keys
tokens
credentials
sensitive SNMP communities
```

Safe metadata is allowed:

```text
Password Configured = Yes
PSK Configured = Yes
Credential Present = Yes
```

Apply redaction to source evidence, raw/unsupported data, validation, preview, Excel, and logs.

## Documentation

Use official vendor documentation as the primary semantic reference.

Prefer project-curated reference files for supported extraction coverage.

Documentation defaults are not explicit source configuration.

If behavior remains unclear:

```text
preserve source
→ mark unknown / unsupported
→ do not guess
```

## Before editing

Inspect first:

```text
current branch
actual paths
actual models
actual symbols
callers
tests
current pipeline
```

Then:

```text
make the smallest coherent change
avoid unrelated refactoring
do not guess APIs
prefer package-relative imports
```

Do not reorganize the repository unless required by the task.

## Testing

Test the real path:

```text
source
→ parser / adapter
→ VendorConfig
→ DerivedViews
→ validation
→ preview / Excel
```

Protect against regressions in:

```text
nested/scoped configuration
unknown/unsupported fields
references
interface topology
policy/NAT ordering
provenance
collection completeness
secret redaction
preview
Excel
```

Architecture tests should enforce:

```text
VendorConfig is not mutated downstream
source_reporting has no firewall semantic model
vendor Excel consumes only vendor state
vendors do not depend on conversion/
web treats vendor results as opaque
secrets never reach preview or Excel
```

Do not claim CI passes unless the current workflow actually ran successfully.

## Priority

```text
correctness
→ source preservation
→ clear semantics
→ traceability
→ maintainability
→ convenience
```
