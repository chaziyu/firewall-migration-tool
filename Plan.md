Below is a Codex-oriented implementation plan that keeps the change narrow and aligned with the repo rule:

> Tokenizer = syntax only  
> Parser = structure + explicit source data only  
> Vendor model = migration-relevant source data  
> Transformer = vendor semantics/defaults/conversion  
> IR = vendor-neutral representation  
> Excel = reporting only

# Phase 0 — Establish the exact scope

## Objective

Define which FortiGate sections are intentionally excluded from migration processing.

Use this initial set:

```python
IGNORED_MIGRATION_SECTIONS = (
    # Logging / telemetry
    "log",
    "system snmp",

    # Management services
    "system ntp",
    "system email-server",

    # FortiGuard / update lifecycle
    "system fortiguard",
    "system auto-install",
    "system autoupdate",
    "system federated-upgrade",
    "system ftm-push",

    # HA / appliance operation
    "system ha",
    "system physical-switch",

    # GUI / presentation / localization
    "system custom-language",
    "system replacemsg-image",

    # Low migration-value appliance behavior
    "system search-engine",
    "system threat-weight",
)
```

Do **not** add these yet:

```text
system object-tagging
system quarantine
system automation-trigger
system automation-action
system automation-stitch
system sdn-connector
system link-monitor
system switch-interface
system virtual-wire-pair
system vdom-link
system pppoe-interface
firewall network-service-dynamic
firewall identity-based-route
firewall auth-portal
vpn certificate crl
vpn certificate ocsp-server
vpn certificate setting
```

Those remain source evidence until their dependency/traffic relevance is reviewed.

---

# Phase 1 — Introduce one shared ignore policy

## File

```text
src/fwmigrate/parsers/fortigate/coverage.py
```

## Objective

Create one authoritative predicate used by parser, scanner, extractor, and tests.

## Required changes

Add:

```python
IGNORED_MIGRATION_SECTIONS = (
    ...
)
```

Add:

```python
def is_ignored_migration_section(path: str) -> bool:
    return _matches_source_prefix(
        path,
        IGNORED_MIGRATION_SECTIONS,
    )
```

Use the existing `_matches_source_prefix()` behavior so:

```text
system snmp
system snmp community
system snmp user
```

are all ignored from one root entry.

Likewise:

```text
log
log syslogd setting
log eventfilter
...
```

should match `"log"`.

## Important constraint

Do not implement multiple lists such as:

```python
IGNORED_EXCEL_SECTIONS
IGNORED_PARSER_SECTIONS
IGNORED_COVERAGE_SECTIONS
```

There should be one source of truth.

---

# Phase 2 — Stop the parser from retaining ignored sections

## File

```text
src/fwmigrate/parsers/fortigate/parser.py
```

## Import

Import:

```python
from fwmigrate.parsers.fortigate.coverage import (
    is_ignored_migration_section,
)
```

If this creates an import cycle because `coverage.py` already imports parser-related modules, do **not** force it.

In that case, move only the ignore policy to a small neutral module:

```text
src/fwmigrate/parsers/fortigate/section_policy.py
```

with:

```python
IGNORED_MIGRATION_SECTIONS
is_ignored_migration_section()
```

Then import that from both:

```text
coverage.py
parser.py
section_scanner.py
```

This is preferable to introducing a circular import.

## Exact function

Modify:

```python
FortiGateParser._process_config_source_node()
```

Current important flow:

```python
if full_path == "vdom":
    ...

if full_path in STRUCTURED_*:
    self._parse_structured_source_section(...)
    return

...

if full_path not in CONTEXTUAL_MODEL_SECTIONS | known_edit_or_global_sections:
    self._parse_unknown_source_section(...)
    return
```

Insert ignored handling **after VDOM traversal** but before structured/known/unknown handling:

```python
if is_ignored_migration_section(full_path):
    return
```

Desired order:

```python
def _process_config_source_node(...):
    if full_path == "vdom":
        ...
        return

    if is_ignored_migration_section(full_path):
        return

    if full_path in STRUCTURED_...:
        ...
```

## Why here

`parse_source_node()` has already consumed the syntax.

So:

```text
config system ntp
...
end
```

is syntactically parsed safely, but the result is discarded before model creation.

This preserves the architecture:

```text
Tokenizer → syntax
Parser → decide whether source structure is migration relevant
```

## Must not create

Ignored sections must never call:

```python
_parse_structured_source_section()
_parse_unknown_source_section()
build_model()
apply_global_set()
```

and must not append to:

```python
self.structured_source_objects
self.config.structured_source_objects
self.source_inventory_items
```

---

# Phase 3 — Protect VDOM behavior

This deserves an explicit test because FortiGate configs may contain ignored sections under VDOMs.

Example:

```text
config vdom
    edit root
        config log setting
            ...
        end

        config firewall address
            ...
        end
    next
end
```

The parser must:

```text
enter root VDOM
↓
drop log section
↓
continue
↓
parse firewall address normally
```

Do not skip the entire VDOM merely because one child is ignored.

The check belongs at the individual `full_path` level.

---

# Phase 4 — Stop scanner coverage from reporting ignored sections

## File

```text
src/fwmigrate/parsers/fortigate/section_scanner.py
```

## Objective

Currently scanner discovery is independent of typed parsing.

Without this change:

```text
parser ignores system ntp
```

but:

```text
Extraction Coverage
```

could still show it.

## Required change

Use:

```python
is_ignored_migration_section(path)
```

inside:

```python
scan_fortigate_sections()
```

Prefer filtering when a completed section result is about to be appended.

Conceptually:

```python
if not is_ignored_migration_section(section.path):
    results.append(section)
```

Do not change scanner syntax behavior.

The scanner should still correctly understand nested:

```text
config
edit
next
end
```

It simply should not return intentionally excluded sections as migration coverage.

---

# Phase 5 — Simplify coverage classification

## File

```text
src/fwmigrate/parsers/fortigate/coverage.py
```

## Current groups to review

```python
SYSTEM_BEHAVIOUR_PREFIXES
MANAGEMENT_LOGGING_PREFIXES
MISC_OPERATIONAL_PREFIXES
NON_BLOCKING_SOURCE_PREFIXES
```

Many entries will become obsolete because ignored sections no longer reach coverage.

Remove ignored entries from these tuples.

For example, remove:

```text
system ha
system physical-switch

log
system snmp
system fortiguard
system ntp
system email-server

system auto-install
system autoupdate
system federated-upgrade
system ftm-push
system custom-language
system replacemsg-image
system search-engine
system threat-weight
```

## Keep classifications for retained source-only sections

Do not delete the entire concepts.

They are still useful for migration-relevant but not-normalized sections.

Target behavior:

```text
ignored
    → absent

supported
    → normalized

migration-relevant but unsupported
    → extract-only / unsupported / review
```

---

# Phase 6 — Review `source_tree.py`

## File

```text
src/fwmigrate/parsers/fortigate/source_tree.py
```

## Objective

Make sure ignored families are not explicitly listed in:

```python
STRUCTURED_OPERATIONAL_SECTIONS
STRUCTURED_IDENTITY_SECTIONS
STRUCTURED_SECURITY_SECTIONS
```

From the currently inspected structure, the primary ignored set is mostly outside these sets already.

Do not delete:

```python
FGSourceCommand
FGSourceNode
FGStructuredSourceObject
```

They remain necessary for important unsupported sections.

Also do not broadly shrink:

```python
STRUCTURED_OPERATIONAL_SECTIONS
```

just because the name says "operational".

Several members are migration-relevant.

---

# Phase 7 — Verify no dedicated FortiGate models remain for ignored sections

## File

```text
src/fwmigrate/parsers/fortigate/model.py
```

Search each ignored section for associated models.

Search terms:

```text
NTP
SNMP
FortiGuard
Email
HA
AutoUpdate
PhysicalSwitch
ThreatWeight
SearchEngine
```

For each model:

### Case A — model used only by ignored FortiGate config

Delete it.

### Case B — generic/cross-vendor concept

Keep it.

For example, do **not** delete generic IR types just because FortiGate stops using them:

```python
IRNTPSettings
IRHighAvailability
```

Those belong to vendor-neutral IR and other vendors may populate them.

---

# Phase 8 — Review `section_registry.py`

## File

```text
src/fwmigrate/parsers/fortigate/section_registry.py
```

Search for ignored paths.

Remove:

- `SectionSpec`
- field maps
- integer field definitions
- list field definitions
- custom builders

only when they exist solely for ignored sections.

Examples of things to search:

```python
SECTION_LIST_FIELDS
SECTION_INTEGER_FIELDS
SECTION_INTEGER_LIST_FIELDS
SectionSpec(...)
register_sections(...)
```

Do not remove generic registry infrastructure.

---

# Phase 9 — Review FortiGate builders

## Directory

```text
src/fwmigrate/parsers/fortigate/builders/
```

Search all builders for references to ignored section names or deleted models.

Directories/files include:

```text
common.py
objects.py
policy_nat.py
routing_vpn.py
security.py
security_profiles.py
security_profiles_extra.py
antivirus.py
application_control.py
dnsfilter.py
webfilter.py
```

Likely most ignored sections will not have dedicated builders.

Delete only functions that become unreachable after parser/model cleanup.

Do not opportunistically refactor unrelated builders in the same change.

---

# Phase 10 — Review transformer references

## File

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Search for fields/models related to:

```text
NTP
SNMP
HA
FortiGuard
email
logging
update
physical switch
```

If FortiGate currently populates:

```python
ir.ntp_settings
ir.high_availability
```

from these ignored source sections, remove only those FortiGate transformation branches.

Do not remove the IR fields themselves.

Desired:

```text
FortiGate system ntp
    → ignored before model
    → transformer never sees it
```

rather than:

```text
parser models it
→ transformer receives it
→ transformer decides to throw it away
```

Early elimination is cleaner.

---

# Phase 11 — Remove dependency rules for ignored sections

## File

```text
src/fwmigrate/parsers/fortigate/dependencies.py
```

Review:

```python
REFERENCE_RULES
```

Search source paths matching the ignored set.

If a dependency rule originates exclusively from:

```text
system ntp
system snmp
system fortiguard
...
```

delete it.

Do not delete rules where the **target** happens to be an ignored type unless the source relationship has been proven irrelevant.

The important question is:

> Can a migration-relevant object depend on this object?

If yes, do not ignore that section yet.

This is particularly why:

```text
object-tagging
quarantine
sdn-connector
```

should remain outside the first ignore set.

---

# Phase 12 — Clean extractor behavior

## File

```text
src/fwmigrate/parsers/fortigate/extractor.py
```

Current important orchestration:

```python
source_sections = scan_fortigate_sections(text)

parser = FortiGateParser(FortiGateTokenizer(text))
fg_config = parser.parse()

ir_config = FGToIRTransformer(...).transform()

classify_section_coverage(...)

dependencies = build_dependency_registry(
    parser.source_inventory_items
)
```

The extractor should not need to maintain another ignore list.

After the previous phases, verify:

```python
parser.source_inventory_items
```

contains no ignored paths.

Verify:

```python
source_sections
```

contains no ignored paths.

Then the rest of extractor logic naturally excludes them.

## Add defensive assertions only in tests

Do not add runtime code like:

```python
inventory_items = [
    x for x in inventory_items
    if not is_ignored...
]
```

unless needed for compatibility.

Prefer removal at source.

---

# Phase 13 — Clean FortiGate Excel source-detail output

## File

```text
src/fwmigrate/report/excel_exporter.py
```

The following should automatically stop showing ignored config once upstream cleanup is complete:

```python
_build_fortigate_source_configuration()
_build_source_inventory()
_build_extraction_coverage()
_build_warnings()
_build_unsupported()
```

Verify `_fortigate_source_inventory_items()` no longer receives ignored sections.

Do **not** add Excel-specific filtering unless necessary.

Bad:

```python
if item.source_path.startswith("system ntp"):
    continue
```

Better:

```text
system ntp never reaches extraction inventory
```

---

# Phase 14 — Remove FortiGate NTP worksheet visibility

There is a separate issue:

```python
IRExcelExporter._build_ntp_settings()
```

creates:

```text
NTP Settings
```

from:

```python
self.ir.ntp_settings
```

## Do not delete this globally

It is vendor-neutral functionality.

## File

```text
src/fwmigrate/report/excel_vendor_visibility.py
```

Add a FortiGate-specific exclusion.

A clean implementation is to introduce something like:

```python
FORTIGATE_EXCLUDED_SHEETS = frozenset({
    "NTP Settings",
})
```

Then inside:

```python
VendorAwareIRExcelExporter._active_sheet_order()
```

apply:

```python
if vendor == "fortigate":
    excluded.update(
        self.FORTIGATE_EXCLUDED_SHEETS
    )
```

Keep:

```python
FORTIGATE_ONLY_SHEETS
```

for the opposite meaning:

> sheets only FortiGate should see.

Do not overload that constant.

---

# Phase 15 — Review `System Settings`

This is important.

The user wants to remove:

```text
GUI/preferences
HA operational tuning
appliance-specific hardware
```

but `system global` contains both migration-relevant and low-value fields.

Do **not** ignore:

```text
system global
```

as a whole.

Current parser handles things such as:

```text
hostname
central-nat
timezone
admin ports
session timers
opmode
```

Some are useful; some are management-only.

Handle this separately at field level.

## File

```text
src/fwmigrate/parsers/fortigate/parser.py
```

Inside:

```python
apply_global_set()
```

for:

```python
section_path == "system global"
```

retain only fields needed for:

```text
hostname
central NAT semantics
operating mode if migration relevant
session behavior if target conversion uses it
```

Management/UI fields should eventually stop becoming typed model fields or `extra_settings`.

Examples to review:

```text
admin_http_port
admin_https_port
admin_ssh_port
admin_telnet_port
admin_console_timeout
admin_hsts_*
admin_login_max
admin_restrict_local
admin_server_cert
```

This should be a **separate commit** after section-level ignored cleanup.

Do not mix both refactors initially.

---

# Phase 16 — Runtime/status commands

Current tokenizer token types are configuration-oriented:

```text
CONFIG
EDIT
SET
UNSET
NEXT
END
APPEND
STRING
COMMENT
```

Runtime commands such as:

```text
diagnose ...
execute ...
get ...
show ...
```

should not become config models.

## Files to verify

```text
src/fwmigrate/parsers/fortigate/tokenizer.py
src/fwmigrate/parsers/fortigate/extractor.py
```

Confirm runtime/status input is either:

- ignored as non-config syntax, or
- reported as unsupported input

but never stored as migration configuration.

Do not add runtime prefixes to `IGNORED_MIGRATION_SECTIONS`, because they are not `config <section>` paths.

This is a separate CLI-input concern.

---

# Phase 17 — Parser unit tests

Create focused tests for the ignore predicate and parser behavior.

Suggested test file:

```text
tests/test_fortigate_ignored_sections.py
```

or use the existing FortiGate parser test module if there is an established pattern.

Test:

```python
@pytest.mark.parametrize(
    "path",
    [
        "log",
        "log syslogd setting",
        "system snmp",
        "system snmp community",
        "system ntp",
        "system email-server",
        "system fortiguard",
        "system autoupdate",
        "system ha",
        "system physical-switch",
    ],
)
def test_ignored_migration_section(path):
    assert is_ignored_migration_section(path)
```

Also negative tests:

```python
@pytest.mark.parametrize(
    "path",
    [
        "system interface",
        "system sdwan",
        "system link-monitor",
        "system switch-interface",
        "firewall address",
        "firewall policy",
        "router static",
        "vpn ipsec phase1-interface",
    ],
)
def test_migration_relevant_section_not_ignored(path):
    assert not is_ignored_migration_section(path)
```

---

# Phase 18 — Parser integration fixture

Use a fixture containing both ignored and important config.

Example:

```text
config system ntp
    set type custom
end

config system fortiguard
    set protocol https
end

config system ha
    set mode a-p
end

config log syslogd setting
    set status enable
end

config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
    next
end

config firewall address
    edit "server1"
        set subnet 10.0.0.10 255.255.255.255
    next
end
```

Assert:

```python
assert all(
    not is_ignored_migration_section(item.source_path)
    for item in parser.source_inventory_items
)
```

Assert relevant models exist:

```text
port1
server1
```

---

# Phase 19 — Extraction tests

Run full:

```python
extract_fortigate_config(...)
```

Assert ignored paths are absent from:

```python
result.source_sections
result.inventory_items
result.dependencies
result.unsupported_items
result.blocking_reasons
result.canonical_ir.audit_entries
```

Do not merely assert status is `EXTRACT_ONLY`.

They should be **absent**.

---

# Phase 20 — Excel tests

## Existing file

```text
tests/test_excel_exporter.py
```

There are already tests asserting presence/order of:

```text
FortiGate Source Configuration
Source Inventory
Extraction Coverage
```

Update/add tests without removing these useful sheets.

Generate workbook from a source containing ignored config.

Assert text does not contain:

```text
system ntp
system fortiguard
system ha
system snmp
system email-server
system autoupdate
log syslogd
```

Check these sheets specifically:

```text
FortiGate Source Configuration
Source Inventory
Extraction Coverage
Extraction Evidence
Review Required
Unsupported
Warnings
```

For FortiGate vendor-aware export assert:

```python
assert "NTP Settings" not in workbook.sheetnames
```

For another vendor that still supports NTP, ensure generic behavior remains unchanged.

---

# Phase 21 — Update streaming/optimized Excel exporters

The repository also has:

```text
src/fwmigrate/report/excel_optimized.py
src/fwmigrate/report/excel_streaming.py
src/fwmigrate/report/experimental_streaming_excel.py
```

Do not independently implement ignore rules there.

They should inherit or reuse the same sheet-order/vendor-visibility behavior.

Run the existing parity test:

```python
test_streaming_fast_export_preserves_semantic_rows_and_required_sheets
```

Update expectations only if `"NTP Settings"` is part of a FortiGate expected sheet list.

Keep:

```text
Source Inventory
Extraction Coverage
FortiGate Source Configuration
```

because they still report migration-relevant evidence.

---

# Phase 22 — Remove dead imports and constants

After functional tests pass, run static cleanup.

Search repo-wide for each deleted symbol.

Remove:

- unused imports
- orphan models
- orphan registry definitions
- unused builders
- unused constants
- obsolete coverage categories

Do not do speculative cleanup before tests pass.

---

# Phase 23 — Commit sequence for Codex

I would have Codex implement this as several small commits.

### Commit 1

```text
fortigate: add ignored migration section policy
```

Changes:

```text
section_policy.py or coverage.py
tests for matcher
```

### Commit 2

```text
fortigate: drop ignored sections during parsing
```

Changes:

```text
parser.py
parser tests
```

### Commit 3

```text
fortigate: exclude ignored sections from source coverage
```

Changes:

```text
section_scanner.py
coverage.py
extractor tests
```

### Commit 4

```text
fortigate: remove dead ignored-section parsing metadata
```

Changes:

```text
model.py
section_registry.py
builders/*
dependencies.py
transformer.py
```

Only where actually dead.

### Commit 5

```text
excel: exclude ignored FortiGate management configuration
```

Changes:

```text
excel_vendor_visibility.py
excel tests
```

### Commit 6

```text
tests: verify ignored FortiGate config never reaches migration output
```

Add broad integration/regression tests.

This commit structure makes regressions easier to identify.

---

# Phase 24 — Definition of done

The work is complete when all of these are true:

```text
FortiGate ignored CLI
    ↓
tokenized
    ↓
structurally consumed
    ↓
discarded
```

and none of it appears in:

```text
FortiGate source model
structured_source_objects
source_inventory_items
source_sections
dependency registry
canonical IR
IR audit entries
unsupported list
review-required list
Excel source inventory
Excel source configuration
Excel extraction coverage
Excel extraction evidence
```

while migration-relevant unsupported configuration continues to be preserved.

The resulting responsibility boundary should be:

```text
Tokenizer
    syntax only

Parser
    structure + explicit migration-relevant source data

FortiGate model
    small migration-relevant source representation

Transformer
    FortiOS semantics/defaults/conversion

IR
    portable firewall concepts

Excel
    report only what survived migration extraction
```

The most important implementation constraint for Codex is: **do not turn this into a generic "drop unsupported sections" change. Only explicitly allowlisted low-value sections should be discarded.**