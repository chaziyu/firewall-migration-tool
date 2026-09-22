# AGENTS.md

This repository is being refactored from an IR-first firewall migration architecture into vendor-native extraction and reporting pipelines.

The immediate priority is:

```text
extract each vendor correctly
→ preserve vendor source semantics
→ build vendor relationships / derived views
→ validate
→ generate vendor-specific preview and Excel
```

Cross-vendor conversion comes later.

Do not force source configuration into a vendor-neutral model merely to support reporting.

## Architecture direction

The target source-reporting architecture is:

```text
Vendor Source
→ Vendor Parser / Source Adapter
→ Vendor Source Config
→ Vendor Relationships / Transforms
→ Vendor DerivedViews
→ Vendor Validation
→ Vendor Web Report / Excel
```

Examples:

```text
Cisco ASA
→ ASA parser
→ CiscoASAConfig
→ ASA relationships / transforms
→ ASADerivedViews
→ ASA validation
→ ASA Excel
```

```text
Juniper SRX
→ Junos tokenizer / hierarchy handling
→ JuniperSRXConfig
→ Junos relationships / transforms
→ JuniperDerivedViews
→ Juniper validation
→ Juniper Excel
```

```text
Cisco FTD
FMC API ┐
FDM API ├→ FTD source adapters
CLI     ┘
→ CiscoFTDConfig
→ FTD relationships / transforms
→ FTDDerivedViews
→ FTD validation
→ FTD Excel
```

```text
Check Point Management API ┐
Gaia / gateway CLI         ├→ Check Point source adapters
                           ┘
→ CheckPointConfig
→ Check Point relationships / transforms
→ CheckPointDerivedViews
→ Check Point validation
→ Check Point Excel
```

Standardize pipeline responsibilities.

Do not standardize vendor data models.

## Current conversion boundary

The repository currently supports source extraction and reporting only:

```text
Vendor source
→ VendorConfig
→ DerivedViews
→ validation
→ vendor Excel / preview
```

Configuration conversion is unavailable. Retained IR and conversion fixtures
are not a source-reporting dependency and must not be routed through web or
vendor Excel paths.

The future directional boundary is reserved in `src/fwmigrate/conversion/`:

```text
VendorSourceConfig
→ VendorDerivedViews
→ pair-specific converter
→ TargetVendorConfig
→ target validation
→ target renderer
```

Future pairs include `cisco_asa_to_fortigate`, `juniper_srx_to_fortigate`,
`cisco_ftd_to_fortigate`, and `checkpoint_to_fortigate`. Do not implement
pair mappings, generic source/target models, or an IR replacement here.

## Core responsibility rules

Use these boundaries:

```text
Tokenizer / Scanner
    syntax and lexical structure only

Parser / Source Adapter
    vendor structure and explicit source commands/data

Command Evaluator
    source command semantics such as set, append, unset, no, delete,
    activation, or vendor-specific equivalents

Vendor Source Config
    explicit vendor source state

Relationships
    object references, memberships, bindings, topology and dependency graphs

Transforms
    vendor-specific semantic normalization and genuine derived values

DerivedViews
    read-only derived representation used by validation and presentation

Validation
    detect and report problems only

Web Report / Excel
    presentation only

Legacy IR Adapter
    vendor-native source state → migration IR
```

Do not move responsibilities across these boundaries without a clear reason.

## Vendor source models are authoritative

Each vendor owns its own source model.

Examples include:

```text
CiscoASAConfig
CiscoFTDConfig
JuniperSRXConfig
CheckPointConfig
```

Do not introduce a shared model such as:

```text
FirewallConfig
CommonAddress
CommonService
CommonPolicy
CommonNATRule
NormalizedFirewallObject
```

for source extraction or reporting.

A shared orchestration protocol is acceptable.

A shared firewall semantic model is not.

## Missing source values

A missing source-model field means:

```text
not explicitly present in the authoritative source
```

It does not automatically mean:

```text
vendor default
disabled
empty
false
zero
inherit
any
```

Keep these concepts distinct:

```text
explicit source value
derived value
effective value
vendor default
unknown value
unsupported source value
```

Do not silently apply vendor defaults to source models.

## Effective values

Only expose an `Effective ...` value when current vendor-specific logic actually calculates it.

Examples where effective values may legitimately exist:

```text
Junos configuration groups / inheritance
resolved interface hierarchy
resolved policy bindings
resolved routing-instance membership
```

Do not invent effective values from documentation defaults merely to make reports look complete.

## Source preservation

Preserve useful source data even when the tool does not fully understand it.

Use the vendor's existing preservation mechanism where possible.

Examples:

```text
raw_extra
unsupported_commands
source_attributes
source metadata
candidate history
raw API response metadata
Source Inventory
Additional Settings
source appendix sheets
```

Do not add fake typed source-model fields merely to satisfy Excel.

When behavior is unclear:

```text
preserve source
→ classify as unknown / unsupported / source-only
→ report it
→ do not guess
```

## Derived data must not mutate source

Relationships, transforms, DerivedViews and validation must treat vendor source configuration as source-of-truth.

Do not:

```text
repair source objects
insert missing references
rename objects
fill defaults
rewrite source values
delete unsupported values
silently correct invalid configuration
```

Derived structures may resolve or interpret source state, but the original source representation must remain traceable.

## Validation

Validation detects and reports.

Validation does not repair.

Validation may detect:

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

Validation output must clearly distinguish:

```text
source configuration issue
unsupported extraction
unknown interpretation
derived-view limitation
collection/input limitation
```

## Relationships

Reference and topology resolution belongs outside parsers.

Examples:

```text
object → group membership
policy → address references
policy → service references
ACL → interface binding
interface → zone
interface → parent
aggregate → member
VPN → interface
route → interface
package → layer
gateway → domain
```

Parsers should capture explicit source state needed to build these relationships.

They should not build reporting topology directly.

## Excel reporting

Excel is a presentation layer.

Each vendor owns its Excel schema and exporter.

Preferred structure:

```text
vendor/
  export/
    excel.py
    excel_schema.py
```

Vendor Excel exporters should consume:

```text
vendor source result
+ vendor DerivedViews
+ vendor validation
```

They must not consume migration IR.

Do not extend the existing generic IR Excel exporter with more vendor-specific conditional branches.

Shared Excel utilities are allowed for presentation-only concerns such as:

```text
header formatting
worksheet navigation
column sizing
filters
freeze panes
safe cell serialization
secret sanitization
```

Shared Excel utilities must not contain firewall semantics.

## Excel compatibility

Existing workbooks are a content compatibility baseline, not an architecture to preserve.

For each vendor:

```text
keep useful existing source fields
+ add current explicit source fields
+ add genuine derived fields
+ preserve unsupported/source appendix information
- vendor-neutral IR fields
- target-vendor fields
- redundant duplicates
- fake effective fields
```

Do not keep `Original / Normalized` pairs unless they genuinely represent different useful values.

## Web architecture

Shared web code should dispatch to the vendor pipeline.

It should not understand vendor firewall models.

Preferred flow:

```text
request
→ identify vendor
→ source-report registry
→ vendor analyze_source()
→ opaque vendor result
→ vendor build_preview()
or
→ vendor export_excel()
```

Do not add vendor semantic logic to `web.py`.

Avoid patterns such as:

```python
if vendor == "cisco_asa":
    inspect asa policies

elif vendor == "juniper_srx":
    inspect junos zones
```

Vendor-specific preview serialization belongs inside the vendor package.

Migration endpoints may continue using the legacy migration pipeline until conversion is redesigned.

## Source reporting contracts

Shared source-reporting infrastructure may know:

```text
vendor ID
display name
supported source extensions
how to invoke vendor analysis
how to build a preview
how to export Excel
```

It must not require:

```text
addresses
services
policies
NAT rules
interfaces
zones
VPNs
routes
```

to have a shared shape.

Treat vendor analysis results as opaque outside the vendor implementation.

## Source accounting terminology

For new source-reporting code, prefer terminology describing extraction reality.

Examples:

```text
extracted
partial
unsupported
unknown
parse error
collection incomplete
```

Avoid using migration terminology such as:

```text
normalized
migration safe
generation safe
target compatible
```

unless the code is actually operating in the conversion pipeline.

Extraction completeness and migration compatibility are different concerns.

## Cisco ASA rules

ASA configuration is command- and mode-oriented.

Preserve:

```text
command ordering
ACL entry ordering
NAT ordering
configuration modes
nameif relationships
security contexts
explicit `no` semantics
```

Do not assume FortiGate-style `config/edit/set` behavior.

Do not convert ASA state to IR merely to resolve source relationships.

ASA source reporting should stop at `CiscoASAConfig` before any legacy ASA-to-IR conversion.

## Cisco FTD rules

FTD has multiple authoritative source types.

Keep these distinct:

```text
FMC REST/API bundle
FDM REST/API bundle
FTD CLI / device evidence
```

Do not assume they contain equivalent information.

FMC/FDM may contain managed policy and object state that plain device CLI does not expose authoritatively.

CLI-only extraction must not manufacture:

```text
ACP rules
managed NAT policy
managed objects
other FMC/FDM-only policy state
```

Preserve the provenance/source plane of extracted data.

Do not route FTD extraction through ASA simply because parts of the runtime configuration use LINA syntax.

## Juniper SRX rules

Preserve Junos-native semantics:

```text
hierarchical configuration
display-set input
logical systems
configuration groups
apply-groups
apply-groups-except
activate / deactivate
candidate history
field provenance
routing instances
address-book scope
```

Group inheritance and other effective values belong in vendor-specific relationships/transforms.

Do not destroy provenance when calculating effective Junos state.

## Check Point rules

Keep these source planes distinct:

```text
Management API
domain/package/layer state
Gaia / gateway CLI
cluster/gateway state
```

Preserve:

```text
UID identity
domain scope
package scope
layer scope
inline layers
gateway association
pagination/completeness state
failed or unsupported collection commands
```

Do not flatten all Check Point rules into a generic policy list before source reporting.

A failed API or CLI collection command does not mean the corresponding configuration is empty.

## Palo Alto / PAN-OS

Apply the same vendor-native architecture when PAN-OS is migrated.

Before changing it:

```text
inspect the existing PAN-OS source model
inspect parser and pipeline stages
identify where IR conversion begins
split source extraction before that boundary
```

Preserve PAN-OS hierarchy and scope rather than forcing it into another vendor's shape.

Do not guess PAN-OS architecture from the other vendor implementations.

## FortiGate

The dedicated `fortigate-extract` repository is the architectural reference for the new extraction/reporting direction.

Use its responsibility boundaries as guidance:

```text
source
→ parser
→ source model
→ relationships/transforms
→ DerivedViews
→ validation
→ Excel
```

Do not copy FortiGate syntax assumptions or source models into other vendors.

Do not move FortiGate-specific architecture back into this repository unless explicitly requested.

## Documentation references

Use official vendor documentation as the primary semantic reference.

Prefer project-provided vendor reference files where they have already been curated for supported extraction coverage.

Examples include:

```text
Cisco ASA CLI References.md
Cisco FTD CLI References.md
Juniper CLI References.md
Check Point R81 CLI References.md
FortiGate Selected CLI References.md
```

Do not treat documentation defaults as explicitly configured source state.

When documentation and existing implementation disagree:

```text
verify source behavior
→ preserve source
→ add validation or unknown state if necessary
→ do not silently guess
```

## Secrets

Never export, log, preview, or preserve actual authentication secrets in reportable source evidence.

Examples include:

```text
passwords
pre-shared keys
private keys
API keys
tokens
secret strings
authentication credentials
SNMP community secrets where sensitive
```

Safe metadata is allowed:

```text
Password Configured = Yes
PSK Configured = Yes
Credential Present = Yes
```

Secret handling must be tested at:

```text
source extraction
source inventory
unsupported/raw data
validation messages
web preview
Excel
logs
```

Do not assume `raw_extra`, unsupported commands or API payloads are safe.

## Before editing

Before implementing a change:

```text
inspect the current branch
inspect actual paths
inspect actual models
inspect actual symbols
inspect current tests
trace the current call path
```

Do not guess APIs or file structure.

Prefer the smallest coherent change.

Avoid unrelated refactoring.

Prefer package-relative imports inside vendor packages where appropriate.

Do not rename or relocate large parts of the repository merely to make the architecture look cleaner.

Establish the new boundary first.

## Refactor strategy

Migrate incrementally.

Preferred order:

```text
1. shared source-report dispatch contract
2. Cisco ASA
3. Juniper SRX
4. Cisco FTD
5. Check Point
6. web preview / Excel dispatch
7. retire remaining IR-based source-reporting assumptions
8. implement conversion pairs one at a time after extraction/reporting is stable
```

A vendor is not considered migrated merely because its parser produces a source model.

It must work through:

```text
source
→ vendor source config
→ relationships/transforms
→ DerivedViews
→ validation
→ preview
→ Excel
```

## Legacy compatibility

During the transition:

```text
new source reporting
    must use vendor-native models

existing migration
    may continue using IR
```

Where necessary, use:

```text
VendorConfig
→ legacy VendorToIR adapter
→ IR
```

Do not make:

```text
VendorConfig
→ IR
→ vendor Excel
```

the new reporting architecture.

## Tests

Test the actual source-report pipeline:

```text
source
→ parser/source adapter
→ VendorConfig
→ DerivedViews
→ validation
→ Excel / web preview
```

Important regression areas include:

```text
nested configuration
contexts / domains / VSYS / logical systems
unknown fields
unsupported fields
reference resolution
interface topology
policy ordering
NAT ordering
source provenance
collection completeness
Excel compatibility
secret redaction
web preview
Excel download
```

Keep conversion tests separate:

```text
VendorConfig
→ legacy IR adapter
→ IR
→ target generator
```

Do not use cross-vendor conversion tests as proof that source extraction is correct.

## Architecture tests

Add or maintain tests ensuring:

```text
vendor source-report code does not depend on IR
vendor Excel does not depend on IR
vendor Excel does not import another vendor's source model
validation does not mutate VendorConfig
shared source-report code contains no firewall semantic model
web source-report endpoints do not inspect vendor model internals
secrets do not appear in previews or workbooks
```

## Change discipline

For each refactor:

```text
trace current behavior
→ identify the IR boundary
→ establish vendor source boundary
→ preserve existing behavior
→ move only vendor semantics needed for source reporting
→ add tests
→ switch one consumer at a time
```

Do not combine:

```text
parser rewrite
model redesign
Excel redesign
web redesign
IR deletion
target-generator changes
```

into one uncontrolled change.

## Do not reintroduce

Do not introduce a new source-reporting equivalent of the old IR under another name.

Avoid:

```text
vendor-neutral source IR
common firewall object hierarchy
generic migration schema used for Excel
cross-vendor normalized policy model
target-vendor concepts inside source models
shared semantic Excel exporter
```

unless explicitly requested as part of the later conversion phase.

## Decision rule

When choosing between architectural convenience and preserving source truth:

```text
correctness
→ source preservation
→ clear semantics
→ traceability
→ maintainability
→ convenience
```

When unsure:

```text
preserve the source
mark it unknown / unsupported
report the limitation
do not guess
```
