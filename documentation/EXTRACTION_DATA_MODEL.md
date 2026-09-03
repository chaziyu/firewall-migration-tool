# Firewall Configuration Extraction Data Model

**Document status:** Proposed authoritative extraction specification
**Project:** Firewall Migration Tool
**Applies to:** Config-file ingestion for all supported vendors
**Related document:** `documentation/IR_DATA_STRUCTURE.md`

---

## 1. Purpose

The extraction model answers a different question from the canonical IR.

`IRConfig` and `ExtractionResult` are separate serialized concepts.
`IRConfig` carries the canonical IR `schema_version`. `ExtractionResult` must
receive its own version only if its serialized format becomes a stable external
interchange contract; `IR_SCHEMA_VERSION` must not be reused for it.

The IR asks:

> What vendor-neutral firewall intent can be normalized and used for cross-vendor migration?

The extraction model asks:

> What configuration was present in the source, what did the parser understand, what reached IR, what is extract-only, and what could not be safely represented?

The extraction model exists to provide **complete accounting of source configuration**.

Its main consumers are:

- Excel export
- parser QA
- migration pre-checks
- audit reports
- troubleshooting
- semantic coverage dashboards
- CI/golden fixture testing

---

## 2. Required invariant: zero silent loss

For every source configuration section/object/record relevant to device or security behavior, the extractor must classify the result.

A source item must be exactly one of:

```text
NORMALIZED
PARTIALLY_NORMALIZED
EXTRACT_ONLY
VENDOR_EXTENSION
UNSUPPORTED
IGNORED_BY_POLICY
PARSE_ERROR
```

The extractor must never represent:

```text
present in source -> silently absent from result
```

A parser can be incomplete. It cannot be silently incomplete.

Malformed network syntax must be classified as `PARSE_ERROR` or
`PARTIALLY_NORMALIZED` and retain sanitized source evidence. Parsing must never
repair an invalid netmask by inventing `/0`, `/32`, or another usable prefix.

Static-route object-count equality does not prove complete normalization.
Coverage must account for route-level parse errors, manual-review state, and
retained unmodeled source settings before reporting `NORMALIZED`.

---

## 3. Relationship to canonical IR

Recommended flow:

```text
             Source file
                       |
                       v
                 Source adapter
                       |
                       v
                ExtractionResult
             +---------+----------+
             |         |          |
             v         v          v
        Canonical   Inventory   Residual /
           IR       extract     unsupported
             |
             +------------------------------+
                                            |
                                            v
                                          Excel

Canonical IR
    |
    +--> target conversion
    +--> Terraform/API deployment
```

Excel should be built from `ExtractionResult`, because IR alone intentionally does not represent every vendor-specific setting.

**Foundation implementation note:** `IRExcelExporter` remains backward-compatible with an `IRConfig`-only input. FortiGate file-upload Excel and migration-package routes provide the executable `ExtractionResult`; its independently scanned source-section, structured inventory, and unsupported evidence populate the authoritative workbook sheets before optimization. Other vendors retain the IR-only fallback. Vendor-specific inventory remains outside canonical IR.

For phase-1 interface extraction, sanitized settings explicitly present inside
a recognized source-interface object are retained in the executable
`IRInterface.source_attributes` compatibility field. The workbook exposes these
as `Interface Source Settings` with `EXTRACT_ONLY` status. Nested secondary interface
IP entries (`config secondaryip`) are extracted into typed models and exposed in the
`Interface Secondary IPs` workbook sheet with accurate `NORMALIZED`, `PARTIALLY_NORMALIZED`,
or `PARSE_ERROR` extraction status. The FortiGate `secondary-IP` parent state is
preserved separately: explicitly disabled or parent-state-ambiguous entries are
retained as inactive source data, marked for manual review, and never counted as
active normalized interface addresses. This prevents known interface keys and
secondary IPs from disappearing while the broader `ExtractionResult.inventory`
model is being implemented.
Aggregate and redundant `system interface` objects preserve the ordered `member`
values in typed canonical topology. Their member relationships are validated
within the same VDOM/context, self-references are unresolved, and the topology
is marked `PARTIALLY_NORMALIZED` for target-platform review. FortiGate-specific
aggregate or redundancy settings such as LACP and minimum-link controls remain
in sanitized source attributes and are not treated as portable semantics.
The phase-4 FortiGate interface field `IRInterface.source_vrf` additionally
preserves a configured numeric `vrf` value. VRF `0` is the explicit default and
does not add a VRF-specific review finding; non-zero values are
`PARTIALLY_NORMALIZED` with manual review because target routing-instance
mapping is not yet implemented. Malformed or out-of-range values retain their
sanitized source evidence and are classified for review rather than coerced.
PAN-OS interface membership under a discovered virtual-router or
logical-router/VRF is preserved separately in
`IRInterface.source_routing_instance` and
`IRInterface.source_routing_instance_type`; it must never be written into the
FortiGate-specific `source_vrf` field. The visible routing-instance name and
type, together with the original virtual-router, logical-router, and VRF names,
are retained in source attributes. Members that do not correspond to an
extracted interface are retained in routing-instance inventory evidence and
require review. Multiple assignments preserve every routing-instance name in
`pan_routing_instance_conflicts` and require manual review rather than choosing
one silently.
Phase 7 adds typed FortiGate IPv6 interface extraction for the primary
`ip6-address`, ordered `ip6-allowaccess`, and common mode/advertisement flags.
Valid IPv6 interface prefixes are normalized into `IRInterface.ipv6_address`
while the exact source value remains in `source_ipv6_address`; malformed input
is retained and classified as a parse issue without an inferred replacement.
IPv6-only interfaces remain valid interface records. Additional IPv6
addresses, delegated prefixes, prefix lists, DHCPv6, router advertisements,
VRRP6, NDP proxy, and IPv6 policy-routing behavior remain in the recursive
sanitized source tree and require manual review when present.
Interface migration status is derived from an ordered review-reason list. A
small allowlist covers only typed interface fields and low-risk inventory
metadata; other retained top-level interface settings are treated as
potentially traffic-affecting unless their behavior is explicitly normalized.
Nested interface blocks are evaluated independently of the parent interface,
so extract-only or unsupported nested semantics remain visible and make
generation unsafe. Reviewed interfaces are `PARTIALLY_NORMALIZED` with
`requires_manual_review = true`; fully represented interfaces remain
`NORMALIZED`.
Target generators must not consume `source_attributes`.

---

# 4. Top-level `ExtractionResult`

Recommended conceptual schema:

```python
ExtractionResult
    schema_version
    extraction_id
    metadata
    source_document

    canonical_ir

    inventory
        system
        network
        routing
        vpn
        security
        identity
        pki
        ha
        sdwan
        qos
        network_services
        management
        logging
        vendor_specific

    source_sections[]
    object_results[]
    unsupported_items[]
    vendor_extensions[]
    residual_blocks[]
    unresolved_references[]
    warnings[]
    errors[]
    statistics
    coverage
```

The exact Python package structure may evolve, but these responsibilities should remain separate.

**Command-Level Extraction Accounting:**
In addition to section-level and object-level tracking, `SourceCommand` carries granular command accounting fields:
`line_number: Optional[int]`, `status: Optional[ExtractionStatus]`, `parser_handler: Optional[str]`, and `requires_manual_review: bool`. This enables deterministic zero-silent-loss validation (`assert_no_silent_loss`) across command-oriented formats like JunOS `display set` by verifying every non-comment input statement against `ExtractionStatus`.


---

# 5. Extraction status enum

Use a single stable status vocabulary across every vendor.

## 5.1 `NORMALIZED`

The source construct is fully understood and represented in canonical IR without known semantic loss.

Example:

```text
FortiGate firewall address/ipmask
    -> IRAddress(type=NETWORK)
```

## 5.2 `PARTIALLY_NORMALIZED`

A meaningful portion reached canonical IR, but some source semantics were not preserved.

Required:

- explicit warning
- missing/approximated field list
- manual-review indicator where security relevant

Example:

```text
VPN Phase 1 normalized
Phase 2 selector feature X unsupported
```

## 5.3 `EXTRACT_ONLY`

The parser extracted a structured representation, but the data is not currently used for cross-vendor conversion.

Examples:

- HA configuration during early implementation
- administrator roles
- dynamic routing before migration support is added

Extract-only data should still appear in Excel.

## 5.4 `VENDOR_EXTENSION`

The feature is useful and structured but intentionally vendor-specific.

Examples:

- FortiGuard-specific settings
- Panorama/FortiManager management relationships
- proprietary cloud/service objects

## 5.5 `UNSUPPORTED`

The parser recognized the construct but there is no safe supported representation.

Required fields:

- source path
- reason
- severity
- raw or sanitized source excerpt when safe

## 5.6 `IGNORED_BY_POLICY`

The product intentionally does not extract or migrate the construct.

Examples might include volatile operational counters or non-configuration telemetry.

This status must include a documented policy reason.

## 5.7 `PARSE_ERROR`

The parser recognized the relevant section/object but could not interpret it reliably.

This is different from `UNSUPPORTED`:

- `UNSUPPORTED`: syntax/feature known, support intentionally absent.
- `PARSE_ERROR`: expected supported syntax could not be parsed safely.

Security-relevant parse errors should usually block live migration.

---

# 6. Extraction metadata

## 6.1 `ExtractionMetadata`

Recommended fields:

| Field | Type | Description |
|---|---|---|
| `extraction_id` | string/UUID | Unique extraction run. |
| `schema_version` | string | Extraction model version. |
| `started_at` | datetime | Start. |
| `completed_at` | datetime/null | Completion. |
| `source_vendor` | string | Selected/detected vendor. |
| `source_product` | string/null | Product family. |
| `source_version` | string/null | Software version. |
| `source_build` | string/null | Build. |
| `hostname` | string/null | Device hostname. |
| `input_method` | enum | `FILE` |
| `parser_name` | string | Parser/client implementation. |
| `parser_version` | string/null | Parser version. |
| `strict_mode` | bool | Whether strict parser behavior was used. |
| `redaction_applied` | bool | Secret-sensitive data redacted. |

---

# 7. Source document model

For config-file ingestion, retain non-secret document metadata.

## 7.1 `SourceDocument`

Recommended fields:

- filename
- byte_size
- detected_encoding
- checksum (e.g. SHA-256)
- line_count
- vendor_detected
- version_detected
- configuration_scope hints
- decode_warnings[]

Do not store the entire raw file redundantly unless required for an explicit audit feature and handled securely.

### Encoding rule

Do not silently use `errors="ignore"` for security-relevant source files.

The current file-upload API requires valid UTF-8 and returns an explicit
decode-stage error with the failing byte offset rather than dropping or
replacing invalid bytes.

Preferred behavior:

1. attempt supported encoding detection;
2. report invalid bytes explicitly;
3. allow controlled replacement only when the operator can see that it occurred;
4. record affected offsets/lines when practical.

---

# 8. Source section inventory

A section scanner should inventory source configuration before or during detailed parsing.

## 8.1 `SourceSectionResult`

Recommended fields:

| Field | Description |
|---|---|
| `id` | Stable extraction ID for the section. |
| `path` | Vendor hierarchy path, e.g. `firewall policy`. |
| `scope_id` | VDOM/vsys/domain/etc. |
| `present` | Whether found. |
| `object_count_source` | Number of source objects/entries if known. |
| `object_count_parsed` | Number parsed. |
| `object_count_normalized` | Number reaching canonical IR. |
| `status` | Extraction status. |
| `parser_handler` | Parser function/class responsible. |
| `line_start` / `line_end` | Source range when file-based. |
| `warnings` | Associated warnings. |
| `errors` | Associated errors. |
| `notes` | Human-readable notes. |

Example:

```json
{
  "path": "vpn ipsec phase2-interface",
  "present": true,
  "object_count_source": 25,
  "object_count_parsed": 25,
  "object_count_normalized": 0,
  "status": "EXTRACT_ONLY",
  "notes": ["Phase 2 is parsed into the FortiGate source model but canonical migration mapping is not complete."]
}
```

---

# 9. Object-level extraction results

Section-level coverage is not enough. Important objects should have individual results.

## 9.1 `ExtractionObjectResult`

Recommended fields:

- id
- source_section_id
- source_reference
- source_name
- source_type
- status
- canonical_ir_ids[]
- inventory_ids[]
- missing_fields[]
- approximated_fields[]
- warnings[]
- errors[]
- requires_manual_review

Examples:

```text
firewall policy 42
  source object -> FGPolicy
  canonical IR -> policy:root:42
  status -> NORMALIZED
```

FortiGate policies have two complementary report paths:

```text
FGPolicy -> IRPolicy -> Policies
SourceCommand -> ExtractionResult.inventory_items
              -> Firewall Policy Source Settings
```

The typed path presents readable source and portable normalized semantics side
by side. The source-command path retains the numeric policy edit ID, configured
policy name (if any), operation, setting key, and ordered sanitized values.
Ordered values are exported as JSON arrays so multi-value commands cannot be
mistaken for a single joined string. Source-detail rows are extraction-only and
must never be consumed by target generators.

FortiGate firewall policy ZTNA settings are retained through typed source
preservation fields for known status, ownership, EMS tags, secondary EMS tags,
geography tags, redirect, and tag-match logic. Configured ZTNA semantics make
the policy `PARTIALLY_NORMALIZED` and require manual review because they are
FortiGate-specific. Unknown future ZTNA settings remain in sanitized
`extra_settings` and continue to be reported as retained unknown policy
settings.

The known FortiGate policy settings `timeout-send-rst`, `auto-asic-offload`,
`np-acceleration`, and `port-preserve` are typed source policy semantics. The
projection path is:

```text
Explicit source command
    -> FGPolicy typed field
    -> IRPolicy source_* field
    -> IRPolicy source_effective_* field
    -> Policies Excel columns
```

Configured `source_*` fields preserve the exact source value; effective
`source_effective_*` fields include documented FortiOS defaults when the
setting was omitted. These fields remain source-scoped and are not automatic
target-platform mappings. Unknown or future policy fields remain in sanitized
`extra_settings` and the Excel `Additional Settings` column.

FortiGate NAT uses authoritative source-resource inventories plus a derived
correlation view:

```text
firewall ippool  -> FGIPPool  -> IRIPPool -> IP Pools
firewall ippool6 -> FGIPPool6 -> IRIPPool

firewall vip -> FGVIP -> FGVIPRealServer
             -> IRVirtualIP -> IRVirtualIPRealServer
             -> Virtual IPs / VIP Real Servers

firewall vipgrp -> FGVIPGroup -> IRVirtualIPGroup -> VIP Groups

policy/central-snat-map/ip-translation + referenced resources
             -> _transform_nat() -> IRNATRule -> NAT Rules
```

IPv6 pools, VIPs, and VIP-group siblings follow the same typed canonical path.
Sanitized commands remain in
`ExtractionResult.inventory_items`, including nested real-server commands, and
unknown options remain in `extra_settings`/`source_attributes`.

`NAT Rules` is derived correlation output and never replaces the IP Pool, VIP,
VIP Real Server, or VIP Group inventories. A manual-review rule remains
reportable but is not eligible for target generation. VIP source/interface/
service restrictions remain separate from policy matches; correlation must not
guess CGN, PBA, full-cone, NAT46, or NAT64 behavior.

```text
firewall address "EMS_DYNAMIC"
  parsed -> yes
  generic meaning incomplete -> PARTIALLY_NORMALIZED
  manual review -> yes
```

---

# 10. Structured inventory model

## FortiGate object provenance and fidelity

FortiGate addresses retain exact `source_section`, `address_family`, and
`source_type` provenance. Nested address `config list` and `config tagging`
entries are typed extract-only metadata. Coverage counts by exact provenance,
including EMS-derived IR address groups under their originating `firewall
address` section. Equal source/parsed/normalized counts measure completeness;
a section remains `PARTIALLY_NORMALIZED` when retained objects require manual
review.

Only `type dynamic` plus `sub-type ems-tag` enters generic dynamic
address-group normalization. Other dynamic sub-types, `interface-subnet`,
`route-tag`, and objects without explicit values remain source-preserved and
visible. Extraction never infers their value from names, routes, interfaces,
zones, or VPN tunnels. SCTP service ranges remain `ServiceProtocol.SCTP`, keep
exact source-port constraints, and require target-platform review.

FortiGate custom-service coverage separates object accounting from semantic
completeness. Equal source, parsed, and IR counts do not make the section
`NORMALIZED` when any service requires review or retains unmodeled
traffic-affecting settings. Configured protocol is retained separately from
the effective FortiOS default, explicit protocol-number zero remains distinct
from omission, and exact destination port zero is not confused with ranges
such as `0-65535`. Service groups inherit partial status from unsafe services,
unsafe nested groups, and unresolved direct members; original memberships are
never removed or broadened.

The inventory is broader than migration IR. It exists primarily for extraction/reporting.

It should include structured representations for source settings that are important to operators even if no target migration is implemented yet.

Recommended inventory domains:

```text
Inventory
├── system
├── scopes
├── network
├── objects
├── policies
├── nat
├── routing
├── vpn
├── security_profiles
├── identity
├── pki
├── high_availability
├── sdwan
├── qos
├── network_services
├── management
├── logging
└── vendor_specific
```

Where a domain is fully portable, the inventory may simply reference canonical IR objects rather than duplicate them.

---

# 11. Unsupported item model

## 11.1 `UnsupportedItem`

Recommended fields:

| Field | Description |
|---|---|
| `id` | Stable extraction ID. |
| `vendor` | Source vendor. |
| `scope_id` | Scope. |
| `source_path` | Native configuration path. |
| `source_type` | Object/section type. |
| `source_name` | Native name/ID. |
| `reason_code` | Machine-readable reason. |
| `reason` | Human-readable explanation. |
| `severity` | INFO/WARNING/ERROR/BLOCKING. |
| `migration_relevant` | bool. |
| `raw_excerpt` | Optional sanitized source excerpt. |
| `recommended_action` | Manual remediation or roadmap hint. |

Suggested reason codes:

- `NO_CANONICAL_MODEL`
- `PARSER_NOT_IMPLEMENTED`
- `SYNTAX_VARIANT_NOT_SUPPORTED`
- `TARGET_CAPABILITY_UNKNOWN`
- `SECRET_REDACTED`
- `AMBIGUOUS_SEMANTICS`
- `INVALID_REFERENCE`
- `UNSUPPORTED_VERSION`

---

# 12. Residual/raw configuration model

Residual capture is the safety net for recognized source blocks that are not normalized.

## 12.1 `ResidualConfigBlock`

Fields:

- id
- vendor
- scope_id
- source_path
- start/end lines
- status
- reason
- sanitized_raw_text
- contains_sensitive_material
- checksum

### Rules

1. Residual data must be sanitized before Excel/report export.
2. Do not retain plaintext secrets merely to satisfy "zero silent loss".
3. If a block cannot be safely exported, retain metadata/checksum and state that content was redacted.
4. Residual blocks should not be fed directly into a target generator.

---

# 13. Unresolved references

## 13.1 `UnresolvedReference`

Fields:

- id
- source_object
- reference_type
- referenced_name/value
- expected_target_type
- scope_id
- severity
- reason
- candidate_matches[]

Examples:

- policy references missing address group
- VIP group references missing VIP
- service group references undefined service
- VPN Phase 2 references missing Phase 1

An unresolved security-policy reference must never automatically become `any`.

---

# 14. Parser warnings and errors

Use structured diagnostics.

## 14.1 `ExtractionDiagnostic`

Fields:

- id
- severity
- code
- message
- source path
- scope
- source reference
- affected canonical IR IDs[]
- remediation
- blocking flag

Recommended severity:

- `INFO`
- `WARNING`
- `ERROR`
- `BLOCKING`

Examples of blocking conditions:

- malformed security policy action
- incomplete NAT rule that could broaden exposure
- corrupted relevant source block
- unresolved source/destination reference in a deployment candidate

---

# 15. Extraction statistics

## 15.1 `ExtractionStatistics`

Recommended counts:

```text
source sections found
source objects found
objects parsed
objects normalized
objects partially normalized
extract-only objects
vendor-extension objects
unsupported objects
parse errors
unresolved references
warnings
blocking errors
```

Also maintain counts by category:

- interfaces
- zones
- addresses
- address groups
- services
- policies
- NAT
- routes
- VPN
- etc.

Counts must have clear semantics. Do not compare source object count with IR count when one source construct legitimately expands to multiple IR objects without documenting the relationship.

---

# 16. Extraction coverage

## 16.1 Coverage metrics

Recommended metrics:

### Section accounting coverage

```text
classified relevant sections / discovered relevant sections
```

Target: **100%**.

### Object parse coverage

```text
successfully parsed source objects / parseable source objects discovered
```

### Canonical normalization coverage

```text
fully normalized source objects / relevant source objects
```

This may be lower than 100% during development and is not itself a failure if everything else is explicitly classified.

### Silent-loss count

```text
relevant discovered items with no classification
```

Target: **0**.

## 16.2 `ExtractionCoverage`

Fields:

- relevant_sections_discovered
- relevant_sections_classified
- source_objects_discovered
- source_objects_parsed
- objects_normalized
- objects_partially_normalized
- objects_extract_only
- objects_vendor_extension
- objects_unsupported
- objects_parse_error
- unclassified_relevant_items
- coverage_percentages

`unclassified_relevant_items > 0` should fail strict parser QA.

---

# 17. Security and secret handling

Firewall configuration is sensitive operational data.

Extraction handling must assume that source files may contain:

- internal addressing and topology
- VPN peer information
- authentication configuration
- administrator identities
- password hashes
- pre-shared keys
- private keys/certificates
- SNMP communities
- API tokens

## 17.1 Redaction policy

Never export plaintext secrets to Excel.

Recommended output:

```text
PSK status: configured (redacted)
Private key: present (redacted)
Password/hash: present (redacted)
```

## 17.2 Raw residual handling

Before storing/exporting residual text, redact known secret-bearing commands/fields.

Vendor adapters should own vendor-specific secret detection patterns.

## 17.3 Logging

Do not log full raw configurations at normal log levels.

Diagnostics should reference source path/line rather than dumping entire secret-bearing blocks.

---

# 18. Excel export model

The standalone **Extract Data to Excel** feature should consume `ExtractionResult`.

Recommended workbook:

```text
Summary
Extraction Coverage
Interfaces
Zones
Addresses
Address Groups
Services
Service Groups
Applications
Schedules
Security Policies
IP Pools
Virtual IPs
VIP Real Servers
NAT Rules
Routes
VPN Tunnels
VPN Selectors
Security Profiles
Identity AAA
Certificates
High Availability
SD-WAN
QoS
Network Services
Management
Logging
Vendor Extensions
Unsupported
Unresolved References
Warnings
```

Sheets with no data may either be retained with headers or omitted according to a single consistent product policy.

The Zones worksheet should preserve source identity and review context with
the columns `VDOM`, `Name`, `Zone Type`, `Members`, `Description`, `Source
Path`, `Manual Review`, and `Additional Settings`. For FortiGate, system zones
and SD-WAN zones with the same name remain separate rows; SD-WAN membership is
derived from SD-WAN member-to-zone relationships rather than system-zone
interface membership.

## 18.1 Summary sheet

Recommended fields:

```text
Source vendor
Product
Hostname
Software version
Input method
Source filename
Extraction timestamp
Extraction status

Interfaces
Zones
Addresses
Address groups
Services
Policies
IP pools
Virtual IPs and nested real servers
NAT rules
Routes
VPN tunnels

Normalized count
Partially normalized count
Extract-only count
Unsupported count
Parse errors
Unresolved references
Blocking issues
Silent-loss count
```

## 18.2 Extraction Coverage sheet

Columns:

| Source Section | Scope | Present | Source Objects | Parsed | Normalized | Status | Warnings | Notes |
|---|---|---:|---:|---:|---:|---|---|---|

This sheet is mandatory for parser QA.

## 18.3 Formula injection prevention

Any string written to Excel that begins with formula-sensitive characters must be escaped/sanitized according to the chosen workbook library's safe-output policy.

At minimum inspect values beginning with:

```text
=
+
-
@
```

Do not allow untrusted firewall object names/comments to execute spreadsheet formulas when the workbook is opened.

---

# 19. Migration ZIP behavior

When performing config conversion, the ZIP should include an extraction workbook generated from the source extraction result **before optimizer pruning or target transformation**.

Recommended structure:

```text
migration_<source>_to_<target>.zip
├── source_inventory_<source>.xlsx
├── migration_report.md
├── migration_report.html
├── native/
│   └── <target config artifacts>
└── terraform/
    └── <terraform artifacts>
```

The Excel workbook must represent source extraction, not the optimized target migration subset.

Recommended flow:

```text
parse / ingest
    |
    v
ExtractionResult
    |
    +--> Excel source inventory
    |
    v
canonical source IR
    |
    v
copy for migration
    |
    v
optimizer / pruning
    |
    v
target generator
```

---

# 20. File and live API consistency



```text
File parser --------+
                    +--> ExtractionResult --> Canonical IR
Live API client ----+
```

The source method may differ, but downstream Excel, validation, and target generation should not require separate vendor-specific workflows.

Differences in source capability should be represented as metadata/coverage, not hidden branching in reports.

---

# 21. FortiGate extraction coverage baseline

For the first complete parser effort, inventory and classify at least the following currently relevant FortiGate areas.

## 21.1 System and scope

- system global
- configured hostname, timezone, and administrative HTTPS port
- VDOM/global scope
- system DNS primary/s…1124 tokens truncated… NAT
- statically resolvable interface-address SNAT primary IPs, with SD-WAN,
  dynamic, missing, unconfigured, and ambiguous egress addresses explicitly
  retained as unresolved/manual-review cases
- unresolved pool/VIP references reported without permissive fallback
- central SNAT when enabled
- port forwarding
- source/destination translation ranges
- NAT64/NAT46 where present

## 21.6 Routing

- static IPv4 and `router static6` are typed and counted separately
- confirmed FortiOS static-route defaults are applied to effective typed fields:
  distance `10`, priority `1`, weight `0`, and enabled `true` when status is
  omitted or `enable`; `source_explicit_fields[]` identifies source fields that
  appeared explicitly
- an omitted destination becomes the appropriate documented default prefix,
  while `dstaddr` remains a destination object/group reference with no
  normalized destination and mandatory manual review
- multiple SD-WAN zones, dynamic gateway, link-monitor exemption, source
  matching, BFD, VRF, weight, route tags, Internet Service matching, malformed
  prefixes, and unknown fields remain observable without guessed behavior
- policy routes
- SD-WAN route/service relationship
- RIP/RIPng, OSPF/OSPFv3, BGP, ISIS, and multicast routing as recursive
  `EXTRACT_ONLY` source trees until normalized; command operations, nested
  configuration, edit identities, and hierarchy remain available for review
- route maps, prefix/access/as-path/community lists, and BFD dependencies are
  separate `EXTRACT_ONLY` routing-dependency inventory; source block presence
  is distinct from whether the block contains configuration commands

## 21.7 VPN

- IPsec Phase 1
- IPsec Phase 2
- multiple selectors
- IKE version
- peer addressing
- proposals
- DH/PFS
- lifetime
- DPD
- tunnel interfaces
- SSL VPN inventory when present

FortiGate Phase 2 interfaces are retained one-for-one as typed
`PARTIALLY_NORMALIZED` compatibility inventory. Coverage reports the distinct
source, parsed, and structured Phase 2 counts. Explicit Phase 1 references,
ordered proposals, named and subnet selectors, auto-negotiate, DH groups,
keepalive, comments, and sanitized additional settings remain visible in IR
and the dedicated `VPN Phase 2` worksheet. Missing Phase 1 references are
preserved and reported for manual review without selector or reference
fallback.

All Phase 2 rows require manual migration review because the canonical model
does not represent the complete FortiGate Phase 2 semantics. A missing Phase 1
reference is an additional audited problem, not the only review condition.

FortiGate Phase 1 interfaces are likewise retained one-for-one as typed
`PARTIALLY_NORMALIZED` compatibility inventory. Portable tunnel fields and
explicit FortiGate source-only IKE, proposal, remote-access, DPD, and unknown
safe settings remain visible in IR and the `VPN Tunnels` worksheet. PSK values
are discarded before source-model construction; only configured/redacted
presence is reported. Source proposals are not replaced with invented target
crypto-profile names. Omitted source settings stay blank, a missing static
peer is not relabeled as dynamic, and unexpected non-secret Phase 1 flag or
IKE-version values remain explicit source attributes for manual review.

FortiGate SSL VPN host-check software is a top-level typed `EXTRACT_ONLY`
collection, independent of portals and SSL VPN enabled state. Nested check
items remain ordered child inventory. Portals retain host-check policy names;
missing host-check, portal, group, address, and pool references stay unchanged
and are audited. SSL VPN settings preserve explicit empty certificate state
without fabricating a default certificate.

## 21.8 Security profiles

Inventory at least profile names/references and structured core settings where supported:

- antivirus
- IPS
- web filter
- DNS filter
- application control
- SSL/SSH inspection
- DLP/file filter if present
- profile groups where present

FortiGate `ips sensor` is currently classified as `EXTRACT_ONLY`. The parser
retains typed sensors and nested entries, including unchanged FortiGate rule
IDs, list-valued severity/protocol filters, actions, rate limits, quarantine
settings, and sanitized unknown attributes. Typed extraction indicates source
inventory completeness; it does not imply portable IPS signature mapping or
target-generation support. Coverage uses the typed parser and reports separate
source, parsed, and IR counts for both sensor objects and nested entries.

Other supported FortiGate security-profile sections are retained as a
recursive structured source tree. Section/subsection hierarchy, edit keys, and
`set`/`unset`/`append` operations remain visible in extraction inventory and
dedicated Excel worksheets. These records are `EXTRACT_ONLY`, remain outside
canonical migration IR, and require manual review; secret-like settings are
redacted or discarded.

## 21.9 Traffic shaping and explicit proxy inventory

- `firewall shaper traffic-shaper` as typed `PARTIALLY_NORMALIZED` inventory,
  retaining configured bandwidth values and units without inventing omitted units
- `web-proxy global` as set-based `EXTRACT_ONLY` inventory when present
- unknown safe settings retained as sanitized source attributes

## 21.10 SD-WAN

- global status, load-balance mode, and sanitized additional settings
- every typed SD-WAN inventory object carries `source_context` (FortiGate VDOM)
- duplicate zone names, member IDs, health-check names, and rule IDs remain
  separate when they occur in different VDOMs
- zones and their additional settings
- members, IPv4/IPv6 gateway/source values, cost, weight, priorities,
  spillover thresholds, volume ratios, status, and comments
- health-check protocol/port/timers/static-route update/VRF/source fields
- service rules with authoritative multi-health-check lists, priority zones,
  SLA comparison/tie-break settings, and nested service SLA hierarchy
- duplication rules and thin, non-speculative neighbor inventory
- unknown future `system sdwan` children remain visible through `FortiGate
  Source Configuration` rather than being suppressed by the dedicated parent
- all SD-WAN data remains `EXTRACT_ONLY` and requires manual review; extraction
  does not claim cross-vendor SD-WAN equivalence
- health checks and nested SLA thresholds
- rules/services, including source/destination selectors, preferred members,
  strategy, priority members, and sanitized additional settings

FortiOS-effective defaults are applied to typed member, health-check, and
service-rule fields only where the FortiOS behavior is confirmed. The parser
retains normalized `source_explicit_fields` metadata for each such object, so
an effective value can be distinguished from a value explicitly present in the
source. Defaulted values are not added to sanitized source attributes.

The discovered hierarchy is typed `EXTRACT_ONLY` inventory. Extraction does
not invent target-vendor routing, health-check, or failover behavior.

## 21.11 Management/logging/services

Extract-only initially where necessary:

- FortiGate `system admin`, `system accprofile`, and `user fortitoken` as typed
  `EXTRACT_ONLY` administrator inventory; passwords, secrets, token seeds, and
  activation codes are discarded during parsing, and no target administrator
  accounts or roles are generated. Ordered guest user groups and every
  explicitly configured IPv4/IPv6 trusted-host restriction are retained.
  Access-profile permission children remain associated with their profile and
  unknown permission settings are retained as sanitized source attributes.
- syslog/FortiAnalyzer destinations
- SNMP metadata with secrets redacted
- DHCP
- LDAP, RADIUS, TACACS+, SAML, and FSSO server metadata, FSSO
  AD-group/provider relationships, local-user non-secret metadata, user groups,
  and nested group-match criteria as typed `EXTRACT_ONLY` inventory; FSSO
  identities remain distinct from LDAP, RADIUS, and TACACS+, and unresolved
  provider/certificate references remain explicit for manual review
- FortiGate `user setting` and `user quarantine` as typed `EXTRACT_ONLY`
  singleton inventory. Certificate and quarantine address-group references are
  resolved by exact source name; missing references remain unchanged and are
  audited.
- SSL VPN globals, portals, authentication rules, and top-level host-check
  software as typed `EXTRACT_ONLY` inventory
- DoS policies with nested anomalies, firewall sniffers, authentication
  schemes, and authentication rules as typed `EXTRACT_ONLY` inventory
- certificate metadata
- FortiGate `vpn certificate remote`, `vpn certificate local`, and
  `vpn certificate ca` objects through one certificate path as
  `EXTRACT_ONLY` inventory, including public X.509 material and metadata;
  password and private-key contents are discarded while presence/encryption
  state is retained as boolean metadata
- FortiGate `firewall ssh local-key` and `firewall ssh local-ca` as typed
  `EXTRACT_ONLY` inventory; public-key presence/source metadata is retained,
  while private-key and password contents are discarded before model creation
- replacement-message, FortiSwitch, and wireless-controller sections as
  explicit `IGNORED_BY_POLICY` coverage evidence because those appliance-only
  domains are outside current firewall migration scope
- FortiManager/Security Fabric integration
- `system session-helper` / ALG inventory, classified as `EXTRACT_ONLY`;
  built-in baseline matches are informational, while custom, customized, or
  incomplete entries require manual target-platform review
- `system session-ttl port` overrides, classified as `EXTRACT_ONLY` and
  retained for manual target-platform review rather than converted into service
  objects

FortiGate operational configuration without portable migration semantics is
retained through sanitized `SourceInventoryItem` records and exposed in the
single `FortiGate Source Configuration` worksheet. This includes system
behaviour, management/logging, automation, and recognized miscellaneous
operational families. Automation triggers, actions, and stitches retain their
recursive `config`/`edit` hierarchy and command operations. These records are
`EXTRACT_ONLY`, require manual review, remain outside canonical IR, and are
omitted from the fallback worksheet when a strong dedicated inventory sheet
already represents the section. Credential-bearing settings such as SNMP
communities, authentication/privacy passwords, API keys, tokens, and private
keys are redacted by source setting name before inventory serialization.

Any present but unimplemented subsection must appear as `UNSUPPORTED`, `EXTRACT_ONLY`, or `VENDOR_EXTENSION` rather than disappear.

Reference existence and semantic migration are separate results. A firewall
policy may successfully resolve a FortiGate user group while still requiring
manual review because target identity enforcement is not implemented. A policy
may likewise resolve an IPS, antivirus, web-filter, application-control, or
profile-group name while the source profile definition remains
`EXTRACT_ONLY`. Neither case may be reported as full target-semantic migration,
and consuming policies must not be emitted without equivalent enforcement.

---

# 22. FortiGate parser processing stages

Recommended architecture:

```text
Raw FortiGate config
      |
      v
Tokenizer / block scanner
      |
      +--> section inventory
      |
      v
FortiGate source model (FGConfig)
      |
      +--> source object results
      |
      v
FortiGate -> IR transformer
      |
      +--> canonical IR
      +--> unsupported/partial results
      |
      v
Cross-reference validator
      |
      v
ExtractionResult
```

The section scanner should not depend on whether a transformer exists. It must detect relevant source blocks independently enough to reveal unsupported sections.

---

# 23. Source line/block tracking

For file ingestion, track source line ranges for important blocks where practical.

Example:

```text
config firewall policy       line 2400
    edit 42                  line 2411
       ...
    next                     line 2430
end                          line 2500
```

This permits diagnostics such as:

```text
Policy 42 references missing address object 'Old_Server'
Source: lines 2411-2430
```

Line tracking greatly improves parser QA and customer troubleshooting.

---

# 24. Parsing philosophy

## 24.1 Prefer token/block parsing over fragile positional regexes

Regex is appropriate for well-bounded scalar syntax, but complex CLI grammars should use a tokenizer/state machine or grammar-aware parser.

A parser should preserve quoting and multi-value semantics.

## 24.2 Preserve unknown keys within known objects

If a known object contains a new FortiOS/PAN-OS/etc. field that the parser does not understand, record the unknown field in extraction diagnostics/vendor metadata rather than silently dropping it.

Example:

```text
Known: firewall policy
Unknown setting: set new-feature-x enable
```

Result:

```text
Policy parsed: PARTIALLY_NORMALIZED
Unknown field: new-feature-x
```

## 24.3 Version-aware behavior

Parser behavior should use detected source version where syntax/semantics differ.

Unknown versions should not automatically fail, but must be reported and should raise confidence warnings when relevant.

---

# 25. Validation stages

Use several validation layers.

## 25.1 Syntax validation

Did the source parser understand the input structure?

## 25.2 Model validation

Are parsed source objects internally valid?

## 25.3 Reference validation

Do groups, policies, NAT rules, VPNs, etc. reference existing objects?

## 25.4 Canonical IR validation

Does normalized IR satisfy IR invariants?

## 25.5 Coverage validation

Were all discovered migration-relevant source sections classified?

## 25.6 Deployment eligibility validation

Are there blocking errors that make conversion/live migration unsafe?

A file may be valid for Excel extraction while not being eligible for live migration.

---

# 26. Extraction completion states

Recommended overall result status:

- `COMPLETE`
- `COMPLETE_WITH_WARNINGS`
- `PARTIAL`
- `FAILED`

Suggested meanings:

### `COMPLETE`

All relevant discovered source items were classified, all expected supported items parsed successfully, and no blocking errors exist.

### `COMPLETE_WITH_WARNINGS`

Accounting is complete, but there are non-blocking unsupported/extract-only/approximation warnings.

### `PARTIAL`

Some relevant data could not be parsed or classified correctly; Excel may still be produced but migration should normally be blocked.

### `FAILED`

Source could not be safely ingested.

Do not label a result `COMPLETE` merely because `IRConfig` is non-empty.

---

# 27. Testing strategy

## 27.1 Golden source fixtures

Maintain versioned, sanitized fixtures:

```text
tests/fixtures/fortigate/
├── fortios_6_4_basic.conf
├── fortios_7_0_basic.conf
├── fortios_7_2_enterprise.conf
├── fortios_7_4_enterprise.conf
├── addresses/
├── policies/
├── nat/
├── vpn/
├── routing/
├── sdwan/
├── ipv6/
├── vdom/
└── edge_cases/
```

No real customer secrets/configuration may be committed.

## 27.2 Expected extraction results

For every major fixture maintain expected:

- source section counts
- source object counts
- canonical IR object counts
- unsupported items
- unresolved references
- warnings
- selected exact field values

## 27.3 Semantic assertions

Weak:

```python
assert len(ir.policies) > 0
```

Preferred:

```python
assert len(ir.policies) == 483
assert policy.action == PolicyAction.ALLOW
assert policy.source_addresses == expected_sources
assert policy.destination_addresses == expected_destinations
assert policy.services == expected_services
assert policy.enabled is True
```

## 27.4 Coverage assertion

Strict fixtures should require:

```python
assert extraction.coverage.unclassified_relevant_items == 0
```

Unsupported items may be non-zero; silent unclassified items may not.

## 27.5 Excel validation tests

Verify:

- workbook opens successfully;
- required sheets exist;
- source counts match expected extraction data;
- values match canonical/inventory data;
- Unicode works;
- long values wrap safely;
- formula injection is neutralized;
- secret values are not present;
- unsupported/coverage sheets are populated correctly.

---

# 28. Recommended package layout

Suggested future layout:

```text
src/fwmigrate/extraction/
├── __init__.py
├── enums.py
├── result.py
├── source.py
├── coverage.py
├── diagnostics.py
├── unsupported.py
├── residual.py
├── validation.py
└── excel_exporter.py
```

Vendor-specific source parsing remains under:

```text
src/fwmigrate/parsers/<vendor>/
```

The generic extraction package must not contain FortiGate/PAN-OS/etc. syntax logic.

---

# 29. Suggested core Pydantic models

Conceptual definitions:

```python
class ExtractionStatus(str, Enum):
    NORMALIZED = "normalized"
    PARTIALLY_NORMALIZED = "partially_normalized"
    EXTRACT_ONLY = "extract_only"
    VENDOR_EXTENSION = "vendor_extension"
    UNSUPPORTED = "unsupported"
    IGNORED_BY_POLICY = "ignored_by_policy"
    PARSE_ERROR = "parse_error"


class ExtractionSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    BLOCKING = "blocking"


class SourceSectionResult(BaseModel):
    id: str
    path: str
    scope_id: str | None = None
    present: bool = True
    object_count_source: int | None = None
    object_count_parsed: int = 0
    object_count_normalized: int = 0
    status: ExtractionStatus
    warnings: list[str] = []
    errors: list[str] = []


class UnsupportedItem(BaseModel):
    id: str
    source_path: str
    scope_id: str | None = None
    reason_code: str
    reason: str
    severity: ExtractionSeverity
    migration_relevant: bool = True
    raw_excerpt: str | None = None


class ExtractionCoverage(BaseModel):
    relevant_sections_discovered: int = 0
    relevant_sections_classified: int = 0
    source_objects_discovered: int = 0
    source_objects_parsed: int = 0
    objects_normalized: int = 0
    objects_partially_normalized: int = 0
    objects_extract_only: int = 0
    objects_vendor_extension: int = 0
    objects_unsupported: int = 0
    objects_parse_error: int = 0
    unclassified_relevant_items: int = 0


class ExtractionResult(BaseModel):
    schema_version: str
    extraction_id: str
    metadata: ExtractionMetadata
    canonical_ir: IRConfig
    source_sections: list[SourceSectionResult] = []
    object_results: list[ExtractionObjectResult] = []
    unsupported_items: list[UnsupportedItem] = []
    residual_blocks: list[ResidualConfigBlock] = []
    unresolved_references: list[UnresolvedReference] = []
    warnings: list[ExtractionDiagnostic] = []
    errors: list[ExtractionDiagnostic] = []
    coverage: ExtractionCoverage
    statistics: ExtractionStatistics
```

These examples are architectural guidance, not a requirement to implement all models in one commit.

---

# 30. PAN-OS address-object extraction baseline

PAN-OS address objects are extracted scope-first and registered only after
successful canonical validation. The supported source types are `ip-netmask`,
`ip-range`, `ip-wildcard`, and `fqdn`; IPv4 and IPv6 family is derived through
semantic IP parsing rather than string heuristics. Descriptions and ordered
tags are portable canonical fields. Bounded structured source attributes retain
the original PAN-OS type/value and any unconsumed child fields.

Each source address entry receives exactly one terminal inventory status:
fully represented valid entries are `NORMALIZED`, valid entries with retained
unrepresented fields are `PARTIALLY_NORMALIZED`, and malformed supported
values are `PARSE_ERROR`. A malformed definition never creates or registers a
degraded canonical address. Address objects and address groups have distinct
resolver identities; ambiguous same-scope names cannot be resolved according
to registration order.

---

## 2.1 Semantic tiers

Extraction status describes source accounting; it does not by itself claim
portable migration support. FortiGate coverage therefore reports a separate
semantic level for covered areas:

- `NORMALIZED`: portable intent is represented without known semantic loss.
- `TYPED_EXTRACT_ONLY`: important source fields are typed and auditable, but
  the vendor-specific behavior is not claimed to be portable.
- `STRUCTURED_EXTRACT_ONLY`: the recursive source tree is authoritative and
  visible, while profile semantics remain unmodeled.
- `UNSUPPORTED`: no safe typed or structured interpretation is available.

For example, local-user status and `passwd-time` are typed, while password
content is intentionally secret and never exported. RADIUS obscure fields are
retained in sanitized Additional Settings. A webfilter nested feature that has
no typed model remains `STRUCTURED_EXTRACT_ONLY` rather than being reported as
fully supported.

---

# 31. PAN-OS groups, services, schedules, and application inventory baseline

PAN-OS static and dynamic address groups retain ordered members, exact dynamic
filters, descriptions, tags, scope, and bounded unknown-field evidence. Static
members resolve through the combined address-reference namespace after all
scoped definitions receive deterministic canonical names. Unresolved,
ambiguous, cyclic, or otherwise unsafe nested members remain visible and force
`PARTIALLY_NORMALIZED`; they are never replaced with permissive built-ins.

Custom TCP and UDP services require exactly one protocol branch and a valid
destination-port expression. Optional source-port expressions use the same
0-65535 validation without inventing an absent source constraint. PAN-specific
tags, timeout overrides, and unknown protocol settings remain sanitized source
evidence and force `PARTIALLY_NORMALIZED`. Invalid services produce
`PARSE_ERROR` and no canonical service. Service and service-group definitions
have distinct resolver identities and a shared service-reference namespace;
unsafe or unresolved group members populate `IRServiceGroup.unsafe_members`.

Daily, weekly, and non-recurring schedules retain every validated source
window. A single daily window, a single non-recurring range, or equal single
weekly windows can use the current canonical schedule fields exactly. Multiple
or differing windows remain untruncated in `source_attributes`, with blank
canonical start/end fields and `PARTIALLY_NORMALIZED` status so extraction does
not broaden enforcement.

Custom App-ID definitions, application groups, application filters, and tag
definitions are `EXTRACT_ONLY` structured inventory. Default ports, timeouts,
dependencies, filter criteria, and bounded signature trees remain visible.
Application filters are never expanded against the mutable PAN content catalog,
and custom applications are never converted into generic services. Every
handled source entry receives exactly one terminal inventory status.

---

# Cisco ASA extraction baseline

`extract_cisco_asa_config(text)` applies the zero-silent-loss contract to
offline Cisco ASA running configuration while preserving the public plugin
contract `parse(...) -> IRConfig`. It returns an `ExtractionResult` containing
canonical IR, section coverage, sanitized command inventory, and unsupported
records. ACL, address, service, interface, route, and NAT syntax is normalized
only where semantics are proven. Crypto/VPN, platform policy, management, and
unknown commands remain explicit extract-only or unsupported inventory.

Cisco ASA and Cisco Secure Firewall Threat Defense are separate source
capabilities. ASA CLI extraction does not claim FMC access-control-policy
coverage. Passwords, enable secrets, tunnel-group pre-shared keys, SNMP
communities, and other credentials must be redacted before export.

The ASA source model retains the three NAT ordering sections (manual before
auto, object/auto, and `after-auto`) and parses source and destination twice-NAT
operands according to their different Cisco grammar directions. Interface-free
manual NAT, PAT pools and modifiers, interface IPv6 translation, static PAT,
and recognized NAT modifiers remain explicit. Semantics without an exact
portable representation are `PARTIALLY_NORMALIZED` and require review; unknown
trailing NAT tokens are never silently discarded.

ASA ACL definitions are separated from their consumers. Only `access-group`
bound transit ACLs become ordinary canonical security policies. Unbound ACLs
and ACLs consumed by crypto maps, class maps, captures, or AAA remain source
inventory. Identity selectors, source and destination TrustSec selectors,
interface-address endpoints, ICMP groups, and network-service references are
preserved independently and force review when canonical enforcement is not
exact. `any`, `any4`, and `any6` remain semantically distinct.

Current structured ASA extraction also includes IPv6 address objects and
network-group members, IPv4/IPv6 interface addressing source settings, IPv4
standby addresses, DHCP `setroute`, `management-only`, IPv4 route tracking and
tunneled flags, IPv6 static routes, time ranges, protocol/ICMP/user/security
groups, and modern network-service objects/groups. VPN, MPF, AAA, failover, and
other platform domains remain extract-only or unsupported until separate
semantic implementations exist. This ASA work does not add a Cisco FTD alias.

---

# 32. PAN-OS security-rule extraction baseline

PAN-OS security rules are extracted independently from local, pre, and post
rulebases; default-security-rules are not included in this baseline. Source
order uses a zero-based index that restarts within each rulebase. Scope,
rulebase position, source index, source path, and rule name remain explicit
source evidence, and rulebase position is part of the deterministic source
record identity.

Canonical policies are constructed only after required match fields and action
are validated. Missing `from`, `to`, source, destination, or service lists are
never replaced by `any`. Missing actions never become `allow`. Exact PAN action
values remain in `source_action`; drop and reset variants map to canonical deny
while forcing review because their source behavior is more specific.

Address, service, schedule, and locally defined application references resolve
through their scoped namespaces after canonical naming. Unresolved references
remain unchanged in both canonical/source evidence, are recorded separately by
reference class, and force `PARTIALLY_NORMALIZED`. Only explicitly configured
`any`, `application-default`, and the small predefined-service set already
recognized by the application are treated specially. Non-local application
names remain unresolved until the predefined App-ID catalog is implemented.

Source-user, category, HIP, negation, tags, group-tag, SaaS selectors, rule
type, inspection flags, profile assignments, and bounded unknown fields remain
complete source evidence. Disabled and logging booleans retain separate
explicit/absent state. A single resolved profile group maps canonically;
ambiguous mixed or direct profile semantics require review. Every source rule
receives exactly one terminal extraction status, and unsafe canonical policies
are withheld or marked ineligible for target generation.

---

# 33. API behavior

Recommended standalone endpoint:

```text
POST /api/extract
```

Returns structured extraction summary/ID.

Recommended Excel endpoint:

```text
GET /api/extract/<extraction_id>/excel
```

or a single upload-and-download endpoint where appropriate.

Input must not require a target vendor.

The source vendor may be selected by the user, but parser validation should verify that the uploaded content is plausible for that vendor.

## Check Point authoritative-leaf accounting

For `checkpoint-export-v1`, authoritative leaves are dedicated object rows,
dictionary-only `objects-dictionary` entries, flattened Access rules, flattened
NAT rules, non-comment Gaia command lines, and explicit failed-command records.
Rulebase section containers are hierarchy, not leaves. Dictionary entries use
`(domain, UID)` identity and are not counted again when the UID is already
represented by a dedicated object command or another rulebase dictionary.
UID-less entries use a conservative type/name/source-scope identity; ambiguous
entries are retained as parse errors.
`count_authoritative_source_leaves()` provides a deterministic test oracle; the
count must equal authoritative inventory leaf records for covered fixtures.

Check Point R81 Access Time is a list-valued OR dimension. Only explicit `Any`
alone or one fully normalized Time object can be represented without list-loss;
missing/empty lists, multiple Time objects, Time groups, unresolved references,
and `Any` mixed with another constraint are partial and require review. Content
Awareness, action modifiers, and richer Track settings remain complete source
evidence and taint or withhold a rule when canonical enforcement would change.
Protocol-only inventory for `service-other` does not make the object normalized
when INSPECT Match/action, reply, signature, aging, timeout, or cluster/session
behavior is present; dependency taint propagates into Access and NAT rules.

Security Zone objects are `NORMALIZED` only when an `IRZone` is emitted.
`show-gateways-and-servers` is authoritative for SmartConsole interface topology
and zone binding, while Gaia is authoritative for OS interface configuration.
Conflicts are preserved and require review. The legacy synthetic Gaia
`set interface ... security-zone ...` form is not evidence of real R81 topology
coverage.

Dictionary occurrences that duplicate a dedicated object are linked to that
inventory item through `source_references`. Dictionary-only portable object
definitions use the ordinary Check Point object/service/time normalizers;
resolver-only actions, Track objects, special `Any`/`Original` values, and
nonportable match objects receive explicit non-canonical accounting statuses.

# 34. Derived migration completeness and generation safety

`ExtractionResult` additively exposes `requires_manual_review`,
`migration_complete`, `generation_safe`, and ordered `blocking_reasons`. These
values are derived from source interpretation and dependency safety, not from
whether canonical IR is non-empty.

Generation safety is false for interpretation-changing incomplete source state,
including central NAT without a complete central-SNAT target mapping,
policy-based NGFW mode with source security policies, traffic-affecting parse or
unsupported sections, and canonical traffic objects requiring review. Inventory
items correlated to partially normalized policies carry the same partial status,
review flag, and reasons. Typed FortiGate source-only traffic rule families such
as PBR, local-in, proxy, shaping, DHCPv6, and TTL policy are also blocking even
though their sanitized source representation was successfully retained. A
multi-VDOM extraction remains generation-unsafe until an explicit mapping from
each source context to a target scope is supplied. Every scanner-discovered section receives exactly one
`ExtractionStatus`; unsupported traffic configuration remains blocking even
when sanitized inventory was retained.

`SourceSectionResult` and `SourceInventoryItem` include optional
`source_context`. For FortiGate this is the VDOM identity separated from the
logical section path. A source name without its context is not a unique identity
in multi-VDOM input.

Incomplete pagination taints every rule from the affected grouped rulebase
before transformation. Scope ambiguity, unsupported actions, nonportable match
objects, time groups, dual-stack source objects, translated-service NAT, and
failed collection commands remain explicit inventory evidence even when no
canonical object is created. Unknown and unnamed objects default to
`UNSUPPORTED` or `PARSE_ERROR`, never `NORMALIZED`.

FortiGate SSL VPN portal child sections are independently counted in coverage
and classified as `EXTRACT_ONLY`. Sensitive bookmark passwords and arbitrary
form-data values are not retained; extraction records only safe metadata and
whether a value was configured.

---

