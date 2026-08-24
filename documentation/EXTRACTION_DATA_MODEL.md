# Firewall Configuration Extraction Data Model

**Document status:** Proposed authoritative extraction specification  
**Project:** Firewall Migration Tool  
**Applies to:** Config-file ingestion and live-device/API ingestion for all supported vendors  
**Related document:** `documentation/IR_DATA_STRUCTURE.md`

---

## 1. Purpose

The extraction model answers a different question from the canonical IR.

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

---

## 3. Relationship to canonical IR

Recommended flow:

```text
             Source file / live device
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

**Phase 1 implementation note:** the initial vendor-neutral `IRExcelExporter` consumes the currently implemented `IRConfig`. Its `Extraction Coverage` sheet marks source-section evidence as unavailable instead of inferring completeness. Phase 2 should populate `ExtractionResult` and adapt the exporter to include authoritative source-section and residual records without moving vendor-specific data into canonical IR.

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
| `input_method` | enum | `FILE`, `LIVE_API`, `LIVE_SSH`, etc. |
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

```text
firewall address "EMS_DYNAMIC"
  parsed -> yes
  generic meaning incomplete -> PARTIALLY_NORMALIZED
  manual review -> yes
```

---

# 10. Structured inventory model

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
- unresolved source/destination reference in a live deployment candidate

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

Config-file and live-device ingestion should produce the same conceptual extraction result.

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
- VDOM/global scope
- DNS
- NTP where present
- administrator metadata with secrets removed
- HA

## 21.2 Network

- system interface
- VLAN/subinterfaces
- aggregate/redundant interfaces
- loopback/tunnel interfaces
- system zone
- management access
- IPv4/IPv6 addressing

## 21.3 Firewall objects

- firewall address
- firewall address6
- IP ranges
- FQDN
- wildcard FQDN
- MAC/dynamic/geography object variants
- address groups
- multicast address objects where relevant
- service custom
- service groups
- schedules
- Internet-service references

## 21.4 Security policies

- firewall policy
- policy order/ID/UUID
- srcintf/dstintf
- srcaddr/dstaddr
- service
- action
- schedule
- enabled/disabled
- logging
- comments
- users/groups when present
- NAT flags
- IP pool references
- Internet services
- security/UTM profile references
- IPv6 policy equivalent where applicable by FortiOS version/mode

## 21.5 NAT

- firewall ippool (normalized as independent canonical IP-pool inventory;
  temporary pool-to-NAT-rule compatibility output does not replace this record)
- VIP (normalized as independent virtual-IP inventory, including nested real
  servers and additional settings; compatibility DNAT output remains separate)
- VIP group
- policy NAT linkage
- central SNAT when enabled
- port forwarding
- source/destination translation ranges
- NAT64/NAT46 where present

## 21.6 Routing

- static IPv4
- static IPv6
- policy routes
- SD-WAN route/service relationship
- BGP extract-only until normalized
- OSPF extract-only until normalized

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

## 21.9 SD-WAN

- zones
- members
- health checks
- rules/services
- SLA thresholds

## 21.10 Management/logging/services

Extract-only initially where necessary:

- syslog/FortiAnalyzer destinations
- SNMP metadata with secrets redacted
- DHCP
- AAA/user groups
- certificate metadata
- FortiManager/Security Fabric integration

Any present but unimplemented subsection must appear as `UNSUPPORTED`, `EXTRACT_ONLY`, or `VENDOR_EXTENSION` rather than disappear.

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

# 30. API behavior

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

---

# 31. Live ingestion behavior

Live clients should produce the same extraction categories as file parsers.

A live API client must not return hardcoded placeholder objects and mark the extraction successful.

If an API domain is unimplemented:

```text
status = UNSUPPORTED
reason = "Live extraction for <feature> is not implemented"
```

This applies equally to all vendors.

---

# 32. Optimizer boundary

The extraction result represents source truth and must remain immutable for reporting purposes.

Never perform unused-object pruning or migration optimization before creating source inventory/coverage.

Correct:

```text
ExtractionResult
     |
     +--> Excel/report
     |
     v
copy canonical_ir
     |
     v
optimizer
     |
     v
target generator
```

Incorrect:

```text
parse -> optimize -> Excel
```

The incorrect flow makes unused-but-present source objects disappear from inventory.

---

# 33. Definition of done for a vendor parser

A vendor config-file parser is considered high-confidence when:

1. Supported source versions are documented.
2. Vendor/source detection is validated.
3. Relevant configuration sections are inventoried.
4. All supported objects are parsed into typed source models.
5. All migration-normalized objects reach canonical IR.
6. Cross-object references are validated.
7. Policy ordering and enabled state are preserved.
8. NAT semantics are represented correctly.
9. VPN relationships/selectors are preserved where supported.
10. Scope/VDOM/vsys/domain context is preserved.
11. IPv4/IPv6 behavior is accounted for.
12. Unknown fields in known relevant objects are reported.
13. Unsupported sections are reported.
14. Parse errors are reported.
15. Secrets are redacted.
16. `unclassified_relevant_items == 0` on strict golden fixtures.
17. Excel counts and key field values match expected fixtures.
18. No unresolved security-relevant reference is converted to a permissive default.

---

# 34. Definition of done for FortiGate phase

For the current FortiGate focus, completion should require:

```text
Every migration-relevant FortiGate section discovered
             |
             +--> correctly normalized
             |
             +--> partially normalized + explicit warning
             |
             +--> extract-only
             |
             +--> vendor extension
             |
             +--> unsupported
             |
             +--> parse error

Unclassified migration-relevant configuration = 0
Silent-loss count = 0
```

Additionally:

- policy-linked SNAT must be correct;
- VIP/DNAT semantics must be correct;
- central NAT presence must be accounted for;
- Phase 1/Phase 2 VPN relationships must be accounted for;
- VDOM scope must be preserved;
- fabricated trust/untrust mappings must not be introduced;
- unsupported dynamic routing/security-management sections must still be visible in extraction coverage;
- Excel must show the complete extraction accounting result.

---

# 35. Final rule

**Extraction completeness and migration completeness are not the same thing.**

The product should be able to say:

> "This configuration was fully accounted for. 82% normalized into portable migration IR, 14% extracted for inventory only, 3% vendor-specific, and 1% unsupported with explicit remediation. Nothing was silently dropped."

That is a stronger and safer definition of parser quality than merely returning a non-empty `IRConfig`.
