# FortiGate NAT extraction: implemented scope and validation

This document describes the executable extraction path, not a claim of universal
FortiOS support or deployment equivalence. The reference baseline is FortiOS 7.4;
an unknown or different version is reported for review. Version detection alone
does not certify every feature of that release.

## Data flow

```text
Configuration file / live CMDB API
    -> FortiGate source objects + sanitized source accounting
    -> FGToIRTransformer -> NATExtractor (existing source normalization)
    -> NATAnalyzer (references -> effective states -> ordered coverage -> diagnostics)
    -> IRConfig + reporting-only ExtractionReport.nat_analysis
    -> Excel source inventory
```

The plugin API still returns `IRConfig`. Its optional `extraction` field is a
compatibility envelope for the reporting companion in `fwmigrate.extraction`;
source syntax is not a target-generation contract. The standalone
`extract_nat_and_security()` helper is a legacy experimental path and is not used
by file upload, live ingestion, or Excel extraction.

## Implemented behavior

| Source | Extraction behavior |
|---|---|
| Policy `nat enable` | Creates policy-linked SNAT, preserving rule ID, sequence, status, matching interfaces, addresses, services and schedule. |
| Interface-address SNAT | Records a dynamic outgoing-interface-address translation. Does not invent an IP for DHCP or routing-dependent interfaces. |
| Policy IP pools | Resolves pool references and retains translated ranges and allocation type. A shared pool can support multiple policy rules. |
| Advanced IP pools | `fixed-port-range` and `port-block-allocation` are valid source types. Source range, block size and blocks per user are retained and validated separately from target compatibility. |
| Predefined services | Recognizes DNS, HTTP, HTTPS, NTP, SSH, PING, RDP, SMTP and ALL without requiring custom definitions. Explicit custom/group definitions override the catalogue. |
| Route-based VPN reference | A parsed IPsec Phase 1 definition establishes its tunnel interface reference even without a separate system-interface entry. |
| Unused pools | Remain in source inventory; do not create independent NAT rules. |
| Static VIP / port forwarding | Retains external/mapped addresses, protocol, external/translated ports, source filters and source-policy references. UDP remains UDP. |
| VIP groups | Preserves members and policy linkage; reports missing members or name conflicts. |
| Central SNAT | Retains IPv4 match conditions, protocol, source/destination/translated ports, translation resources, sequence and status. |
| Central NAT mode | Policy SNAT flags are retained but do not produce duplicate SNAT rules when central NAT or policy-based NGFW mode is active. |
| Central `nat disable` | Retains an identity/no-translation definition; this is distinct from a disabled rule. |
| Inactive central table | Remains in inventory when central NAT is disabled. |
| `set`, `unset`, `append` | Captures effective settings and explicit unset/append operations; unsupported script/reordering commands are reported. |
| File syntax | Preserves quoting, multiline strings, nested NAT settings, scope and line locations. Invalid structure produces blocking diagnostics. Invalid UTF-8 uploads are rejected. |
| Live API | Captures source fields and all advertised result pages; unavailable/truncated endpoints are reported as unknown, not empty. |

NAT zones come only from actual source zones or explicit operator mappings.
Interface roles/names do not establish NAT trust/untrust zones. Empty zone cells
are not `any`; inspect the separate interface columns.

## Review-required cases

These remain visible rather than being silently dropped or automatically made
permissive:

- IPv6 NAT, NAT64/NAT46 and unimplemented NAT variants.
- Multiple VDOMs in one input: scoped source records are retained, but flat legacy
  address/policy models cannot safely merge them. Supply one VDOM per input for
  canonical normalization.
- Virtual servers/load balancing and nested VIP features without a canonical
  mapping.
- Address ranges/multiple mapped addresses requiring allocation validation,
  multiple pools and target allocation compatibility for specialized pool types.
- Interface-derived VIP external addresses (`0.0.0.0`), ambiguous filters and
  unresolved interfaces, schedules, services, addresses or pool references.
- Combined SNAT/DNAT and VIP-related outbound translation precedence. No reverse
  SNAT rule is guessed from `extintf any`.
- Unknown settings, missing required values, invalid ports/addresses, duplicate
  IDs/names and cyclic references.
- Restrictions in referenced objects that the shared models cannot represent,
  including address-group exclusions and service source-port constraints.

Original dependency settings are retained as `reference:` snapshots in the source
settings worksheet. They are supplementary source evidence, not extra settings
on the referring policy.

## Workbook interpretation

- **NAT Rules:** normalized definitions and any explicitly flagged partial rules.
  Includes original and translated values, interfaces, source policy IDs, status,
  sequence, pool references, configured/effective state and review/migration flags.
  `DISABLED`, `CONFIGURED_NOT_EFFECTIVE`, `SHADOWED` and `REVIEW_REQUIRED` are
  distinct from extraction status. VPN no-NAT intent is in coverage/policy summary;
  it does not inflate the configured translation-rule count.
- **NAT Inventory:** discovered policy/NAT objects, including unused resources,
  inactive entries and unsupported objects; this is not a list of active rules.
  `Usage State` distinguishes active, disabled-only and unused/unreferenced
  resources; the original `Status` remains the extraction classification.
  Active/disabled policy references, subtype, mappings, source validity and target
  compatibility are separate columns. ACTIVE is a relationship state, not proof
  that every referencing policy or allocation works.
- **NAT Source Settings:** sanitized explicit fields and nested/reference
  snapshots. Long values are split into numbered parts to avoid silent loss.
- **NAT Policy Summary:** policy names/IDs, effective defaults, matching fields,
  pool types, fixedport, expected translation and analysis classification.
- **NAT Extraction Coverage:** source, accounted, parsed and normalized-source counts per
  section and scope. One source item can produce multiple canonical objects;
  these counts must not be equated with NAT rule counts.
- **NAT Traffic Coverage:** ordered IPv4 policy-domain coverage. Each row displays
  source ranges, ingress, destination, services and egress; percentage is source
  address coverage *within that domain*, not all applications or Internet traffic.
  Earlier specific translated domains are excluded from broader rows only when
  their other match dimensions fully cover the displayed domain. Denies are not
  excluded; disabled rules do not consume first-match coverage. Partial service,
  destination or unknown matches cannot get a guessed 100%.
- **NAT Diagnostics:** structured configuration findings (see below).
- **NAT Extraction Notes:** syntax errors, unresolved references, unsupported features,
  version assumptions and target-generation restrictions.

Absent source keys are not necessarily false or disabled. They may use a
documented baseline default or be unknown. `fixed_source_port` represents strict
port retention; it is not conflated with central NAT's best-effort `port_preserve`.

Coverage is intentionally limited to NAT sections and policy-NAT linkage. The
general workbook Summary does not label the entire configuration `COMPLETE`
merely because a workbook was generated. Unknown API counts remain unknown;
positive unclassified source counts make extraction partial.

## Static analysis and diagnostics

The analyzer consumes parsed FortiGate models and the extractor's scoped reference
graph, never a second CLI parser. Inclusive interval arithmetic resolves IPv4
networks/ranges/nested groups without enumerating hosts. Source file order, not
numeric policy ID, drives first-match analysis. Incomplete/multiple scopes,
negation, dynamic addresses, schedules, unknown topology, pool selection and
central-policy NAT composition remain UNKNOWN/REVIEW_REQUIRED.

| Diagnostic | Meaning |
|---|---|
| NAT-001 | Overlapping VIP ingress, external IPv4, protocol and port intervals; differing simple mappings fail, complex/range mappings require review. Includes unreferenced VIPs. |
| NAT-002 | Enabled private-to-Internet policy domain without SNAT; verify upstream NAT before remediation. |
| NAT-003 | Only disabled NAT policies cover the displayed network domain. |
| NAT-004 | VIP uses extintf any; actual exposure also depends on filters and policy. |
| NAT-005 / NAT-006 | Unused / disabled-only pool references. Unused resources may still affect ARP/local addresses. |
| NAT-007 | VIP has no enabled policy reference. |
| NAT-008 | Private-to-IPsec no-NAT policy intent. PASS is not tunnel/selector validation. |
| NAT-009 | Specific-before-general ordering, or possible overlapping-policy shadowing. |
| NAT-010 | One-to-one source/pool cardinality; mismatch is a capacity warning, not invalid syntax. |
| NAT-011 | Fixed-port source allocation does not span the referencing policy's source domain. |
| NAT-012 | Enabled VIP references do not match ingress/source filters or post-DNAT service. |
| NAT-REVIEW | Unknown, partial or unmatched traffic domain needing operator review. |

`effective` is not a conflict-free or capacity certification. Counts and diagnostic
results are computed independently; an enabled mapping can still participate in
a VIP conflict. Target generation remains guarded. No source file is rewritten.

### Supplied focus fixture (September 2026)

The supplied `fortigate_nat_focus_test_FortiOS74.conf` differs from the original
example expectations. The analyzer must not force its results to 9 effective:

- It has 12 configured rules (6 SNAT, 6 DNAT), with 6 effective, 5 not effective
  (2 disabled, 1 unreferenced VIP, 2 service-mismatched VIPs), and 1 unknown.
- The two service-mismatched VIPs translate to TCP/443 but their policies specify
  TCP/8443 and TCP/10443. Policy service matching is post-DNAT.
- The voice policy spans a /24, but its fixed-port source allocation covers only
  10 addresses. Full deterministic coverage requires review.
- Traffic: 4 PASS, 2 WARN, 1 FAIL. Diagnostics: 3 PASS, 7 WARN, 4 FAIL (including
  the additional allocation and service checks). Pool/VIP usage counts still
  match the requested 3 active pools, 1 disabled-only pool, 1 unused pool, 5 active
  VIP references and 1 unreferenced VIP.

The separate repository-owned synthetic fixture exercises the original ten
scenarios with internally aligned service/source ranges: 12 configured/9 effective,
5 PASS/1 WARN/1 FAIL coverage, and 3 PASS/5 WARN/2 FAIL diagnostics. Test inputs
are distinct; customer files are not copied into the repository.

## Migration safety boundary

Extended FortiGate NAT rules currently have `migration_eligible=False`. All
registered target generators, and the relevant direct generators, reject them.
This applies even when source extraction is normalized: legacy target generators
have not been validated for the extended NAT fields, ordering, interfaces and
allocation semantics. Excel extraction remains available for review.

Do not remove this guard or flip the flag to obtain a configuration file. Enabling
a target requires semantic generator tests for the supported NAT subset, explicit
handling of disabled/review-required rules, and target capability validation.

## Verification

Run the production-path regressions:

```powershell
python -m pytest tests/test_fortigate_nat_analysis.py tests/test_fortigate_nat_extraction.py tests/test_parser.py tests/test_excel_exporter.py -q
```

To include the supplied local focus fixture without committing it, set
`FWMIGRATE_NAT_TEST_CONFIG` to its absolute path before running the tests. The
opt-in regression checks its actual discrepancies, not forced reference totals.

Tests use synthetic inputs and mocked APIs, never real firewall devices. They
verify actual Excel cells and the upload endpoint, not only isolated helper
functions. The full suite also requires the repository's missing `examples/`
fixtures; missing-fixture failures are not a passing migration matrix.

For an operational configuration, compare every source NAT object and reference
against the inventory and inspect all blocking diagnostics. Passing these
regressions does not certify arbitrary customer configurations.

## Vendor references

- [FortiOS 7.4.8 central SNAT CLI](https://docs.fortinet.com/document/fortigate/7.4.8/cli-reference/135632652/config-firewall-central-snat-map)
- [FortiOS 7.4 central NAT mode](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/421028/central-snat)
- [FortiOS VIP CLI](https://docs.fortinet.com/document/fortigate/7.4.10/cli-reference/939799654/config-firewall-vip)
- [FortiOS dynamic SNAT and pool types](https://docs2.fortinet.com/document/fortigate/7.4.8/administration-guide/29961/dynamic-snat)
- [FortiOS predefined services](https://docs.fortinet.com/document/fortigate/7.0.15/administration-guide/713430/services)
- [Fortinet: post-DNAT policy service matching](https://community.fortinet.com/fortigate-3/troubleshooting-tip-vip-configured-for-allowing-a-specific-service-is-getting-denied-by-forward-check-policy-0-177139)
- [Fortinet fixed-port source allocation](https://docs.fortinet.com/document/fortigate/7.4.6/fortinet-carrier-grade-nat-field-reference-architecture-guide/223024/kernel-based-nat-pools)
