# FortiGate and PAN-OS source report / Excel review

- Input distinction: this original review used `PA1410_primary_09102026.xml`. The follow-up request names `PA1410_secondary_08102026.xml`. Secondary-file acceptance and additional findings F9/F10 are recorded separately in `fortigate-panos-secondary-source-excel-review-2026-10-22.md`. The primary-file counts below must not be reused for the secondary file.

- Reviewed: 22 October 2026, Asia/Kuala_Lumpur.
- Baseline: branch `main`, commit `edd1a371`. Working tree was clean before this review.
- Scope: supplied source files, extraction, browser report, FAST/FULL Excel, and export workflow.
- Baseline result: both files loaded and exported successfully. Checked core data and policy order survived export. Eight report/workflow defects were reproduced below.
- Implementation result: F1–F8 are fixed in the working tree. The six-phase plan was applied after authorization. The findings below retain the original reproductions for traceability; they describe the pre-fix behavior.

## Implemented fixes and final acceptance

- F1/F8, Phase 1: PAN-OS Overview now counts string reference entries. Validation retains native owner identity, routes by owner type, and opens exact owners. Backend and frontend regressions cover same-name scoped/pre/post rules. The supplied XML reports five references, and all five owner links open correctly.
- F2/F4, Phase 2: FortiGate preview retains policy authentication, inspection, logging, additional settings, and the omitted typed sections/children. Missing optional lists remain null; explicit empty lists remain empty. Tests verify nested redaction and that reporting does not mutate source configuration.
- F3, Phase 3: FortiGate Extraction shows all 13,229 source-object records across 393 paths, including DNS/NTP evidence. Counts remain distinct: 3,514 source-only, 180 empty sections, 7,315 typed with additional settings, 2,220 typed, zero model gaps. Original CLI field names, source lines, scope, parents, commands, and unset evidence are retained safely.
- F5/F6, Phase 4: obsolete Excel requests cannot download or update newer export state. Errors appear beside the export control. Browser checks passed all eight success/failure combinations across file, vendor, snapshot, and workspace replacement. Retry and error placement passed at 1440 px and 390 px.
- F7, Phase 5: shared presentation formatting wraps long visible business values and bounds row height at 409 points. Short/scalar cells and technical source evidence remain plain. Both streaming and normal writers retain the existing safety/overflow behavior. Workbook notes explain how to inspect very long values.
- Phase 6: the checked-in optional browser harness is `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\browser\source_report.py`. Synthetic and supplied-file runs passed. Checks include all report tabs, Details, scope filtering, search beyond the first 200 rows, mobile layout, actual FAST/FULL downloads, failure/retry, and stale results. No JavaScript errors occurred.
- All four downloaded XLSX files reopened successfully. Compared 1,702,355 cell values with the baseline: zero differences, excluding generated timestamps and row-two display guidance. Sheet order, filters, column widths/visibility, freeze panes/views, hyperlinks, merged cells, and row outlines were unchanged across 177 worksheets.
- Scanned the final workbook XML against 543 FortiGate and eight PAN-OS sensitive source-value occurrences of at least 12 characters: zero hits. This is supplementary evidence; the security regression tests cover short and synthetic secret values too.
- Read-only renders of FortiGate `Policies!F45:P58` and PAN-OS `Security Policies!F3:O12` show wrapped long values without column spill. Rows remain bounded; very long values may require the formula bar or existing overflow sheets.
- Final browser observations, measured with the full Python suite running concurrently: FortiGate load 12.574 s, search 0.281 s, preview envelope 20,574,316 bytes; PAN-OS load 16.650 s, search 0.179 s, preview envelope 8,091,720 bytes. Added FortiGate source evidence increases response size. These are observations, not isolated server benchmarks or performance guarantees.
- Actual download/reopen verification: FortiGate FAST 1,030,392 bytes / 14.451 s, FULL 4,345,373 bytes / 46.419 s; PAN-OS FAST 368,095 bytes / 18.407 s, FULL 1,711,771 bytes / 37.722 s. Timings include reopening/scanning workbook cells and concurrent test load.
- Final local evidence is under `C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\fixed-supplied`: four workbooks, browser screenshots/results, value-validation results, and workbook renders. Customer files and generated evidence were not added to version control.
- No source model, vendor semantics, endpoint, database, dependency, migration, or deployment changes were needed. Existing passing behavior and support boundaries remain covered by the checks below and the phase plan.
- Final implementation validation: `.venv/Scripts/python.exe -m pytest -q` passed 2,983 tests and 16 subtests, with one skipped test, in 388.45 seconds. Frontend `npm test` passed 247 tests; `npm run lint` and `npm run build` passed. Global compileall, Ruff, and `git diff --check` passed. Vite retains its existing bundle-size warning. Phase-specific commands/results are recorded in the companion plan. The validation section near the end of this review records the earlier pre-fix baseline runs.

## Inputs and reproducibility

- FortiGate: `C:\Users\ziyu.cha-c\Downloads\Config File\FortiGate Example.conf`
  - 2,908,995 bytes.
  - SHA-256: `8ab528b1f9627c96f9321cade26ef3c25c79d9a1e1169561fbfb6893d1557881`.
- PAN-OS: `C:\Users\ziyu.cha-c\Downloads\Prasarana - help hongye\PA1410_primary_09102026.xml`
  - 875,550 bytes.
  - SHA-256: `bc5439efbefa705e49d02ba904bb324e388829dc5088f6a20ac2b275ea81c1ed`.
- Files were treated as source data. No instructions embedded in source content were followed.
- Used Flask `create_app()` test client for real `/api/preview` and `/api/extract/excel` calls. Excel calls used the sanitized evidence returned by preview, matching the frontend transport.
- Built the frontend. Used Chromium against a separate Flask server on `127.0.0.1:5057`.
- Exercised upload, every main report tab, object details, 390 px mobile view, actual downloads, a controlled HTTP 500 export failure, and a delayed export followed by a vendor change.
- Temporary workbooks, screenshots, JSON measurements, and reproduction scripts are under `C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022`. They are local review evidence, not committed fixtures.

## What worked

| Checked inventory | FortiGate | PAN-OS |
| --- | ---: | ---: |
| Interfaces | 83 configured; 122 topology rows including VPN attachments | 8 |
| Addresses | 5,209: 5,204 IPv4 + 5 IPv6 | 4,346 |
| Address groups | 204 | 21 |
| Configured services | 818 | 55 |
| Configured service groups | 25 | 7 |
| Ordinary security policies | 1,724 | 34 |
| Explicit default security rule overrides | Not applicable | 1 |
| Static routes | 204 | 8 |
| Route-based IPsec Phase 1 / Phase 2 | 39 / 173 | No tunnels present |
| Policy-derived NAT rows / explicit NAT rules | 275 derived rows | 4 explicit rules |
| FAST / FULL worksheets | 42 / 60 | 20 / 55 |

- FortiGate's 84 interface `edit` occurrences contain 83 unique names. One interface is edited twice. This is not evidence of a dropped interface.
- PAN-OS's 35 Excel security policy rows comprise 34 ordinary rules and one default-rule override. This is not an extra invented policy.
- FortiGate browser services contain 1,799 derived service rows and 223 derived group rows. Configured counts remain 818 and 25. The separate Excel derived-expansion sheet has 2,022 rows. These counts represent different views and should not be compared as identical populations.
- Independently counted the main FortiGate CLI sections and PAN-OS shared/VSYS XML object containers. A broad `.//service/entry` count also picks up unrelated XML containers; the scoped count is 55 actual service objects.
- Compared explicit FortiGate policy fields against the native model: all checked interfaces, addresses, services, actions, logging, groups, UTM settings, and IPS assignments matched their source commands.
- Compared 11 FortiGate policy fields across all 1,724 rules in each profile: 18,964 comparisons per workbook, zero mismatches. Policy ID order matched the native source order.
- Compared 10 PAN-OS policy fields directly against XML for all 34 ordinary rules in each profile: 340 comparisons per workbook, zero mismatches. Rule names remained in XML order.
- Compared common FAST/FULL sheets from header row 3 onward: 235,787 FortiGate cells and 75,375 PAN-OS cells. PAN-OS had no differences. FortiGate differed only in the expected Unsupported-sheet evidence-location text.
- Actual browser downloads matched the corresponding API-generated workbook values and sheet sets. Only the Summary generation timestamp differed.
- All four API exports returned HTTP 200 and reopened successfully with `openpyxl`. No formula cells, Excel error cells, or cells exceeding 32,767 characters were found. PAN-OS FULL included a Text Overflow sheet.
- Checked 551 long credential-value occurrences identified from the input files, including FortiGate passwords, PSKs, SNMP authentication/privacy passwords, and PAN-OS password hashes. None of those candidates appeared in preview JSON or either profile's workbook XML. This is a bounded candidate scan, not proof against every possible secret format.
- No JavaScript page errors occurred in the two normal browser walkthroughs. Actual downloads completed successfully.
- At 390 px, document width remained 390 px for both reports. Mobile object details used a modal dialog. Wide report tables remained within their own scroll containers.

## F1: PAN-OS overview reports zero unresolved references when five exist — P1

- What happens: upload the supplied XML and inspect Overview. It displays `Unresolved references: 0` alongside five validation errors. References contains five rows. Excel's Unresolved References worksheet also contains five rows.
- Root cause: `build_panos_preview()` puts strings from `analysis.derived.unresolved_references` in `sections.unresolved_references`. `SourceReport()` counts them with `asRows()`, which deliberately discards strings.
- Exact code:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\web_report.py`, `build_panos_preview()`, `sections.unresolved_references`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx:225`, `unresolved` overview metric.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\reportPresentation.ts:11`, `asRows()`; `reportSections()` already supports primitive section rows.
- Smallest fix: count the reference array entries without filtering away primitive rows. Preserve the existing PAN-OS API representation.
- If skipped: the summary falsely tells engineers there are no unresolved references.
- Acceptance: Overview, References, validation context, and Excel agree on the five reported unresolved references. Include object-row and string-row inputs in the regression.

## F2: FortiGate browser omits extracted policy settings and whole report sections — P1

- What happens: policy Details has no logging, comments, user/group matching, or inspection-profile fields. These values exist in the native model and in both Excel profiles.
- Verified affected policies: 1,596 logging settings; 827 comments; 92 group assignments; one user assignment; 810 UTM settings; 349 IPS sensor assignments; 17 web-filter profiles; 940 SSL/SSH profiles.
- Whole examples absent from preview sections: two zones, 23 user groups, two admin profiles, 11 IPS sensors, seven external resources, and the SD-WAN configuration. Excel exposes these families. DNS/NTP and several nested child settings are also available in Excel but have no matching browser view.
- Root cause: `build_web_report()` uses narrow hand-written projections. `_source_rows()` receives allowlists. The policy projection drops many existing `FGPolicy` fields. Neither object Details nor column selection can recover data absent from the response.
- Exact code:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\web_report.py`, `_source_rows()`, `build_web_report()` policy rows, `source_sections`, and final `sections` dictionary.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\model\policy.py`, existing `FGPolicy` fields.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\reportPresentation.ts`, `SECTION_KEYS`, `FORTIGATE_DETAILS`.
- Smallest fix: extend the vendor-owned safe report projection. Add missing fields and sections using existing models. Keep summary columns compact and expose full values through Details. Add sanitized additional settings for useful evidence not represented by named fields.
- Do not serialize raw model dictionaries without the FortiGate redaction rules. Do not import Excel exporters into the source preview.
- If skipped: engineers cannot verify security-relevant source settings in the browser even though the report appears loaded successfully.
- Acceptance: field presence and values agree across model, preview Details, and Excel for the examples above, including nested entries and scopes.

## F3: FortiGate browser provides no extraction coverage or source-only evidence — P1

- What happens: this upload contains 13,229 source-object records. FULL Excel reports 393 source paths, 3,694 records under 349 source-only paths, and 48,707 inventory command/detail rows. Those 3,694 records comprise 3,514 `SOURCE_ONLY` records and 180 explicit `EMPTY_SECTION` records. The browser has no Extraction tab, no source-only count, and no source inventory.
- This does not mean extraction discarded these records. They are preserved for FULL Excel. The defect is that the browser does not disclose or expose the preserved evidence.
- Root cause: `FortiGateSourceReporter.build_preview()` passes only config, derived views, validation, and top-level count. It does not pass `analysis.extracted.source_objects`. `build_web_report()` returns no extraction sections.
- Exact code:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\source_report.py:80`, `FortiGateSourceReporter.build_preview()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\web_report.py:192`, `build_web_report()`.
  - Existing accounting helpers: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\extraction\coverage.py`, `build_typed_source_inventory()`, `build_typed_source_identity_index()`, `find_typed_source_object()`, `extraction_status()`, `supports_path()`.
  - Existing Excel presentation: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\export\excel_rows.py`, `_coverage_rows()`, `_iter_fortigate_source_inventory_rows()`.
- Smallest fix: supply extraction evidence to the vendor report builder. Reuse existing accounting functions and the frontend Extraction group. Report object-record counts separately from Excel's command-expanded row count.
- If skipped: users cannot assess how much source state has only generic preservation. FAST also omits the detailed inventory, making this distinction especially relevant.
- Acceptance: expose all 13,229 object records through bounded browser rendering, show the 3,514 source-only records and 180 empty sections separately, and keep `MODEL_GAP` distinct. Current FULL Excel had no model gaps. Retain parity with its path-level coverage count without labelling empty sections unsupported.

## F4: FortiGate preview changes missing policy lists into explicit empty lists — P2

- What happens: `FGPolicy.srcaddr` is `None` for five supplied rules. Preview sends `source_addresses: []`. Fourteen rules have an absent service list but preview sends an empty array. All 1,724 rules' absent IPv6 address lists are presented as empty arrays.
- Minimal reproduction: parse a policy with only `set name "minimal"`. The native source address field is `None`; preview returns `[]`.
- Root cause: expressions such as `list(item.srcaddr or ())`, `list(item.service or ())`, and their IPv6 equivalents in `build_web_report()` erase the distinction.
- Exact code: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\web_report.py`, policy row projection around lines 378–410. `_source_rows()` already has a local pattern for preserving unreported list fields.
- Smallest fix: preserve `None` for absent/unset optional source lists. Keep an explicitly reported empty collection distinct. Apply the same rule to other optional source lists touched while repairing this projection; derived relationship collections remain derived collections.
- If skipped: Details presents absence as an empty configured value and contradicts the source-state contract.
- Acceptance: missing, explicit empty, populated, and unset cases remain distinct in preview and Details. Source models must remain unchanged by reporting.

## F5: A stale export downloads after the source context changes — P1

- Reproduction: load FortiGate; intercept and hold `/api/extract/excel`; click Export Excel; change source vendor to Palo Alto; release the successful old response.
- Actual: `fortigate-source-report.xlsx` downloads while the selected vendor is `palo_alto` and the old preview is gone.
- Root cause: `exportWorkbook()` captures `analysisRequest.current`, but checks it only when setting success text. It creates the object URL and clicks the download link before checking the request. Its error and `finally` updates are unconditional too.
- Exact code: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\source\SourceConfiguration.tsx`, `exportWorkbook()`, `clearAnalysis()`, `changeVendor()`, and source replacement paths.
- Smallest fix: invalidate export completion on source changes. Guard download, error, success, and busy-state changes against the active export and source identity. Reset the visible export state when its source is cleared. An obsolete request may complete on the server but must not affect the new workspace.
- If skipped: a user can receive a workbook unrelated to the current visible configuration. An old failure can also be shown against a newer source.
- Acceptance: delayed success/failure after file, vendor, snapshot, or workspace change produces no stale download or UI update. Test that an old completion cannot clear a newer export's busy state.

## F6: Export failure is rendered below the current viewport — P2

- Reproduction: load either supplied file, remain in Policies, and return a controlled HTTP 500 with a recognizable safe error message for Excel export.
- Actual: the export button returns to its idle state. The only error banner is after the entire report. At a 1440 × 1000 viewport its top was approximately 1,335 px for FortiGate and 1,356 px for PAN-OS. It was outside the viewport containing the export control.
- Root cause: export errors share the general `error` state and the final page-level `ErrorBanner`. The sticky export area receives success text but no export error.
- Exact code:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\source\SourceConfiguration.tsx`, `exportWorkbook()` and final `ErrorBanner`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`, report header, export controls, and preview status.
- Smallest fix: display an export-specific accessible error beside the export controls. Clear it on retry or source change. Keep analysis errors in their existing source-upload context.
- If skipped: failure can look like an export that silently did nothing.
- Acceptance: the failure message is visible beside the initiating control at desktop and mobile widths, is announced, and does not persist into a different source.

## F7: Excel business-table cells lack wrapping and readable row sizing — P2 usability limitation

- Actual workbook properties: both vendors and both profiles write business data cells with `wrap_text=None` and no explicit data-row height. The worksheet default is 18 points.
- Existing tests intentionally keep ordinary data rows plain for lightweight exports. This finding concerns demonstrated long-value readability, not lost cell data. Preserve lightweight scalar rows when adding targeted formatting.
- Concrete cases: FortiGate FULL `Policies!L50` contains 424 characters and 13 newlines; `Policies!G55` contains 233 characters and 17 newlines. PAN-OS `Security Policies!K9` contains a 474-character destination list.
- A read-only artifact render of PAN-OS `Security Policies!F3:O12` shows long comma-separated lists spilling into adjacent blank columns. That blurs the boundary between addresses and negate/user columns. The FortiGate renderer auto-expanded newline rows, but the saved workbook itself does not supply those heights or wrapping settings.
- Exact code:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\export\excel.py`, `_write_table_sheet()` and `_write_table_sheet_fast()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\export\excel.py`, `_write_table()`. `_BODY_ALIGNMENT` is defined but not assigned to data cells.
- Smallest fix: use wrapped, top-aligned body cells for long/list/detail columns and bounded row heights in both regular and streaming writers. Preserve raw values, existing columns, filters, hidden evidence, and freeze panes.
- If skipped: exported values remain stored, but review requires manual resizing and can be misread. Exact Microsoft Excel layout behavior was not tested.
- Acceptance: verify saved styles/heights, render the concrete ranges, and inspect in native Excel when available. Keep formula protection and Text Overflow preservation intact.

## F8: PAN-OS validation findings cannot open their source objects — P2

- What happens: all five supplied PAN-OS errors have domain `reference`. Validation shows five Details buttons and zero View object buttons, although the owners are four policy findings and one security-profile-group finding.
- Root cause: `PANOSValidationIssue` already carries `object_type`, `source_path`, and `source_identity`. `build_panos_preview()` drops those fields from `sections.validation`. The UI resolves targets only from `domain`, and its map has no `reference` route. Sending every reference finding to Policies would also be wrong for the profile-group finding.
- Exact code:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\web_report.py`, `validation_rows` and `source_row()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\validation\models.py`, `PANOSValidationIssue`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`, `VALIDATION_TARGETS`, `ValidationTable()`, `ValidationReport.navigateToObject()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\reportPresentation.ts`, `matchingSourceRows()`.
- Smallest fix: retain existing owner metadata in preview. Route by owner type before issue domain. Match the exact existing source identity before falling back to legacy scope/name matching.
- If skipped: engineers must manually find owners, and future name-only navigation would risk selecting the wrong same-named rule or scoped object.
- Acceptance: all five findings open the correct owners. Include duplicate names across VSYS and pre/local/post rulebases; ambiguous legacy data must not silently choose one object.

## Validation performed

- Backend batch A: 155 passed in 73.57 seconds.
  - `.venv/Scripts/python.exe -m pytest -q tests/vendors/fortigate/test_source_reporting.py tests/vendors/fortigate/test_source_inventory.py tests/vendors/fortigate/test_coverage_accounting.py tests/vendors/palo_alto/test_source_reporting.py tests/vendors/palo_alto/test_excel_report.py tests/test_excel_style.py tests/test_excel_pipeline_review_regressions.py`
- Backend batch B: 206 passed, eight subtests passed in 77.74 seconds.
  - `.venv/Scripts/python.exe -m pytest -q tests/vendors/fortigate/test_web_report.py tests/vendors/fortigate/test_security.py tests/vendors/palo_alto/test_web_report.py tests/vendors/palo_alto/test_security.py tests/test_web_panos_report_fidelity.py tests/test_web_source_reporting.py tests/vendors/fortigate/test_source_pipeline_correctness.py`
- Frontend: `npm test` passed all 244 tests. `npm run build` passed TypeScript and Vite compilation. Vite reported the existing bundle-size warning.
- Executed the supplied-file HTTP, workbook, field reconciliation, secret-candidate, browser, failure, and delayed-response checks described above.
- Existing passing tests did not cover the eight reproduced findings sufficiently. Passing results do not override these reproductions.

## Boundaries and non-findings

- No migration output, candidate push, live device collection, live device validation, commit, or deployment was performed.
- Native Microsoft Excel opening, recalculation, printing, and repair prompts were not tested. Workbook verification used saved XLSX structure, `openpyxl`, and representative artifact renders.
- This was a focused review, not a complete proof of every vendor command, every extracted field, or every secret alias.
- PAN-OS correctly reports 86 source-only and 58 partial records. Preserving an unsupported feature in inventory/appendix is an intentional support boundary, not by itself a defect.
- FortiGate FULL had no reported model gaps. Source-only sections must remain visible rather than being guessed into typed configuration.
- The one FortiGate error/227 warnings and five PAN-OS errors are tool-reported findings. This review does not independently certify every diagnostic as a real device defect. Built-in objects and source-only domains may need further vendor-specific validation work before changing those diagnostics.
- No unsupported feature should be enabled merely to make the reports look complete. The fix plan is limited to the verified report/workflow defects.
