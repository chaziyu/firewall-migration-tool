# FortiGate and PAN-OS source report / Excel implementation plan

- Planning baseline: `main` at `edd1a371`, reviewed on 22 October 2026.
- Findings: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\documentation\fortigate-panos-source-excel-review-2026-10-22.md`.
- Implementation authorized after review. Preserve unrelated edits and rerun CodeGraph against changed symbols.
- Keep vendor extraction, source models, relationships, and reporting boundaries. No migration changes, new vendor-neutral models, new packages, database changes, or dependencies are required.
- Shared causes: F2/F4 are losses in the FortiGate report projection; F3 needs the same reporter to receive extraction evidence. F5/F6 share export state and its presentation. F1/F8 share the report's count/owner handling but do not require changing vendor semantics.
- Every phase ends with its checks and a progress entry in this plan containing the command, result, and remaining limitation. Do not mark a phase complete on code inspection alone.
- Secondary-file follow-up: the earlier acceptance used `PA1410_primary_09102026.xml`. The current request uses `PA1410_secondary_08102026.xml`. Keep those results separate. Phases 7-9 below address three additional defects reproduced with the secondary file.

## Phase 1: Correct PAN-OS reference counts and owner navigation

- Progress: implemented. Backend report/fidelity tests: 15 passed. Frontend PAN-OS/presentation/validation tests: 28 passed. `npm run build` passed. Supplied-file browser acceptance follows in Phase 6. The frontend test run emitted a Vite HMR port warning; tests passed.

- Objective: fix F1 and F8 while preserving the current unresolved-reference API representation.
- Dependencies: none. Inspect callers of `build_panos_preview()`, `source_row()`, and `matchingSourceRows()` before editing.
- Files to modify:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\web_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\reportPresentation.ts`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\palo_alto\test_web_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\test_web_panos_report_fidelity.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\panosReport.test.mjs`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\reportPresentation.test.mjs`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\validationReport.test.mjs`
- Existing changes:
  - In `SourceReport()` replace `asRows(sectionsData.unresolved_references).length` with a count that retains string entries. Keep unavailable distinct from a known zero.
  - In `build_panos_preview().validation_rows`, include the existing `object_type`, `source_path`, and `source_identity` from `PANOSValidationIssue`.
  - In nested `source_row()`, include the native `source_identity(item)` already imported in this file. Use the same JSON-safe representation for rows and findings.
  - In `ValidationTable()` and `ValidationReport.navigateToObject()`, choose owner type first and issue domain second. Both call sites must use the same routing logic.
  - Extend the existing owner-to-section map for the affected `policy` and `security-profile-group` owners. Preserve the existing routes for other vendors.
  - In `matchingSourceRows()`, prefer exact native source identity when present. Keep the current ID/scope/name path for older rows. Do not fall back to a name after a supplied exact identity fails to match.
- New logic:
  - One small local target-route helper may be added to `SourceReport.tsx` to avoid repeating owner/domain precedence. No routing framework or new component is needed.
  - Return no exact match for conflicting identities. Preserve all ambiguous legacy matches for explicit review rather than selecting the first.
- What not to do:
  - Do not change `PANOSDerivedViews.unresolved_references` from strings, rewrite reference resolution, or suppress the five findings.
  - Do not point every `reference` finding to Policies. One supplied owner is a security profile group.
  - Do not infer a VSYS, rulebase, or owner from a display name.
- Compatibility and risks:
  - Preview metadata is additive. Keep existing keys and string reference lists intact.
  - Source identity includes ownership, path, order, and rulebase context. JSON array equality must be structural, not JavaScript reference equality.
  - Tests and callers with old metadata must keep working. No source model changes are needed.
- Validation:
  - Add a real reporter-to-normalized-preview test with unresolved policy and profile-group references. Render that response through the frontend harness; do not hand-build only the expected UI shape.
  - Assert Overview and References both report five entries for the supplied XML.
  - Assert all five validation findings expose owner links and open the correct source object.
  - Test object and string reference rows, missing reference data, explicit zero, duplicate names across scopes, and same-name pre/local/post rules.
  - Run the listed backend tests and frontend report/validation tests, then `npm run build`.

## Phase 2: Restore FortiGate fields and preserve absent values

- Progress: implemented. Focused FortiGate report/HTTP checks: 29 passed, eight subtests passed. Frontend presentation/workflow checks: 24 passed. The old tests expecting absent IPv4 lists as `[]` were updated to require `None`; populated IPv6 lists remain unchanged. Supplied-file field/count checks follow in Phase 6.

- Objective: fix F2 and F4 using the existing vendor-owned report projection.
- Dependencies: Phase 1 establishes shared identity/count behavior. This phase does not require an API route change.
- Files to modify:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\web_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\reportPresentation.ts`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\fortigate\test_web_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\test_web_source_reporting.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\reportPresentation.test.mjs`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\reportWorkflow.test.mjs`
- Existing changes:
  - Extend policy rows in `build_web_report()` with existing source fields: IPv4 negate flags; service negate; users/groups; logging/comments; UTM and inspection mode; profile type/group; antivirus, IPS, web/DNS/application/SSL profiles; source NAT pool controls and VPN binding where explicitly present.
  - Preserve existing field aliases consumed by the frontend. Expose `explicit_fields` and sanitized additional settings so Details can distinguish explicit values from derived values.
  - Replace `list(optional_field or ())` in the affected source projections with nullable handling. Use the `_source_rows()` convention for unreported lists. Keep actual explicit empty lists as empty.
  - Extend `source_sections` and final `sections` using existing typed data for the omitted families: zones, user groups, admin profiles/permissions, IPS sensors/entries, external resources, service categories, SD-WAN and its children, SSL VPN settings/authentication rules, interface secondary IPs, VIP real servers, and DHCP child settings. DNS/NTP use source records rather than `FGConfig` models; expose those in Phase 3 when extraction evidence becomes available.
  - Verify exact existing field names on the corresponding models and Excel row builders before projecting them. Do not add fields to a source model merely to match a worksheet.
  - Use nested Details for child data where that avoids duplicate lists. Keep owner name, VDOM/global CLI scope, and child identity with every row.
  - Add section names to `SECTION_KEYS` only where an existing category applies. The current Additional sections fallback may display less common families.
  - Extend `FORTIGATE_DETAILS` for policy authentication, logging, inspection, and additional settings. Keep the current default table columns compact.
- New logic:
  - Add a small FortiGate-only safe projection helper in `web_report.py` if needed to retain unrepresented explicit fields consistently.
  - Reuse `sanitize_source_attributes()` / `sanitize_source_value()` from `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\security\extraction.py`.
  - Do not import private Excel formatting helpers into web reporting. Keep projection allowlists explicit and secret-safe.
- What not to do:
  - Do not calculate effective defaults in React, fill missing lists, or treat missing source action/status as an explicit configured value.
  - Do not replace configured service objects with expanded derived counts. Label existing derived views clearly.
  - Do not expose credential values through nested child dictionaries or additional settings.
  - Do not implement currently unsupported FortiOS domains to improve coverage numbers.
- Compatibility and risks:
  - Keep existing preview keys. New section arrays and optional fields are additive. Nullable optional list values correct the current lossy representation.
  - Preserve original source/derived values and ordering. Reporting must not mutate `FGConfig`.
  - Additional preview data increases response size. Measure it against the current supplied-file baseline rather than adding an arbitrary silent limit.
- Validation:
  - Use synthetic source commands for every newly exposed security-relevant policy field, plus nested sections and credentials that must be redacted.
  - For the supplied file, assert 1,596 logging settings, 827 comments, 92 group assignments, 810 UTM settings, 349 IPS assignments, and 940 SSL/SSH assignments remain visible with exact values.
  - Assert two zones, 23 user groups, two admin profiles, 11 IPS sensors, seven external resources, and the SD-WAN configuration are reachable.
  - Test absent, unset, explicit empty, populated, `no`/disabled, zero, and same-named objects in multiple VDOMs.
  - Compare the native model before/after preview. Search serialized preview for synthetic secrets at every added nesting level.
  - Run the listed backend/frontend tests and a real browser Details check for the supplied file.

## Phase 3: Expose FortiGate extraction coverage and preserved source evidence

- Progress: implemented. Report/coverage/security tests: 33 passed, eight subtests passed. Frontend report checks: 25 passed. Supplied-file native analysis + preview took 2.373 seconds; report JSON was 17,635,022 bytes before the source envelope. Verified all 13,229 records, 393 paths, 3,514 source-only records, 180 empty sections, 7,315 typed records with additional settings, and zero model gaps. DNS/NTP remain source evidence searchable by source path. Browser responsiveness is checked in Phase 6.

- Objective: fix F3 without inventing a second extraction-classification system.
- Dependencies: Phase 2's safe projections. Reuse the existing frontend Extraction group and incremental row loading.
- Files to modify:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\source_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\web_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\reportPresentation.ts`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\fortigate\test_web_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\fortigate\test_coverage_accounting.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\reportWorkflow.test.mjs`
- Existing logic to reuse, without duplicating it:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\extraction\coverage.py`: `build_typed_source_inventory()`, `build_typed_source_identity_index()`, `find_typed_source_object()`, `extraction_status()`, `supports_path()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\extraction\source_inventory.py`: `SourceObjectRecord` and `SourceCommandRecord`.
  - Excel's `_coverage_rows()` and `_iter_fortigate_source_inventory_rows()` in `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\export\excel_rows.py` are parity references, not web dependencies.
  - DNS is currently presented by `_generic_source_rows()` for `system dns`; NTP uses `_ntp_setting_rows()` for `system ntp` and `_ntp_server_rows()` for `system ntp ntpserver` in the same Excel row-builder file. These read explicit source records and do not imply typed DNS/NTP models.
- Existing changes:
  - Pass `analysis.extracted` from `FortiGateSourceReporter.build_preview()` into `build_web_report()` via an optional keyword argument. Preserve direct callers that currently provide config/derived/validation only.
  - If extraction evidence is unavailable for a legacy direct caller, omit coverage/mark it unavailable. Do not fabricate a zero source-only count.
  - Return `sections.extraction_coverage`, `sections.source_inventory`, and explicit summary counts when evidence is available.
  - Finish F2's DNS/NTP visibility through safe source-record projection for `system dns`, `system ntp`, and `system ntp ntpserver`. Add named source-setting sections or make the paths directly searchable in Extraction. Preserve settings, parent server ID, scope, and source path. Do not infer defaults or add source models.
  - Count source objects separately from expanded commands. Use one browser inventory row per `SourceObjectRecord`, with nested sanitized command evidence, field values, unset fields, line range, CLI scope/path, and parent identity.
  - Compute classification once per record using the existing identity index. Keep `EMPTY_SECTION`, `TYPED`, `TYPED_WITH_RAW_EXTRA`, `MODEL_GAP`, and `SOURCE_ONLY` distinct.
  - Add FortiGate detail/column labels for evidence and coverage. Extend the current PAN-OS-only coverage notice with vendor-appropriate FortiGate wording; do not apply PAN-OS status names to FortiGate.
- New logic:
  - Add a vendor-only evidence-building function in `web_report.py`. Build the typed inventory/index once per preview.
  - Keep all returned evidence accessible through current filters and incremental rendering. If a transport bound becomes necessary after measurement, report total/returned/truncation and provide a real retrieval path; never truncate silently.
- What not to do:
  - Do not create a neutral source model or move extraction semantics into React.
  - Do not reuse `_ExcelContext` or create an Excel workbook to build preview data.
  - Do not call source-only records extraction failures or inflate their count with command rows.
  - Do not expose unsanitized raw source or persist customer data in browser storage.
- Compatibility and risks:
  - Additive preview sections. No endpoint, database, dependency, or collection-envelope change.
  - The supplied file has 13,229 object records and 48,707 Excel inventory detail rows. Preserve this distinction in tests and labels.
  - Check payload size, preview time, search responsiveness, and first rendering. Avoid per-record scans of the entire typed inventory.
- Validation:
  - Assert the supplied source has 13,229 accessible records, 393 coverage paths, 3,514 `SOURCE_ONLY` records, 180 `EMPTY_SECTION` records, and zero current model gaps. Excel's path-level total is 3,694 records under 349 source-only paths; explain that this includes the empty sections.
  - Test actual model gaps separately with a controlled fixture. Test global scope, repeated edits, nested parent identity, empty sections, and unset commands.
  - Navigate/search the last source record in the browser, including beyond the initial 200 rows.
  - Compare classification/counts against FULL Excel and inspect safe command evidence. Run coverage/web-report tests and frontend report tests.

## Phase 4: Bind export completion to the current source and show failures at the control

- Progress: implemented. `npm test`: 247 passed. `npm run lint` and `npm run build`: passed. Synthetic browser acceptance passed eight delayed success/failure cases across file, vendor, imported snapshot, and confirmed New workspace replacement. Old completions did not download or clear newer exports' busy state. Both vendors' controlled errors were visible beside the export controls at 1440/390 px; retry cleared the error and downloaded successfully.

- Objective: fix F5 and F6 with local export state changes.
- Dependencies: none on backend phases. Apply after Phase 3 so the final browser test covers the complete report.
- Files to modify:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\source\SourceConfiguration.tsx`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\reportWorkflow.test.mjs`
  - New browser regression: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\browser\source_report.py`.
- Read-only caller dependency: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\App.tsx`, `App.newWorkspace()` and the keyed `SourceConfiguration` mount.
- Existing changes:
  - In `exportWorkbook()`, capture the current source identity and a monotonically increasing export request ID before awaiting the blob.
  - Check both before creating/clicking the download link. Apply the same check in success, catch, and finally paths.
  - Invalidate export request state in `clearAnalysis()`, which already handles vendor/file/source replacement paths. Reset exporting, export success, and export error for the cleared source.
  - `App.newWorkspace()` clears workspace state and remounts `SourceConfiguration` through its key. Add local unmount invalidation in `SourceConfiguration` so an old export cannot download after that component disappears. Do not change unrelated workspace storage behavior.
  - Add dedicated export-error state. Pass it to `SourceReport` and render the existing `ErrorBanner` in the export header/status area. Retain general analysis errors where they are already used.
  - Update all existing `SourceReport` callers/harnesses for the new optional presentation prop. Keep the collect view's export feedback visible in its own action area.
- New logic:
  - Local request guards and export error state only. No new state library, job system, or transport wrapper is needed.
  - Keep the server request allowed to finish; the UI must ignore obsolete results. Cancellation can be deferred unless needed for a demonstrated resource problem.
- What not to do:
  - Do not approve exports again, disable source replacement permanently, or alter the existing safe evidence payload.
  - Do not let an old request clear a newer export's loading state.
  - Do not show raw server exception text beyond the existing safe API error contract.
- Compatibility and risks:
  - Frontend-only behavior. No endpoint or workbook format change.
  - Browser download is a side effect; the guard must run before that side effect, not merely before success text.
  - File/vendor/snapshot changes and component unmount must all invalidate the request.
- Validation:
  - Reproduce a held export followed by vendor/file/workspace changes; release success and failure separately. Assert no stale download, error, success message, or loading-state update.
  - Start a new export while the old request is still pending. Completing the old request must leave the new request busy.
  - Inject safe HTTP 500, then retry successfully. Assert the error is visible beside Export Excel at 1440 px and 390 px and clears on retry/source change.
  - Download both supplied files normally and reopen the actual browser files. Run frontend tests, lint, and build.

## Phase 5: Make Excel business rows readable without changing values

- Progress: implemented with shared `readable_report_row()`. Excel/style/HTTP tests: 269 passed, two subtests passed. Normal and streaming writers preserve values, scalar types, hidden evidence, and short plain rows while wrapping long visible business values. Existing all-unstyled assertions were narrowed to the new business-cell contract. Compileall and Ruff on changed Python files passed. Supplied-file renders/value comparisons follow in Phase 6.

- Objective: fix F7 for both vendors and profiles.
- Dependencies: no schema changes from earlier phases. Keep the exact existing FAST/FULL inclusion rules.
- Files to modify:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\export\excel.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\export\excel.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\fortigate\test_excel_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\palo_alto\test_excel_report.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\test_excel_style.py` only if shared formatting behavior changes.
- Existing changes:
  - Apply wrapped, top-aligned body-cell formatting to the long/list/detail columns in `_write_table_sheet()` and `_write_table_sheet_fast()`.
  - In PAN-OS `_write_table()`, assign the existing `_BODY_ALIGNMENT` to equivalent body cells using `WriteOnlyCell`.
  - Compute a conservative bounded row height from the content and existing column width before appending each streaming row. Reuse formatting constants within each writer. Do not run a post-save full-workbook styling pass.
  - Cover visible policy address/service fields, group members, comments, review reasons, and additional settings. Preserve scalar number types and identity columns.
  - Keep short scalar rows plain. Update affected Excel test assertions, especially `test_full_keeps_styled_headers_and_plain_data_rows()`, only for long/list business cells that now need formatting. Preserve the general unstyled-cell contract in `test_shared_dimensions_preserve_explicit_widths_and_unstyled_source_cells()` and keep source inventory plain unless a demonstrated case requires otherwise.
  - Keep large technical inventory rows bounded. Clearly indicate when manual expansion is needed; stored content must remain complete.
- New code:
  - A small local body-row formatting helper is sufficient. Introduce a shared presentation helper in `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\source_reporting\excel_style.py` only if the two implementations would otherwise duplicate substantive logic.
  - No new workbook sheets, packages, or dependencies are required for this formatting fix.
- What not to do:
  - Do not shorten values, alter separators to change meaning, remove membership entries, or change named columns.
  - Do not replace streaming export, shrink fonts to force content to fit, or expand every row to the Excel maximum.
  - Do not change `excel_safe_value()` or bypass `report_cell_value()` / Text Overflow handling.
- Compatibility and risks:
  - Formatting-only XLSX change. Preserve filters, hyperlinks, freeze panes, hidden columns, outline levels, and evidence sheet names.
  - Streaming writers need row dimensions before row XML is emitted. Confirm the generated XLSX, not just the in-memory objects.
  - Row heights are bounded by Excel limits. Very long evidence may still require formula-bar review or the existing overflow sheet.
  - Measure output size and export time against the reviewed file sizes; avoid a large style object per cell.
- Validation:
  - Reopen both profiles for both vendors. Assert wrap/top alignment and explicit readable heights on representative long/list rows.
  - Render FortiGate `Policies!F45:P58` and PAN-OS `Security Policies!F3:O12`; inspect the report values without column spill.
  - Compare all exported cell values, sheet sets, formulas, filters, and hidden columns against the pre-fix baseline, allowing only intentional formatting differences and timestamps.
  - Recheck illegal-character escaping, formula-leading values, overflow chunks, source redaction, and streaming behavior using existing tests.
  - Inspect native Microsoft Excel if available. Otherwise report that layout-engine verification remains outstanding.

## Phase 6: Lock the supplied-file path and close the review

- Progress: complete. All eight findings passed the final supplied-file browser flow. Final full backend suite: 2,983 passed, one skipped, 16 subtests passed in 388.45 seconds. Frontend: 247 tests passed; lint and production build passed. Global compileall, Ruff, and `git diff --check` passed. No new dependencies were installed.
- Final supplied-file acceptance:
  - Both source uploads, all report tabs, Details, scope filters, search beyond the first 200 records, 390 px layout, and four real FAST/FULL downloads passed with no JavaScript page errors.
  - PAN-OS shows five unresolved references and all five validation owner links work. FortiGate exposes all 13,229 source-object records, 393 coverage paths, and zero model gaps. Source-only/empty/additional-settings counts remain explicit.
  - Eight stale-export success/failure checks passed across file/vendor/snapshot/workspace changes, including keeping a newer request busy. Desktop/mobile HTTP 500 and successful retry checks passed.
  - Reopened four XLSX files and compared 1,702,355 baseline cell values: zero differences, excluding timestamps and added display guidance. Across 177 sheets, sheet order, filters, widths/hidden columns, views/freeze panes, hyperlinks, merges, and outlines were unchanged.
  - No hits from 551 sensitive source-value occurrences in the final workbook XML. Existing security and synthetic redaction regressions also passed.
  - Inspected final FortiGate `Policies!F45:P58` and PAN-OS `Security Policies!F3:O12` read-only renders: long values wrap without column spill. Very long values remain bounded and need formula-bar/overflow inspection as indicated by the worksheet notes.
- Commands executed from `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool`:
  - `.venv/Scripts/python.exe -m pytest -q`
  - `.venv/Scripts/python.exe -m compileall -q src tests`
  - `.venv/Scripts/python.exe -m ruff check src tests`
  - `git diff --check`
  - `.venv/Scripts/python.exe tests/browser/source_report.py --url http://127.0.0.1:5057 --fortigate "C:\Users\ziyu.cha-c\Downloads\Config File\FortiGate Example.conf" --palo-alto "C:\Users\ziyu.cha-c\Downloads\Prasarana - help hongye\PA1410_primary_09102026.xml" --output-dir "C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\fixed-supplied"`, using the installed Chromium executable via `--chromium`.
  - The same browser command without source paths passed against its inline synthetic fixtures, with output in `fixed-synthetic` beside the supplied-file evidence.
  - From `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend`: `npm test`, `npm run lint`, `npm run build`.
- Measurements and local evidence: recorded in the review's implemented-fixes section. FortiGate's complete source inventory increases the preview envelope to 20.57 MB; PAN-OS is 8.09 MB. Browser loads were 12.574/16.650 seconds under concurrent full-suite load. Export/reopen checks were 14.451/46.419 seconds for FortiGate FAST/FULL and 18.407/37.722 seconds for PAN-OS. These are observations, not isolated server benchmarks.
- Limits: native Microsoft Excel opening/recalculation/printing was not tested. The build retains the existing Vite bundle-size warning. Unsupported vendor semantics remain source evidence/manual review. No commit, push, deployment, or live device operation was performed.

- Objective: verify all eight fixes together and retain a repeatable regression path.
- Dependencies: Phases 1–5 complete with their individual checks.
- Files involved:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\browser\source_report.py`, created in Phase 4; extend it rather than creating a second browser harness.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\test_web_source_reporting.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\test_web_panos_report_fidelity.py`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\documentation\fortigate-panos-source-excel-review-2026-10-22.md`
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\documentation\fortigate-panos-source-excel-fix-plan-2026-10-22.md`
- What to do:
  - Give the browser harness optional FortiGate/PAN-OS input paths, matching the style of the existing browser scripts. Use small synthetic fixtures for routine checked-in regressions; supplied customer files remain local.
  - Follow upload → native extraction → normalized preview → browser Details → sanitized-evidence Excel request → actual downloaded XLSX.
  - Reconcile counts and representative exact fields, not just HTTP status or file existence.
  - Verify report scope filtering, search beyond the initial 200 rows, source replacement, accessible errors, 390 px layout, and stale export handling.
  - Record final preview size/time and FAST/FULL export time/size. Reviewed HTTP timings were approximately 2.7 s FortiGate preview, 5.9/23.1 s export; PAN-OS FAST/FULL export 12.2/19.0 s. Browser load was approximately 3.0/10.1 s. These are observations under concurrent local checks, not hard performance requirements.
  - Update each finding with fixed code, regression test, command, and actual result. Keep any unverified native Excel or vendor-semantic boundaries explicit.
- What not to do:
  - Do not add real customer configuration or generated workbooks to fixtures or version control.
  - Do not commit, push, deploy, or contact a live firewall as part of this plan without a later delivery instruction.
  - Do not treat a successful export as complete source interpretation or live-device acceptance.
- Compatibility and new files:
  - Test-only browser helper; no production dependency change. Existing Playwright is optional tooling, as with the current browser scripts.
  - No new API, database, configuration, or semantic source schema is needed.
- Final validation:
  - `.venv/Scripts/python.exe -m compileall -q src tests`
  - Run the affected backend suites listed in the review, including both vendor Excel/report/security tests and shared source-report regressions.
  - Run available Ruff against changed Python files. Run broader required CI checks where local tooling cannot reproduce them.
  - From `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend`, run `npm test`, `npm run lint`, and `npm run build`. Run `npm ci` if dependencies are not already installed consistently with the lockfile.
  - Execute the browser harness against the built frontend and Flask for both supplied inputs.
  - Reopen all four downloaded workbooks; verify the reference count, policy order, exact checked fields, source evidence, redaction, and formatting.
  - Run `git diff --check` and inspect the final diff for unrelated changes. Report checks that could not run; do not convert them into pass claims.

## Phase 7: Complete IPsec finding navigation

- Objective: fix F9. Two secondary-file findings have owner type `ipsec-tunnel` and no source-object link.
- Prerequisite: Phase 1's source identity and owner routing. Preserve the existing uncommitted fixes.
- Existing code to change:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`, `VALIDATION_TARGETS`: add `ipsec-tunnel` mapped to existing `vpn_tunnels`. Reuse `validationTarget()` and `matchingSourceRows()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\browser\source_report.py`, `review()`: include IPsec owners in the navigation checks. Assert every matching owner link is present and opens an exact matching object.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\validationReport.test.mjs`: add a focused routing regression using the existing component harness pattern.
- New code: test coverage only; no new production component or API.
- Do not modify reference resolution, invent a missing tunnel interface, or change the underlying findings.
- Risks: same-named tunnels in different scopes must retain exact source identity. A missing target interface does not prevent navigation to the existing owning tunnel.
- Validation: demonstrate the absent link before editing; run the frontend regression and build; verify both supplied IPsec findings in the browser.
- Progress: implemented after documenting F9. Focused frontend regression passed; full frontend suite passed 248 tests, lint and build. Expanded supplied-file browser navigation passed, including both IPsec owners. Source findings remain unchanged by navigation.

## Phase 8: Report named network addresses as review evidence

- Objective: fix F10. Two interface addresses, nine route destinations, and one route next hop are explicit address-object names. Literal-only validation falsely calls all twelve malformed.
- Authority: selected PAN-OS reference plus official [Tunnel interface help](https://docs.paloaltonetworks.com/ngfw/help/11-1/network/network-interfaces-tunnel) and [Static route help](https://origin-docs.paloaltonetworks.com/ngfw/help/10-2/network/network-virtual-routers/static-routes). Both allow IP Netmask address objects.
- Prerequisites: trace `resolve_references()` -> `build_derived_views()` -> `validate_panos_config()` -> native preview and Excel. `derived.static_routes` retains the native route objects and source identities.
- Existing code to change:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\relationships\references.py`, `resolve_references()`: recognize exact named address candidates for IPv4 interface entries and route `destination` / `nexthop_ip_address`. Reuse `ReferenceIndex` and `_scope_device()`.
  - Add one local relationship helper. Emit explicit `SOURCE_ONLY` / `AMBIGUOUS` review evidence. Same-device candidate existence is not proof of effective VSYS/template visibility, compatible address type, address family, or next-hop prefix. Do not mark these references `RESOLVED` or choose a candidate.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\validation\validator.py`, `validate_panos_config()`: consume those relationship records by exact owner identity, field, and source token. Emit a named-address review warning. Avoid also reporting the token as a malformed IP literal. Keep literal validation for values without recognized reference evidence.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`, `VALIDATION_TARGETS`: map native `static-route` owners to existing `routes` so the new review warnings keep their source-object links.
- New tests:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\palo_alto\test_network_address_references.py`: native XML through model, relationships, validation, preview and both workbook profiles. Cover exact source preservation, shared/same-device candidates, missing names, other devices, duplicate names, unsupported address types, invalid literals, and unchanged source models.
  - Extend the frontend and browser owner-navigation regressions from Phase 7 for native static-route owners.
- Do not substitute object values into source fields, infer a VSYS, implement effective network routing, change migration mappings, or suppress review requirements. No parser, source schema, API, database, or dependency change is needed.
- Compatibility: report diagnostics intentionally change from twelve false malformed errors to explicit review warnings. Business-table values, order, ownership, source evidence and sheet sets must remain intact. Validation/review text and counts may change in both workbook profiles.
- Risks: address-object existence alone does not prove valid network use. Keep unresolved/missing values erroneous and ambiguous or unverified object use visible. Conversion must still fail closed on unsupported raw named network values.
- Validation: first reproduce the false errors with a small synthetic configuration. Add the relationship/report regressions, then run affected source and PAN-OS conversion tests. Rerun both supplied files through the built frontend, actual FAST/FULL downloads, exact source field comparisons, secret scans, and workbook renders. Compare unaffected workbook cells with the baseline; explain all intentional diagnostic changes.
- Progress: implemented after documenting F10. Six new backend cases cover model/relationships/validation/preview and both Excel profiles. Full backend suite passed 2,989 tests and 16 subtests with one skipped in 430.84 seconds. Expanded browser acceptance passed. Business cell comparison found zero changes; only expected diagnostic text/counts changed. Route review warnings use the existing `route` owner family so Excel's review index retains their reasons. Full effective address-object resolution remains outside this fix.

## Phase 9: Recognize documented predefined reference names

- Objective: fix F11, confirmed while checking the remaining secondary-file diagnostics. Two EDL references and nineteen vulnerability-profile references are documented predefined tokens, not missing custom objects.
- Prerequisites: Phase 8. Preserve `_resolve()` explicit typed/source-only candidate precedence and ambiguity handling.
- Authority: official [EDL token list and version support](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008V15CAE) and [predefined vulnerability profiles](https://docs.paloaltonetworks.com/ngfw/help/10-2/objects/objects-security-profiles-vulnerability-protection). Bulletproof/Tor tokens require PAN-OS 9.0 or later; feed availability also depends on content/licensing. Recognizing a token does not establish those runtime prerequisites.
- Existing file: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\relationships\references.py`.
  - Extend `_PREDEFINED_IP_EDLS` with the two exact documented `panw-bulletproof-ip-list` and `panw-torexit-ip-list` tokens.
  - Extend `_resolve()` after explicit candidate and source-only candidate checks. Recognize `default` and `strict` only for `vulnerability-profile` references.
  - Use existing `SOURCE_ONLY` evidence with a reason that states availability/effective content is unverified. Do not return `RESOLVED`, synthesize profile definitions, obtain live feeds, or infer profile actions.
- Tests: extend `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\palo_alto\test_reference_semantics.py` for all four EDLs, both vulnerability tokens, misspellings, explicit overrides and ambiguity. Run all PAN-OS source and directional conversion tests, plus report HTTP/Excel regression suites.
- No source schema, API, database, dependency or migration capability change. Arbitrary missing custom references remain errors. Explicit source objects take precedence over predefined names.
- Validation: reproduce the 21 false unresolved findings; assert the supplied secondary file retains exactly the two missing tunnel-interface references after correction. Recheck actual browser exports, source values/order, credential scanning and changed review counts. Business values must stay intact; diagnostic text, counts, review-row population and Unresolved References legitimately change.
- Progress: implemented after reproducing F11 with a failing regression. All PAN-OS source/parser tests, all five PAN-OS directional conversion suites, and affected HTTP/Excel/style regressions passed: 709 tests in 147.98 seconds. Compileall, Ruff and `git diff --check` passed. The 2,989-test full-suite result belongs to the state before this additional correction. Final supplied-file browser/workbook acceptance is recorded in the secondary review; effective predefined content and runtime availability remain unverified.
