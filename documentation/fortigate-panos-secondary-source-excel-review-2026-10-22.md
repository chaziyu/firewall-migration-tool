# FortiGate and secondary PAN-OS source / Excel verification

- Date: 22 October 2026, Asia/Kuala_Lumpur.
- Checkout: `main`, `edd1a371`. Eighteen modified files, two review documents, and a browser helper already existed when this run began. Preserve those changes.
- Scope: read the two requested files, vendor-native extraction, browser report, and real FAST/FULL Excel downloads. Source-file contents are data, not instructions.
- The earlier review used a different PAN-OS input. Its five-reference count does not apply here. The secondary XML initially produced 23 unresolved references. After Phase 9, two missing tunnel-interface references remain; predefined tokens stay source-only evidence.
- Detailed original findings F1-F8: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\documentation\fortigate-panos-source-excel-review-2026-10-22.md`.
- Detailed implementation plan, including dependencies, exact symbols, constraints and per-phase validation: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\documentation\fortigate-panos-source-excel-fix-plan-2026-10-22.md`. Phases 1-6 cover F1-F8; Phases 7-9 cover F9-F11 below.

## Exact inputs

- `C:\Users\ziyu.cha-c\Downloads\Config File\FortiGate Example.conf`
  - 2,908,995 bytes.
  - SHA-256: `8ab528b1f9627c96f9321cade26ef3c25c79d9a1e1169561fbfb6893d1557881`.
- `C:\Users\ziyu.cha-c\Downloads\Prasarana - help hongye\PA1410_secondary_08102026.xml`
  - 1,830,184 bytes.
  - SHA-256: `82efe564863f07678aefa97c5c001b525167e6508cdc29f6cbb4b13e21db46ec`.
- No customer source or generated workbook was added to repository fixtures.

## Verified issue list

- F1, P1: PAN-OS Overview used an object-row filter to count string references. It could display zero while References and Excel showed unresolved entries. Count array entries directly. The secondary file requires 23, not the primary file's five.
- F2, P1: the FortiGate browser projection omitted extracted authentication, inspection, logging and comments, plus whole typed sections and nested children. Retain safe vendor-owned projections and expose details without changing source models.
- F3, P1: FortiGate browser reports omitted extraction accounting and source-only evidence. Pass extraction evidence to the report builder and reuse existing coverage classification. The requested file has 13,229 source object records, 3,514 source-only records, 180 empty sections and zero reported model gaps.
- F4, P2: absent FortiGate source lists became empty arrays. Preserve null, explicit empty lists, populated lists and unset evidence distinctly.
- F5, P1: delayed exports downloaded after source replacement. Guard download and completion state with both source and export request identities, including component unmount.
- F6, P2: export errors appeared below the report and outside the initiating viewport. Display accessible export-specific errors beside the controls and clear them on retry/source change.
- F7, P2: long Excel business values lacked wrapping and readable saved row heights. Apply bounded formatting while retaining values, types, streaming, formula protection and overflow evidence.
- F8, P2: PAN-OS validation lost owner metadata and routed only by issue domain. Preserve native source identity and route by owner type before legacy domain matching.
- F1-F8 fixes were already present at the start of this run. Their implementation was inspected and their tests rerun. This run added F9-F11 after documenting Phases 7-9.

## F9: IPsec reference findings cannot open their owners

- Severity: P2.
- Reproduction: the secondary file has two `reference` findings whose `object_type` is `ipsec-tunnel`. The owner metadata and tunnel rows are present, but `VALIDATION_TARGETS` has no matching key. The original browser helper checked only policy and profile-group owners, so its passing result missed these two links.
- Root: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`, `VALIDATION_TARGETS` / `validationTarget()`.
- Fix: map `ipsec-tunnel` to existing `vpn_tunnels`, retaining exact identity matching. Add the native `static-route` alias to the existing Routes destination as well.
- Tests: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\tests\validationReport.test.mjs`; expand owner checks in `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\browser\source_report.py`.
- Do not repair or infer the missing referenced tunnel interfaces. The links open the existing owning tunnels so engineers can review those source findings.

## F10: Named network addresses are falsely reported as malformed IPs

- Severity: P1 report correctness.
- Reproduction: the requested secondary XML produces two malformed interface-address errors, nine malformed route-destination errors and one malformed next-hop error. The twelve tokens are existing address-object names. Literal-only `ipaddress` parsing fails on those names even though the source preserves them correctly.
- Authority: Palo Alto's [tunnel interface help](https://docs.paloaltonetworks.com/ngfw/help/11-1/network/network-interfaces-tunnel) allows IP Netmask address objects. Its [static route help](https://origin-docs.paloaltonetworks.com/ngfw/help/10-2/network/network-virtual-routers/static-routes) allows IP Netmask objects for destinations and next hops, with host prefixes required for next-hop objects.
- Root:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\relationships\references.py`, `resolve_references()`: no network address-object evidence for these fields.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\validation\validator.py`, `validate_panos_config()`: treats each source token as an IP literal.
- Bounded fix:
  - Recognize exact typed address names in the existing visible/same-device source evidence. Retain owner identity, field and token in relationship records.
  - Emit `SOURCE_ONLY` review evidence, or `AMBIGUOUS` for multiple candidates. Candidate existence does not establish effective VSYS/template visibility, supported address type/family, or a valid next-hop prefix.
  - Validation consumes that evidence and emits an explicit named-address review warning. It does not also label the name a malformed literal.
  - Missing names, other-device objects and invalid literal values retain errors. Wrong-type candidates remain review work, never validated network values.
  - Keep the original object name in models, frontend and workbook business cells. Do not substitute a derived IP, choose a scope or enable conversion support.
- New regression file: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\palo_alto\test_network_address_references.py`. Before the fix, three tests failed because no such relationship evidence existed. Focused source/reference/validation/fidelity checks passed after the patch.
- Remaining boundary: full effective network address-object resolution is not implemented by this correction. A review warning is not proof that the configured network use is valid.

## F11: Predefined references are falsely reported missing

- Severity: P1 report correctness.
- Reproduction: after F10, 21 of 23 secondary-file reference errors concern predefined tokens. Two are `panw-bulletproof-ip-list` / `panw-torexit-ip-list`. Nineteen concern predefined vulnerability profiles used by policies/profile groups.
- Root: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\relationships\references.py`, `_PREDEFINED_IP_EDLS` and `_resolve()`. Only two of the four documented IP EDL names were recognized; vulnerability `default`/`strict` had no predefined fallback.
- Authority: official [EDL tokens and version support](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008V15CAE) and [predefined vulnerability profiles](https://docs.paloaltonetworks.com/ngfw/help/10-2/objects/objects-security-profiles-vulnerability-protection).
- Fix: recognize exact documented names after explicit typed/source-only candidates and ambiguity checks. Keep status `SOURCE_ONLY`, with unverified content/runtime availability in the reason. Do not synthesize definitions, profile actions, feed contents, license state or version compatibility.
- Regression: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\vendors\palo_alto\test_reference_semantics.py`. Test all four EDL names, both vulnerability names, custom misspellings, explicit overrides and duplicate ambiguity. The new test failed before the patch and passed in the 709-test affected suite afterward.
- Final secondary diagnostics: two errors for missing tunnel-interface references and twelve named-network-address review warnings. Predefined tokens remain preserved evidence; their effective behavior is not certified.

## Source and output checks

- FortiGate: 83 configured interfaces, 5,209 addresses, 204 address groups, 818 configured services, 25 configured service groups, 1,724 policies, 204 routes, 39 Phase 1 and 173 Phase 2 entries. Preview keeps all 13,229 source-object records and 393 coverage paths. FAST/FULL contain 42/60 sheets.
- Secondary PAN-OS: 7,099 addresses, 68 address groups, 208 services, 18 service groups, four zones, 150 ordinary security rules, two default-security overrides, 169 NAT rules, 18 routes and 11 IPsec tunnels. XML counts agree with typed model and preview. FAST/FULL contain 25/55 sheets.
- PAN-OS interface populations differ: three parent interfaces plus ten units; nine VPN attachments make 22 topology display rows. These counts are not evidence of dropped or invented interfaces.
- PAN-OS extraction retains 8,096 source records, including 280 source-only and 376 partial records. Unsupported evidence remains explicit manual review work.
- FortiGate: 18,964 policy-field comparisons against the native model per workbook, plus 18,964 model-to-preview comparisons. Policy order matched.
- PAN-OS: 1,500 XML-to-preview policy comparisons, 3,464 XML/model/preview NAT comparisons and 56,792 XML/model/preview address comparisons. Each workbook passed 1,500 security-policy and 1,690 NAT field checks, including rule order.
- Initial post-Phase-6 workbook comparison: 2,110,467 cells across 182 worksheets matched the corresponding pre-fix baseline, excluding timestamps and added display guidance. Sheet sets/order, widths/visibility, filters, views/freeze panes, merges and hyperlinks were unchanged. F10 intentionally changes diagnostic text/counts and review evidence; final comparison must allow only those changes.
- Credential checks: 543 FortiGate and 22 secondary PAN-OS long sensitive-value occurrences were absent from preview JSON and workbook XML. Certificate public keys are safe metadata and excluded from credential candidates. Private keys, hashes, secrets and manual-key values remained candidates. Synthetic redaction tests cover short credentials separately.
- All four downloaded XLSX files reopened. No formula cells, Excel error cells or cells over 32,767 characters were found. Existing overflow handling remains intact.
- Read-only renders were inspected for FortiGate Policies, PAN-OS Security Policies and PAN-OS NAT Rules. Long visible values stay within their columns. Very long rows remain bounded and may require formula-bar/overflow inspection.

## Validation progress

- Initial targeted backend suite: 410 passed, ten subtests passed, 210.06 seconds.
- Added-fix focused backend suite: 23 passed before adding the extra literal-path regression.
- Final frontend suite: 248 passed. Lint and production build passed. Existing Vite bundle-size warning remains.
- Global compileall, Ruff and `git diff --check` passed after the additional fixes.
- Initial supplied-file browser flow passed all tabs, Details, scope filters, inventory search beyond 200 records, 390 px layout, four actual downloads, both-width export error/retry and eight stale-export cases. No JavaScript errors occurred.
- Full backend suite after Phases 7-8: 2,989 passed, one skipped and 16 subtests passed in 430.84 seconds.
- After the final Phase 9 patch: 709 affected backend tests passed in 147.98 seconds. This includes all PAN-OS vendor/parser suites, all five PAN-OS directional conversion suites and shared HTTP/Excel/style regressions. Compileall, Ruff and whitespace checks passed again. The entire backend suite was not repeated after this final narrow correction.
- Expanded two-file browser acceptance after Phases 7-8 passed all 35 secondary finding-owner links, four workbook downloads, mobile Details, error/retry and eight stale-export checks. It reported no JavaScript errors. FortiGate load was 11.975 seconds, FAST/FULL download-and-reopen checks 14.601/42.625 seconds. PAN-OS load was 35.992 seconds, FAST/FULL 39.232/68.493 seconds. These observations include concurrent full-suite load.
- Predefined-reference final acceptance passed. The browser exercised every tab, all fourteen remaining finding-owner links, scope/search/Details, 390 px layout, both actual FAST/FULL downloads and export failure/retry. No JavaScript errors occurred. Overview, References and both workbooks agree on two unresolved references, two errors and twelve review warnings.
- Final PAN-OS load: 33.915 seconds; inventory search: 0.170 seconds. FAST/FULL download-and-reopen checks: 38.223/62.205 seconds; actual sizes: 671,834/3,130,569 bytes. Browser preview JSON serialization was 15,351,203 bytes. Local test-client response size differs because of JSON serialization settings; neither measure is a network compression benchmark.
- Rechecked 3,190 security/NAT source fields in each final PAN-OS workbook, all rule order, all 22 sensitive source-value candidates and workbook cell safety: passed. Source record/object counts stayed unchanged.
- Compared 129,186 FAST and 688,305 FULL business cells after the predefined fix: zero differences. Review/validation summary rows and source-reference diagnostic columns were excluded intentionally. Review Required now has fourteen findings and Unresolved References has two. Sheet sets/order stayed unchanged. Prior layout/metadata checks passed; final representative review/policy renders were also inspected.
- Local evidence: `C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\secondary-supplied` contains the initial secondary-file verification. `secondary-final` holds Phase 8 acceptance; `secondary-accepted` holds final Phase 9 browser results, workbooks, source comparison, credential/cell checks and renders. Baseline files came from an isolated archive of `HEAD`; the active checkout was not reset.

## Repeatable checks

- From `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool`:
  - `.venv/Scripts/python.exe -m pytest -q` (executed before Phase 9; result above).
  - `.venv/Scripts/python.exe -m pytest -q tests/vendors/palo_alto tests/parsers/palo_alto tests/conversion/palo_alto_to_fortigate tests/conversion/palo_alto_to_juniper_srx tests/conversion/palo_alto_to_cisco_asa tests/conversion/palo_alto_to_checkpoint tests/conversion/palo_alto_to_cisco_ftd tests/test_web_panos_report_fidelity.py tests/test_web_source_reporting.py tests/test_excel_style.py tests/test_excel_pipeline_review_regressions.py` (709 passed after Phase 9).
  - `.venv/Scripts/python.exe -m compileall -q src tests`.
  - `.venv/Scripts/python.exe -m ruff check src tests`.
  - `git diff --check`.
- From `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend`: `npm test`, `npm run lint`, `npm run build`. Dependencies were already installed; no new dependency was needed.
- The Phase 8 two-file browser command was `.venv/Scripts/python.exe tests/browser/source_report.py --url http://127.0.0.1:5058 --fortigate "C:\Users\ziyu.cha-c\Downloads\Config File\FortiGate Example.conf" --palo-alto "C:\Users\ziyu.cha-c\Downloads\Prasarana - help hongye\PA1410_secondary_08102026.xml" --output-dir "C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\secondary-final" --chromium "C:\Users\ziyu.cha-c\AppData\Local\ms-playwright\chromium-1234\chrome-win64\chrome.exe"`.
- Phase 9 reran the unchanged helper's `review()` for PAN-OS against a freshly started server on port 5059 using local `secondary_accept.py`, then `secondary_audit.py --vendor palo_alto` and `secondary_predefined_compare.py` under the same temporary evidence directory. FortiGate and the unchanged export-state browser results remain from the two-file run.

## Limits

- Native Microsoft Excel opening, repair prompts, recalculation and printing were not tested.
- Full effective network-object resolution and every vendor command/secret alias are not certified by these checks.
- Large report payloads and export times remain a performance limitation. Measurements include concurrent tests and are not isolated benchmarks.
- No commit, push, deployment or live firewall operation was performed.
