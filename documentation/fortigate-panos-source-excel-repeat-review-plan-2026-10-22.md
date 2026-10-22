# Repeated FortiGate / PAN-OS source and Excel review

- Requested sequence: push the reviewed work to `main`, repeat the same source/frontend/Excel checks, document a fix plan, then execute it.
- Initial delivery: `a443cf3b82f7c06f9ca427d7721cd2556c44f773` pushed to `origin/main`. Local and remote hashes matched and the working tree was clean immediately after delivery.
- Inputs remain the exact files from the preceding review. Customer files and generated workbooks stay outside version control.
  - `C:\Users\ziyu.cha-c\Downloads\Config File\FortiGate Example.conf`, SHA-256 `8ab528b1f9627c96f9321cade26ef3c25c79d9a1e1169561fbfb6893d1557881`.
  - `C:\Users\ziyu.cha-c\Downloads\Prasarana - help hongye\PA1410_secondary_08102026.xml`, SHA-256 `82efe564863f07678aefa97c5c001b525167e6508cdc29f6cbb4b13e21db46ec`.
- Current source-report scope: extraction, native models, derived views, frontend report/Details, actual FAST/FULL downloads, source field/order reconciliation, credential scanning, layout and stale export/error handling. A support boundary is not automatically a new bug.
- Confirmed additional finding R1: GitHub Dependabot alert 6 is critical. `requirements/constraints-python312.txt:18` pins `certifi==2026.7.22`, within the affected range for GHSA-6q48-6c7w-9gw2. This concerns trusted CA roots used by outbound HTTPS clients, not a demonstrated offline workbook data mismatch.
- Authority: [maintainer advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2) and [repository alert](https://github.com/chaziyu/firewall-migration-tool/security/dependabot/6). The advisory body names 2026.10.18; GitHub's structured vulnerability record requires 2026.10.19. Use the latter. The [PyPI release metadata](https://pypi.org/pypi/certifi/2026.10.19/json) confirms that release exists and supports Python >=3.7.
- The [reviewed GitHub advisory](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) clarifies that 2026.10.19 retains unaffected emSign roots. Verify absence of the compromised `emSign ECC Root CA - G3` root, not absence of every root whose name contains emSign. Its certificate SHA-256 is `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`, independently found in the old wheel and absent from the patched wheel.

## Phase 1: Repeat the pushed reporting path

- Objective: verify the delivered commit against both requested files and identify reproducible remaining defects.
- Files involved, read-only unless a concrete regression is found:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\browser\source_report.py`, `run()`, `review()`, `workbook_check()` and `stale_exports()`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\fortigate\source_report.py`, `FortiGateSourceReporter`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\source_report.py`, `PaloAltoSourceReporter`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\frontend\src\features\report\SourceReport.tsx`, report counts, validation navigation and Details.
- Existing logic: retain the eleven reviewed fixes. No additional reporting change is justified merely by repeating the check.
- New code: none unless a new failing case establishes a defect. Reuse the existing optional browser helper and local field/credential checks.
- Dependencies: successful initial push; existing Python/frontend dependencies; a fresh local Flask instance serving the built frontend.
- Validation: full backend suite; all frontend tests, lint and build; both file uploads and all report tabs; fourteen remaining PAN-OS finding-owner links; mobile layout; four actual downloads; eight stale completion cases; export error/retry; source/model/preview/workbook counts and values; credential/cell safety; comparison against the previously accepted workbooks.
- Do not change customer configuration to remove the two missing tunnel-interface findings or infer the twelve network address-object uses. Do not install support for unsupported vendor semantics.
- Risks: preview and export timings depend on concurrent suite load. Chromium blocks port 5060; use the known browser-compatible 5057 local port. The first browser attempt on 5060 failed before application access and is not a report defect.
- Progress: complete. Full backend: 2,990 passed, one skipped, 16 subtests passed in 377.56 seconds. Frontend: 248 passed; lint and production build passed. Compileall, Ruff and whitespace checks passed. Both actual-file browser flows passed with no JavaScript errors, including all fourteen PAN-OS owner links, mobile Details, four downloads, error/retry and eight stale completion cases.
- Value/layout reconciliation: 2,111,317 cells across 182 sheets matched the previously accepted workbooks, excluding only the Summary generation timestamp. Sheet order, column widths/visibility, views/freeze panes, filters, merges, hyperlinks and saved row heights/hidden/outline state matched.
- Source checks repeated: 18,964 FortiGate policy fields per workbook; 3,190 PAN-OS security/NAT fields per workbook; all rule order; 56,792 XML/model/preview address checks; 3,464 NAT checks. No mismatches. All four XLSX files reopened with no formula/error cells or oversized cell values. All 543 FortiGate and 22 PAN-OS long sensitive source-value occurrences remained absent from preview/workbook XML.
- Remaining source findings: two unresolved PAN-OS tunnel-interface references and twelve named network-address review warnings. No source repair or new reporting change was justified. Preserved source-only/partial coverage and all 13,229 / 8,096 source records.
- Timings under concurrent tests: FortiGate load 10.581 seconds; FAST/FULL download/reopen 12.939/43.579 seconds. PAN-OS load 35.406 seconds; FAST/FULL 38.941/84.201 seconds. Preview JSON serialization 20,574,316 / 15,351,203 bytes. These are observations, not isolated benchmarks.
- Evidence: `C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\repeat-main`, including `browser-results.json`, `audit-results.json`, `baseline-comparison.json`, screenshots and four downloaded workbooks. Values and saved layout were unchanged, so the preceding visual renders remain applicable.

## Phase 2: Replace the vulnerable constrained CA bundle

- Objective: fix R1 with the smallest dependency change.
- Prerequisite: verify advisory identity, affected range, patched release and current constraint. Those checks completed before this plan was written.
- File to modify: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\requirements\constraints-python312.txt`.
- Exact section: the `certifi==2026.7.22` requirement at line 18. Replace it with `certifi==2026.10.19`.
- Existing logic to change: constrained release/deployment installations currently select a CA bundle containing the affected trust roots.
- New logic/files/functions: no production code, source schema, API, database, package or function is required. Record the security refresh date/advisory beside the constraint if useful for provenance.
- Read-only callers/dependencies:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\.github\workflows\ci.yml`, `release-dependencies` install/test job.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\.github\workflows\snyk-security.yml`, constrained install.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\.github\workflows\osv-scanner.yml`, constraints scanning.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\pyproject.toml`, existing dependency ranges and `collection` / `deployment` extras.
- Do not bulk-refresh unrelated pins, disable TLS verification, add custom CA bypasses, alter source models or touch live devices. Leave the running workspace environment unchanged while its full-suite test is active.
- Constraints/risks: removing compromised CA trust can reject endpoints chaining to those roots. Preserve verification and report certificate failures normally. Do not assume patching a constraints file updates already-installed environments.
- Once the normal workspace full suite and temporary browser server have finished, update only that workspace's installed certifi from the verified patched wheel too. Do not bulk-update its dependencies. Run the focused TLS checks against that runtime after the change.
- Validation: create a new temporary Python 3.12 virtual environment, as the constraint file requires. Install `.[dev,collection,deployment]` using the updated constraint; run `pip check`, confirm the exact certifi version, parse/load its CA bundle, inspect removal of the compromised G3 root, run outbound public HTTPS smoke with normal verification, and run source/web/collection/deployment smoke tests. Exercise the repository's package build path where locally supported. New application regression tests are unnecessary for a one-line dependency pin.
- Progress: pin updated after this plan was recorded. The normal workspace runtime was updated to the same verified 2026.10.19 wheel after full tests/server shutdown. Its `pip check` passed; 120 focused TLS/deployment tests passed in 13.90 seconds. The compromised G3 certificate is absent and an SSL context loads successfully.
- Clean dependency install passed on Python 3.12.10: `uv pip install --python C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\repeat-main-release312\Scripts\python.exe --index-url https://pypi.org/simple --constraint requirements/constraints-python312.txt -e ".[dev,collection,deployment]"`. All 47 packages installed; `python -m pip check` reported no broken requirements. Downloads were slow; aborted installer attempts were replaced by this successful isolated install without changing application dependencies.
- Isolated runtime smoke passed: certifi 2026.10.19; 120 roots; the exact compromised G3 fingerprint was the only removed root relative to 2026.7.22; all other fingerprints unchanged. SSL context creation, verified HTTPS to public PyPI (HTTP 200), Flask import and `/api/vendors` (HTTP 200), and installed `fwmigrate --help` all passed. The patched wheel SHA-256 matched PyPI: `42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b`.
- Certificate inspection emitted a cryptography deprecation warning for an existing nonpositive serial in both bundles. It did not prevent SSL context loading or HTTPS verification. No trust bypass was introduced.
- Constrained Python 3.12 tests passed: `python -m pytest -q tests/test_collection_tls.py tests/deployment tests/test_web_source_reporting.py tests/test_web_panos_report_fidelity.py tests/vendors/fortigate/test_source_reporting.py tests/vendors/palo_alto/test_source_reporting.py tests/vendors/fortigate/test_excel_report.py tests/vendors/palo_alto/test_excel_report.py`: 320 passed and two subtests passed in 113.97 seconds. Phase 2 is complete.
- Package build: `uv build --wheel --out-dir C:\Users\ziyu.cha-c\AppData\Local\Temp\fwm-excel-review-20261022\repeat-release-build` succeeded. This is build evidence, not certification of a standalone wheel-hosted frontend or a Windows Gunicorn deployment.

## Phase 3: Verify and deliver the follow-up

- Objective: finish the repeated review and leave `main` synchronized with the remote.
- Dependencies: Phases 1-2 validated. Keep their evidence separate: source tests on the normal workspace interpreter, constrained dependency checks on Python 3.12.
- Files involved: this plan/results document and the Phase 2 constraint. Change source files only if Phase 1 demonstrates a new defect and the plan is updated first.
- What to do: record exact command/results, any remaining source findings and limits; inspect the staged diff; commit and push the follow-up to `main`; verify local/remote commit equality and a clean working tree. Inspect the dependency alert's actual state after pushing, without assuming it closes immediately.
- What not to do: no force push, unrelated changes, real source/workbook commits, deployment or live firewall operations. Do not dismiss the alert manually or claim CI passed before its results arrive.
- Compatibility: reporting values, schema and existing FAST/FULL inclusion rules stay unchanged. Only the constrained CA bundle changes.
- Validation: compileall, Ruff, `git diff --check`, staged diff review, package/import smokes, actual alert state and final Git state. Stop temporary local servers after browser verification.
- Progress: local validation complete. Compileall, Ruff and `git diff --check` passed again after the dependency change. The follow-up diff contains only the certifi pin/provenance comment and this review/plan record. Temporary browser servers were stopped. Commit, push and remote/alert checks follow this recorded result.
- Remote evidence for the initial delivery: all seven CI jobs reported success, while the workflow still reported in progress at the last check. OSV run [39801829539](https://github.com/chaziyu/firewall-migration-tool/actions/runs/39801829539) failed for R1 only. That failure is the reason for the Phase 2 change; a new scan must establish its remote result after the follow-up push.
- Limits: native Microsoft Excel was not opened. XLSX files were reopened programmatically, browser downloads inspected, and workbook cell/layout metadata compared. Neither source findings nor offline export success certifies a live firewall configuration. Package build success does not certify a standalone wheel-hosted frontend or Windows Gunicorn deployment. Existing Vite bundle-size warnings remain outside these data-correctness fixes.
