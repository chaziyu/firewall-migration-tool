# Excel export frontend and FAST generator review

Reviewed 2026-10-23 on branch `work`. This records the original review and proposed plan. The implemented outcome, operating limits and final verification are recorded in [Excel Export Reliability and Efficiency](excel-export-improvements-2026-10-23.md).

The successful export paths have good existing coverage. FortiGate FAST and both PAN-OS profiles already use openpyxl write-only workbooks. FAST deliberately omits specified evidence sheets; those omissions are documented behavior, not defects. Shared formula protection, oversized-text preservation, XML character handling, and vendor ownership must survive optimization.

## Findings, ordered by implementation priority

### F01 — Failed streaming exports leave worksheet files and writers open (P2)

Locations: `src/fwmigrate/vendors/fortigate/export/excel.py:130`, `:142`, `:157`; equivalent build/save lifecycles exist in the other vendor exporters. Input boundary: `src/fwmigrate/web_support/request_source.py:58`.

The workbook build and save paths have no exception cleanup. openpyxl write-only worksheets create temporary XML files; normal saving removes them, but an exception before completion does not. Process-exit cleanup is insufficient for the long-lived server.

Reproduced through `/api/extract/excel`: valid FortiGate address configuration with a list-valued `source.source_name` returns 400 after streaming has started, leaving **four worksheet files** present in openpyxl's temporary-file registry. Generator finalization also emits lxml errors. This malformed metadata is accepted by the non-snapshot evidence path. Ordinary frontend filenames are strings; the reproduction exercises the API boundary and error lifecycle.

Plan: validate evidence metadata before analysis; give workbook construction and saving an explicit exception-safe lifecycle. Ensure partially built workbooks remain reachable for cleanup if construction itself raises. Close generators/writers, remove only files owned by that workbook, and close partial archives/output buffers. `Workbook.close()` alone does not provide write-only writer cleanup in the installed openpyxl version. Encapsulate any version-specific cleanup and test it against supported versions; do not clean the process-global registry indiscriminately during concurrent exports.

Acceptance: malformed metadata fails before workbook allocation; injected row-build and save failures leave no owned temporary files or open writers and do not affect another export.

### F02 — Collection failure reasons disappear from Excel (P2)

Location: `src/fwmigrate/source_reporting/collection_excel.py:24`.

`CollectionPart` carries `failure_reason`, and snapshots preserve it. The shared worksheet writer always puts `None` in the part's final column, then writes only top-level warnings. A reason supplied solely on a failed part is lost from both profiles.

Reproduced through the FAST HTTP endpoint with a PARTIAL snapshot containing `CollectionPart('routes', 'FAILED', False, 0, 'TIMEOUT')`: the worksheet contains `routes / FAILED / False / 0`, but **TIMEOUT appears nowhere in the workbook**.

Plan: export the sanitized per-part failure reason in a clearly labelled field while retaining top-level warnings and explicit completeness values. Prefer appending a named column to preserve existing column positions if consumers depend on them.

Acceptance: the same failed-part reason survives snapshot import, HTTP export, and workbook readback in FAST/FULL; missing counts remain missing and explicit zero remains zero.

### F03 — Snapshot/live ingestion inherits the previous vendor's profile (P2)

Locations: `src/frontend/src/features/source/SourceConfiguration.tsx:154`, `:174`, `:209`.

`changeVendor` and workspace restoration select FULL for PAN-OS. Snapshot import and `acceptCollection` change the vendor without updating `excelProfile`. Thus a FortiGate-to-PAN-OS snapshot transition inherits FAST, which omits PAN-OS source inventory, extraction coverage, and appendix sheets. The reverse transition can unexpectedly retain FULL.

Reproduced with the actual component handlers and a lightweight hook harness: restored FortiGate/FAST → import PAN-OS snapshot → report vendor `palo_alto`, profile **fast**. Live collection has the same missing assignment by code inspection.

Plan: centralize source acceptance and vendor-specific profile defaults. Apply the same policy to upload, snapshot, live collection, automatic vendor selection, and restoration; define explicitly when a deliberate user choice should persist.

Acceptance: cover both vendor transition directions and all ingestion paths; the displayed profile must equal the submitted `excel_profile`.

### F04 — Oversized requests become HTTP 500 (P2)

Locations: `src/fwmigrate/web_api/source.py:173`, `:240`; preview has the same broad exception handling. Frontend: `src/frontend/src/features/source/FileUpload.tsx:19`.

Flask raises `RequestEntityTooLarge` while parsing an oversized body. The route's catch-all converts it into a generic export/preview 500. The frontend checks only for empty files and provides no early size feedback.

Reproduced with `MAX_CONTENT_LENGTH=100` and a body above that limit: both `/api/extract/excel` and `/api/preview` return **500**, rather than 413. Existing global-limit coverage tests a different route, so it misses this regression.

Plan: preserve HTTP exceptions and return a safe, consistent JSON 413 response. Add a frontend size check informed by server capabilities, distinguishing raw-source and snapshot-envelope limits. Retain backend enforcement.

Acceptance: oversized multipart and JSON requests return 413, normal invalid source remains 400, and generation never starts for rejected requests.

### F05 — A successful HTML/JSON response is downloaded as XLSX (P2)

Locations: `src/frontend/src/api/client.ts:56`; `src/frontend/src/features/source/SourceConfiguration.tsx:194`.

`postBlob` accepts any HTTP-success body. An authentication page or proxy fallback returning 200 becomes a `.xlsx` download and the UI reports success.

Reproduced by calling the actual helper with HTTP 200 `text/html`: it returns an HTML Blob successfully.

Plan: allow callers to specify expected content types; the Excel caller must reject HTML/JSON and empty bodies with a safe diagnostic. Handle supported XLSX/octet-stream responses deliberately. Avoid requiring the XLSX MIME type for unrelated ZIP/text downloads that share this helper. A ZIP signature alone does not establish a valid workbook.

Acceptance: XLSX succeeds; 200 HTML/JSON and empty responses do not start a download or show workbook-ready status.

### F06 — Source changes ignore exports without cancelling their requests (P2)

Locations: `src/frontend/src/features/source/SourceConfiguration.tsx:74`, `:129`, `:185`; `src/frontend/src/features/source/sourceApi.ts:33`; `src/frontend/src/api/client.ts:56`.

Request counters correctly prevent a stale export from downloading. They do not abort fetch or Blob buffering. Replacing a source also sets `exporting=false`, allowing another expensive request while the previous one continues. The transport has no AbortSignal argument or export cancellation mechanism.

Plan: pass AbortSignal through the download helpers, abort superseded/unmounted requests, provide explicit cancellation, and retain identity checks as race protection. Browser abort does **not** guarantee Flask stops its synchronous generation; independently bound active export work, and introduce cooperative server cancellation only if the measured workload warrants it.

Acceptance: source replacement and unmount abort the old client request; stale completion/error cannot affect the current report; cancellation is distinguished from export failure.

## Memory and speed opportunities

### M01 — Streaming rows retain per-row formatting objects

Location: `src/fwmigrate/source_reporting/excel_style.py:29`, especially `:45`; invoked by both FortiGate and PAN-OS streaming writers.

Every wrapped business row creates a `RowDimension` retained in `sheet.row_dimensions`. The height is capped, but the retained map grows with row count. Write-only cell streaming therefore does not make this formatting path constant-memory.

Isolated 20,000-row experiment, measuring incremental Python allocations before workbook save:

| Case | Retained row dimensions | Peak traced bytes |
| --- | ---: | ---: |
| Short strings | 0 | 7,340 |
| Wrapped strings, current helper | 20,000 | 8,179,373 |
| Wrapped strings, remove dimension after each streaming append | 0 | 14,965 |

The isolated removal experiment preserved **49-point heights on both first and last rows** after workbook readback with installed openpyxl 3.1.5. This validates an approach, not a completed production change. Apply it only after a write-only row is serialized; normal worksheets still need their dimensions until save. Verify supported openpyxl versions and all title/header/outline cases.

Also precompute column letter/width/hidden metadata once per worksheet. Currently every scalar cell performs these lookups even when it cannot require wrapping. Bound height-estimation work once the height cap is reached instead of wrapping the entire remaining text. Preserve full cell text and overflow behavior.

### M02 — Several FAST paths still materialize whole row collections

Locations: `src/fwmigrate/vendors/cisco_ftd/export/excel.py:165`; `src/fwmigrate/vendors/juniper_srx/export/excel.py:391`; PAN-OS `_child_rows` and other list-returning builders in `export/excel_rows.py:146`; FortiGate list-returning builders such as `_unresolved_reference_rows` at `export/excel_rows.py:1576`.

FTD assembles rows for many worksheets simultaneously before writing. Juniper builds native detail rows and Additional Settings before writing. PAN-OS and FortiGate have some per-sheet lists. Write-only workbooks do not eliminate these allocations.

Plan: replace presentation row lists with per-sheet iterator factories, starting with measured large collections. Retain vendor-owned data and ordering. Preserve the initial-row peek used to omit empty sheets. Do not move vendor derivation into shared export infrastructure.

### M03 — Repeated presentation work

FortiGate cells pass through `_excel_safe` and then `report_cell_value`, both applying Excel string safety. Normalize vendor values once and keep formula/XML/overflow protection centralized at the final cell boundary. Secret redaction is a separate requirement and must remain intact.

FortiGate policy order/NAT indexes are built for more than one sheet. Cache only genuinely reused indexes within the request. Its issue-result cache retained 4,103 entries for 4,604 lookups in the baseline experiment, with 501 hits; profile whether retaining misses/empty results is worthwhile.

PAN-OS FULL traverses every row builder twice to obtain a row-count note (`export/excel.py:125`). This is outside FAST, but affects the frontend's PAN-OS default. Replace the counting pass with cheap vendor-owned counts where safe, or put the actual count in the summary after one traversal. Do not trade it for whole-sheet row buffering.

### M04 — Measure the complete request and transfer lifecycle

Locations: `src/fwmigrate/web_api/source.py:191`, `:193`, `:211`; `src/fwmigrate/web_support/request_source.py:37`; `src/fwmigrate/web_support/request_controls.py:102`.

Every export resends sanitized source and redoes sanitization, parsing, derivation, and validation. This is intentional request-owned behavior. The endpoint retains the complete compressed XLSX in BytesIO; the browser waits for the entire Blob. JSON parsing can also retain raw request bytes alongside decoded evidence. The processing semaphore releases at request teardown, before the response body has necessarily finished transferring, so it does not cover all retained download-buffer memory.

Plan: instrument source decode/sanitize, parse, extraction, derived views, validation, row creation/XML serialization, ZIP save, response preparation, and transfer separately. Pass metrics into the analysis path: currently `collect_metrics` constructs endpoint metrics but does not pass them to `analyze_source`. Avoid unnecessary raw JSON caching/copies after validating actual request ownership. Consider a dedicated export concurrency/memory limit, accounting for slow downloads as well as generation.

Do not introduce a process-global parsed-source cache: it changes the existing request-owned lifecycle and retains customer data. Do not assume adding workers is safe; the deployment explicitly requires one Gunicorn worker. If large output buffers dominate measured RSS, evaluate bounded producer/consumer ZIP response streaming, including backpressure, disconnect cleanup, permits, and the loss of JSON error responses after headers are sent. Do not introduce disk spooling without deciding its data-retention implications.

## Measured baseline

Used `scripts/benchmark_fortigate_fast_excel.py` in this environment with openpyxl 3.1.5 and lxml enabled. These are single synthetic runs, not production estimates or percentile measurements.

| Input | Analysis | FAST export | Peak traced export allocation | XLSX size |
| --- | ---: | ---: | ---: | ---: |
| 1,000 addresses / 500 groups / 500 services / 2,000 policies | 0.194 s | 0.397 s | 2.48 MB | 230,022 bytes |
| 5,000 addresses / 2,500 groups / 2,500 services / 10,000 policies | 1.313 s | 1.706 s | 10.47 MB | 1,051,667 bytes |

The smaller run spent approximately 370 ms building the workbook and 20 ms saving ZIP output; Policies accounted for about 201 ms. These measurements favor row construction/serialization work before ZIP compression tuning. cProfile also identifies readability and repeated value conversion as relevant costs. Profiled timings include profiler overhead and should not be compared directly with the table.

The benchmark starts tracemalloc **after analysis** and performs a second export for its memory measurement. It excludes pre-existing analysis/source allocations, process RSS, native allocations, browser memory, and transport buffering. Its synthetic data has no NAT rows and no validation issues in this run; add those workloads before generalizing the results. lxml is available here but is not a declared project dependency; compare both XML backends before deciding whether to require it.

## Proposed delivery sequence

1. **Correctness and lifecycle fixes:** F01–F05, with focused regressions for HTTP status, metadata validation, failure-reason preservation, profile transitions, content-type validation, and failure cleanup. Add source-identity/profile context to completion status so the reported result is clear.
2. **Frontend request lifecycle and first memory reduction:** F06 and M01. Keep existing stale-response protection. Prove readback parity for values, heights, hyperlinks, filters, hidden evidence columns, and long-text continuation. Measure allocation growth with wrapped rows at increasing sizes.
3. **Generator efficiency:** M02–M03, one vendor at a time. Prioritize FTD/Juniper eager materialization and common per-cell work. Keep FAST/FULL omissions unchanged. Use request-local indexes only when reused.
4. **Complete profiling and capacity tuning:** M04; extend the benchmark to all vendors, supported XML backends, validation-heavy configs, NAT, deeply nested groups, many scopes/VDOMs, long comments, unsupported evidence, concurrent exports, and slow/disconnected clients. Measure browser serialization/Blob retention, process peak RSS, temporary storage, and latency. Decide on output streaming or jobs only from those results.

For each change, compare unprofiled warmed repeated runs on the same machine, record median/p95 and peak RSS, and validate the generated workbook. Set numeric performance targets after that baseline; do not use machine-specific elapsed-time limits in correctness tests. Add Excel row/column-limit coverage and an explicit split-or-reject policy before supporting outputs that can exceed workbook limits; no limit-overrun workbook was reproduced in this review.

Preserve explicit-source semantics, absent versus false/zero/empty, scope ownership, row order, unsupported evidence, redaction, formula protection, and reconstructable text overflow. Use synthetic credential sentinels when checking every worksheet XML part. No optimization should infer defaults or mutate the analyzed source model.

## Verification and limits

- Targeted Python Excel/shared-style/HTTP/FortiGate/PAN-OS selection: **307 passed; 2 subtests passed**.
- Additional FTD/Check Point/ASA/Juniper reporting selection: **72 passed**.
- Frontend suite: **255 passed**, run using the repository's Node 24.22.1 baseline after installing locked dependencies. The initial attempt with missing frontend dependencies was not a valid verification run.
- Additional isolated reproductions established F01–F05 and M01. F06 follows the request lifecycle in the current code; server-side cancellation was not exercised.
- No production application changes, full Python-suite claim, live-device checks, or real-browser download-compatibility claim. Immediate object-URL revocation is worth browser coverage but is not classified as a reproduced bug here.

Local benchmark artifacts: `/workspace/review-artifacts/excel-fast-baseline.json`, `excel-fast-baseline-5x.json`, `excel-fast-profile.pstats`, and `excel-fast-profile.json`. Test logs: `/workspace/review-artifacts/excel-review-frontend-tests.log` and `excel-review-other-vendors.log`.
