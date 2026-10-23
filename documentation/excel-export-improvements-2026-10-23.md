# Excel export reliability and efficiency

Implemented against `main` at `e3c9bf9e`, following the [frontend and FAST generator review](excel-export-fast-mode-review-plan-2026-10-23.md).

## Behavior changes

- All six vendor exporters own workbook XML writers and ZIP archives through exception-safe lifecycles. Failed row construction or ZIP writes clean up only that workbook's temporary files. Caller-owned output streams remain caller-owned. Both write-only and normal worksheet save failures are covered.
- Non-snapshot source names are validated before parsing/generation. Oversized source, snapshot, multipart and JSON requests return JSON HTTP 413; malformed request envelopes return 400. The vendor endpoint advertises the source/snapshot upload limits, which the upload controls use to reject oversized replacements without discarding the current file.
- Collection part failure reasons now appear in the existing **Warnings** column of Collection Evidence, preserving column positions and top-level warnings. Explicit zero counts and false completeness values are retained.
- PAN-OS defaults to FULL and other vendors default to FAST across automatic vendor selection, upload, snapshot import, live collection and restoration. Explicit profile choices persist independently per vendor for the current component session.
- Excel downloads require XLSX or octet-stream content and a nonempty body. HTTP 200 HTML/JSON fallbacks cannot become successful `.xlsx` downloads. Unrelated ZIP/text download callers retain their existing contracts.
- The Cancel export button, source replacement and unmount abort the client request. Existing request-identity checks still suppress stale results. Completion status identifies the vendor and profile. Download links are attached for the click and object URLs are revoked after a short delay.
- Excel worksheet row/column limits cause an explicit failure (HTTP 422 for the Excel endpoint), including the shared Text Overflow path. Oversized reports are rejected rather than silently truncated.

## Resource and performance changes

FortiGate/PAN-OS streaming writers release row dimensions immediately after serialization. They reuse per-sheet column metadata and stop estimating row height once Excel's height cap is reached. Wrapped text, saved row heights, hidden evidence, original values and overflow parts remain available.

FTD presentation rows are generators rather than a workbook-wide collection of materialized tuples. Juniper native detail and Additional Settings rows stream one worksheet at a time, with loops restricted to the selected sheet. Several PAN-OS and FortiGate builders also stream their rows. These changes retain vendor-owned models and source order.

FortiGate skips caching empty validation lookups, reuses the policy-order index and avoids applying Excel string safety twice at the final cell boundary. Formula/XML safety remains centralized at that boundary; secret redaction remains separate and intact. PAN-OS indexes interface units by scoped parent instead of repeatedly scanning all units. PAN-OS FULL calls each row builder once; worksheet row counts remain in Summary, and the detail-sheet note now directs readers there.

The Excel endpoint avoids retaining Flask's raw JSON-body cache and constructs the source digest without concatenating complete source byte buffers. The frontend memoizes source/review identity serialization so export-status renders do not repeatedly stringify an unchanged source or destination configuration. Source sanitization/snapshot validation and analysis receive optional timing metrics; FortiGate's existing parse/extract/derive/validate metrics now reach endpoint diagnostics.

`FWMIGRATE_MAX_CONCURRENT_EXPORTS` defaults to **2**, independently of `FWMIGRATE_MAX_CONCURRENT_REQUESTS`. The export permit covers generation and the retained response buffer until the response is consumed or closed. Busy exports return HTTP 429 with `Retry-After: 1`; other API requests remain available. Disconnects, errors and repeated closes release permits safely. The application still requires one Gunicorn worker.

Browser cancellation does not promise to interrupt synchronous Flask generation. Source analysis remains request-owned; no process-global customer-data cache was introduced. Completed output still uses BytesIO on the server and Blob in the browser. Current synthetic measurements support keeping bounded synchronous generation; a background-job system or producer/consumer ZIP transport would add lifecycle and error-handling complexity without a demonstrated need in these cases.

## Measurements

Sequential before/after runs used the same machine, openpyxl 3.1.5 with lxml, one warmup and five measured repetitions for FAST. Wrapped-comment runs used three repetitions. Times below measure export only. Allocations are from a separate export-only tracemalloc pass, excluding the already-built analysis; they are **not total process memory**.

| Case | Median export before → after | Peak traced export allocation before → after |
| --- | ---: | ---: |
| FortiGate, 1,000 addresses / 500 groups / 500 services / 2,000 policies | 0.430 → 0.303 s | 2.80 → 2.22 MB |
| Same FortiGate input, long policy comments | 0.677 → 0.423 s | 3.66 → 2.26 MB |
| PAN-OS FAST, integrated Panorama fixture | 0.0226 → 0.0191 s | 0.65 → 0.66 MB |
| Juniper FAST, 1,000 address objects | 0.412 → 0.407 s | 5.61 → 4.95 MB |

FortiGate's measured FAST improvement is approximately **29% in time and 21% in export allocation** for the basic case; the wrapped case improves approximately **38% in both**. The small ASA/FTD/Check Point fixtures stayed around their baseline times (tens of milliseconds); no speedup is claimed for them. PAN-OS FULL's integrated fixture improved from 0.0865 to 0.0821 s median, with overlapping p95 times; the stronger guarantee is the tested elimination of its second row-building traversal.

Whole-pipeline traced allocation and RSS remain dominated by input analysis on these cases. For example, FortiGate basic process peak RSS was about 118.4 → 117.4 MB. Export-only savings must not be reported as an equivalent whole-process reduction.

The benchmark also exercised 2,000 NAT rows and a validation-heavy FortiGate configuration, all six vendors with the non-lxml backend, and four concurrent slow HTTP downloads. With the default two-export limit, the latter produced four successes and four expected 429 responses across two rounds, with capacity recovered on completion.

Reproduce with `scripts/benchmark_excel_exports.py`. It supports all six vendors, FAST/FULL, caller-provided files, synthetic FortiGate basic/wrapped/NAT/validation workloads, scaled FortiGate/Juniper data, HTTP concurrency and delayed response reads. Each vendor/profile runs in a child process. It reports median/p95, export and pipeline allocations separately, process RSS where available, backend/version, statuses and value-free stage metrics. Set `OPENPYXL_LXML=False` to compare XML backends. Small synthetic fixtures do not establish production capacity, and readback validation is outside generation timing.

## Verification

- Full Python suite, Python 3.12: **3,212 passed, 2 skipped; 16 subtests passed**.
- Frontend: **261 tests passed**; ESLint and TypeScript/Vite production build passed on Node 24.22.1.
- Python compileall, Ruff and diff whitespace checks passed.
- openpyxl **3.1.0** minimum-version and non-lxml lifecycle/style selections: **96 passed each**. Production-version validation used openpyxl 3.1.5.
- Real Chromium acceptance against the built frontend and Flask: actual FortiGate/PAN-OS FAST/FULL downloads and workbook readback, desktop/mobile error/retry handling, **8 stale-export checks**, and **5 added format/cancellation/profile-default checks**, with no page JavaScript errors.
- Workbook value comparison against the baseline passed for **all six vendors, FAST and FULL**. Summary timestamps and the intentional PAN-OS FULL detail note change were excluded; report data values matched.
- Added regressions cover fault injection during build/save, archive/file cleanup, concurrent workbook isolation, bounded streaming dimensions with saved-height readback, collection failure reasons, metadata validation before analysis, oversized requests, slow/closed responses, metrics privacy, Excel limits and one-pass PAN-OS FULL generation.

Local test/benchmark artifacts are under `/workspace/review-artifacts/`; they are not repository fixtures. No live devices were contacted. The full suite covers existing source-preservation, redaction, scope, ordering, reference and overflow behavior.
