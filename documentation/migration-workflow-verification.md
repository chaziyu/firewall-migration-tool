# Migration workflow verification — 2026-10-14

The implemented story is source upload → sanitized evidence → deterministic draft →
engineer placement/selection → signed approval → artifact generation → matching
preview/download/bundle, with explicit project resume and conservative candidate recovery.
No real firewall was contacted, mutated or committed. The application was served only
on local loopback for verification, not deployed.

## Checks

- Recorded targeted baseline re-run: **391 passed**, 12.60 s.
- Final Python: **1,723 passed, 8 subtests passed**, 79.44 s.
- Frontend: `npm ci` completed; **71 tests passed**; ESLint and TypeScript/Vite production build passed.
- `python -m compileall -q src tests` and `.venv/bin/ruff check src tests` passed.
- Real browser: system Chromium through Playwright, built Vite assets served by Flask.
  `python tests/browser/migration_workflow.py --url http://127.0.0.1:5000`.
  Playwright/Chromium are optional verification dependencies, not application requirements.

## Browser evidence

The walkthrough uses synthetic FortiGate and destination XML fixtures and real local
API handlers. Two HTTP failures are deliberately injected by the browser transport:
one draft request after staging a port, and one build after successful approval.
They exercise error handling without changing backend semantics or contacting a device.

- Uploaded source and explicit destination evidence; keyboard activation of a root exception focused its mapping input; reviewed ownership and parent port.
- Derived VLAN configuration included in the exact approval preview.
- Failed draft retained the previous review, staged port and retry inputs.
- Approval succeeded; failed generation retried with **one** approval request.
- Preview, `.set` and the bundle's `.set` matched SHA-256
  `4ba22d14fda6d4ba409e397264081cd6f5cb1852e1544c1107bf8260f30b7c1e`.
- Downloaded project, reloaded app, imported into new in-memory state: **6 proposals**
  restored and artifact build disabled until new approval.
- Embedded forged approval rejected, existing destination retained.
- **No JavaScript page errors**.

## Acceptance coverage

| Scenario | Evidence |
| --- | --- |
| Supported destination migration and identical command surfaces | Browser walkthrough; web migration/export integration suites |
| Offline/no destination and templates | Real source → draft → approval → renderer integration test; deployment ineligible; template remains unverified |
| Missing parent and many dependents | Scoped root issue test; existing graph/port-group tests; browser parent → VLAN placement |
| Duplicate names across VDOMs | Existing conversion and frontend scoped identity tests; issue identity includes VDOM |
| Unsupported inspection and mixed mapping/manual causes | Web migration design integration test; no security commands, deployment blocked |
| Service/name collisions, reuse, dependent rebuilding, reapproval | Existing deterministic-draft and target-reuse suites; service rename project round trip |
| All reused/no changes | Existing conversion/artifact suites; no artificial command introduced |
| Partial approval/manual coverage/supporting-only export | Existing artifact/export and frontend workflow suites; independent readiness contract |
| Failed/out-of-order draft or context change | Component request harness; real browser injected failure retains edits/read-only review |
| Approval success/build failure | Browser: retry generation, exactly one approval request |
| Explicit project/new-session resume, malformed or forged file | Browser reload/import; project API tests for schema, size, unsupported version/pair, source mismatch, service rename and seeded secrets |
| Partial write/dirty candidate/unknown outcome | Fake-transport deploy → inspect → dirty retry; zero replayed commands |
| Candidate drift/lost or expired session/server restart | Existing deployment/session suites; new inspection creates no session; commit still rejected |
| Ambiguous commit/network interruption after write | Fake-transport tests and structured unknown outcomes; accepted counts preserved only when known |
| Large configuration/pagination/search/focus | 2,000-object browser fixture, 30 rendered proposal rows, search narrows to one and retains focus |

## Local performance observations

Synthetic explicit IPv4 fixture: **2,000 addresses, 116,038 source bytes**.
Backend preview: **342.0 ms**; draft preparation: **744.8 ms**, HTTP 200 with
2,000 configuration rows. Browser load through the draft: **1,179.4 ms**;
search to one matching row: **31.1 ms**. Reruns measured 1,828.2 ms / 33.4 ms and 1,049.5 ms / 17.6 ms. These are local observations,
not a performance threshold or hosted capacity guarantee. Existing frontend tests
also measure 10,000-row grouping and 11,319-row dependency ordering.

## Remaining platform limits

Hardware/licensing and vendor/device equivalence require engineer/device verification.
Application locks are process-local and are not exclusive firewall locks. Keep the
documented one-worker baseline. Lost sessions cannot be reconstructed from client
hashes; inspect and reconcile with the operator before preparing afresh. Commit
uncertainty requires operator verification of jobs/running state. No automatic replay,
discard, rollback or commit was added. Customer topology remains sensitive even after
backend secret redaction; projects are explicit files, not automatic persistent storage.

## 2026-10-18: Five-pair coverage expansion

This increment adds scoped source accounting, optional browser destination review
for ASA/SRX/Check Point, Check Point UID reuse, native FortiGate central SNAT
evidence, restricted fixed-pool NAT, and disjoint reverse-direction source NAT.
ASAv and vSRX were selected as VLAN baselines. The first advanced increment is
Check Point IPv6 host/network objects. See the [support matrix](migration-support-matrix.md)
for exact prerequisites and manual boundaries.

### Executed checks

- Full Python suite: **2,415 passed, 1 skipped, 8 subtests passed**, 234.84 s.
- After the last destination comparison guard changes: **106 focused SRX and Check Point tests passed**, including target proxy ARP rejection.
- Frontend: **148 tests passed**. ESLint and TypeScript/Vite production build passed.
- Python compileall, Ruff and `git diff --check` passed.
- Real browser: headless Microsoft Edge, built frontend and real Flask API on loopback.
  `python tests/browser/migration_pair_destinations.py --url http://127.0.0.1:5058 --chromium "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`

The browser walkthrough passed all three new destination flows at **390 x 844**:
native source upload, explicit destination upload/completeness, platform choices,
review/source coverage, explicit approval, preview, file download and bundle.
Each downloaded command/request file matched the preview bytes, approved SHA-256
and its bundle member. No JavaScript page errors were observed. A long Check Point
blocker name exposed horizontal overflow; wrapping was fixed and the flows rerun.
The temporary test server used a larger request limit for repeated walkthroughs.
No real firewall was accessed or changed.

### Roadmap status

- Phases 1-4: metadata, source accounting, destination review and native NAT evidence implemented.
- Phase 5: restricted fixed-pool NAT and ASAv VLAN subinterfaces implemented. Interface PAT and VIP/DNAT remain gated.
- Phase 6: restricted fixed-pool NAT and tagged-only vSRX trunks implemented. Addressed untagged parents and broader allocation remain gated.
- Phase 7: IPv4 range objects and destination UID handling implemented. Check Point schedules and NAT requests remain gated.
- Phase 8: multiple source NAT rules with provably disjoint direct IPv4 prefixes implemented. General NAT/security associations, no-NAT exceptions and port translations remain gated.
- Phase 9: explicit IPv6 host/network objects implemented for Check Point. IPv6 policies, other advanced families and other pairs remain manual.
- Phase 10: software checks above executed. Live device acceptance and packet-flow/hardware validation remain unverified.

This is a verified bounded expansion, not completion of every feature in the wider
roadmap. Existing pending work remains visible and cannot emit unsupported commands.
