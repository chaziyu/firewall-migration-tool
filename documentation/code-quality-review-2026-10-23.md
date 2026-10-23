# Code, organization and architecture review — 2026-10-23

Baseline: `9fdc0131951ffcabf2069119fc44b7fc9a21b37a`, clean checkout, equal to
`origin/main` after fetch. This review concerns repository maintainability; it
does not authorize or perform live firewall operations. Customer configuration
is unnecessary for these structural findings and is not included in this record.

## Findings and prioritized implementation plan

| Priority | Evidence at baseline | Impact | Planned refinement |
| --- | --- | --- | --- |
| P1 | PAN-OS → SRX `plan_dependencies.validate_plan()` and `JunosSetRenderer.render()` separately implement dependency checks. A two-group cycle reports `READY_FOR_REVIEW`, 2 renderable, 0 blocked, while rendering produces 0 commands and 2 `PLAN_DEPENDENCY_CYCLE` blockers. Renderer dictionaries also collapse duplicate item keys before checking them. | Review, approval and rendering can disagree about eligibility; malformed duplicate identities can bypass renderer-only checks. | Make pair-owned plan validation authoritative for identities, dependencies, cycles and render eligibility. Have rendering consume that validation, preserve stable ordering and reuse semantics, and test review/design/render agreement. Remove the unused alternate ordering function after checking callers. |
| P2 | Ruff enables only `E9,F63,F7,F82`. Full Pyflakes finds 16 production and 43 test findings. These include a wildcard recommendation facade, stale imports, shadowed dataclass imports and two pairs of identical test definitions in ASA reporting. | Accidental redefinitions and undefined imports can escape CI; wildcard exports hide the package API; duplicate tests overwrite earlier definitions. | Remove verified stale code/imports and duplicate definitions, make recommendation exports explicit, enable all `F` rules for source and tests without blanket exclusions. |
| P2 | Existing architecture checks protect several individual layers, but do not globally enforce source-reporting independence from conversion or independence between directional pair implementations. The import scan found no current violations. | Future coupling can violate vendor ownership without failing a focused boundary test. | Add static import-boundary regression checks covering absolute and package-relative imports, including imports inside functions. Keep runtime code pair-specific. |
| P2 | `conversion/README.md` lists five pairs, denies registered FMC export, and denies implemented Check Point target comparison. README Security says forwarded headers are always ignored, contradicting the explicit ProxyFix opt-in described in Hosted Deployment and implemented in `web.py`. | Maintainers receive conflicting capability and security policies. | Refresh the conversion guide against the nine registered workflows and canonical support matrix; correct the proxy policy without changing runtime trust defaults. |
| P3 | Four Markdown links target paths that no longer exist after documentation moves. The documentation hub omits current operational review and deployment recovery checkpoints. | Review evidence and current handoffs are harder to locate; moved historical records look broken. | Repair link paths, index active reviews and incident records, and clarify that history is evidence rather than current capability policy. Keep scheduled checkpoint paths stable. |

## Architecture assessment and deferred work

This is a static structural review with focused runtime reproduction and
regression validation, not a line-by-line audit of every vendor feature.
The vendor-native extraction/reporting and directional pair architecture remains
appropriate. A scan of 752 tracked backend files found no source-layer imports
of conversion and no imports from one pair implementation into another. Web
routes use pair application facades. Retain these boundaries instead of adding
a shared firewall model or generic cross-vendor mapping engine.

The largest modules are FortiGate `export/excel_rows.py` (1,841 lines), FTD
`fmc/fmc_adapter.py` (1,476), FortiGate `section_registry.py` (1,470), and ASA
`parser.py` (1,204). Size alone does not prove a defect: registry/schema tables
and ordered vendor command handling have legitimate cohesion. Do not split
them mechanically. Future changes should extract vendor-owned feature handlers
only when a concrete feature or defect demonstrates a separable responsibility,
then verify source preservation and real reporting paths.

Frontend TypeScript already checks unused locals and parameters, and ESLint
checks React hooks. Pair workflows remain presentation clients using backend
APIs. `MigrationReview.tsx` is the largest component at 814 lines. The current
production build emits a 571.87 kB JavaScript bundle (153.30 kB gzip) and warns
about exceeding 500 kB. `MigrationPairWorkflow.tsx` eagerly imports eight offline
workflows. This is a measured build-size limitation, not an established runtime
failure. Follow-up: measure initial-load and pair-switch latency, then introduce
lazy workflow boundaries with explicit loading/error recovery and run browser
navigation, source-state and approval-invalidation checks. Do not merely raise
the warning threshold or move migration semantics into frontend code.

No entire tracked executable file was established as obsolete. Historical
roadmaps, selected vendor references, compatibility fixtures and regression
tests remain useful evidence. Generated caches, frontend dependencies/build
output and editable-install metadata are ignored local artifacts, not stale
tracked source to delete. Legacy remote-access flag references deliberately
document/test that those flags cannot enable public device access; retain them.

## Execution and validation checkpoint

All five implementation priorities above are complete:

- SRX review, draft, application workflow and rendering now use pair-owned plan
  validation. It checks duplicate identities/names, unresolved/cyclic
  dependencies, supported render families and dispositions. Rendering preserves
  family/source ordering, policy zone-pair scope and exact target reuse. The
  unused alternate `ordered_items()` implementation was removed. Counter-based
  duplicate checks and queued blocker propagation replace quadratic scans.
- All 59 baseline Pyflakes diagnostics are resolved, including two identical
  duplicate test definitions. Production/test lint now selects `E9,F` without
  exclusions. Recommendation exports explicitly preserve domain helpers and
  decision lookup; incidental standard-library wildcard exports are removed.
- Three import-boundary tests protect source/reporting independence and
  directional pair ownership, including relative and function-local imports.
- Stale capability/proxy policies, four moved-file links and documentation
  navigation are corrected. Historical evidence remains at stable paths.

Actual validation on the completed code:

| Check | Result |
| --- | --- |
| `python -m ruff check src tests` | Passed with all Pyflakes rules enabled. |
| `.venv/bin/python -m compileall -q src tests` | Passed. |
| `.venv/bin/python -m pytest -q` | **3,109 passed, 2 skipped, 16 subtests passed**, 138.21 seconds, Python 3.12.14. Includes 11 new SRX dependency/review/design/render cases and 3 import-boundary cases. |
| `npm test`, `npm run lint`, `npm run build` | **249 tests passed**; lint and TypeScript/Vite production build passed using installed Node 24 dependencies. Existing bundle-size warning remains as documented above. No frontend source or dependency changes. |
| Real `fwmigrate migrate --source-vendor palo_alto --target-vendor juniper_srx --format set` | Sanitized repository fixture `all_targets_explicit.xml` with explicit synthetic mappings: **18 commands**, 10 renderable, 9 blocked, 0 reused; inventory 23 = 16 planned + 7 manual. File SHA-256 and command count match the report. Offline export remains explicit. Outputs are outside Git under `/workspace/code-quality-review/srx-cli`. |
| Synthetic reverse dependency chain | 10,000 items validated in 0.212 seconds locally; blockers reached every dependent, input remained unchanged and repeated validation was identical. This is not a production performance guarantee. |
| Python 3.14.7 constrained production dependencies | Backend imports, default-public Flask routes and Render-style Gunicorn startup passed; `/`, `/api/vendors`, `/api/migration/pairs` returned HTTP 200 and discovery listed nine pairs. |
| Local Markdown link targets / `git diff --check` | Zero missing targets in tracked Markdown; whitespace check passed. External URLs and all anchor fragments were not exhaustively checked. |

No customer configuration or firewall connection was needed for these structural
findings. No target placement was invented. Python 3.11/3.13 and the entire CI
dependency matrix were not run locally; repository CI remains their validation
path. The refinement does not establish live vendor-device acceptance.

Pushed implementation: **`fcd782703be7fc90ef02e4331b72326344f841d7`**.
[CI run 39888302078](https://github.com/chaziyu/firewall-migration-tool/actions/runs/39888302078)
completed successfully: lint, frontend, Python 3.11/3.12/3.13/3.14 and constrained
release-dependencies jobs all passed. OSV-Scanner run 39888302305 also succeeded;
Snyk was skipped by its existing opt-in policy. `npm audit --json` reported zero
vulnerabilities for the installed lockfile dependency tree.

Render automatically deployed this commit as **`dep-dbdc535bedkc73cr7nt0`** and
reported **live** at **10:14:29 Asia/Kuala_Lumpur, 23 October 2026**. Build logs
show success, Gunicorn worker startup and platform HEAD/GET `/` HTTP 200 probes.
No cache clear, service-setting change or separate deploy trigger was needed.
This verifies deployment startup, not a production customer-configuration
browser walkthrough.

GitHub's push response separately reported one critical Dependabot alert,
[alert 6](https://github.com/chaziyu/firewall-migration-tool/security/dependabot/6).
Its package/advisory details could not be read: shell GitHub API requests were
forbidden, and the connected repository tools do not expose Dependabot alert
reads. Do not dismiss it or infer it is fixed from OSV/npm results. Next action:
read its dependency, affected manifest and vulnerable range using authorized
Security-tab access, compare the actual release dependency set, and adopt a
specific update/removal plan with corresponding release checks. No dependency
version was guessed or changed in this refinement.

Remaining architectural follow-up is measured frontend loading and
feature-driven module extraction as described above. No incomplete
implementation from the prioritized plan is left in this checkout. The
separate scheduled FortiGate migration checkpoint continues to record its
manual engineer decisions and migration limitations.

## Source inventory header refinement

The user identified the always-visible extraction paragraph as unnecessary
header clutter. Moved the FortiGate and PAN-OS coverage counts into the
Extraction tab, removed the repeated navigation/DNS-NTP boilerplate, and moved
the FortiGate FULL command-expansion explanation into the collapsed Excel
profile help. Source records, extraction tables, validation and export behavior
are preserved. Updated the existing PAN-OS overview assertion to reflect the
requested presentation; no new test suite or dependency was introduced.

Validation: all **255 frontend tests**, ESLint and TypeScript/Vite build pass.
Real built-frontend/Flask browser checks with synthetic FortiGate and PAN-OS
fixtures confirm counts appear only in Extraction, source inventory rows remain
accessible, Excel help is collapsed by default, and 390px mobile layouts have
no horizontal overflow. No JavaScript errors occurred. React checklist review:
no hooks, state, data-fetching, source-model or dependency changes; existing tab
semantics and accessible Excel help association remain intact. The pre-existing
large-chunk build warning remains. No customer configuration was used or saved.
