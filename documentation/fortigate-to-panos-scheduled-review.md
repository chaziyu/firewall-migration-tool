# FortiGate to PAN-OS scheduled migration review

## Input and execution scope

- Run: 23 October 2026, 02:35 Asia/Kuala_Lumpur.
- Repository baseline: `5ff2d250` on remote `main`; checkout fast-forwarded from `edd1a371` before editing.
- Input: user-uploaded `FortiGate Example.conf`, SHA-256 `8ab528b1f9627c96f9321cade26ef3c25c79d9a1e1169561fbfb6893d1557881`.
- Retrieve missing input through upload ID `file_00000000b7d081faae93f23b197187ac`. The raw config and full generated reports stay outside Git in private workspace files. This document contains aggregate evidence only.
- Authorization covers implementing, testing, committing and pushing repository fixes to `origin/main`. It does not authorize live firewall deployment or device commits.
- No prior scheduled-review checkpoint was present. No competing migration/test process was present at startup. Preserve unrelated changes and reconcile remote updates before each push.

## Baseline findings and plan

The real `fwmigrate migrate --input <uploaded-config> --output <private-directory> --format set` path completed. It planned 10,426 items, reported `NEEDS_MAPPING` and 111 unresolved required decisions, and emitted zero commands. No target evidence or engineer mappings were supplied.

1. **Readiness overstatement (correctness):** 1,784 services and five schedules with no target VSYS were incorrectly classified as `CREATE`, command-renderable and satisfied despite producing zero commands. Direct plan tests reproduced the same hole for addresses. Family-specific validation branches bypassed the final VSYS check. Plan: enforce scope independently of value validation; retain device-scoped route and management-profile exceptions; test the renderer and actual parsed CLI path with and without explicit mappings.
2. **SD-WAN omission (coverage):** the uploaded source contains an SD-WAN section with one zone and no members, health checks or services. The recommendation builder reports only those three child families, so the zone has no migration coverage row. Plan: report zones and explicitly configured top-level settings as manual SD-WAN design, preserving VDOM identity and source absence without inventing target semantics.
3. **Required target decisions:** VSYS, virtual-router, interface and zone placement require engineer confirmation. Empty commands without mappings are expected. Do not manufacture placements to obtain a runnable export.
4. **Manual/unsupported source work:** initial coverage has 947 rows: 722 recommendation-only and 225 source-only. These are review requirements, not 947 independent converter bugs. Main groups: 439 local users; 173 IPsec phase2 and 39 phase1 objects; 83 interfaces without executable placement; 61 SSL VPN host-check definitions; 30 wildcard FQDNs; 23 user groups; 19 session helpers; 14 administrators; 13 SSL VPN portals; 11 IPS sensors; 10 each service categories and SSL VPN bookmarks; seven each external resources and VIP groups; two each admin profiles, address6 templates and protocol options; one each SSL VPN settings and per-IP shaper. Target identity/authentication, VPN credentials/selectors, GlobalProtect, decryption/inspection, unsupported object semantics and hardware placement remain engineer work unless a verified subset can be implemented.
5. **Source defects/limits:** validation additionally reports invalid address values/names, incomplete explicit service/schedule values and routes requiring target mapping. Fix source evidence or implement verified semantics; never replace invalid or absent values with permissive defaults.

Semantic references: repository-selected FortiOS `config system sdwan` reference (zones, status, load-balance-mode), PAN-OS 11.1 scope guidance, and existing pair-specific CLI paths. No device validation has occurred.

## Cycle 1 — scope validation

Implemented an independent VSYS check before family-specific value validation. Services, schedules and direct address plans without placement now block with `missing_target_vsys`. Existing device-scoped route and management-profile handling remains intact.

Regression tests cover unmapped and explicitly mapped addresses/services/schedules, report dispositions and counts, command scope, plus parser → derived views → planner → validation → renderer → actual CLI artifacts.

Full uploaded-config rerun: zero commands, zero command-renderable items and zero satisfied items; `NEEDS_MAPPING`, 111 unresolved decisions and 947 coverage rows remain. This corrects the misleading 1,789-item readiness claim without inventing target choices.

Validation:

- Scope regressions: three cases failed before the fix; seven tests passed after it.
- Full Python suite: 2,993 passed, two skipped, 16 subtests passed; one environment failure because the checkout lacked its declared Gunicorn dependency. Installed `gunicorn>=23,<27` into the local virtual environment, then reran the affected migration/API suites and Gunicorn tests: **716 passed**. No dependency file change was necessary.
- `python -m compileall -q src tests`: passed.
- `ruff check src tests`: passed (installed the declared supported Ruff range in the runtime).
- Frontend: `npm ci`, **249 tests**, lint and production build passed. Build retains its existing >500 kB bundle-size warning.
- Real input CLI rerun confirmed corrected counts as recorded above.

Pushed to `origin/main`: **`00e8f429`** (`Require target VSYS before reporting PAN-OS objects as renderable`).

## Cycle 2 — SD-WAN manual-work coverage

Implemented recommendation-only coverage for each SD-WAN zone and for explicit top-level status/load-balance settings or preserved additional settings. These recommendations require manual target design and cannot emit commands or be approved as supported configuration. SD-WAN zones are not guessed to be PAN-OS security zones. Absent status/load-balancing remains absent. Additional raw settings are reported by count, without exposing their values.

Five focused regressions cover zone-only parsed source through the real pipeline and approval draft, enabled/disabled settings without children, VDOM-scoped duplicate zone names, non-mutation, raw-value redaction and empty sections without invented manual work. Four cases reproduced the omissions before the fix. All five pass after it; the related recommendation/deterministic-draft selection totals 38 passing tests.

Real uploaded-config rerun: **948** unplanned rows (723 recommendation-only, 225 source-only), including one `sdwan_zone`. The existing 111 unresolved decisions and zero executable/renderable/satisfied counts remain correct.

Web API checks on the full input: source upload and offline design preparation both returned HTTP 200. Before the SD-WAN fix, draft configuration counts were 7,775 ready proposals, 2,636 unsupported and 917 needing input. These are pre-approval proposals, not evidence of deployment readiness.

Follow-up audit: 32 IPv4 pools are defined, 18 are referenced by policies, and 14 are unreferenced. Standalone IP-pool definitions currently have no coverage row. Next cycle should distinguish pools completely represented by satisfied NAT consumers from unrepresented definitions; do not simply mark every pool unsupported or silently discard unused definitions.

Validation:

- Full Python suite: **2,999 passed, two skipped, 16 subtests passed**.
- Real Chromium walkthroughs against the built frontend/Flask passed in offline and destination-aware modes, including approval, export integrity and a 2,000-object search case; no JavaScript errors.
- The full uploaded-config browser check found a workflow defect: searching manual work for `SD-WAN` returned no results because the coverage reason was generic. Coverage reasons now include their feature family. The updated regression verifies the family survives into the draft issue explanation. After this final wording change, **711 migration/API tests**, compileall and Ruff passed.
- Full uploaded-config browser check after the fix: upload → prepared review in **19.38 seconds**, `SD-WAN` search found the source zone, all five API responses were HTTP 200, and zero JavaScript errors occurred.
- The Playwright-managed browser download was denied by the environment network policy; the preinstalled `/usr/bin/chromium` ran the checks successfully. No network-policy bypass was used.

Pushed to `origin/main`: **`07e41578`** (`Expose omitted SD-WAN settings and zones in migration review`).

## Cycle 3 — unrepresented IPv4 pools and CLI visibility

The full input has 32 IPv4 pool definitions but only 18 are referenced by source policies. All 14 unused definitions previously disappeared from coverage. A smaller source containing one supported address and one unused pool could therefore report a complete, ready export while omitting the pool.

Implemented pool coverage through source-policy identity (VDOM and policy ID) and actual translated-address NAT plans. This includes split service rules and combined SNAT/DNAT. An arbitrary policy reference, interface-address SNAT, missing translation, wrong policy or ambiguous source policy cannot hide an unrepresented pool. Like existing interface coverage, a pool represented in a blocked NAT plan is accounted for by that plan's status and warnings; it is not claimed to be executable. This is more useful than duplicating every blocked NAT rule as a second pool task. Unrepresented definitions remain manual work with an explicit reason; retirement requires an engineer decision.

Eight initial regression cases reproduced the coverage omissions before the fix and pass afterward. Two additional real parsed NAT cases verify active versus disabled pool consumers; a covered pool does not override its NAT rule blockers. The real parsed-source regression also invokes the CLI and verifies that an independent supported address still exports while the omitted pool makes the migration partial. Scope regressions plus the initial pool cases: **15 passed**; final pool file: **10 passed**.

CLI review improvement: print unplanned-source totals, recommendation-only/source-only counts and the exact JSON report path. The previous terminal output showed mapping/validation counts but hid the separate manual-work total. README documents the distinction and standalone-pool limit.

Full uploaded-config rerun: **962** coverage rows (723 recommendation-only, 239 source-only), including exactly **14 IP pools** and the SD-WAN zone. `NEEDS_MAPPING`, 111 unresolved required mappings and zero commands/renderable/satisfied items remain correct. Compileall and Ruff pass. Full Python suite: **3,007 passed, two skipped, 16 subtests passed**. Follow-up after adding terminal summary and extra consumer/approval checks: **721 migration/API tests passed**, plus Ruff and compileall. Final real-input CLI output prints `Unplanned source configuration: 962 (723 recommendation-only, 239 source-only)` and the private report path.

Further reproduced workflow issue: CLI-style migration with explicit interface/zone mappings creates the physical interfaces but no corresponding target zones when the source uses interfaces directly. Security/NAT consumers then block on missing zone references. Web configuration planning already supports these interface-backed zones. Next cycle: reuse that existing pair-specific topology path for CLI exports with explicit confirmed mappings, without manufacturing mappings or enabling device execution.

Pushed to `origin/main`: **`2511142f`** (`Report unrepresented IPv4 pools and CLI manual-work totals`).

## Cycle 4 — CLI interface-backed zones

Reproduced a source with two physical interfaces, one outbound policy and interface-address SNAT: a complete explicit mapping document still produced `PARTIAL` because no zone definitions were planned. Added an opt-in pair-specific pipeline/planner switch so the CLI uses the existing interface-backed zone planning path. It consumes only final confirmed target mappings. Existing web approval behavior and default programmatic pipeline behavior are unchanged. This does not enable broader configuration approval or CLI device operations.

The CLI regression failed before the fix with complete mappings. It now verifies both branches: explicit VSYS/VR/ports/zones produce their correctly scoped zone commands before dependent policy/NAT commands and a ready export; omitted zone mappings produce no zones or rule commands and remain unresolved. Source input is not mutated. Combined selection with pool and pipeline regressions: **31 passed**; Ruff, compileall and diff whitespace checks pass.

Final validation:

- **3,011 Python tests passed, two skipped, 16 subtests passed** on the final implementation.
- Compileall, Ruff and whitespace checks passed.
- Full-input CLI: zero commands, `NEEDS_MAPPING`, 111 unresolved mappings, 962 unplanned items (723 recommendation-only, 239 source-only). The new zone path creates nothing without confirmed mappings.
- Full-input Chromium: prepared review in **19.85 seconds**; searching `IP-pool` showed all **14** source objects in manual work; five API endpoints returned HTTP 200; zero JavaScript errors.
- Earlier frontend validation remains applicable: 249 tests, lint and production build passed; no frontend files were changed in this run.

Pushed to `origin/main`: **`6c1b086c`** (`Plan explicitly mapped interface zones in PAN-OS CLI exports`). Final JSON consistency checks also confirm that no item is marked renderable, satisfied or rendered when this unmapped source emits zero commands.

### Browser/API verification

Story: an operator uploads the FortiGate source, Flask analyzes it and prepares the design, and React shows supported proposals and separate manual work.

| Boundary | Result | Evidence |
| --- | --- | --- |
| UI renders | Passed | Built frontend served by Flask; Chromium loaded migration flow |
| Client to API | Passed | Full source upload and design preparation returned HTTP 200 |
| API to source/planner | Passed | Real input used CLI/API pipelines; scoped regressions cover parsing through rendering |
| Data to response | Passed | Coverage/report consistency and unavailable approval for unsupported work verified in tests |
| Response to UI | Passed | SD-WAN family search found the omitted zone; pool search showed 14 source objects; no page errors |

## Continuation checkpoint

All four implementation cycles are complete and validated. The raw input checksum remains unchanged. No firewall was contacted or committed. Full JSON output and diagnostic logs are private workspace artifacts, not repository files; final migration report is `/workspace/migration-review-private/cycle4/migration_report.json`.

Remaining work is explicit in the report: 111 target mapping decisions and 962 coverage rows, plus validation/render blockers on planned items. The coverage total is not the number of software bugs or all blocked items. In particular, source defects, unsupported matching/inspection, identity/authentication, IPsec/SSL VPN, source-only objects, and hardware/capacity constraints require review. A complete executable migration cannot be produced from this source alone without target choices and verified semantics.

Next scheduled run:

1. Fetch current `origin/main`, read this checkpoint and verify the original upload checksum. Resume only if a code cycle was interrupted after this checkpoint; otherwise start a fresh audit on the latest implementation.
2. Reproduce the full-input CLI and browser review. Do not invent target placements to turn `NEEDS_MAPPING` into `READY`. Use supplied engineer evidence if it becomes available.
3. Prioritize checking the full preserved source-section inventory against migration coverage, including sections outside modeled `FGConfig` families. Then review unsupported matching/NAT/order/dependency cases for small, verified subsets that can be improved safely.
4. Record evidence and a concrete prioritized plan, implement actionable issues, run affected paths and required checks, and push validated fixes to `main`. Preserve manual requirements and source evidence.

Usage quota is not exposed to this runtime; no claim is made that quota was exhausted. This checkpoint supports continuation within the later run's actual execution limits.

## 07:40 run — cycle 5: preserved native source inventory

Resumed on 23 October 2026 in Asia/Kuala_Lumpur from clean `540c28cb`; remote `main` matched, no prior migration/test process was active, and the original upload checksum matched. All earlier implementation cycles were finished, so this run followed the source-inventory audit in the checkpoint.

Evidence: native extraction contains **3,514 SOURCE_ONLY records across 172 source paths** outside typed `FGConfig` families, none previously counted by migration coverage. Examples by section (aggregate counts only): 1,774 Internet Service name records; 452 dashboard widgets; 427 web-filter category records; 131 dashboards; 101 DNS-filter category records; 64 SSL/SSH exemptions; 29 URL-filter entries; 27 DNS domain-filter entries; 22 DLP file-pattern entries; 16 local certificate records; 16 application-list entries; and other preserved settings. These records include both security-relevant configuration and configuration an engineer may choose to retire. Their absence from coverage was not evidence of successful conversion.

Plan and implementation: pass the existing vendor-native `source_inventory` explicitly into the pair-specific CLI pipeline, web draft and signed-artifact pipeline, following the established source-inventory pattern in other directional pairs. Reuse extraction's typed-object identity/classification helpers. Report native `SOURCE_ONLY` and `MODEL_GAP` records as unsupported manual work; skip empty sections and already modeled records. Preserve CLI scope, VDOM, source path, parent identities and line provenance. Encode full source identity without delimiter collisions. Do not copy command values or credential material into coverage rows, infer target semantics, or expand automatic approval.

The four focused tests cover real parser/derived/planner/render paths, CLI export, native scope/parent identity, absence of raw setting values, web manual-only drafts, rejected approval and partial signed artifacts. Focused tests pass. Ruff, compileall and whitespace checks pass.

Real full-input CLI rerun: **4,476** coverage rows = 723 recommendation-only + 3,753 source-only (the prior 962 plus 3,514 newly visible native records). Still `NEEDS_MAPPING`, 111 unresolved mappings, zero commands, zero renderable/satisfied items. This is improved accounting, not new conversion failures.

Validation completed: **3,015 Python tests passed, two skipped, 16 subtests passed**; Ruff, compileall and whitespace checks passed. The existing offline Chromium approval/export walkthrough passed with no JavaScript errors. A full-input Chromium check reached prepared review in **24.60 seconds**, found all **16 local certificate records** by their native section name in manual work, saw five HTTP 200 API responses and no page errors. No frontend source changed. No target firewall was contacted.

Next cycle: inspect remaining typed source families for missing migration accounting, especially central SNAT and unknown zone settings. Do not infer activation/defaults from the mere presence of preserved records.

Pushed to `origin/main`: **`bca0f47e`** (`Account for preserved native sections in PAN-OS migration coverage`).

## Cycle 6 — central NAT coverage and conservative conversion guard

A synthetic source variant on the same pipeline reproduced a separate correctness hole: one explicit modeled central-SNAT entry plus an independent supported address produced `READY`, zero unplanned records and no NAT plan. Typed central-SNAT records were missing from the source-only family list. Native central/NGFW mode evidence could also be omitted from planner inputs, allowing per-policy NAT or VIP plans despite unsupported source-mode semantics.

Official authority: Fortinet's [FortiOS 7.4.3 Central SNAT guide](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/421028/central-snat) describes ordered central-SNAT matching and the bypass of per-policy NAT when central mode is enabled; [Central DNAT](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/448790/central-dnat) distinguishes central VIP handling. The exact 7.4.6 pages could not be fetched through the documentation tool. This change adds no positive cross-version translation: it preserves evidence and requires review.

Plan and implementation: expose central-SNAT entries as source-only manual work using their source policy IDs; pass native inventory through both pipeline and draft planner calls, including the service-name override rebuild; mark policy NAT and VIP plans for manual mode/order verification in affected source scopes. An unscoped/global control is not guessed into a single VDOM. No activation state is inferred from table presence or enable/disable/unset evidence. Explicit disabled controls currently also require manual review because verified source-mode translation is not implemented. Other VDOMs retain their existing supported paths.

Nine focused regressions passed after reproducing seven failures: retained disabled central entries and IDs; native enabled/disabled/unset/NGFW controls; VDOM separation; VIP and dependent security blocking; and web replanning after a service-name override. Related pool/combined-NAT/native-inventory tests also passed. Ruff and compileall pass.

The uploaded example has zero central/NGFW mode controls and zero modeled central-SNAT entries. Its CLI repeat remains **4,476** unplanned records, **111** unresolved mappings and zero executable commands. This additional fix addresses a verified source variant, not a newly discovered central-NAT setting in the uploaded file.

Validation completed: **3,024 Python tests passed, two skipped, 16 subtests passed**. Ruff, compileall and whitespace checks passed. Chromium showed the central-mode verification reason in manual work with zero JavaScript errors. The full uploaded-config CLI repeat retained the counts above.

Pushed to `origin/main`: **`2f0d22d2`** (`Keep central NAT manual and block unverified policy NAT conversion`).

## Cycle 7 — native zone retention and unsupported settings

Reproduced another CLI/pipeline omission: one interface in a source zone, with explicit VSYS/VR/port/native-zone mappings, reported `READY` with zero coverage gaps but planned zero zones because no policy referenced it. Omitting the native-zone mapping also lost the source zone from coverage. Separately, arbitrary preserved zone settings and typed zone tagging were silently dropped while a zone and its dependent security policy remained executable.

Plan and implementation: honor explicit native-zone mappings even without policy references; add coverage for source zones absent from the plan; preserve every source contributor when checking consolidated zones, preventing duplicate gap rows. Pending zone gaps use zone/target-zone decision identity rather than interface identity. Unknown zone settings and source tagging now require manual target/metadata review; normal dependency validation blocks their zone and consumer rule commands. Source state is not repaired or mutated. The selected FortiOS 7.4.6 `config system zone` reference documents zone membership, intra-zone control and tagging; no target semantics are invented for unclassified settings.

Three cases failed before the fix; four new regression cases now cover explicit versus missing mappings, unknown-setting dependency blocking and tagging review. Existing consolidation regressions now also verify contributor-aware coverage. Focused zone tests: **11 passed**; Ruff and whitespace checks passed. The uploaded example's two source zones were already represented and had no raw extra settings; final full-input counts and full-suite results are recorded below after validation.


Cycle 7 validation: **3,028 Python tests passed, two skipped, 16 subtests passed**; Ruff, compileall and whitespace checks passed. Chromium showed zone tagging's manual metadata review reason with zero JavaScript errors. The full uploaded-config CLI repeat remains `NEEDS_MAPPING`, 111 unresolved mappings, 4,476 review records (723 recommendation-only and 3,753 source-only) and zero commands. Consistency assertions confirm every report item is unrendered, unsatisfied and not command-renderable. Frontend validation results are recorded in the final checkpoint below.

Pushed to `origin/main`: **`0e28a2e2`** (`Retain explicitly mapped zones and expose unsupported zone settings`).

## Latest checkpoint — after the 07:40 run

Three additional implementation cycles are finished, validated and pushed: `bca0f47e` (native inventory), `2f0d22d2` (central NAT) and `0e28a2e2` (zone retention/review). No code cycle is left half-finished. The raw uploaded configuration remains outside Git and its original SHA-256 still matches.

Final checks: **3,028 Python tests passed**, two skipped, 16 subtests passed; **249 frontend tests passed**, frontend lint/build passed, Python Ruff/compileall and diff checks passed. The frontend build retains its existing large-bundle warning. Offline browser approval/export, full-input native-certificate search, central-mode manual-review and zone-tagging manual-review checks passed without JavaScript errors. No target firewall was contacted or committed.

Use `/workspace/migration-review-private/run0740/cycle7/migration_report.json` as the latest private full-input report while this workspace exists. Its baseline is now **4,476 review records and 111 required mapping decisions**, with zero executable commands. The 3,514 newly visible records are retained source evidence, not 3,514 newly introduced conversion errors; some require target implementation and others require an explicit retirement decision. Counts can overlap with blocked planned objects and are not a count of independent software bugs.

Next scheduled run should fetch current `main` and verify the upload again, then start a fresh audit using these updated counts. Prioritize typed source attributes and hierarchy that may still be silently ignored, scoped identities in manual-work reporting, and dependency/order correctness. Verified positive translation for central/NGFW mode and zone tagging remains unimplemented; the new guards intentionally require review, including explicit disabled/unset mode controls. Add automation only with version-specific semantic evidence and preserve required target decisions. Record each finding and plan, implement/test/push coherent fixes, and update this checkpoint before stopping. Usage quota remains unavailable; no exhaustion claim is made.

## Cycle 8 — nested address metadata review

Resumed from clean `92b88112`, matching fetched `origin/main`; no prior migration/test process was active. The uploaded file's SHA-256 still matches. The real CLI baseline remains `NEEDS_MAPPING`, 111 unresolved mappings, 4,476 unplanned records and zero commands.

Finding: typed nested tagging on IPv4 addresses and address groups was ignored by planning. A supported host/group/policy variant reported `READY` and emitted its consuming security rule despite unconverted categories/tags or unknown settings inside a tagging entry. Native inventory could not close this gap because the entries were already classified as typed extraction. The uploaded example has no such address/group tagging, so this is a reproduced source variant, not a newly discovered setting in the example.

Authority: the repository's selected FortiOS 7.4.6 reference, `documentation/official-cli-references-selected version/FortiGate Selected CLI References.md`, sections `config firewall address` and `config firewall addrgrp`, explicitly defines nested tagging entries, category and tags. No automatic equivalence with PAN-OS metadata is assumed.

Plan: require manual metadata review on tagged addresses/groups, preserve source state and nested evidence, use normal dependency blocking for groups/policies, and expose the reason in browser review. Keep warnings free of nested values. Ten real-extraction/pipeline/web cases failed before implementation; validate those plus the full suite, real example CLI and browser before pushing.

Cycle 8 completed: all ten new regressions and 24 focused address/inventory checks passed. Full Python validation: **3,038 passed, two skipped, 16 subtests passed**; Ruff, compileall and whitespace checks passed. Chromium showed tagging review for both object types with zero JavaScript errors. The signed approval/export walkthrough passed, including artifact integrity and 2,000-object search. The full uploaded-config CLI repeat retains 4,476 records, 111 unresolved mappings and zero commands. No frontend source changed and no device was contacted.

Pushed cycle 8 to `origin/main`: **`382623e7`** (`Require review for unconverted nested address tagging`).

## Cycle 9 — manual-work source identities

Finding in the real example: 19 session-helper records produce only 13 distinct `(VDOM, kind, name)` review identities, because generic coverage chooses a helper's nonunique protocol label before its native edit ID. The same helper in global scope is incorrectly relabeled root. Related synthetic cases show read-only region/vendor tables using descriptive names instead of IDs, and SSL-VPN realms/bookmark owners replaced by array offsets. Singleton settings also use offsets that change when another scope is inserted. These names reach the deterministic browser review tasks and make manual work hard to correlate with source.

Authority: selected FortiOS 7.4.6 CLI reference sections `config system session-helper`, `config firewall region`, `config firewall vendor-mac`, `config vpn ssl web realm`, `config vpn ssl web user-bookmark` define their native edit keys; vendor extraction's typed source inventory also records the canonical fields.

Plan: use the documented family-specific identity fields, retain preserved unparsed native IDs, name singleton records by family, and preserve `None` scope instead of inventing root. Models without a VDOM field remain unscoped in this coverage; no global/VDOM placement is guessed. Verify duplicate-label helpers, global/root/blue isolation, malformed IDs, owner/path identities and browser manual tasks, then repeat the real CLI and required validation. Four initial real-path regressions failed before the fix.

Cycle 9 completed: four new regression cases and 17 focused identity/inventory/central-NAT checks passed. **3,042 Python tests passed, two skipped, 16 subtests passed**; Ruff, compileall and whitespace checks passed. Full-input report assertions now find 19 distinct native session-helper identities. Chromium prepared the full example in **21.63 seconds**, displayed all 19 helpers as unique source objects, observed five HTTP 200 API responses and zero page errors. A duplicate-label synthetic browser check also passed. CLI totals remain 4,476 review records, 111 mappings, zero commands. Frontend checks also passed: **249 tests**, lint and build; the existing large-bundle warning remains.

Pushed cycle 9 to `origin/main`: **`bfee92d4`** (`Preserve native source identities in manual migration coverage`).

## Cycle 10 — one-time expiration notification loss

Finding in the uploaded example: all three one-time schedules with explicit `expiration_days` were marked `SUPPORTED` without warnings by `plan_schedules`; their explicit event-log notification setting has no representation in `PlannedSchedule`. A valid synthetic schedule with explicit expiration controls also permitted its consuming policy to export and reported `READY`. Four regressions failed; the absent/unset control case already passed.

Authority: selected FortiOS 7.4.6 `config firewall schedule onetime` reference defines `expiration-days` as writing an event-log message a configured number of days before expiry (including the permitted value zero). The selected PAN-OS schedule hierarchy covers time ranges; this implementation has no verified equivalent notification translation. This setting is not interpreted as the traffic-match expiration date or as disabled when zero.

Plan: retain the existing time-range conversion, add a manual notification/monitoring review blocker whenever the source control is explicit, and let existing dependency validation block consuming rules. Missing/unset values must remain distinct and must not invent a notification requirement. Verify zero/nonzero/absent/unset behavior, web review, full-input CLI/report consistency and the required full validation before committing/pushing.

Cycle 10 focused validation: **25 schedule checks passed**, including the five new cases. The full-input CLI report now includes exactly three expiration-notification review warnings, remains `NEEDS_MAPPING` with 111 decisions and 4,476 unplanned records, and reports zero commands/renderable/satisfied items. All 10,426 report items are unrendered, unsatisfied and not command-renderable; report consistency assertions passed.

Chromium prepared the full input in **22.22 seconds**, showed all three explicit expiration-notification schedules in manual work, observed five HTTP 200 API responses and zero page errors. The synthetic notification check and signed approval/export/2,000-object walkthrough also passed without JavaScript errors. Ruff, compileall and whitespace checks passed. Full-suite completion is recorded below.

Cycle 10 full validation: **3,047 Python tests passed, two skipped, 16 subtests passed**. The frontend's 249 tests, lint and build also passed during this continuation; no frontend source changed. No live firewall was contacted and no candidate or device commit was performed.

Pushed cycle 10 to `origin/main`: **`9f3677fb`** (`Expose unsupported one-time schedule expiration notifications`).

## Latest checkpoint — continuation after the 07:40 run

Three additional coherent cycles are complete and pushed: `382623e7` (address/group tagging review and dependency blocking), `bfee92d4` (native coverage identities and preserved unknown/global scope), and `9f3677fb` (explicit one-time expiration notifications). No implementation is half-finished. The upload remains outside Git and its original SHA-256 still matches. Private full-input artifacts now live at `/workspace/migration-review-private/continue/cycle10/`; use `migration_report.json` while this workspace exists.

Validation at this checkpoint: **3,047 Python tests passed**, two skipped, 16 subtests passed; **249 frontend tests passed**, frontend lint/build passed; Python Ruff/compileall and whitespace checks passed. The existing frontend bundle-size warning remains. Synthetic and full-input browser reviews, signed approval/export integrity and large-object search passed with no JavaScript errors. The report has **111 required decisions**, **4,476 unplanned records** (723 recommendation-only + 3,753 source-only) and **zero executable commands/renderable/satisfied items**. Three explicit schedule notification requirements are now visible on planned schedule rows; they do not increase the unplanned-record count. All 19 native session-helper identities are distinguishable. These totals include overlapping source evidence and blocked objects, not independent software defect counts.

Manual requirements remain: engineer-selected VSYS/virtual routers/interfaces/zones and target evidence; unsupported source sections and feature designs such as SD-WAN, SSL-VPN, identity/admin settings and retained certificates; secure target VPN authentication and tunnel design; central/NGFW controls, tagged objects and schedule notifications when present. The uploaded file has no central mode controls or address/group tagging. Models without native VDOM evidence remain unscoped; this continuation does not invent their placement. No live device operations were performed.

Exact next actions:

1. Fetch `origin/main`, read this checkpoint, check branch/status and active local processes, and verify the uploaded config hash before running the CLI into a new private directory. Resume any newer checkpoint first.
2. Compare the real CLI report with this baseline and inspect browser manual work. Do not add target mappings merely to make commands appear.
3. Audit remaining typed attributes and nested hierarchy against planning/coverage. Candidate areas for investigation include object comments/descriptions and Security Fabric ownership controls; determine which are represented, safely automated, explicitly retired, or still require manual review using selected official references. No implementation plan for these candidates has yet been adopted.
4. Check native inventory versus typed records without VDOM fields before extending scope-sensitive automation. Preserve unknown scope and retained evidence; do not repair source models in conversion or infer defaults from absent/unset controls.
5. For each verified issue, record evidence and impact, propose and execute a bounded plan, validate real CLI/browser paths plus required checks, then commit/push safely to main. Keep artifact approval, dependency blocking, ordering and secret redaction intact. Stop with a concrete checkpoint when the run ends; remaining usage quota is not exposed.

## Cycle 11 — object comment preservation and review

Resumed clean `3f941307`, matching fetched `origin/main`; no previous migration/test process was active, and the uploaded config hash still matches. Fresh real CLI baseline: `NEEDS_MAPPING`, 111 required decisions, 4,476 unplanned records, zero commands.

Finding: explicit source comments are dropped by address/group/service plans even though extraction retains them. The uploaded example has 64 address comments, 27 address-group comments, seven service comments and one service-group comment. This loses operator context and creates manual re-entry work. Address/group target comparison currently checks only values/members, so simply adding rendering without metadata-aware reuse could still claim an unpreserved comment was satisfied.

Authority: selected FortiOS 7.4.6 reference defines object comments. Selected PAN-OS reference sections 3.1/3.2 define address and address-group descriptions. Official [PAN-OS 11.1 configure hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy) confirms address, address-group and service description paths; it does not document a service-group description path. Do not invent one.

Prioritized plan: carry address/group and normalized service comments into pair-owned planned descriptions and the shared reviewed renderer paths, preserving absent versus explicit empty values. Require matching explicit target description evidence for exact reuse when source description is present; conflicting or missing target evidence remains manual, with no overwrite. Keep native service-group comments visible for manual review where target metadata syntax is unverified. Validate extraction immutability, empty values, source-service splitting, native target XML comparison, CLI digest and signed web preview/download.

Cycle 11 regression evidence: 14 of the initial 20 new cases failed before implementation; 56 focused description/address/reuse checks then passed. The first full suite found one existing oversized-source bundle regression (3,066 passed): newly rendered metadata containing a control character aborted the artifact instead of preserving it as blocked source evidence. Added target-description validation, without changing the retained value, so invalid objects and consumers are excluded while other objects and source appendix exports remain available. Added unsafe-control, tab, over-limit, exact-limit and escaped-newline regressions. Official [PAN-OS 11.1 address help](https://docs.paloaltonetworks.com/ngfw/help/11-1/objects/objects-addresses) documents the 1,023-character description limit.

The real-file planner now preserves all 64 address and 27 group comments as descriptions. The CLI repeat retains baseline counts and all items remain unrendered/unsatisfied without mappings. Chromium passed a modified approval/export walkthrough with a synthetic comment: the same description appears in preview, downloaded set and bundle with a matching digest, plus the existing 2,000-object search and zero page errors. Final full validation follows below.

The browser check also exposed missing manual-work reporting for invalid descriptions when placement was unresolved. Planning and validation now use one pair-owned target text constraint helper, retaining invalid text as evidence and exposing a manual cause before approval. Full-suite validation of the initial address/validation portion passed (3,074 tests, two skipped, 16 subtests); the final combined run below includes the subsequent shared planning checks and service handling.

The service variant reproduced 11 failures before implementation. Service comments now follow normalization onto every generated service member, preserving context when one source service splits into multiple target services. The generated group's comment is represented on its service members. An explicit native source service-group comment instead blocks that group and consuming policy for manual metadata review; no undocumented service-group description command is emitted. [PAN-OS 11.1 services help](https://docs.paloaltonetworks.com/ngfw/help/11-1/objects/objects-services) and [address-group help](https://docs.paloaltonetworks.com/ngfw/help/11-1/objects/objects-address-groups) confirm the 1,023-character descriptions for supported object types. All 44 new metadata regressions pass, including native target XML reuse, invalid-description review before placement, split-service propagation and dependency blocking.

Cycle 11 completed: **3,091 Python tests passed, two skipped, 16 subtests passed**. Ruff, compileall and whitespace checks passed. Frontend **249 tests**, lint and build passed (existing bundle-size warning only). All 98 source address/group/service comments are preserved in planning; the seven source service comments produce eight expanded service descriptions. One native source service-group comment is now explicit manual work. The real CLI remains `NEEDS_MAPPING`, 111 decisions, 4,476 unplanned records and zero commands/renderable/satisfied items; validation findings increase by one for the newly visible group requirement. Full-input Chromium prepared review in **22.83 seconds**, showed that requirement, returned five HTTP 200 API responses and no page errors. Invalid-description manual work, signed description preview/download/bundle consistency and 2,000-object search also passed. No target device was contacted.

Pushed cycle 11 to `origin/main`: **`e5da3708`** (`Preserve object comments in reviewed PAN-OS migrations`). The execution transport briefly disconnected before the first push process could start; after it recovered, the clean local commit was intact, remote ancestry was checked again and the normal fast-forward push succeeded.

## Cycle 12 — searchable session-helper review labels

Finding: cycle 9 correctly replaced nonunique session-helper names with native edit IDs, but its generic coverage reason discarded the helper type entirely. Two native `sip` helpers retained distinct IDs 1 and 2 yet searching `sip` in browser manual work returned zero objects. The same reporting path handles all 19 helper records in the uploaded example. This made manual application/helper review unnecessarily difficult despite correct identities.

Authority: selected FortiOS 7.4.6 `config system session-helper` reference defines the numeric edit ID separately from the helper type selected by `set name`. These fields must remain distinct.

Plan: include the explicitly configured helper type and native section in manual review text, retaining native ID and scope as identity. Do not copy arbitrary raw settings, infer an absent helper type, or add target commands. Verify scope separation, duplicate labels, absent type, redaction, API review tasks, real CLI coverage and browser search. Three new regressions failed and the absent-type case already passed before implementation; Chromium independently reproduced the zero-result search.

Cycle 12 focused validation: all four new cases and **12 related identity/inventory checks passed**; Ruff, compileall and whitespace checks passed. The real CLI report now retains 19 distinct scoped native helper IDs with explicit searchable types and section names. Coverage/mapping totals and zero-command/renderable/satisfied consistency assertions remain unchanged. Chromium's `sip` search now finds both synthetic source objects; the full uploaded-config review prepared in **20.23 seconds**, displayed all 19 helpers by native section/type text, observed five HTTP 200 API responses and zero page errors. Full-suite completion follows below.

Cycle 12 completed: **3,095 Python tests passed, two skipped, 16 subtests passed**. Ruff, compileall and whitespace checks passed. The frontend's 249 tests, lint/build and existing bundle-size warning were checked earlier in this continuation; no frontend source changed. Full-input browser search, scoped helper identity/type reporting and secret-redaction regressions pass. The source checksum is still unchanged. No live firewall was contacted.

Pushed cycle 12 to `origin/main`: **`899861b1`** (`Keep native helper types searchable in manual migration review`).

## Latest checkpoint — object metadata and helper review

Two additional cycles are complete and pushed: **`e5da3708`** (object comments, metadata-aware reuse and invalid-metadata review) and **`899861b1`** (searchable session-helper types with native IDs). No implementation or adopted plan is left half-finished. The brief execution disconnect recovered without losing the local commit; both code commits were pushed normally after ancestry checks. Raw uploaded configuration remains outside Git and its original SHA-256 still matches.

Actual validation: **3,095 Python tests passed, two skipped, 16 subtests passed**; **249 frontend tests**, lint/build, Python Ruff/compileall and whitespace checks passed. The existing large frontend bundle warning remains. Real CLI checks, full-input Chromium review, metadata/identity searches, and signed preview/download/bundle integrity passed. Malformed metadata stays as source evidence, blocks dependent commands, and is visible as manual work before placement is resolved. The existing oversized-evidence bundle regression passes. No device deployment, candidate preparation or firewall commit occurred.

Latest private report: `/workspace/migration-review-private/continue2/cycle12/migration_report.json`. It remains `NEEDS_MAPPING`, **111 required decisions**, **4,476 unplanned records** (723 recommendation-only + 3,753 source-only), **36,883 validation findings**, and **zero commands/renderable/satisfied items**. All report items are unrendered and unsatisfied. The extra validation finding exposes the example's one native service-group comment; it is attached to an already planned group, so the unplanned count does not rise. These counts overlap source evidence and dependencies; they are not independent defect counts.

The uploaded example's **98 explicit address/group/service comments** now survive planning (64 address, 27 address-group, seven service; the latter expand to eight service descriptions). Those descriptions render only after valid target placement and approval. One native service-group comment remains manual because a PAN-OS 11.1 service-group description path is unverified. All 19 session helpers retain scoped native IDs and searchable helper types. Their application/helper behavior still requires manual target design; no helper commands are automated.

Remaining manual migration requirements: engineer-selected VSYS, virtual routers, interfaces, zones, target ownership/evidence; supported-feature prerequisites and unsupported source sections, including SD-WAN/SSL-VPN/identity/admin/certificate work; secure VPN authentication/tunnel design; the three explicit schedule expiration notifications and native service-group metadata. The prior conservative central/NGFW and tagged-object guards remain in place for sources that contain those settings. Missing or unknown placement is not inferred.

Exact next actions for the next repeat:

1. Fetch current `origin/main`, inspect status/instructions and this checkpoint, coordinate with active local work, and verify the uploaded input hash. Resume any newer unfinished checkpoint before auditing again.
2. Run the actual CLI into a fresh private directory and compare these totals; review the browser workflow as needed. Keep target mappings undecided without engineer evidence.
3. Audit remaining typed attributes/hierarchy against plans and manual coverage. Candidate areas include VIP/NAT metadata and scope/distribution controls on schedules; verify source/target version semantics before adopting an implementation plan. This continuation adopted no unfinished plan for these candidates.
4. Preserve native IDs, global/VDOM/parent scope, explicit empty versus absent/unset state, references, ordering, dependencies, secret redaction and signed artifact identity. Reuse must not silently lose explicit source metadata or overwrite destination metadata.
5. Record findings and a bounded plan before implementation; run affected real paths and required checks, commit and push validated changes without force, then leave another concrete checkpoint. Usage quota is not exposed; no exhaustion claim is made.

## Cycle 13 — VIP comment preservation

Resumed clean `ba0f59cd` after the separate repository quality refinement
(`fcd78270`, CI Python 3.11–3.14/release/frontend/lint all passed; automatic Render
deployment succeeded). Fetched `origin/main` matches this checkout and the
uploaded input checksum still matches. No prior implementation is unfinished.
The actual uploaded-file CLI baseline remains `NEEDS_MAPPING`, 111 required
decisions, 4,476 unplanned records and zero commands/renderable/satisfied items.

Finding: extraction retains **13 explicit comments among 279 VIPs**, but
`planning/addresses.py` omits every VIP comment when building its PAN-OS address
representation. The existing address metadata rendering and exact-reuse checks
therefore receive no description. A source comment can disappear even when the
address value is converted/reused correctly. The example's seven VIP groups
have no comments; their existing native manual coverage is separate.

Authority: selected FortiOS 7.4.6 reference `config firewall vip` explicitly
defines `set comment`. The selected PAN-OS 11.1 reference section 3.1 defines
`set address <name> description <value>`. The prior address-description limit
and CLI text constraints remain applicable. No NAT-rule metadata path or VIP
behavior is inferred from an address description.

Plan: retain the VIP comment on the existing pair-owned generated address,
including explicit empty versus absent/unset values. Apply the existing shared
description constraint during planning so invalid metadata is manual even
before placement; preserve its original sanitized value as evidence. Reuse
must require matching explicit target descriptions and must not overwrite
target metadata. Verify source immutability, VDOM separation, secret redaction,
consumer dependency blocking, CLI hashes and signed preview/download/bundle
bytes. Repeat the actual uploaded-file CLI and required applicable validation,
then commit/push and record the exact checkpoint.

Regression evidence: 13 of the initial 18 cases failed before implementation.
The signed-web case also exposed a prerequisite omission: a source containing
only unreferenced VIPs receives no VSYS decision, although address planning
already produces VSYS-scoped objects for those VIPs. Amend the bounded plan to
require an explicit VSYS for every planned VIP address, including an
unreferenced VIP; do not infer VSYS, interfaces or VRs. Add a scoped requirement
regression and verify the signed workflow can approve that address while its
unresolved NAT remains excluded.

Cycle 13 completed: **20 new regressions pass**. Full validation: **3,129 Python
tests passed, two skipped, 16 subtests passed**, 137.77 seconds; Ruff with all
Pyflakes rules, compileall and whitespace checks passed. The frontend's 249
tests, lint and build passed earlier in this continuation; no frontend source
changed. The existing bundle-size warning remains documented in the quality
review.

The real input's 279 VIP address representations now retain all **13** native
VIP comments. The actual CLI remains `NEEDS_MAPPING`, **111 decisions**, **4,476
unplanned records**, **36,883 findings**, zero commands/renderable/satisfied
items, unchanged validation summaries and a matching empty-command SHA-256.
All report item consistency assertions passed. Output is private at
`/workspace/migration-review-private/continue3/cycle13/migration_report.json`.

Chromium prepared the full uploaded input in **19.76 seconds**, confirmed 279
VIP address review rows with 13 descriptions, retained all 19 helper search
identities, observed five HTTP 200 API responses and zero page errors. A
synthetic signed VIP-description walkthrough passed explicit approval,
failed-generation retry without reapproval, command preview, set download and
bundle digest equality, source reload invalidation and 2,000-object search.
The full-file browser inspection used counters at the client's JSON parse
boundary because Chromium's inspector cache evicted the large response body;
no product change was made for that tooling limitation. No live device was
contacted. The uploaded file checksum is unchanged.

Pushed cycle 13 to `origin/main`: **`d6ff2836`** (`Preserve VIP comments and require
explicit VIP address scope`).

## Cycle 14 — flattened VIP-group metadata coverage

Finding: a native VIP group with an explicit comment can flatten into supported
VIP address/NAT/security commands and disappear from manual coverage. A
synthetic reproduction emitted seven security and seven NAT commands and
reported the group represented with zero coverage gaps, although no target
object carries its comment. The uploaded example has seven VIP groups with
no comments, so this is a verified source variant rather than new source
metadata in the example.

Authority: selected FortiOS 7.4.6 `config firewall vipgrp` defines `set comments`
separately from membership and interface. The current implementation flattens
membership; it does not create a PAN-OS address-group object for this native VIP
group. Do not invent a metadata destination or copy group text onto arbitrary
member or policy objects.

Plan: keep the verified flattened membership and traffic commands eligible,
but retain a scoped native source-group coverage record whenever its comment
is explicit, including empty values. Explain that group metadata still needs
manual review, separately from unresolved membership/consumer coverage when
that also remains. Omitted/unset comments must not create a new requirement.
Never copy arbitrary comment text into issue messages. Verify source
immutability, native scope identities, unchanged verified commands, partial
artifact/coverage reporting, CLI and browser manual-work visibility. Then run
the real uploaded input and required applicable validation before pushing.

Cycle 14 completed: six of eight new regressions failed before the fix; all
eight now pass, alongside **56 focused VIP/description/coverage checks**. A
fully mapped native fixture still emits the same 25 commands with identical
traffic conversion, while a source-group comment changes its artifact from
`READY` to `PARTIAL` with one scoped metadata coverage record. Explicit empty
comments remain reviewable; omitted/unset values do not invent work. Native
VDOM identities and source immutability remain intact. Issue text does not copy
the source comment and does not hide unresolved membership/consumer coverage.

Full validation: **3,137 Python tests passed, two skipped, 16 subtests passed**,
122.20 seconds. Ruff with all Pyflakes rules, compileall and whitespace checks
passed. Chromium displayed one native VIP-group manual metadata task with zero
page errors. No frontend code changed; the earlier 249 frontend tests,
lint/build and cycle 13 signed-browser walkthrough remain applicable.

The actual uploaded-file CLI repeat remains `NEEDS_MAPPING`, 111 decisions,
4,476 unplanned records, 36,883 findings, zero commands/renderable/satisfied
items. Coverage and validation summaries exactly match cycle 13, all item
consistency assertions pass, and the command-file SHA-256 matches the report.
Latest private report:
`/workspace/migration-review-private/continue3/cycle14/migration_report.json`.
No customer data was committed and no firewall operations occurred.

Cycle 13 remote verification also completed: GitHub CI run **39904026678** and
OSV-Scanner run **39904027049** succeeded. Render automatically deployed
`d6ff28361d3807f249bd6077250cda3e871f7f76` as **`dep-dbden5dbedkc73ctlfg0`** and
reported it live; no manual deploy or cache clear was needed.
