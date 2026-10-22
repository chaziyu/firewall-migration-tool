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
