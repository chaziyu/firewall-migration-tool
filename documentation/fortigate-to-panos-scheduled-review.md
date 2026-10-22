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
