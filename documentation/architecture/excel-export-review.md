# Palo Alto and Juniper Excel review implementation

Reviewed base: `origin/main` at `b2d39d7a` (`update`), fetched on 2026-10-19.

The source-reporting fixes from the prior 13-finding review have been applied. The existing overflow implementation on latest main was retained and verified through both vendor exporters. Changes preserve vendor-native models and keep explicit source, effective state, validation and presentation separate.

## Findings addressed

| Finding | Implementation | Regression evidence |
| --- | --- | --- |
| F01: PAN SNMPv3 credentials | Recognize `authpwd` and `privpwd` in structured and raw evidence sanitization. | Direct model, preview, snapshot, HTTP FAST/FULL and XLSX XML sentinel checks; ordinary names/settings survive. |
| F02: hierarchical upload corruption | Sanitize token spans in the original source instead of rewriting hierarchy with display-set formatting. | Direct/upload/snapshot equivalence, punctuation preservation and idempotent redaction. |
| F03: quoted comment markers | Recognize comments outside quoted/escaped strings; preserve command line positions. | A quoted `/*` no longer discards following configuration; quoted syntax and escape cases remain intact. |
| F04: hierarchy syntax integrity | Add lexical token kinds, quote state and source spans; reject incomplete quotes, comments, lists, braces and statements. Evaluate hierarchy tokens directly. | Quoted delimiters remain values; malformed uploads return 400; multiline values and source lines survive source and effective-object analysis. |
| F05: case-sensitive identifiers | Preserve names in activation, inheritance groups, effective lookup and effective-state projection. | `Foo`/`foo`, `G`/`g` and distinct logical-system names remain separate. |
| F06: PAN scope ambiguity | Add canonical scope/device/template ownership and source-record identifiers to source-bearing sheets. | Identical objects on different device serials remain distinguishable in FAST and FULL. |
| F07: reference joins | Index reference results by family and complete source-owner identity. | A security policy no longer displays a same-named NAT rule's address references. |
| F08: validation joins | Carry source-owner identity through validation and use it in both preview and Excel. Legacy diagnostics only attach when ownership is unambiguous. | An invalid route in VR2 does not annotate a valid same-named route in VR1. |
| F09: VSYS ordering | Include standalone/unassigned VSYS owners and retain explicit source-only/incomplete ordering where effective context is unavailable. | All extracted standalone rules have visible ordering with a limitation, without guessed Panorama assignments. |
| F10: missing feature fields | Add Junos Application Settings, Interface Details and Interface Addresses sheets. Export PAN unit names, explicit VLAN tags and additional existing interface fields. | Top-level TCP/443 and named UDP/53 term settings survive; unit suffix 100 does not overwrite explicit VLAN tag 200. |
| F11: NAT distribution | Retain scalar distribution values; preserve unrecognized or nested shapes as partial evidence. | All five documented scalar choices reach the NAT sheet; a future choice remains visible and reports PARTIAL. |
| F12: oversized cells | Retain latest main's Text Overflow mechanism. | End-to-end vendor FAST/FULL readback reconstructs long text, including a formula-like continuation and Unicode, without formula cells. |
| F13: non-entry coverage | Inventory registered non-entry typed nodes before extraction, including failure cases. Calculate coverage in vendor source analysis and reuse it in preview/Excel. Avoid duplicate appendix traversal. | Present/explicit-empty imports agree across model, inventory, preview and coverage; failed extraction retains evidence and reports UNSUPPORTED. |

The main regression file is [test_excel_pipeline_review_regressions.py](../../tests/test_excel_pipeline_review_regressions.py). It contains 40 parameterized cases and checks that reporting does not mutate source configurations. Existing tests were updated where the previous expected result encoded a reviewed defect or assumed that a growing workbook schema had a fixed last column.

## Latest-main startup repairs

Latest main contained committed merge-conflict markers in Python, TSX and tests. These prevented importing the Flask application and building the browser client. The conflicts were resolved against actual available APIs and models:

- Retain workflow metadata and dependency-ordered rendering.
- Preserve Check Point's existing offline-only destination contract; remove incomplete references to nonexistent destination UI/types/API arguments.
- Preserve explicit approval and reuse the current signed approval when retrying a failed build.
- Remove conflict-side references to absent coverage functions and ASA approval-group fields instead of inventing new migration capabilities.
- Repair the new browser test fixture's missing required workspace field.

No deployment capability was added.

## Workbook compatibility

Ownership columns are appended to existing PAN sheet schemas. Junos gains three detail sheets, while its existing topology and summary sheets remain available. Consumers should select columns by header rather than assume a fixed final column. Original explicit values, unknown fields, inactive state and unsupported evidence remain separate; source-only rule order is labelled as incomplete.

The NAT distribution tests use synthetic XML informed by the selected vendor reference. They do not establish compatibility with every PAN-OS release or replace testing authentic sanitized device exports.

## Verification

Results on the implementation:

- `python -m compileall -q src tests`: passed.
- `ruff check src tests`: passed.
- `git diff --check`: passed.
- New source-to-Excel regression file: **40 cases**, all passed in the full run.
- Full Python suite: **2,565 passed, 50 failed, 2 skipped; 8 subtests passed**.
- All 50 remaining failures are in FortiGate → Cisco ASA migration tests or its CLI/HTTP wrappers. The shared cause is an existing read of `policy.fixedport` in `conversion/fortigate_to_cisco_asa/planning/acl.py`, although `FGPolicy` has no such attribute. Both this planner file and the FortiGate policy model are unchanged relative to fetched main. This remains an upstream migration blocker outside the Palo Alto/Juniper source-to-Excel plan; the full suite is not green.
- Earlier targeted reporting/collection/HTTP/architecture selection: **682 passed**. A later selection covering final syntax and evidence changes: **169 passed**.
- Frontend: **146 tests passed**; ESLint and the TypeScript/Vite production build passed.

The full Python output is available at `/workspace/review-artifacts/implementation-pytest.log`; browser-test output is at `/workspace/review-artifacts/implementation-frontend-tests.log`.

Synthetic FULL workbooks were also generated through `/api/extract/excel` for manual review:

- `/workspace/review-artifacts/fixed-palo_alto-report.xlsx`: separate device ownership, explicit VLAN tag and source-only rule order.
- `/workspace/review-artifacts/fixed-juniper_srx-report.xlsx`: application protocol/ports, interface/unit/address details and case-distinct inactive state.
