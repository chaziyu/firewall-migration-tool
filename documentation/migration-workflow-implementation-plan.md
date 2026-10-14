Migration workflow and conversion reliability implementation plan

Recorded: 2026-10-14. Status: implemented; local verification recorded below.

## Purpose and execution contract

The user finds Plan migration confusing and inconvenient and wants a convenient,
understandable, reliable workflow. This document records the review and an
implementation plan that a new Codex session can execute without this chat.

The plan was invoked for implementation and a push to repository main. Application
changes are implemented and tested locally. This is not permission to connect to
or change a real firewall.
Live candidate pushes and commits require separately authorized real-device work.

Read AGENTS.md before implementation. Reinspect current code and git status;
paths and findings below describe the reviewed checkout, branch `work`, and may
have changed. Preserve user edits. No application changes were made during the
review. No browser usability run or real-device validation was performed.

## Outcome

A user should always understand:

1. Which source and destination this migration concerns.
2. What is already handled, what needs a choice, and what requires manual work.
3. What the next useful action is and why.
4. Exactly which changes they are approving and exporting.
5. Whether an artifact is exportable versus eligible for candidate preparation.
6. How to recover from a failed request, interrupted deployment, or closed browser.

Keep the deterministic FortiGate → PAN-OS engine and its safety boundaries.
Simplify how users operate it; do not weaken requirements to make screens green.

## Verified starting points

| Finding | Code evidence | Consequence |
| --- | --- | --- |
| Unsupported behavior can appear as missing input | `planning/policies.py` makes several unsupported policy behaviors PARTIAL; `design/deterministic.py` configuration classification falls back to NEEDS_INPUT unless status is UNSUPPORTED or a target conflict | Users can repeatedly edit mappings that cannot fix the underlying semantics |
| Failed preparation has no useful recovery journey | `MigrationWorkflow.tsx` clears the candidate session on failure and suggests preparing again; `deployment/palo_alto_ssh.py` rejects nonempty candidate diffs before preparation | A partially applied push can leave a candidate that cannot simply be retried |
| Review refresh clears working context before success | `MigrationReview.tsx:loadReview` clears deterministicDraft and artifact before awaiting prepare | A failed request removes the last successful proposal view |
| Resume is not a complete user feature | `storage/workspaceStore.ts` deliberately stores memory-only state and clears legacy IndexedDB state | Refresh loses the session; mapping/decision exports are separate advanced tools |
| Destination requirements arrive late | Target XML is labeled optional, but `application/artifact_eligibility.py:deployment_serial` requires approved destination serial and baseline evidence | A user can finish planning before learning they cannot prepare a candidate |
| Workflow is fragmented | `SourceConfiguration.tsx`, `MigrationReview.tsx`, `MigrationDesignReview.tsx`, and `MigrationWorkflow.tsx` each expose stages or actions | Users must understand proposal, approval, artifact, and deployment state themselves |
| Readiness has multiple legitimate meanings | Artifact status and deployment eligibility are separate; tests demonstrate READY artifacts with no eligible destination serial | A single green Ready label would be misleading |

Conversion paths above are relative to
`src/fwmigrate/conversion/fortigate_to_palo_alto/`; component paths are under
`src/frontend/src/features/` unless explicitly qualified.

Existing strengths to preserve: signed exact design approval, deterministic
planning, target reuse classification, dependency blocking, command identity/hash,
destination serial/baseline checks, candidate validation, explicit commit, and
visible unsupported coverage. Passing tests establish tested behavior, not full
vendor equivalence or real-device compatibility.

## Non-negotiable constraints

- No vendor-neutral firewall IR, shared semantic model, or new migration pair.
- Source remains immutable and explicit-only. Missing values are not defaults.
- Parsing, vendor semantics, planning, validation, and rendering stay backend-owned.
- Suggestions and saved proposals are not engineer approval.
- CREATE, CONFIGURE, REUSE, and BLOCK retain existing semantics. CONFIGURE needs
  explicit approval; blocked dependencies and unapproved items emit no commands.
- Preview, download, bundle, and deployment use the same RenderedMigration.
- Offline mode or manual-work acknowledgement must not bypass deployment gates.
- No automatic commit, candidate discard, rollback, or replay after an uncertain
  outcome. Application locks are not exclusive device locks.
- Do not add automatic persistent storage of customer configurations. Resume uses
  an explicit sanitized file. Credentials, tokens, secrets, candidate session IDs,
  and live execution authority must not enter that file.
- Retain the documented one-worker deployment baseline. Distributed coordination
  is outside this effort; explain recovery when process-local state is lost.
- Keep existing mapping YAML, target-intent YAML, and decisions JSON workflows
  compatible, under advanced tools.

## Proposed user journey

One migration workspace, one progress indicator, one primary next action:

`Load configurations → Place configuration → Resolve exceptions → Review changes → Export or deploy`

### 1. Load configurations

- Reuse the loaded source and existing upload/collection flows.
- Ask for intent: **Plan offline** or **Prepare for a destination firewall**.
  Intent changes guidance, not backend authorization.
- Offline mode can use no target or an architecture template; show unverified
  compatibility clearly. Destination mode requests actual destination evidence
  and exposes missing device/serial/baseline requirements immediately.
- Keep DESTINATION versus TEMPLATE evidence roles explicit; never infer that an
  uploaded template is the actual firewall.
- Show source scope, completeness, coverage, and manual-work inventory early.
  Distinguish automatic coverage, unresolved decisions, and manual implementation.
- Hardware capacity/licensing remain unverified where XML cannot establish them.

### 2. Place configuration

- Guide ownership first: source VDOM → destination VSYS and virtual router.
- Allocate parent interfaces next; expose child/VLAN consequences using the
  existing dependency graph, then resolve zones.
- Explain suggestions with evidence and affected scope. Do not auto-confirm
  ambiguous target choices or invent target names/ownership.
- Keep expert bulk editing, but include affected scope and exact proposed values
  in the review. Show a human-readable identity instead of raw decision keys.

### 3. Resolve exceptions

- Group by root cause and guide to the next resolvable choice.
- Distinguish **Needs your choice**, **Blocked by a prerequisite**, **Conflict**,
  and **Requires manual implementation**.
- Each issue shows reason, resolution, affected source identities, and a direct
  action only when the application can actually resolve it.
- One missing port should be one task with dependent policies/routes listed,
  not a long list of apparently independent failures.
- Display deduplicated affected counts; label overlapping or estimated counts.
- Manual-work acknowledgement records awareness only. It cannot mark unsupported
  configuration executable or make a partial artifact deployment-ready.

### 4. Review changes

- Group by interfaces/zones, objects/services, policies, NAT, routes, and other
  supported families. Summarize creates, reuses, approved additive changes,
  excluded items, and manual work separately.
- Show meaningful source → target comparisons from backend facts. For policies,
  show match/action and ordering where available; for NAT show translated values;
  for placement show ownership, port, zone, and prerequisites.
- Keep raw evidence/JSON/commands in expandable technical details.
- Selection includes visible dependency expansion. Approve exact values,
  operations, scope, and dependencies, never only a summary count.
- Primary action: **Approve these changes and generate commands**. Preserve the
  existing separate signed approval and build APIs behind this coordinated UI.
- If generation fails after approval succeeds, permit Retry generation against
  that current approval. Do not silently repeat approval or lose the selection.
- Partial approval remains supported and explicitly labeled.

### 5. Export or deploy

- Clearly show **Ready for export**, **Partial export**, **No changes needed**,
  and a separate **Eligible for candidate preparation** assessment.
- Reasons for ineligibility link to the exact resolution where possible.
- Export includes coverage/manual-work information and the same command hash as
  preview. Supporting objects without traffic rules must remain obvious.
- Live flow: preflight → prepare and validate candidate → review validation →
  explicit commit → confirmed outcome or outcome unknown.
- Revalidation is available when useful, not presented as mandatory after an
  already successful automatic validation.
- Show password re-entry requirements clearly; do not persist credentials for
  convenience. Distinguish submitted, completed, failed, and unknown outcomes.

## Phased implementation

Complete phases in order. Keep each phase reviewable and run its targeted tests.
Do not stop after cosmetic UI changes: classification, recovery, and resume are
part of the intended result. Update this document's execution log as work proceeds.

### Phase 0 — Reproduce and lock down behavior

Inspect current source, symbols, callers, tests, and any available codegraph per
AGENTS.md. Read relevant runtime skills if executing in a managed environment.

- Reproduce unsupported-policy classification with actual source → derived →
  draft input, using an unmapped inspection setting and fully supplied mappings.
- Reproduce failed draft prepare after a successful draft, preserving staged edits.
- Reproduce a push failing after at least one accepted command, then retry against
  a dirty candidate using a fake transport, never a real firewall.
- Record baseline API response shapes and existing export/import compatibility.
- Add regression tests for these concrete behavior gaps as part of their fixes;
  avoid snapshot-only tests that merely repeat implementation structure.

Deliverable: reproducible cases and an updated scope note if current code already
fixes a finding. Do not reintroduce old behavior to match this plan.

### Phase 1 — Authoritative issue and readiness contract

Primary files:

- `src/fwmigrate/conversion/fortigate_to_palo_alto/design/deterministic.py`
- `src/fwmigrate/conversion/fortigate_to_palo_alto/design/draft.py`
- `src/fwmigrate/conversion/fortigate_to_palo_alto/review/`
- `src/fwmigrate/conversion/fortigate_to_palo_alto/recommendations/support_guidance.py`
- `src/fwmigrate/conversion/fortigate_to_palo_alto/artifact_status.py`
- `src/fwmigrate/conversion/fortigate_to_palo_alto/application/artifact_eligibility.py`
- `src/fwmigrate/web_api/migration.py`
- `src/frontend/src/features/migration/{types,reviewTypes,reviewPresentation}.ts`

Add a pair-specific structured issue contract. Proposed fields (adapt to existing
contracts rather than duplicating them): stable issue ID/code, category, source
identity/scope, affected item/decision keys, prerequisite keys, explanation,
resolution kind, and executable action metadata where supported.

Use stable backend codes/structured causes, not English-message substring tests
in React. Categories may be additive to legacy status fields to preserve clients.
Do not blindly classify every PARTIAL item as manual: distinguish missing mappings,
unsupported semantics, target conflicts, and mixed causes. Preserve all causes;
an item may need a mapping and still require manual implementation afterward.

Expose independent coverage, approval, artifact/export, and deployment readiness
facts. Reuse existing eligibility logic; do not make a competing frontend gate.
For pre-artifact screens, distinguish known missing prerequisites from final
eligibility, which still requires an authenticated current artifact.

Acceptance:

- Unsupported inspection cannot be advertised as fixable by mapping approval.
- A mapping action appears only for an editable current decision.
- Dependency groups retain VDOM identity and do not merge unrelated same names.
- Missing mappings, target collisions, manual-only work, and mixed causes have
  correct reasons and next actions in draft and final plan views.
- Rendering and approval guarantees remain unchanged.

### Phase 2 — Transactional review updates and edit preservation

Primary files: `MigrationReview.tsx`, `hooks/useMigrationReviewActivity.ts`,
`reviewDrafts.ts`, `MigrationWorkflow.tsx`, and `storage/workspaceStore.ts`.

- Separate last successful review, staged edits, pending request, request error,
  and current executable eligibility.
- Immediately revoke executable eligibility on semantic context changes, but
  keep the previous successful review visible as stale/read-only.
- On prepare success, atomically publish matching draft/document/context.
- On failure, retain previous view and staged overrides/service-name proposals;
  show Retry with the same intended inputs. Never relabel stale evidence current.
- Continue using request versions so old responses cannot overwrite new context.
- Use semantic identity/digests for invalidation where supported, not incidental
  React object identity. Do not preserve approvals across changed signed context.
- Retain the last generated artifact only as an explicitly historical preview
  if needed; stale data must not be downloadable/executable as a current artifact.

Acceptance: failed revalidation, rapid target replacement, source change during
request, out-of-order responses, and editing back to an original value behave
predictably. An unchanged successful refresh must not unnecessarily force manual
re-entry. No stale request restores deployment eligibility.

### Phase 3 — Unified guided workspace

Primary files: `features/source/SourceConfiguration.tsx`, migration components,
`MigrationReview.tsx`, `MigrationWorkflow.tsx`, `PlanReview.tsx`, presentation
helpers, and relevant styles. Inspect App/navigation before changing routing.

- Implement the five stages above with accessible progress and one primary action.
- Keep navigation state distinct from backend validity; users may inspect earlier
  stages without changing configuration or revoking approval.
- Preserve existing entry points from source reports and live migration.
- Replace duplicate stage numbers, raw statuses/keys, and competing next buttons.
- Add human-readable summaries and direct blocker navigation using existing IDs.
- Keep pagination/search for large configurations; avoid rendering all detailed
  rows or expanding full JSON by default.
- Coordinate approval → generation with distinct success/failure states.
- Show confirmation expiration and renewal action based on backend facts; client
  clocks may guide UX but cannot authorize execution.

Acceptance: a user can complete a small migration without understanding
deterministicDraft, disposition enums, signed envelopes, or decision keys. Advanced
tools remain accessible. Keyboard focus reaches the chosen exception/action;
loading/error/status announcements are usable. Apply the React review skill if
its multi-component-edit trigger applies in the implementation session.

### Phase 4 — Candidate recovery and uncertain outcomes

Primary files:

- `src/fwmigrate/deployment/{models,palo_alto_ssh}.py`
- `src/fwmigrate/web_api/deployment.py`
- `src/fwmigrate/conversion/fortigate_to_palo_alto/application/deployment_feedback.py`
- `src/frontend/src/features/migration/{MigrationWorkflow.tsx,migrationApi.ts}`
- `src/frontend/src/api/client.ts`

Introduce structured recovery information distinguishing:

- Rejected before writes.
- Some commands accepted / candidate may have changes.
- Commands sent but validation failed.
- Validated candidate with current matching session.
- Session lost/expired or candidate changed.
- Transport interruption / final outcome unknown, including commit uncertainty.

Preserve sanitized attempted/succeeded counts and failed index where trustworthy.
A timeout or missing response is not proof that no changes occurred.

Minimum recovery path must be functional: show known state, artifact/target
identity, safe next steps, and a read-only recheck of target identity, baseline,
and candidate state using existing verified transport helpers. Dirty or uncertain
candidate state requires operator reconciliation; do not offer a blind retry as
the main action. Explain that candidate changes may include other administrators'
work. Only a verified clean baseline allows a new prepare.

Do not create an automatic resume-from-command-index feature. Do not recreate a
validated session merely from client-submitted hashes. Lost-session handling can
remain conservative: report recovery required, inspect state, reconcile, then
prepare afresh. A safe authenticated session recovery enhancement is separate
from this minimum and must not weaken artifact/serial/fingerprint checks.

Acceptance: fake-transport tests cover partial push, failed validation, dirty
candidate, expired/missing session, concurrent candidate changes, network failure
after a write, and ambiguous commit response. UI keeps execution disabled until
backend-authoritative prerequisites are met. No duplicate mutation on retries or
double clicks; credentials clear according to existing policy.

### Phase 5 — Explicit project download and resume

Primary files: storage types/store, migration API/import-export handlers,
`web_support/request_source.py`, and current sanitization helpers (locate/reuse).

Use a versioned pair-specific JSON project format, rather than serializing the
entire React workspace. Proposed allowlist:

- Format identifier/version, pair, export timestamp.
- Backend-sanitized source evidence and optional target evidence.
- Evidence role and selected device; desired offline/destination workflow mode.
- Mapping proposals/overrides, service-name overrides, and source identity bindings.
- Harmless navigation preferences if useful.

Do not include credentials, raw transport output, signed approvals, artifacts as
execution authority, candidate sessions, or unknown arbitrary fields. Use existing
redaction at the backend boundary, not a new frontend regex sanitizer. Exported
files still contain sanitized customer topology: label their contents clearly.

On import: validate size/version/pair/schema before replacing state; sanitize and
reparse evidence; rebuild derived data and draft; validate mapping identities;
report unmatched entries; restore values as proposals, require new approval and
fresh deployment checks. A malformed file must not destroy the current project.
Imported destination evidence is not proof that the live device is unchanged.

Keep legacy import/export tools working. Add an obvious Download project action
and Resume project entry point, and a clear explanation that refresh otherwise
loses in-memory work. A before-unload warning may supplement explicit save, but
is not the recovery feature.

Acceptance: export → refresh/new app instance → import restores evidence and
proposals, including staged mappings and service renames, without restoring live
authority. Test malformed/oversized/unsupported-version files, mismatched source
identities, expired/forged approvals embedded in files, and seeded secrets. The
current workspace remains intact on rejected imports.

### Phase 6 — Integrated verification and documentation

Complete the acceptance matrix below. Update README user instructions, explain
offline versus destination planning, partial export, manual work, project resume,
and candidate recovery. Remove obsolete descriptions of the old nested flow.
Document unresolved platform limits honestly.

## Validation strategy

Review baseline command executed successfully (391 passed in 6.91 seconds):

```bash
.venv/bin/python -m pytest -q tests/conversion/fortigate_to_palo_alto tests/test_web_migration_design.py tests/test_web_migration_artifacts.py tests/test_web_migration_exports.py tests/test_migration_deployment_regressions.py
```

This baseline did not run frontend tests, a browser, the entire Python suite, or
real-device tests. Frontend dependencies were absent at review time. Do not claim
those passed based on the recorded backend run.

Relevant existing tests to extend:

- `tests/conversion/fortigate_to_palo_alto/`
- `tests/test_web_migration_design.py`, `tests/test_web_migration_artifacts.py`
- `tests/test_web_migration_exports.py`, `tests/test_web_migration_interface_mapping.py`
- `tests/test_web_candidate_sessions.py`, `tests/test_migration_deployment_regressions.py`
- `tests/deployment/test_palo_alto_ssh.py`, `tests/test_web_workspace.py`
- Architecture boundary tests under `tests/architecture/`.
- `src/frontend/tests/migrationWorkflow.test.mjs`
- `src/frontend/tests/migrationGuidedReview.test.mjs`
- `src/frontend/tests/migrationReviewPresentation.test.mjs`
- `src/frontend/tests/workspaceStore.test.mjs`

Use genuine source → derived → draft → approval → plan → renderer integration
tests for semantic changes. Use fake transport only for device operations.
Component harness tests alone do not prove browser navigation, focus, file
download/import, or state behavior across an actual reload.

| Scenario | Required result |
| --- | --- |
| Small supported migration with destination evidence | Guided completion; exact approved commands; consistent preview/download/bundle hash |
| Offline source with no target | Planning/export possible where supported; unverified destination visible; live preparation blocked |
| Template uploaded | Never treated as verified destination |
| Missing parent port, many dependents | One root task; affected scope visible; resolution updates dependents |
| Same object names across VDOMs | Separate identity and ownership preserved |
| Unsupported policy inspection/mixed causes | Manual work explicit; no false promise that mapping fixes it |
| Existing service/name collision | Reuse or rename based on backend comparison; dependents rebuilt; changed configuration reapproved |
| All selected objects reused | No-changes result; no artificial command or candidate push |
| Partial approval or unsupported coverage | Explicit partial export; excluded items accounted for; deployment stays blocked |
| Draft request fails or returns out of order | Previous view/staged edits retained; stale execution unavailable |
| Approval succeeds, generation fails | Retry build without silent reapproval; selection/context retained |
| Project export and new-session import | Proposals restored; secret-free; approvals and candidate authority absent |
| Partial push/unknown outcome | Recovery guidance and read-only inspection; no blind replay |
| Candidate changes after validation | Commit rejected; clear recovery state |
| Expired approval/session or server restart | Explicit renewal/recovery path; no manufactured eligibility |
| Large configuration | Pagination, root-cause grouping, responsive input, stable selection/focus |

Run applicable repository checks, using the available virtualenv/environment:

```bash
python -m compileall -q src tests
ruff check src tests
python -m pytest -q
```

From `src/frontend`:

```bash
npm ci
npm test
npm run lint
npm run build
```

Run a real browser walkthrough against the built frontend/Flask or Vite proxy.
Follow AGENTS.md for serving; Flask `/` requires built frontend assets. If browser
automation is unavailable, record that limitation and precise manual steps rather
than claiming an end-to-end pass. Measure a representative large fixture and
record fixture size/timing; do not invent a performance threshold without a baseline.

## Completion and reporting

- All phases implemented or explicitly recorded as blocked with concrete reasons.
- No regression of the conversion, scope, redaction, artifact, or deployment gates.
- All required tests/checks run, with actual results and remaining limitations.
- User documentation matches the final flow.
- Final implementation summary identifies changes, tests, and material limitations.
- Do not deploy the app, push to a device, or submit a commit to a firewall as a
  side effect of implementing this plan.

## New-session handoff prompt

> Implement `documentation/migration-workflow-implementation-plan.md` in this
> repository. Read AGENTS.md and the entire plan first, inspect current state, then
> execute phases 0–6 in order. Preserve the pair-specific deterministic conversion
> architecture and all approval, redaction, dependency, artifact, and deployment
> safeguards. Complete the application changes and relevant tests, including a
> browser walkthrough where available. Keep the plan's execution log updated so
> work can resume across sessions. Do not stop at cosmetic UI changes or a new
> proposal. Do not connect to or mutate a real firewall or deploy the application.
> Record any real blocker and test limitations accurately.

## Execution log

- 2026-10-14: Review recorded; 391 targeted backend tests passed. No application
  changes. This implementation plan created for execution in a later session.
- Phase 0: completed. Clean `work` checkout inspected, no codegraph present. Re-ran recorded baseline: 391 passed in 12.60 s. Confirmed classification, destructive draft refresh, and blind-retry recovery gaps; API envelope and legacy import/export contracts preserved. Integrated newer main commits through d2709158 before final verification.
- Phase 1: completed. Draft issues carry stable IDs/codes, scoped identities, deduplicated affected keys/sources, explanations, prerequisites and editable mapping actions. Unsupported inspection and mixed causes remain manual after placement. Final support guidance exposes additive structured categories/actions; independent coverage, approval, export and deployment facts preserve existing gates. Integration tests cover offline partial exports and root-port grouping.
- Phase 2: completed. Failed draft requests retain the last successful draft and staged mappings/service renames as read-only evidence. Retry retains exact intended inputs; request versions suppress stale responses. Semantic evidence comparisons govern invalidation. Navigation and retained selection do not authorize execution.
- Phase 3: completed. Five-stage workspace, explicit intent/evidence role (template by default), scoped exception actions/manual awareness, exact configuration/prerequisite approval, coordinated approval/build with generation retry, independent export/deployment status and approval renewal. Advanced legacy files, guided/bulk editors and pagination remain. Applied React best-practices review.
- Phase 4: completed. Structured recovery distinguishes pre-write rejection, accepted/attempted counts, partial push, validation failure, unknown outcomes, session loss, drift and confirmed commit. Read-only artifact-authenticated inspection checks live serial, baseline, clean diff and stable candidate; it never creates a session or writes migration commands. UI prevents duplicate submissions and blind replay. Fake transports cover partial write, dirty retry, lost session and interrupted commit; private transport output stays excluded.
- Phase 5: completed. Explicit allowlisted v1 FortiGate/PAN-OS project download/import sanitizes and reparses evidence, validates size/schema/pair/identity, restores staged mapping and service-name proposals, and reports unmatched identities. Unknown fields and embedded authority are rejected; malformed imports retain the current workspace. Credentials, approvals, artifacts and candidate sessions are absent. Browser refresh/new-session round trip verified.
- Phase 6: completed. README updated; optional real Chromium walkthrough and synthetic fixtures committed. Full Python suite, frontend tests/lint/build, compileall and Ruff results recorded in `migration-workflow-verification.md`. No app deployment or real-device operation performed. Hardware/licensing verification, exclusive device locking, distributed coordination and process-local session recovery remain intentionally outside scope.
