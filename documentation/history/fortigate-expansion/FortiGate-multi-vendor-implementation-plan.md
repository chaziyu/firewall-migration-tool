# FortiGate multi-vendor migration implementation plan

Prepared: 2026-10-17.
Repository: C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool
Intended executor: GPT-6 Luna, Extra High reasoning.
Status: planning document. No implementation is authorized merely by this file existing.

## Purpose and execution scope

- Implement FortiGate migration to juniper_srx, cisco_asa, cisco_ftd and checkpoint.
- Preserve the implemented fortigate -> palo_alto and palo_alto -> fortigate workflows.
- Deliver reviewed offline exports first. Add destination-aware comparison before additive target configuration.
- Each new pair must work through source analysis, requirements, target decisions, deterministic design, explicit approval, plan validation, dependency disposition, rendering, preview and download.
- Initial support is a documented subset. Every excluded source feature remains visible as manual work.
- No live deployment, publish, install-policy, commit, save-config or automatic policy assignment for the new pairs.
- FTD milestone means FMC-managed FTD. FDM is a distinct later implementation.
- Do not add other vendors or FortiGate-to-FortiGate migration.
- Do not rewrite the existing PAN-OS conversion to make it generic.

This plan is self-contained. Existing paths and symbols were inspected. New paths and symbols below are proposed additions, not claims that they already exist. Reconcile this snapshot with the checkout before editing. If the code has drifted, preserve the objective and choose the smallest compatible implementation.

## Instructions for the executing chat

- Read repository AGENTS.md and C:/Users/ziyu.cha-c/.codex/RTK.md.
- Use CodeGraph first whenever locating code or tracing callers while .codegraph exists. Do not create, regenerate or upgrade its index.
- Use current code and tests as authority. Do not implement from this document without inspecting the named code.
- Prefix shell commands with rtk. Use PowerShell and .venv/Scripts/python.exe.
- Preserve every change present when the new chat starts, including untracked files. Never reset, clean, stash, overwrite or publish them as a convenience.
- No branch change, commit or push unless directly requested. Do not create a new chat or delegate to subagents without authorization.
- Once implementation is explicitly requested, proceed phase by phase. Do not stop after creating scaffolding or offer to continue with authorized work.
- Do not claim completion of all targets after implementing only SRX or object conversion.
- Maintain a short progress log during execution. After each phase record files, behavior, commands actually run, results and remaining blockers.
- Follow the repository's applicable skills. Do not treat this document as overriding AGENTS.md.
- Explain a genuine blocking uncertainty. Continue independent work while awaiting information.
- Never invent vendor commands, endpoints, API fields, defaults or writable schemas.

## Verified repository snapshot

- Runtime: React/Vite frontend, Flask backend, fwmigrate CLI.
- Flask serves src/frontend/dist. A production build is needed before browser verification through Flask.
- Python compatibility target is 3.11-3.14; frontend CI uses Node 24.
- Existing dependencies include pydantic, Click, PyYAML, Flask and openpyxl.
- Source reporters are registered for fortigate, palo_alto, juniper_srx, cisco_asa, cisco_ftd and checkpoint.
- conversion/builtin.py currently registers only FortiGateToPaloAltoPlanner and PaloAltoToFortiGatePlanner.
- MigrationPlannerRegistry supports register/get. Its contract returns opaque pair-specific plans.
- main.migrate contains explicit existing-pair branches and format checks.
- SourceConfiguration currently chooses PAN-OS for FortiGate and FortiGate for PAN-OS, using vendor checks.
- PAN-OS forward migration has a mature deterministic design and destination-aware pipeline.
- The reverse pair demonstrates a smaller export-only web/application lifecycle.
- sign_envelope/verify_envelope authenticate arbitrary transport envelopes. verify_artifact constructs a PAN-OS RenderedMigration and must remain PAN-specific.
- RequestSource source_digest is SHA-256 of sanitized UTF-8 source + NUL + vendor identifier.
- _require_complete_collection checks snapshot collection status. It does not establish that every native manager collection/page is complete.
- Workspace state is memory-only. restoreWorkspace clears historical persisted customer data.
- AGENTS.md's descriptive current-pair text mentions only the forward pair; current code also contains the reverse pair. Preserve the architectural rules and verify actual capabilities from registration.
- The working tree is dirty. It contains the completed reverse-pair implementation and separate PAN-OS set-upload/deployment changes. They may be uncommitted when this handoff is used.
- Previous execution reported 2,245 Python tests passed, 1 skipped, 8 subtests passed, and 134 frontend tests passed. These are historical results, not validation of future edits. Rerun relevant checks.

## Non-negotiable boundaries

- VendorConfig contains explicit source state only. Missing is unknown/not explicitly configured, not any, false, empty, zero, disabled or a documented default.
- Derived/default/operational facts stay distinguishable from explicit source facts.
- Do not mutate extracted source or derived views.
- Reuse FortiGate-owned relationships and transforms, not PAN-OS planned objects.
- Do not add a vendor-neutral IR, generic semantic migration schema, TargetVendorConfig, shared firewall object model or generic cross-vendor mapping engine.
- Shared code may own registration, pair discovery, request transport, HMAC integrity and presentation. Plans, decisions, target equivalence and rendering remain pair-owned.
- Canonical pair package groups: planning, design, review, target, recommendations, rendering, application.
- Web routes import migration semantics through each pair's application facade only.
- Source reporting must remain usable without importing conversion.
- A suggestion is not confirmation. Only AUTO or CONFIRMED decisions feed a planner.
- Explicit mapping confirmation does not approve executable configuration.
- CONFIGURE is approved additive work only. REUSE emits no creation commands. BLOCK emits no commands.
- Unsupported/missing earlier traffic rules must not expose later allows.
- Never export secrets in commands, API payloads, raw evidence, errors, reports, workbook cells or logs.
- New-pair artifacts must never pass the PAN-OS deployment verifier or reach a network transport.

## Read map: existing implementation

Read selectively through CodeGraph. This is a location map, not an instruction to dump every file.

### Shared registration, acquisition and composition

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/contracts.py: PairMigrationPlanner.plan, VendorSourceConfig, VendorDerivedViews.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/registry.py: MigrationPlannerRegistry.register/get.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/builtin.py: _BUILTIN_PLANNERS, register_builtin_migration_planners.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/source_reporting/builtin.py: _BUILTIN_REPORTERS, register_builtin_source_reporters.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/main.py: vendors, migrate, disabled deploy/commit.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web.py: create_app, route composition and signing-key setup.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/source.py: register_source_routes, list_vendors, capabilities.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_support/request_source.py: RequestSource, analyze_request_source, _require_complete_collection.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_support/artifact_signing.py: sign_envelope, verify_envelope, PAN-specific verify_artifact.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/deployment.py: register_deployment_routes and nested _request_artifact.

### Source facts shared by the new directional planners

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/source_report.py: FortiGateSourceReporter.analyze_source, FortiGateSourceResult.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/derived.py: DerivedViews, build_derived_views.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/relationships/references.py: scoped reference index.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/relationships/interface_topology.py: interface/zone/topology relationships.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/transform/services.py: native service expansion.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/transform/nat.py: NormalizedSourceNAT, transform_nat.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/extraction/source_inventory.py: SourceObjectRecord, SourceCommandRecord, capture_source_objects.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/vendors/fortigate/model/source.py: FGConfig source collections. Inspect it; do not import its concrete type into conversion in violation of architecture tests.

### Workflow examples; preserve their public behavior

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_palo_alto/planner.py: FortiGateToPaloAltoPlanner.plan.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_palo_alto/pipeline.py: run_migration_pipeline, apply_explicit_options.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_palo_alto/application/review.py: build_review_state, confirm_interface_mappings.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_palo_alto/application/artifact_eligibility.py: approval and deployment boundary.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/migration.py: register_migration_routes and prepare/approve/export flow.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/palo_alto_to_fortigate/application/workflow.py: build_review, approve_design, build_artifact, verify_export_artifact, proposal import/export.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/palo_alto_to_fortigate/design/deterministic.py: build_deterministic_draft, approve_draft, validate_approval.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/palo_alto_to_fortigate/plan_dependencies.py: iterative dependency assessment.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/palo_alto_to_fortigate.py: register_palo_alto_to_fortigate_routes.

### Frontend and tests

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/source/SourceConfiguration.tsx: SourceConfiguration, clearAnalysis, vendor/target selection and workflow mounting.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/source/sourceApi.ts: loadSourceVendors, previewSource.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/MigrationReview.tsx: existing PAN review.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/MigrationWorkflow.tsx: existing PAN export/deployment.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/paloAltoToFortigate/MigrationWorkflow.tsx: smaller export-only workflow and async invalidation.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/paloAltoToFortigate/migrationApi.ts: prepare/approve/build/download and approvalSelection.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/storage/workspaceTypes.ts: Workspace.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/storage/workspaceStore.ts: saveWorkspace, restoreWorkspace.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/architecture/test_conversion_boundary.py.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/architecture/test_web_migration_boundary.py.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/architecture/test_vendor_source_report_boundaries.py.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_reverse_migration.py.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_set_import.py.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_palo_alto/test_cli_compatibility.py.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/migrationWorkflow.test.mjs.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/reverseMigration.test.mjs.
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/workspaceStore.test.mjs.

## Technical decisions settled by this plan

### Direction and delivery order

1. Preserve PAN-OS support.
2. Complete one SRX vertical slice.
3. Add destination comparison for SRX.
4. Implement ASA, then FMC FTD, then Check Point using the validated lifecycle pattern.
5. Release each pair separately after its gates. Do not expose an empty planner as implemented.

### Minimal shared infrastructure

- Add metadata discovery and orchestration only.
- A proposed MigrationWorkflowRegistration holds pair_id, source_vendor, target_vendor, display_name, api_prefix, supported_formats, export_available, destination_aware_available and deployment_available.
- Pair IDs and route registrations are server-owned constants.
- MigrationWorkflowRegistry has register, get and list. Duplicate keys fail; lookup normalizes vendor IDs only, not source object names.
- Keep PairMigrationPlanner and its existing registry compatible. An export-enabled registration must have a real registered planner and application path.
- Add GET /api/migration/pairs in a migration-specific route module. Do not make source_reporting depend on conversion.
- Do not change /api/vendors into a migration support declaration.
- Keep existing /api/capabilities live-device field unchanged.
- For the CLI, preserve the two existing execution branches. Add registered application dispatch for additional pairs; future targets should not add more inline semantic branches.
- A new-pair CLI handler accepts file paths, format and its own mapping document. It owns native analysis and pair semantics.
- Reject explicitly supplied PAN-only target-device, target-intent or automation options for new targets. Detect explicit CLI parameter use rather than rejecting an unchanged legacy default.
- Preserve existing default --format set. SRX uses set; ASA uses cli; FMC and Check Point use bundle.
- This requires no new database, package dependency, daemon or live collector.

### Pair models and decisions

- Each pair defines its own options, decisions, target-native plan and rendered result.
- Use frozen planned records. Never put an extracted config inside a plan as a writable target model.
- Source identity includes vendor, VDOM, family, explicit object/policy identity and ordering/path where needed.
- policy_id 0 and order 0 are valid values if source models allow them. Do not use truthiness to collapse them.
- Duplicate names across VDOMs are distinct. Target name allocation follows that target's case sensitivity, reserved names and limits.
- Unknown references, duplicate identities and conflicting destination objects are blockers.
- Requirements may be prepared with incomplete target choices. Building a renderable plan requires valid explicit target scope/profile.
- Missing source action/status/match fields require an authoritative derived fact with provenance or an explicit permitted target decision. A target choice cannot overwrite an explicit source value.
- Engineer confirmation cannot make an unsupported feature equivalent.

### Ordering and dependencies

- Use graphlib.TopologicalSorter or the existing iterative pattern. Avoid recursive traversal for thousands of rules.
- Every emitted rule expansion retains source rule identity and relative order.
- Start conservatively with predecessor dependencies. A blocked or unapproved earlier source rule blocks successors in the affected evaluation scope.
- If an unsupported rule's matching scope cannot be established, block the entire selected traffic slice.
- Never generate a later broad allow after silently omitting a deny.
- NAT, routing, zones and generated address objects are real dependencies.
- Avoid circular edges between a policy and its NAT. Plan dependencies must describe data prerequisites.
- If NAT activation and its consuming policy require atomic approval, represent that as a pair-owned approval group. Selecting either expands the group and its prerequisites. A blocked group emits no activating operations.
- A blocking disposition with an empty reason list is still blocked.

### Destination evidence

- Offline mode means no destination evidence. Mark collisions, traffic baseline, capacity, cabling and licensing unverified.
- Destination-aware mode uses native reporter analysis plus pair-specific checks of scope and completeness.
- Missing tables, API pages or fields do not prove absence.
- A manager bundle with a successful outer upload may still contain incomplete collections.
- REUSE requires semantic equivalence and correct ownership, not a name match.
- CREATE requires evidence that the target identity is absent in the relevant complete scope, and safe ordered placement.
- Start CONFIGURE disabled. Add only explicitly defined additive operations with tests; no replacements/deletions/binding swaps.
- Destination changes revoke approval and artifacts. Retain entered proposal values only when safe as unapproved proposals.

### Web lifecycle and artifact integrity

For each new pair, use its own API prefix and application facade.

- SRX prefix: /api/migration/fortigate_to_juniper_srx.
- ASA prefix: /api/migration/fortigate_to_cisco_asa.
- FMC FTD prefix: /api/migration/fortigate_to_cisco_ftd.
- Check Point prefix: /api/migration/fortigate_to_checkpoint.
- All request source envelopes use vendor=fortigate and sanitized source_text, or an accepted complete FortiGate snapshot.
- Proposed new-pair request fields are source, options and optional target_source. Approval requests add draft and selected_groups; build requests add approval. Download requests supply artifact and an allowlisted payload name; bundle requests also supply the bound source evidence for its workbook.
- Configuration groups, options and artifact payloads remain pair-specific. Similar transport field names do not justify a shared semantic plan/decision schema.
- An incomplete requirements/prepare request returns available source scopes, missing choices and blockers without creating export authority. Invalid syntax/type/scope receives a sanitized 4xx error. Missing mandatory target choices must not become defaults or a server error.
- For split Check Point evidence, the pair's target_source contains the reporter-supported native Management/Gaia bundle, preserving the two planes and their completeness. Do not add a second ad hoc parser in web transport.

- POST /requirements: requirements, missing choices, coverage and blockers; no executable authority.
- POST /design/prepare: deterministic signed draft from current source/options/target.
- POST /design/approve: verify signature, recompute current draft, validate selected groups and prerequisites, sign approval.
- POST /build: verify approval, recompute the approved context, validate and render selected eligible work.
- POST /preview: return the exact artifact payload projection. Do not re-render.
- POST /download: return the requested approved payload bytes.
- POST /bundle: package the same approved executable bytes plus report/proposals/source inventory.
- POST /decisions/export and /decisions/import: restore proposals only; never restore signed approval.

Existing pair endpoints remain unchanged. Use these proposed names consistently in new frontend clients.

- New envelope types are pair-specific constants, for example fortigate_to_juniper_srx:draft:v1, :approval:v1 and :artifact:v1.
- Explicitly validate envelope type, schema version, pair and context in addition to verifying HMAC.
- Approval binds source digest, selected VDOM, target digest/scope, target version/profile, mappings, decisions, exact operations, dependencies and selected groups.
- Approval expires after a documented bounded TTL; use the existing 24-hour pattern unless code requires a stronger bound.
- Reject missing, NaN/infinite, boolean or out-of-range timestamps.
- Canonical JSON must be stable, reject non-finite values and exclude only transport signature fields.
- New CLI text bytes use UTF-8 and LF joining without a trailing newline. Count includes the actual emitted CLI lines. Test non-ASCII values and escaping.
- Management bundles use API operation counts; do not call requests CLI commands.
- Multi-file artifacts include a signed manifest binding every executable payload's filename, media type, exact-byte SHA-256, length, order and operation dependencies.
- JSON request payloads are canonicalized once at build and retained as exact immutable bytes/encoded content. Downloads must not pretty-print them differently.
- Use an explicit allowlist of artifact filenames. Reject traversal, absolute paths and duplicate names.
- A workbook generated from the bound sanitized source is supporting evidence, not executable authority. Do not claim its ZIP container timestamps are deterministic.
- Generated IDs, operation order or selected scope must not change between approval and rendering.
- No API keys, cookies, login calls, passwords or session identifiers in a request bundle.
- Report executable readiness honestly. Symbolic request bundles are not directly vendor-importable files.
- New artifacts have deployment_available=false. Existing PAN deployment endpoints must reject them before transport.

## Phase 0: Preflight and preserve the checkout

- Objective: start safely from the user's real workspace.
- Prerequisites: explicit user instruction to execute.
- Files: existing AGENTS.md, pyproject.toml, src/frontend/package.json and the working-tree files reported by git status.
- Inspect branch, status, installed Python/Node runtimes and applicable skills.
- Record the initial dirty file list in the execution progress log. Do not reproduce customer source in it.
- Confirm both current pair packages exist. Inspect representative approvals/renderers/tests.
- Run focused existing regression tests before structural edits. Record any failure and use a clean-process targeted rerun before calling it existing.
- Do not run git clean/reset, create an index, install dependencies speculatively or alter deployment settings.
- Validation gate: current behavior and unrelated dirty files are understood; no baseline failures are hidden.
- Suggested progress file, created during execution: C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/FortiGate-multi-vendor-execution-progress.md.

## Phase 1: Source coverage fixtures and semantic baselines

- Objective: establish support boundaries before any new renderer can activate traffic.
- Dependencies: Phase 0.
- Existing symbols: FortiGateSourceReporter.analyze_source, build_derived_views, transform_nat, native source inventory.
- New files: shared fixture paths and coverage test listed in the file manifest.
- Build a complete happy-path fixture with explicit VDOM, interface mode/IP, zone membership, addresses/groups, TCP/UDP services, policy order, matches/actions/status and logging.
- Add variants for duplicate VDOM names, nested groups, group cycles, unknown references, raw_extra, unknown commands, central NAT, unsupported VIP/PAT, schedules, policy routing, SD-WAN, inspection and partial collection.
- Use native source text as input. Model-only unit fixtures cannot establish the end-to-end path.
- Verify the source fields used by planning are actually extracted. If missing, mark the feature unsupported; do not parse semantic values out of raw strings in conversion.
- Specifically account for central-SNAT sections: current DerivedViews.nat is not evidence that all central rules are supported.
- Record verified baseline versions in coverage documentation. Existing selected references use FMC 7.7 and Check Point R81 references. Junos baseline is not settled by this inspection.
- Pick one exact initial ASA/Junos target baseline only after checking official documentation and representative syntax. Do not silently use latest or fabricate a version.
- Allowed without a lab: offline syntax/reference verification, source parse-back and schema validation, all labeled accordingly.
- Do not change source extraction just to make a conversion test pass. Any necessary native extraction fix needs a separate focused test through its evaluator/extractor/derived boundary.
- Validation: fixture extraction, VDOM isolation, unknown-state preservation, byte/model digest unchanged after repeated planning and source reporting still independent of conversion.
- Gate: every source item is either covered, blocked or manual. No present NAT/inspection behavior is silently discarded.

## Phase 2: Pair discovery and orchestration

- Objective: let the UI/CLI select implemented pairs without spreading vendor branches.
- Dependencies: Phase 1.
- Existing edits: conversion/builtin.py, main.py, web.py, architecture tests.
- New files: conversion/workflow_registry.py and web_api/migration_pairs.py.
- Add MigrationWorkflowRegistration and MigrationWorkflowRegistry as metadata/transport registration only.
- Add register_migration_pair_routes(app) for GET /api/migration/pairs. Return a stable ordered list of public registration metadata without internal callables.
- Initially advertise only the two existing pairs. Add a new pair after its release gate.
- Keep /api/vendors and source-report contracts unchanged.
- In main.migrate, retain existing pair execution behavior and format defaults. Route new pairs through registered CLI application functions.
- Extend --format choices with bundle. SRX requires set, ASA cli, management targets bundle.
- New pairs reject unsupported legacy flags when explicitly supplied. An irrelevant default must not turn into hidden target behavior.
- Do not build a generic planner pipeline, change PAN approval schemas or make discoverability depend on source vendor being collectable.
- Validation: registry duplicates/case normalization, unavailable target rejection, capability list excludes unfinished targets, existing CLI golden/compatibility tests and architecture checks.
- Gate: existing exports remain byte-compatible; empty/new placeholders are not selectable.

## Phase 3: SRX scope, options, objects and topology

- Objective: establish the first new target-native plan without traffic policies.
- Dependencies: Phase 2 and verified Junos baseline.
- New package: fortigate_to_juniper_srx. Create only modules needed for this phase; see exact manifest paths.
- Proposed symbols: FortiGateToJuniperSRXPlanner, SRXMigrationOptions, SRXMigrationPlan, SRXMigrationDecision, build_mapping_requirements.
- Options: explicit source_vdom, target_context, target version/mode, interfaces, zones, routing placement, timezone and permitted missing-policy-field choices. Keep these SRX-owned.
- Initial scope: one selected FortiGate VDOM -> one explicitly selected standalone root Junos context and one verified routing domain. Logical systems/tenants remain manual until isolation is implemented.
- Requirements expose missing choices and explain unsupported evidence.
- Objects: IPv4 host/network/range if verified, FQDN only with verified runtime-semantics boundary, static groups and TCP/UDP service expansion.
- Do not assume target predefined application names have the same meaning as FortiGate service names. Create verified custom applications where needed.
- Honor source-port and destination-port semantics. A service override/group cycle/non-TCP-UDP feature remains blocked until explicitly supported.
- Topology: mapped Layer 3 interfaces/units, explicit IPv4 masks and VLAN parents, zones, simple static route dependencies.
- Reject duplicate physical ownership, invalid unit numbers, unverified aggregate membership and incompatible zone merges.
- A target zone containing extra source interfaces can broaden matching. Detect it; a label mapping alone does not prove equivalence.
- Unknown DHCP/secondary/management/IPv6/VRF behavior blocks affected topology and downstream policies.
- Do not set host-inbound-management services as a side effect of traffic policy migration.
- Validation: actual source -> SRX plan, deterministic names, reserved names, missing fields, group references, duplicates across VDOMs, topology dependencies and no source mutation.
- Gate: objects/topology are reviewable with complete blockers. No traffic-policy export capability yet.

## Phase 4: SRX policies, schedules, ordering and validation

- Objective: support a verified non-NAT L3/L4 traffic subset.
- Dependencies: Phase 3.
- New symbols: plan_policies, plan_schedules, validate_plan, build_plan_dependency_index, assess_render_disposition, JunosSetRenderer.
- Map explicit source interfaces/zones to reviewed zone pairs. Preserve expansion provenance and source ordering for every generated rule.
- Support only verified actions and logging. Preserve explicit disabled state with valid target inactive representation.
- Unknown policy action/status/schedule/logging requires a valid decision or blocker; no implicit permissive values.
- Preserve explicit ALL/any semantics only when native source resolution establishes the special value. A user object named all is not a universal match.
- Preserve address/service negation only after target equivalence is tested; otherwise block.
- Schedules: matching confirmed timezone, verified one-time/uniform weekly intervals first. Overnight/DST/different intervals remain manual until implemented.
- Block policies depending on NAT until Phase 5; never export them as untranslated permits.
- Block identity, Internet Services, unsupported application/security profiles, shaping, SSL inspection and unclassified policy settings.
- Add manual coverage for default/intrazone behavior. Do not imply that a set of explicit rules is a complete replacement firewall.
- Use predecessor dependencies, duplicate/cycle checks and iterative rendering disposition.
- Render object/topology prerequisites before policies. No commit, delete, replace or broad management access.
- Validation: allow/deny order, unsupported earlier rule, unapproved predecessor, multi-zone expansion, inactive rules, schedule boundaries and safe CLI quoting.
- Parse generated set lines with the native Junos source path and compare supported fields; parse-back is additional evidence, not live acceptance.
- Gate: only non-NAT, fully supported traffic groups can be exported by the CLI; manual work is reported.

## Phase 5: Restricted SRX NAT and traffic-group approval

- Objective: add the first verified NAT subset without changing packet matching.
- Dependencies: Phase 4.
- New logic in SRX planning/nat.py and related policy dependencies.
- Begin with isolated single-rule interface SNAT and single literal-address pool SNAT when source settings establish equivalent behavior.
- Preserve match selectors, order, translated address, port behavior, disabled state and source policy relation. Do not guess port-preservation behavior.
- Pool translation requires explicit return-routing/proxy-ARP design.
- DNAT begins with one address-only mapping and one provably matching policy. Require explicit ingress, mapped host, post-NAT routing/zone and ARP choice.
- Junos performs destination NAT before route/security lookup. Generate policy matching against verified translated selectors.
- Protect against newly permitting direct-to-private-address traffic. Verify a baseline-supported target match constraint or keep the DNAT policy blocked. Do not invent the command spelling.
- Multiple NAT rules, uncertain overlap, identity/no-NAT exceptions, static bidirectionality, PAT, NAT64/46 and unrepresented central-SNAT rules remain blocked initially.
- A present but unsupported NAT section must be visible and block potentially affected policies even when DerivedViews.nat contains no normalized entry.
- Model activating NAT + consuming policy as an atomic review group if independent activation could alter unrelated traffic.
- Do not introduce cyclic plan edges to force group approval.
- Validation: public versus private destination, wrong ingress, no-NAT preceding translation, overlapping rules, translation-only approval, disabled NAT, pool return path and changed topology.
- Gate: supported NAT is exact; uncertain traffic produces no activating commands.

## Phase 6: SRX deterministic review, web export and frontend slice

- Objective: finish one usable vertical slice before repeating the pattern.
- Dependencies: Phases 3-5.
- New SRX files: design/deterministic.py, application/workflow.py, application/cli.py, review/workflow.py, recommendations/support_guidance.py, web_api/fortigate_to_juniper_srx.py and its frontend directory.
- Implement build_review, approve_design, build_artifact, verify_export_artifact, export_decisions/import_decisions and write_files.
- Reuse HMAC transport functions. Recompute source/options/target context at approval and build.
- Draft deterministic identity excludes generated artifact UUID and wall-clock time. Approval expiration belongs to approval, not the deterministic plan digest.
- Display exact settings and dependency-expanded/atomic groups before the user approves.
- Validate selection server-side even if frontend expanded it. Reject duplicates, unknown keys, blocked groups and graph cycles.
- Generate artifact UUID after approved context is established. Bind payload bytes and report.
- Bundle contains juniper_config.set, migration_report.json, migration_decisions.json, target_mapping.yaml and sanitized source_inventory.xlsx.
- Source workbook is built from the artifact's bound source digest; never accept a different source at bundle time.
- Frontend stages: Source, Target setup, Review, Download. Use existing Button/ErrorBanner/LoadingState/FileUpload and API helpers.
- Add pair discovery and a target selector to SourceConfiguration. Mount existing PAN and reverse workflows as before; mount SRX only when capability is enabled.
- Preserve live PAN set upload and deployment views.
- Workspace state remains memory-only and tagged by pair/source. Pair or source changes revoke all authority; same-context validation failure retains proposals.
- Guard async responses by context/request generation. A late response cannot restore an artifact after target change.
- Failed build can retry the same current approval; a changed plan/context cannot.
- Contextual controls only: schedules/NAT/profile fields appear when relevant. All decisions affecting output remain accessible.
- Validation: Flask test_client real source -> prepare -> approve -> build -> preview/download/bundle; exact byte hashes; tampering/expiry/cross-pair rejection; component handler tests and browser happy path.
- Gate: enable SRX offline export capability only when both CLI and browser flows pass. No live-deployment controls.

## Phase 7: SRX destination-aware comparison

- Objective: add evidence-backed reuse and safe placement.
- Dependencies: Phase 6.
- Existing entry point: extract_juniper_source in vendors/juniper_srx/source_analysis.py. Inspect native derived dependencies/provenance, not only parsed collections.
- New logic: SRX target/evidence.py and target/comparison.py.
- Require verified target context, version/mode and completeness for every involved configuration family.
- Account for inactive statements, groups, apply-groups, inherited values, address-book attachment and routing instances.
- If explicit/effective ownership cannot be established, BLOCK; do not flatten inheritance into invented explicit state.
- REUSE only exact equivalent configuration. CREATE only proven absence plus safe existing policy/NAT placement.
- An existing policy list is not a blank canvas. Require a verified insertion anchor/order or keep traffic-rule creation blocked.
- CONFIGURE remains blocked until a specific additive operation is defined and tested; never replace an interface address or membership.
- Destination metadata/fingerprint is part of approval context. Mode/profile mismatch blocks generation.
- Validation: identical reuse emits no creation commands; inherited conflict, absent evidence, populated policy table, unknown anchor and changed baseline fail closed.
- Gate: destination-aware capability enabled separately from offline export. Device compatibility remains unverified.

## Phase 8: ASA implementation in three checkpoints

- Objective: deliver a complete reviewed ASA export using ASA-native policy behavior.
- Dependencies: proven lifecycle from Phase 6. Do not import SRX semantic models.
- Existing evidence: CiscoASASourceReporter.analyze_source; CiscoNATRule in vendors/cisco_asa/model/nat.py; native reference and context handling.
- New package/classes: fortigate_to_cisco_asa, ASAMigrationOptions, ASAMigrationPlan, ASAMigrationDecision, FortiGateToCiscoASAPlanner, ASACLIRenderer.
- Checkpoint A: one routed context, mapped interfaces/nameif/security-level as explicit decisions, IPv4 network/service objects/groups, verified time ranges and static routes.
- Checkpoint B: ordered access-list entries and explicit access-group bindings. Explain generated ACE expansion per source rule.
- Do not infer security levels or inside/outside from names. Do not replace an existing access-group binding.
- Critical semantic gate: an ingress ACL does not encode every FortiGate dstintf restriction. A route-selected egress is not automatically equivalent to an explicit interface match.
- Initially accept only cases where restrictions are representable or proven by a complete bound topology/routing design. If proof cannot exclude unintended egress, block the policy. Never silently omit dstintf.
- Preserve real-address ACL matching for NAT. Verify deny/drop/reject and logging semantics instead of mapping labels.
- Checkpoint C: isolated verified dynamic PAT and restricted static mappings, explicit NAT section/order, inactive state, real/mapped address handling, return routing and proxy ARP.
- Static NAT may be bidirectional. Do not turn a one-directional source VIP into broader reverse translation.
- Account for existing manual/auto/after-auto rules and identity/no-NAT exceptions. Unknown interactions block activation.
- Target comparison is ASA/context-specific: object equivalence, existing interfaces, ACL attachments, NAT ordering and complete evidence.
- Implement the same pair-owned application/HTTP/proposal/approval/export lifecycle as SRX with ASA types.
- Output asa_config.cfg plus report/mapping/source workbook. Never emit write memory or a change-context operation without an explicitly implemented multi-context design.
- Initial manual work: transparent/BVI mode, multi-context allocation, unsupported inspection/identity/VPN, complex NAT and unrepresentable interface constraints.
- Validation after A: object/topology parse-back, names and contexts. After B: ACL order/bindings, disabled rules, wrong-egress negative cases. After C: real/mapped address packet cases, NAT sections, bidirectionality, approval/dependency tests.
- Gate: advertise only the supported ASA subset after the full API/CLI/browser vertical slice passes. A route proof checkbox alone is not technical evidence.

## Phase 9: FMC-managed FTD implementation in three checkpoints

- Objective: export a verified FMC request specification, not ASA device CLI.
- Dependencies: Phase 6 lifecycle; exact FMC 7.7 writable schema verification.
- Existing evidence: extract_cisco_ftd_source, CiscoFTDConfig.source_plane/domain/device metadata, CiscoFTDAccessControlRule/Policy and native collection completeness.
- New package/classes: fortigate_to_cisco_ftd, FTDMigrationOptions, FTDMigrationPlan, FTDMigrationDecision, FortiGateToCiscoFTDPlanner, FMCRequestRenderer.
- Checkpoint A: explicit FMC/API version, domain, device/cluster, security zones, object ownership and target policy scope.
- FMC destination evidence must come from complete FMC collections. FDM/device CLI evidence is not an FMC baseline.
- Produce network/port objects/groups with target API field names checked against official writable schemas. A GET extraction shape is not automatically a POST body.
- Checkpoint B: access-control rule order, default action, prefilter effects, inheritance, device overrides and current policy assignment.
- Keep source-interface/destination-interface restrictions through verified zone placement; refuse broadening zone merges.
- New policy creation can be planned, but do not assign it to a device automatically.
- Checkpoint C: restricted NAT policy/rules with explicit order/section and target policy relationships. Resolve every original/translated selector and UUID scope.
- New objects lack server UUIDs. Use pair-owned symbolic operation references, not invented UUIDs or ambiguous names.
- Request-bundle records define operation_id, HTTP method, versioned relative path/template, body, prerequisite operation IDs, expected response ID binding and reviewed scope.
- Clearly distinguish existing resolved target UUIDs from planned response bindings. Include a binding specification and dependency order; do not claim unresolved bodies are directly executable/importable.
- Permit only reviewed configuration endpoint prefixes. No user-controlled arbitrary URL, authentication endpoint or deployment operation.
- Render fmc_operations.json and a reviewer-facing binding/ordering description; executable operation bytes are covered by the artifact manifest.
- No credentials, token acquisition, policy assignment, deployment request, on-device write or automatic runner in this milestone.
- Existing unsupported inspection/profile/source identity behavior blocks affected allow rules, even if a plain ACP rule would be syntactically valid.
- Validation: versioned minimal/invalid request fixtures, response-binding graph, duplicate/cross-domain UUIDs, incomplete pagination, overridden values, inherited/default/prefilter behavior, rule order, NAT and exact artifact bytes.
- Gate: label output Reviewed FMC request bundle. It is neither a native FMC backup nor a vendor-supported import package. Enable only after all references are bound or explicitly defined as valid planned bindings.

## Phase 10: Check Point implementation in three checkpoints

- Objective: preserve the Management/Gaia split through planning and export.
- Dependencies: Phase 6 lifecycle; verify writable Management API schema for chosen R81 target/API version.
- Existing evidence: CheckPointSourceReporter.analyze_source; CheckPointSourceResult.collection/scope/source_metadata; CPPolicyPackage, CPAccessRule, CPManualNATRule.
- New package/classes: fortigate_to_checkpoint, CPMigrationOptions, CPMigrationPlan, CPMigrationDecision, FortiGateToCheckPointPlanner, CPManagementRenderer, GaiaCLIRenderer.
- Checkpoint A: explicit domain, management target/API version, gateway/cluster, package, layer, install-on and insertion anchor. Resolve object UIDs within domain.
- Generate host/network/range/service/group/time object operations only for verified fields. Preserve enabled and negation semantics.
- Checkpoint B: one selected access layer initially, ordered rules and explicit tracking/default/cleanup behavior.
- Do not flatten inline layers, merge packages, assume install-on Any or treat a gateway assignment as interface matching.
- FortiGate interface restrictions must be represented by verified Check Point policy/topology semantics or block the rule.
- Checkpoint C: restricted manual NAT with verified original/translated matches and order. Existing automatic NAT/object nat-settings can affect results; account for them or block.
- Keep Gaia interface/route planned operations and evidence separate from Management API policy objects.
- Gaia IP/subnet/topology changes may affect gateway topology/anti-spoofing management state. Do not claim Gaia CLI alone completes the gateway design; block dependent policy where required evidence is absent.
- Use separate output files checkpoint_management_operations.json and gaia_config.clish plus a manifest binding both.
- UID response bindings for newly created objects are explicit and Check Point-owned. Do not import FTD semantic classes to reuse a similar JSON shape.
- Do not generate login/session IDs, credentials, publish, install-policy, policy assignment, save config or destructive commands.
- Initial manual work includes multi-domain merging, inline layers, automatic NAT conversion, VPN communities/secrets, inspection/identity and cluster topology changes.
- Validation after each checkpoint: domain/UID ownership, layer/section order, install-on, mixed Management/Gaia completeness, automatic/manual NAT interaction, response bindings, hashes and all approval negative cases.
- Gate: label output as a reviewed split configuration bundle. State remaining gateway topology and activation work explicitly.

## Phase 11: Complete target UI, workspace and compatibility integration

- Objective: give all released pairs a coherent workflow without replacing PAN-OS UX.
- Dependencies: completed corresponding vendor vertical slice.
- Existing files: SourceConfiguration, sourceApi, workspaceTypes, workspaceStore, existing common controls and PAN/reverse workflows.
- New files: migration/pairApi.ts, MigrationPairWorkflow.tsx and four pair-specific frontend directories.
- pairApi loads only discovery metadata and handles transport. Pair modules retain their own options, requirements and response types.
- MigrationPairWorkflow dispatches to pair components; it must not contain NAT mapping, default logic or command construction.
- Keep existing PAN workspace fields compatible. Add a typed discriminated union for new-pair workspace state, tagged by pair and source digest. Do not use an untyped cross-vendor options bag.
- Store state in memory only; existing source/target change invalidation must clear the new-pair state too.
- Do not add a shared semantic configuration-row model just to reuse a table. Presentation projections may show strings/labels/dependencies from backend-owned reports.
- Reuse common navigation/review UI only after two real call sites show identical behavior. Do not refactor all existing components first.
- Target setup controls are contextual: SRX zones/context; ASA nameif/ACL placement; FMC domain/device/policy/UUID bindings; Check Point domain/package/layer/install-on/Gaia evidence.
- Review separates mapping validation, exact design approval and artifact download.
- Search/paginate long mapping lists, configuration review and expanded approval details. A 2,500-rule plan must remain usable.
- Unavailable targets are absent or explicitly disabled with an implementation reason; they never submit to PAN endpoints.
- Changing pair, scope, mappings, version, mode, destination or operations revokes authority and invalidates pending requests.
- Failed validation retains edited values. Failed download does not silently regenerate or broaden approval.
- Validation: actual handler/hook tests, workspace invalidation, pair selection, request races, conditional controls, explicit review/approval and both pre-existing workflows.
- Gate: no mixed pair artifacts or destination evidence can survive a target switch.

## Phase 12: Final integrity, regression and release

- Objective: prove the affected real paths and document practical limits.
- Dependencies: every released pair's gates.
- Update architecture tests to include all implemented pair package names and facade-only web imports. Do not relax forbidden IR/concrete-config boundaries.
- Confirm source-report modules have no conversion imports.
- For every pair test: raw FortiGate source -> native analysis -> requirements -> decisions -> draft -> approval -> plan -> target comparison -> dependency disposition -> renderer -> preview/download/bundle.
- Compare actual output bytes, file hashes/counts and request operation counts. Test duplicate artifact filenames and path traversal rejection.
- Exercise source/profile/target/operations/dependency mutation, signature tampering, expired approvals, cross-pair/schema imports and unapproved selection.
- Prove every new artifact is rejected by /api/deploy, /api/inspect-candidate, /api/validate-candidate and /api/commit without constructing a device transport.
- Seed synthetic secret canaries in source, raw evidence and manager metadata; inspect JSON, commands, errors and every XML worksheet/shared-string part in exported XLSX.
- Run focused tests after each change. Run complete Python/frontend checks after integration, not after every trivial edit.
- Production browser verification must use a built frontend. Test synthetic files only and use authorized browser tooling.
- A previous browser run could not upload because Edge extension file-URL permission was disabled. Recheck current tools/settings; do not bypass it through hidden state/network injection or claim browser success.
- Record unrun device/API validation precisely. Parse-back and local schema tests do not establish actual target acceptance.
- Update README, conversion/README and pair-specific usage/coverage documents only after behavior is implemented.
- Only then add each new pair to builtin discovery with the correct offline/destination capability flags.
- Preserve existing API routes and CLI defaults. Do not publish or deploy.
- Gate: no unaccounted source behavior, no unsupported activation, all required validation results recorded, exact supported subset stated per vendor.

## Validation commands

Run from the repository root unless a workdir is specified. Inspect installed tools before changing dependencies.

- rtk .venv/Scripts/python.exe -m compileall -q src tests
- rtk .venv/Scripts/ruff.exe check src tests
- rtk .venv/Scripts/python.exe -m pytest -q tests/architecture
- rtk .venv/Scripts/python.exe -m pytest -q tests/conversion/fortigate_to_palo_alto tests/conversion/palo_alto_to_fortigate tests/test_web_reverse_migration.py tests/test_web_set_import.py
- rtk .venv/Scripts/python.exe -m pytest -q tests/conversion/fortigate_to_juniper_srx tests/test_web_fortigate_to_juniper_srx.py
- Repeat the preceding focused command with the actual implemented ASA/FTD/Check Point test paths.
- rtk .venv/Scripts/python.exe -m pytest -q
- Workdir C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend: rtk npm test
- Same frontend workdir: rtk npm run lint
- Same frontend workdir: rtk npm run build
- rtk git diff --check
- rtk git status --short

Use npm ci when dependencies are missing or lockfile reproduction is needed. Do not reinstall packages routinely. If Python/platform/runtime compatibility cannot be reproduced locally, state which CI jobs remain necessary. Never claim CI passed from a local run.

## Required test scenarios and expected results

- Same object name in two VDOMs: distinct source keys; selecting one never resolves through the other.
- Missing explicit field: a required decision or blocker, not a permissive source default.
- Explicit disabled rule: stays disabled; absent status is not assumed enabled.
- Unsupported earlier deny: no later allow activation in its possible matching scope.
- Partial approval of a rule chain: predecessors/atomic prerequisites are expanded or selection is rejected.
- Broken/cyclic dependency: no affected commands; human-readable root blocker.
- Long chain: at least 2,500 items without recursion failure or quadratic predecessor storage.
- Nested group/wildcard/predefined name: no accidental all/any conversion.
- Repeated target name: deterministic disambiguation or collision blocker respecting target rules.
- NAT outside normalized source path: manual coverage and dependent-policy blocking.
- Destination incomplete table/page: no CREATE/REUSE assertion from absence.
- Target extra behavior: no REUSE without proving it harmless.
- Wrong target mode/ownership: BLOCK.
- Same-context validation error: staged edits survive, stale authority does not.
- Changed source/pair/target/version: draft/approval/artifact revoked; late response ignored.
- Imported proposal: values only, no executable authority.
- Tampered artifact/report/body/file list: download/build rejected.
- Same artifact preview/download/bundle: exact identical executable bytes.
- New API object: planned response binding, never fabricated UUID.
- New-pair artifact sent to PAN deploy endpoints: rejected before network connection.
- Source secret canary: absent from all exported/logged/error surfaces.

## Definition of done

For each new destination:

- Real native source input works through the complete CLI and browser review/export path.
- Requirements and target decisions preserve scope and explicit/unknown distinctions.
- Supported rules preserve order, matching, state and dependencies.
- Unsupported features are visible and block unsafe dependent output.
- Target-native renderer and validator use a documented verified baseline.
- Destination-aware support is advertised only if completeness/reuse/placement tests pass.
- Approval and artifacts are bound to the exact current pair/context/operations.
- Download bytes are the reviewed bytes; API operation bindings are explicit.
- New artifacts cannot deploy through PAN-OS endpoints.
- Relevant tests, lint/build and full integration checks have actual recorded results.
- Usage docs state supported subset, manual steps and unverified device acceptance.
- Existing PAN-OS forward, reverse FortiGate and set-upload workflows remain working.

Completing metadata/scaffolding, producing objects only, or adding four selectable labels is not completion.

## Explicitly deferred work

- Live transport/execution for new targets and any automatic commit/publish/install-policy/save.
- FDM output, FortiManager orchestration and additional vendors.
- Broad multi-VDOM merging, ASA multi-context deployment, Junos tenants/logical systems, Check Point multi-domain merging.
- Full VPN conversion, secret provisioning, identity federation, inspection/decryption equivalence, SD-WAN and dynamic routing.
- Advanced NAT until exact match/order/bidirectionality/port behavior is implemented and tested.
- Model/hardware capacity, cabling, licensing, live candidate state and exclusive locking claims.
- Generic engine/framework/IR, source-schema redesign, unrelated UI cleanup and new runtime dependencies.

An unsupported feature remains visible. If it affects a policy, defer that policy too. Do not downgrade a requirement silently to make more commands render.

## Progress log format for context recovery

For each completed phase record:

- Phase/checkpoint and completion date.
- Objective achieved and supported behavior.
- Files changed, with full paths.
- Exact validation command and result; skipped checks and reason.
- Remaining uncertainty and affected capability flags.
- Next phase and first symbols to inspect.
- Initial dirty worktree changes still preserved.
- No credentials, customer configuration, connection tokens or source excerpts.

On resuming a compacted/new execution chat, read the progress log and git diff first. Verify status before repeating or rewriting a completed phase.

## Official reference locations and limitations

Local selected references:

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/official-cli-references-selected version/FortiGate Selected CLI References.md
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/official-cli-references-selected version/Juniper_Selected_CLI_References.md
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/official-cli-references-selected version/Cisco_ASA_Selected_Configuration_References.md
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/official-cli-references-selected version/Cisco_FTD_Selected_Configuration_References.md
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/official-cli-references-selected version/Check_Point_R81_Selected_CLI_and_Management_API_References.md

Official pages checked during the preceding review:

- [ASA access rules and real-address matching](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html)
- [ASA NAT overview and bidirectionality](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html)
- [Junos NAT processing](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html)
- [Junos destination NAT](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-destination.html)
- [Junos address-book scope](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html)
- [FMC 7.7 REST resource reference](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/Objects_In_The_REST_API.html)
- [Check Point R81 management API boundary](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_CLI_ReferenceGuide/Topics-CLIG/SPROVG/Managing-Security-through-API.htm)
- [Check Point Gaia/Management API distinction](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/API-for-Gaia.htm)

These establish architecture/processing constraints. They do not verify every future command or request body. Check the exact baseline's official writable schema when implementing each feature. If documentation is unavailable, keep that feature blocked and state the uncertainty.

## Exact new-file manifest

All entries below are proposed new files. Existing-file modifications are identified in the read map and phase instructions. Create modules only when the corresponding phase needs them; this is not permission to pre-create four empty frameworks.

## Proposed mapping-file contracts

These are pair-specific application input shapes. They are not vendor command/API payloads and not a shared migration schema. Keys below are proposed design decisions for the new modules. Validate them strictly; missing required values become requirements/blockers.

- Every new options class rejects unknown keys, wrong types, duplicate normalized target identities, control characters and invalid target names.
- Each input value retains engineer provenance. Imported YAML/JSON is proposal input, not design approval.
- Empty mappings can load requirements but cannot generate a traffic artifact.
- Scope selection is explicit; do not insert root as a missing-field fallback.
- Source keys are generated by requirements from the current source; do not let arbitrary imported identities become planner input.
- Parse IP/mask, port intervals, VLAN IDs, route distance, timezone syntax and naming limits at the correct pair boundary. Unknown semantic equivalence still blocks after syntax passes.
- Native target version/mode must match the declared profile when destination evidence is used.

SRXMigrationOptions proposed fields:

- source_vdom: selected source VDOM string.
- target_context: explicit standalone root context for the initial subset.
- profile: pair-owned target version, routing/flow mode, verified physical/logical port inventory.
- interfaces: source interface identity -> target physical/unit placement.
- zones: source zone/interface identity -> target security-zone placement.
- routing_instances: source routing identity -> explicitly selected supported target routing domain.
- timezone: confirmed source/target timezone match for schedule conversion.
- policy_settings: generated source policy key -> allowed target choices for omitted source fields.
- nat_settings: generated source NAT identity -> reviewed ARP/return-route/translation prerequisites.
- Do not accept target_context for logical systems/tenants until that support is implemented.

ASAMigrationOptions proposed fields:

- source_vdom, target_context and profile: explicit routed ASA version/context/port inventory.
- interfaces: source identity -> interface, nameif and explicit security-level choice.
- acl_bindings: source ingress scope -> new/reused ACL and reviewed binding/placement.
- routing: reviewed native route/topology placement; proof evidence references are bound to the target digest.
- timezone, policy_settings and nat_settings: ASA-owned meanings and supported choices.
- An egress_equivalent boolean must not substitute for validating dstintf preservation.

FTDMigrationOptions proposed fields:

- source_vdom, management_version, api_version, domain_uuid.
- device_uuid or explicitly supported cluster UUID, selected from current destination evidence.
- access_policy: existing UUID or explicit planned-create identity, plus placement/default action decisions.
- security_zones: source interface/zone identity -> existing/planned FMC zone with verified device membership.
- nat_policy: existing UUID or explicit planned-create identity and rule placement.
- timezone, policy_settings, nat_settings and verified object reuse selections.
- Offline exports may retain explicit unbound environment parameters but must label them unresolved and non-executable. They cannot claim destination-aware readiness.
- Do not accept FDM management-plane identifiers or a made-up UUID to complete missing fields.

CPMigrationOptions proposed fields:

- source_vdom, management_version, api_version, domain identity.
- gateway_or_cluster: explicit verified install target identity.
- policy_package, access_layer and insertion_anchor: existing UID or explicitly modeled planned creation where the API supports it.
- install_on: explicit selected target identities; never inferred Any.
- topology: pair-owned source interface placement and Management/Gaia evidence associations.
- timezone, policy_settings, nat_settings and verified UID reuse selections.
- management_evidence and gaia_evidence remain distinct inputs/scopes; absence of Gaia evidence cannot prove interface or route readiness.
- No field accepts credentials, publish/session state or arbitrary API URLs.

Requirements responses must enumerate exact policy keys, permissible choices and why each is needed. Ship example mapping documents with complete synthetic source fixtures after the first successful native pipeline test. Do not write examples with guessed identity strings.

### Shared additions

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/workflow_registry.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/migration_pairs.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/pairApi.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/MigrationPairWorkflow.tsx
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/test_workflow_registry.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/test_fortigate_multi_vendor_source_coverage.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_migration_pairs.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/fixtures/fortigate/multi_vendor_explicit.conf
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/fixtures/fortigate/multi_vendor_blockers.conf
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/migrationPairs.test.mjs

### fortigate_to_juniper_srx

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/models.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/options.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planner.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/requirements.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/decisions.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/validation.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/plan_dependencies.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/source_scope.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/naming.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/design/deterministic.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/review/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/target/profile.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/target/evidence.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/target/comparison.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/recommendations/support_guidance.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/application/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/application/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/application/cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/topology.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/policies.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/schedules.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_juniper_srx/rendering/renderer.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/fortigate_to_juniper_srx.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToJuniperSrx/MigrationWorkflow.tsx
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToJuniperSrx/migrationApi.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToJuniperSrx/types.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/conftest.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_scope_objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_topology.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_policies.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_target_comparison.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_approval_artifacts.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_juniper_srx/test_cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_fortigate_to_juniper_srx.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/fortigateToJuniperSrx.test.mjs
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/fortigate_to_juniper_srx-migration.md

### fortigate_to_cisco_asa

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/models.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/options.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planner.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/requirements.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/decisions.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/validation.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/plan_dependencies.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/source_scope.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/naming.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/design/deterministic.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/review/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/target/profile.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/target/evidence.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/target/comparison.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/recommendations/support_guidance.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/application/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/application/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/application/cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/topology.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/acl.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/schedules.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/planning/nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_asa/rendering/renderer.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/fortigate_to_cisco_asa.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCiscoAsa/MigrationWorkflow.tsx
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCiscoAsa/migrationApi.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCiscoAsa/types.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/conftest.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_scope_objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_topology.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_acl.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_target_comparison.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_approval_artifacts.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_asa/test_cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_fortigate_to_cisco_asa.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/fortigateToCiscoAsa.test.mjs
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/fortigate_to_cisco_asa-migration.md

### fortigate_to_cisco_ftd

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/models.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/options.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/planner.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/requirements.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/decisions.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/validation.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/plan_dependencies.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/planning/source_scope.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/planning/naming.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/design/deterministic.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/review/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/target/profile.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/target/evidence.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/target/comparison.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/recommendations/support_guidance.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/application/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/application/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/application/cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/planning/objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/planning/access_control.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/planning/nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_cisco_ftd/rendering/fmc.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/fortigate_to_cisco_ftd.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCiscoFtd/MigrationWorkflow.tsx
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCiscoFtd/migrationApi.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCiscoFtd/types.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/conftest.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_scope_objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_access_control.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_fmc_evidence.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_response_bindings.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_approval_artifacts.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_cisco_ftd/test_cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_fortigate_to_cisco_ftd.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/fortigateToCiscoFtd.test.mjs
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/fortigate_to_cisco_ftd-migration.md

### fortigate_to_checkpoint

- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/models.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/options.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planner.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/requirements.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/decisions.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/validation.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/plan_dependencies.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planning/source_scope.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planning/naming.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/design/deterministic.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/review/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/target/profile.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/target/evidence.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/target/comparison.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/recommendations/support_guidance.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/application/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/application/workflow.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/application/cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planning/objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planning/access_policy.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planning/nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/planning/gaia.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/rendering/management.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/conversion/fortigate_to_checkpoint/rendering/gaia.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/fwmigrate/web_api/fortigate_to_checkpoint.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCheckpoint/MigrationWorkflow.tsx
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCheckpoint/migrationApi.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/src/features/migration/fortigateToCheckpoint/types.ts
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/__init__.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/conftest.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_scope_objects.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_access_policy.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_nat.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_management_gaia.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_response_bindings.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_approval_artifacts.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/conversion/fortigate_to_checkpoint/test_cli.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/tests/test_web_fortigate_to_checkpoint.py
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/src/frontend/tests/fortigateToCheckpoint.test.mjs
- C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/fortigate_to_checkpoint-migration.md

Add package __init__.py files where required by the established import/test layout. Do not create unused re-export shims. If one proposed module is too small to justify a separate file, keep its function in the existing canonical package module and record the consolidation in the progress log; do not change the architectural boundaries.

