# FortiGate Multi-Vendor Execution Progress

Updated: 2026-10-17 (Asia/Kuala_Lumpur)

## Phase 0: Preflight and preserve the checkout - complete

- Baseline: branch main; HEAD and origin/main both 949415836471cd21241de8d363b134eac22df3ff.
- Runtime: .venv/Scripts/python.exe reports Python 3.14.7; Node reports v24.20.0.
- Initial focused regression: 681 passed in 35.15s.
- CodeGraph was used before source inspection. The repository has separate source reporting and pair-specific migration boundaries.
- Junos release baseline selected: 25.2R1. ASA target baseline selected: 9.20, single context, routed mode; target syntax was checked against Cisco's 9.20 guides.
- All pre-existing dirty paths were preserved. Startup inventory:
  README.md
  documentation/PAN-OS-migration-command-verification.md
  src/frontend/src/App.css
  src/frontend/src/features/migration/MigrationReview.tsx
  src/frontend/src/features/migration/MigrationWorkflow.tsx
  src/frontend/src/features/migration/components/MigrationDesignReview.tsx
  src/frontend/src/features/migration/migrationApi.ts
  src/frontend/src/features/source/SourceConfiguration.tsx
  src/frontend/src/storage/workspaceStore.ts
  src/frontend/src/storage/workspaceTypes.ts
  src/frontend/tests/migrationWorkflow.test.mjs
  src/frontend/tests/workspaceStore.test.mjs
  src/fwmigrate/conversion/README.md
  src/fwmigrate/conversion/builtin.py
  src/fwmigrate/main.py
  src/fwmigrate/web_api/deployment.py
  src/fwmigrate/web_support/request_source.py
  tests/architecture/test_conversion_boundary.py
  tests/architecture/test_web_migration_boundary.py
  documentation/FortiGate-multi-vendor-GPT-6-Luna-handoff.md
  documentation/FortiGate-multi-vendor-implementation-plan.md
  documentation/PAN-OS-to-FortiGate-migration.md
  src/frontend/src/features/migration/components/MigrationSetUpload.tsx
  src/frontend/src/features/migration/paloAltoToFortigate/
  src/frontend/tests/reverseMigration.test.mjs
  src/fwmigrate/conversion/palo_alto_to_fortigate/
  src/fwmigrate/deployment/panos_set_import.py
  src/fwmigrate/web_api/palo_alto_to_fortigate.py
  src/fwmigrate/web_support/set_import_artifacts.py
  tests/conversion/palo_alto_to_fortigate/
  tests/deployment/test_panos_set_import.py
  tests/fixtures/palo_alto/fortigate_conversion.xml
  tests/test_web_reverse_migration.py
  tests/test_web_set_import.py
- No customer configuration or credential data is recorded here.

## Phase 1: Source coverage and collection completeness - complete

- Added synthetic FortiGate fixtures tests/fixtures/fortigate/multi_vendor_explicit.conf and tests/fixtures/fortigate/multi_vendor_blockers.conf. They cover VDOMs, topology, objects/groups, schedules, ordered policies, unknown settings and unsupported NAT, SD-WAN, and policy-routing evidence.
- Added tests/test_fortigate_multi_vendor_source_coverage.py for explicit extraction, preserved unknown evidence, source immutability and collection completeness.
- Updated src/fwmigrate/web_support/request_source.py so incomplete or unsupported parts fail the snapshot trust check even when the outer snapshot claims SUCCESS. Complete empty parts and raw source envelopes remain valid.
- Central SNAT and policy-routing remain untyped source evidence and must block affected target policy flows.
- Validation: focused regression including PAN-OS, reverse migration, set upload, migration design, collection and architecture tests: 705 passed in 14.15s. Ruff passed. git diff --check passed.

## Phase 2: Pair discovery and CLI dispatch - complete

- Added src/fwmigrate/conversion/workflow_registry.py for directional pair lookup, duplicate rejection, stable listing, public metadata and optional pair-owned CLI dispatch.
- Updated src/fwmigrate/conversion/builtin.py, src/fwmigrate/main.py and src/fwmigrate/web.py. Added src/fwmigrate/web_api/migration_pairs.py with GET /api/migration/pairs.
- Only FortiGate to PAN-OS and PAN-OS to FortiGate are registered. Existing pair branches remain. New pairs must register their own CLI application and only become discoverable after their gate.
- Added tests/conversion/test_workflow_registry.py and tests/test_web_migration_pairs.py; extended tests/test_web_reverse_migration.py.
- Validation: focused regression: 717 passed in 14.32s. Ruff passed. git diff --check passed. A synthetic PAN-OS CLI smoke run produced palo_alto_config.set and migration_report.json with NEEDS_MAPPING.
- No new target pair is discoverable yet.

## Phase 3: SRX source scope, objects and topology - complete

- Added the initial pair package under src/fwmigrate/conversion/fortigate_to_juniper_srx/: __init__.py, models.py, options.py, planner.py, requirements.py, planning/naming.py, planning/objects.py and planning/topology.py.
- Added tests/conversion/fortigate_to_juniper_srx/__init__.py, conftest.py, test_scope_objects.py and test_topology.py.
- Plans one selected FortiGate VDOM to explicitly mapped Junos root/standalone context and inet.0. Other VDOMs remain visible as non-blocking manual findings.
- Supports only explicitly configured IPv4 prefixes/ranges, static address groups, TCP/UDP service expansions, mapped Layer 3 physical/VLAN interfaces, zones and simple static routes. Missing or unsupported fields block the affected item.
- Rejects duplicate source interfaces, duplicate target physical ownership, invalid/overlapping route data, group cycles, unknown references, unsupported protocols and zone merges. Source data is not mutated. Source comments are excluded from plan settings.
- Updated synthetic fixtures only: explicit VLAN mode/status, an IPv4 range, sensitive-looking non-secret comment text, service-group cycles and an incomplete route.
- Vendor syntax checked: FortiOS 7.4 address range uses explicit iprange/start-ip/end-ip; Junos 25.2R1 generic static logical-unit range is 0 through 16385, with platform/interface compatibility varying. Hardware compatibility is not claimed.
- Juniper refs: https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/306021697/config-firewall-address and https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/unit-edit-interfaces.html
- Validation: focused integration regression: 726 passed in 14.27s. Ruff passed for the SRX package/tests. git diff --check passed.
- Gate result: object and topology plans are reviewable with blockers. No traffic-policy export capability exists yet.
- Next: Phase 4, SRX policy ordering, schedules, validation, dependency disposition and set-line rendering.

## Phase 4: SRX policies, schedules, ordering and rendering - complete

- Added pair-owned policy planning in src/fwmigrate/conversion/fortigate_to_juniper_srx/planning/policies.py. It requires complete source inventory, explicit fields and supported non-NAT actions; resolves source references through FortiGate relationships; maps only verified IPv4 ALL semantics; expands source interfaces into mapped zone pairs; preserves order with predecessor dependencies; and blocks unknown scope, untranslated central SNAT/router policy evidence, unsupported policy sections and unsupported inspection/identity settings.
- Added recurring and one-time schedule planning in planning/schedules.py. Timezone must be explicitly confirmed and available through IANA timezone data. Overnight intervals, schedule groups, unknown fields and DST-sensitive intervals remain blocked. The recurring DST screen checks the fixed 2026 annual cycle; extend or replace this check if the target baseline or supported horizon changes.
- Added JunosSetRenderer in rendering/renderer.py. It validates dependency cycles and missing references, emits only dependency-complete items, orders prerequisites before policies, hashes the exact newline-terminated UTF-8 command text, and emits no commit/delete/replace commands. Inactive policies use Junos deactivate. It omits source comments.
- Tightened target zone token validation and Junos static route preference range checks. Corrected one-time Junos schedule timestamps to the documented yyyy-mm-dd.hh.mm form after checking the Juniper CLI reference.
- Added tzdata>=2024.1 to pyproject.toml and locked tzdata==2026.5 in requirements/constraints-python312.txt. The local .venv installed tzdata 2026.5 for validation; pip check reported no broken requirements.
- Kept multi_vendor_explicit.conf faithful to its source VLAN zone membership. Policy tests use a separately analyzed synthetic variant without that unsupported VLAN member so they can exercise the supported policy path. This is test-only; real zones containing unsupported VLAN interfaces remain blocked.
- Juniper references checked: security policy configuration and ordering, address books/address sets, custom applications/application sets, scheduler statements and scheduling, logging, static routes and preference, plus the start-date format. See https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html, https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-address-book.html, https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/applications-edit-destination-port.html, https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/scheduling-security-policy.html, https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/schedulers-edit-start-date.html, https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html and https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/preference-edit-routing-options.html.
- Validation: focused pair suite: 25 passed in 0.66s. Broader Phase 4 regression: 668 passed in 12.91s. SRX Ruff passed. `pip check` found no broken requirements. `git diff --check` passed. Rendered synthetic set lines round-tripped through JuniperSRXSourceReporter with no unsupported commands and resolved policy references.
- Gate result: offline non-NAT SRX policy/schedule set output is available for complete, mapped synthetic inputs. Source inventory must be passed by CLI/web callers in Phase 6. VLAN topology remains blocked pending target platform compatibility evidence. Native Junos CLI/vSRX validation was not available or performed.
- Next: Phase 5, inspect and add only verified restricted SRX source NAT; block unsupported, central and ambiguous NAT without exposing untranslated permits.

## Phase 5: SRX NAT evidence and traffic-group blocking - gated

- Added `planning/nat.py`. Enabled policy NAT now creates a pair-owned `source_nat` review item linked to its source policy. The policy depends on that item, both share one deterministic `approval_group`, and there is no policy/NAT dependency cycle.
- The plan preserves normalized source mode, address/pool, egress, source policy identity, zone pair and policy selectors for review. It blocks missing/ambiguous/multiple normalization, disabled source policies, unsupported modes, unverified earlier permit overlap, pool return-route/proxy-ARP requirements, and missing port-preservation evidence.
- FortiGate VIP/VIP group evidence is reported. Policies that reference a VIP as a destination receive `POLICY_DESTINATION_VIP_DNAT_UNSUPPORTED`. Central SNAT remains blocking through source inventory, even if no normalized per-policy NAT exists.
- No Junos NAT commands are rendered. FortiGate `FGPolicy` does not extract `port-preserve`; the policy's source-port choice cannot be proven from the current model. Official FortiOS 7.4 documentation says policy SNAT preserves an original source port when available by default, while Junos source interface NAT uses port-overloading behavior. Pool NAT also needs explicit return-routing/proxy-ARP choices. DNAT remains blocked because the current policy mapping cannot safely constrain translated versus direct-to-private matches.
- Official refs checked: https://docs.fortinet.com/document/fortigate/7.4.0/new-features/758009/fine-tuning-source-port-behavior-for-snat-7-4-4, https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/nat-security-source-and-source-pool.html, https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-port-overloading-interface-source-nat.html, https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html and https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-destination.html.
- Changed paths: `src/fwmigrate/conversion/fortigate_to_juniper_srx/models.py`, `planner.py`, new `planning/nat.py`, new `tests/conversion/fortigate_to_juniper_srx/test_nat.py`, and this progress log.
- Tests added in `tests/conversion/fortigate_to_juniper_srx/test_nat.py` use native FortiGate source text. They cover interface/pool NAT, earlier permit overlap, disabled policy, missing/multiple normalized entries, dependent VIP rules, atomic grouping and zero NAT activation output.
- Validation commands/results: `rtk proxy .venv\Scripts\python.exe -m pytest -q tests/conversion/fortigate_to_juniper_srx` (32 passed); the focused cross-pair/source/deployment/architecture regression command from Phase 4 with the SRX suite included (675 passed in 14.48s); `rtk proxy .venv\Scripts\python.exe -m ruff check src/fwmigrate/conversion/fortigate_to_juniper_srx tests/conversion/fortigate_to_juniper_srx` (passed); `rtk git diff --check` (passed).
- Gate status: fail-closed coverage is implemented; the plan's first verified active NAT subset is not enabled because exact source-port equivalence is not established by extracted source evidence. Do not call NAT supported or remove its blockers without a native extraction change and exact Junos equivalence proof.
- Remaining Phase 5 risks: pool SNAT return routing/proxy ARP and PAT remain unverified; DNAT policy behavior remains blocked to prevent direct-to-private exposure. Continue Phase 6's independent non-NAT SRX review/export slice while these NAT cases stay blocked.

## Current remaining work

- Phase 9: FMC-managed FTD reviewed request specification is blocked pending exact FMC 7.7 writable schemas.
- Phase 10: separate Check Point Management and Gaia outputs.
- Phase 11-12: shared target comparison and integration/release gates as ordered in the implementation plan.

## Phase 9: FMC-managed FTD - gated on versioned writable schemas

- Checked Cisco's FMC 7.7 REST API Quick Start Guide. It documents the `POST` endpoint paths for networks, network groups, protocol/port objects, access policies, access rules and NAT policies, plus insertion controls for access-rule ordering. It does not publish the request-body schemas needed to create these resources.
- Cisco's documentation points operators to the API Explorer served by the installed FMC for the exact OpenAPI specification. Access to an FMC 7.7 instance is not available in this offline implementation, and no live FMC calls or sandbox credentials were used.
- The public Cisco DevNet schemas found during research identify themselves as cdFMC API 1.17.0. They were not treated as proof of the on-prem FMC 7.7 writable schema.
- Blocked scope: request bodies for network/port objects and groups, ACP/default action/rule ordering, and NAT rules. Without those bodies, no FMC operation bundle can be labeled reviewed or emitted as executable request specifications. No pair registration, guessed POST body, user-controlled URL, authentication flow, policy assignment, or deployment operation was added.
- Official references checked: [FMC 7.7 REST API overview](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/About_The_Firepower_Management_Center_REST_API.html), [FMC 7.7 REST object endpoints](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/Objects_In_The_REST_API.html), and Cisco's [API Explorer guidance](https://developer.cisco.com/docs/secure-firewall/).
- Validation: reviewed official published endpoint and API Explorer documentation; no implementation tests were run because no FTD code was enabled.
- Next: continue Phase 10 independently. Reopen Phase 9 only when the FMC 7.7 OpenAPI export or equivalent versioned writable schema is available; validate fixtures against that schema before enabling the pair.

## Phase 8: FortiGate to Cisco ASA - complete for the verified offline subset

- Selected Cisco ASA 9.20 with one VDOM, one security context and routed firewall mode. Official ASA 9.20 references checked: [interface configuration](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/interface-basic.html), [access rules](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html), [NAT](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html), and the [ASA 9.20 CLI guide PDF](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config.pdf) for time-range behavior.
- Pair package covers explicit IPv4 address/range objects and groups, TCP/UDP destination-port services and groups, mapped physical interfaces, static IPv4 routes, recurring weekly time ranges, ordered extended ACL entries, and default-deny ACL entries. Missing or unknown source fields block affected items.
- FortiGate destination-interface restrictions other than `any`, unsupported inspection/identity settings, and policy order without explicit IDs block. Disabled rules remain `inactive`. The renderer emits no `access-group` without complete target binding evidence.
- NAT, VIPs, VIP groups and dependent policy activation remain blocked: ASA syntax is documented, but source/target NAT ordering, direction, real/mapped matching, and proxy-ARP equivalence have not been proven. No NAT commands are rendered.
- Added pair-owned React workflow, typed API client and memory-only workspace state. It supports explicit context/mode/version and interface decisions, review, dependency-closed signed approval, exact artifact preview, config download, reviewed bundle, and proposal import/export. ASA remains isolated from the PAN-OS `MigrationWorkflow` and deployment routes.
- Changed frontend paths: `src/frontend/src/features/source/SourceConfiguration.tsx`, `src/frontend/src/storage/workspaceTypes.ts`, `src/frontend/src/storage/workspaceStore.ts`, `src/frontend/src/features/migration/fortigateToCiscoAsa/`, and `src/frontend/tests/migrationWorkflow.test.mjs`, `src/frontend/tests/workspaceStore.test.mjs`.
- Added `documentation/fortigate_to_cisco_asa-migration.md` with the supported subset and explicit manual limits.
- Validation: ASA package/API/CLI tests: 14 passed; frontend tests: 140 passed; frontend lint and production build passed; `git diff --check` passed.
- Browser check: headless Microsoft Edge with the synthetic FortiGate source completed target setup, dependency review, signed approval, preview, config download, and reviewed bundle download. Both downloaded configurations matched the exact signed preview bytes. The server logged 200 for each ASA API call. The only HTTP errors were 404s for two font files; they did not block the workflow.
- Native ASA/ASAv/vASA acceptance was not available or performed. Checkpoint C NAT/VIP output remains manual because source/target ordering, direction, return path and proxy-ARP equivalence are unproven. Phase 11 still owns browser destination-snapshot completeness controls.
- Next: Phase 9 FMC-managed FTD request-specification slice. Preserve ASA NAT/VIP blockers and the native-device validation limit.

## Phase 6: SRX deterministic review, web export and frontend slice - complete

- Added deterministic pair/source/options-bound draft identity, server-side dependency and approval-group expansion, duplicate/unknown/blocked/cycle rejection, expiring signed approval, signed offline artifact verification, and pair/source-bound proposal import/export.
- Added review reports with item settings, blockers, dependency details and guidance. CLI output now writes this complete report with command count/SHA, source digest and offline-only limits.
- Added FortiGate -> Juniper SRX CLI `set` dispatch. `--target-config` remains rejected until Phase 7; the CLI does not require web approval and does not enable deployment.
- Added Flask routes for requirements, prepare, approve, build, exact command preview/download, bundle and proposal import/export. The bundle reuses the artifact command bytes and includes a sanitized FULL-profile source workbook.
- Added server-discovered target selection and the React SRX Source/Target setup/Review/Download flow. Workspace state is memory-only and tied to pair/source; pair/source changes clear approval and artifacts. Failed same-context revalidation preserves options. Target timezone requirements refresh after VDOM selection.
- Browser preview, downloads and bundle all validate the same signed artifact. `/api/deploy` rejects SRX envelope types before PAN-OS transport; this is covered by a transport-factory sentinel test.
- Changed backend paths: `src/fwmigrate/conversion/fortigate_to_juniper_srx/application/workflow.py`, `application/cli.py`, `design/deterministic.py`, `review/workflow.py`, `recommendations/support_guidance.py`, `src/fwmigrate/conversion/builtin.py`, `src/fwmigrate/main.py`, `src/fwmigrate/web.py`, and new `src/fwmigrate/web_api/fortigate_to_juniper_srx.py`.
- Changed frontend paths: `src/frontend/src/features/source/SourceConfiguration.tsx`, `sourceApi.ts`, `types.ts`, `src/frontend/src/storage/workspaceStore.ts`, `workspaceTypes.ts`, and new `src/frontend/src/features/migration/fortigateToJuniperSrx/` files.
- Added `tests/conversion/fortigate_to_juniper_srx/test_design.py`, `test_cli.py`, `tests/test_web_fortigate_to_juniper_srx.py`, and SRX approval/pair-discovery and workspace invalidation checks in frontend tests.
- Validation: focused cross-pair/source/deployment/architecture regression: 141 passed in 9.17s. SRX backend Ruff passed. Frontend `rtk npm test`: 138 passed; `rtk npm run lint` and `rtk npm run build` passed. `rtk git diff --check` passed.
- Browser check: headless Microsoft Edge through the preinstalled Python Playwright runtime uploaded a synthetic FortiGate source, selected SRX, mapped VDOM/interfaces/zones, prepared and approved a review, verified rendered security-policy lines, and downloaded both `juniper_config.set` and the migration bundle. No browser or dependency was added to the repository.
- Gate result: SRX offline set export is enabled for supported mapped non-NAT items. NAT and VLAN compatibility remain blocked. Destination comparison and live deployment are unavailable. Native Junos CLI/vSRX validation was not performed.
- Next: Phase 7, inspect Juniper native derived state and provenance, then add fail-closed destination comparison without weakening the offline export gate.

## Phase 7: SRX destination-aware comparison - comparison implemented; UI discovery gate deferred to Phase 11

- Added pair-owned target evidence/comparison in `src/fwmigrate/conversion/fortigate_to_juniper_srx/target/`. It uses native Juniper source analysis and derived inheritance, including local/inherited statement paths, inactive state, group-resolution issues, dependencies, address-book attachment and routing-instance context.
- Target metadata must match the planner's root context, Junos 25.2R1 baseline and standalone mode. Callers must declare complete target configuration families. The report identifies this as operator-declared snapshot completeness, not live device validation. The sanitized configuration and metadata fingerprint are bound into the design draft, approval and artifact; a changed snapshot invalidates approval.
- Exact effective item configuration is `REUSE` and emits no creation commands. A complete declared family with no matching or conflicting item can be `CREATE`. Conflicts, inactive target entries, incomplete extraction/dependencies, unresolved groups and profile mismatches block. `CONFIGURE` is not emitted. Traffic-policy creation remains blocked because an insertion anchor cannot be established. Exact policy reuse also requires matching zone-pair order and no unresolved address-book, routing-instance, group-order or destination-NAT interaction.
- Wired destination evidence through the SRX web API and `--target-config`. CLI metadata is supplied under `target_evidence` in `--zone-map`, with `context`, `version`, `mode` and `complete_families`. Preview/download/bundle continue to use the signed command bytes. Reports set `destination_snapshot_compared` and `snapshot_evidence_complete`; `destination_verified` stays false without a live-device check.
- Juniper references checked: [show configuration](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-configuration.html) reports the committed configuration; [display set](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-pipe-display-set.html) renders recreatable set commands; [display inheritance](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-pipe-display-inheritance.html) exposes inherited values and their source; [apply-groups](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/apply-groups.html) defines group priority; [address-book behavior](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html) documents zone attachment and lookup priority.
- Added `tests/conversion/fortigate_to_juniper_srx/test_target_comparison.py`, target-fingerprint/approval coverage in `tests/test_web_fortigate_to_juniper_srx.py`, and target-config CLI coverage in `tests/conversion/fortigate_to_juniper_srx/test_cli.py`.
- Validation: SRX/API suite: 54 passed; cross-pair/source/deployment/architecture regression: 152 passed; SRX/backend Ruff passed; `rtk git diff --check` passed. Native Junos/vSRX acceptance was not available or performed.
- Registry `destination_aware_available` remains false until Phase 11 adds target snapshot upload and completeness controls to the browser workflow. CLI and API comparison are implemented and tested. No new target deployment path was added.

## Phase 10: FortiGate to Check Point - complete for the verified offline subset

- Completed 2026-10-17. Added a pair-owned Check Point Management API 1.8.1 request specification and a separate Gaia static-route file. Management and Gaia stay separate; no live transport, package publish, policy installation, or Gaia save operation is emitted.
- Supported subset: one selected VDOM; IPv4 host/network objects; explicit TCP/UDP services; complete acyclic address/service groups expanded to leaf UIDs; ordered explicit IPv4 policies only with `any` interfaces, `always` schedule, explicit disabled NAT/UTM and supported actions/logging; explicit IPv4/IPv6 Gaia static routes with a same-family gateway and disabled blackhole.
- Unsupported/blocked scope: IPv6 policy matching, interface-bound policy, unknown fields or state, non-always schedules, NAT/central SNAT, identity/inspection, ambiguous or cyclic references, unsupported earlier rules, and route topology/selection fields outside the verified subset. Destination comparison remains unavailable. Existing target objects/package contents require manual checking.
- Official baselines checked: [Check Point Management API R81 v1.8.1](https://sc1.checkpoint.com/documents/latest/APIs/#web/add-access-rule~v1.8.1), [Gaia R81 IPv4 static routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv4-Static-Routes-Gaia-Clish.htm), and [Gaia R81 IPv6 static routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv6-Static-Routes.htm).
- Backend paths: `src/fwmigrate/conversion/fortigate_to_checkpoint/`, `src/fwmigrate/web_api/fortigate_to_checkpoint.py`, and Check Point route registration in `src/fwmigrate/web.py`.
- Added tests in `tests/conversion/fortigate_to_checkpoint/` and `tests/test_web_fortigate_to_checkpoint.py`. Coverage includes UIDs/order, dependency chain of 2,500 items, cycles, nested/mixed-protocol groups, duplicate/scoped names, central SNAT, unknown secret canary, Gaia IPv4/IPv6, exact approved bytes, stale/tampered artifacts, and a PAN-OS transport-construction sentinel for all deployment endpoints.
- Check Point CLI accepts `--format json` and writes unapproved review material. Web download still requires current signed approval. New artifacts are not sent through PAN-OS deployment transport.
- No Check Point Management server or Gaia device was available; no live acceptance or native device validation was performed.

## Phase 11: Pair workflow, discovery, and memory-only workspace - complete

- Added `src/frontend/src/features/migration/pairApi.ts` for server discovery and `MigrationPairWorkflow.tsx` for dispatch to SRX, ASA, and Check Point pair components. PAN-OS and reverse workflows retain their existing components and paths. Unavailable pairs show an explicit disabled message and never fall through to another pair.
- `SourceConfiguration.tsx` uses the shared pair dispatcher and server discovery. SRX, ASA, and Check Point state now use a pair-tagged `NewPairMigrationWorkspace` union in `workspaceTypes.ts`; `workspaceStore.ts` clears it on source, pair, target, or workflow-context changes. No customer configuration is persisted.
- Changed pair-owned frontend paths: `src/frontend/src/features/migration/fortigateToJuniperSrx/`, `fortigateToCiscoAsa/`, and `fortigateToCheckPoint/`; pair discovery/API paths: `pairApi.ts`, `SourceConfiguration.tsx`, and `sourceApi.ts`; state paths: `workspaceTypes.ts` and `workspaceStore.ts`.
- Added dispatcher coverage in `src/frontend/tests/migrationPairWorkflow.test.mjs`, target selection coverage in `migrationWorkflow.test.mjs`, and typed workspace invalidation coverage in `workspaceStore.test.mjs`.
- Validation: `rtk npm test` passed 142/142; `rtk npm run lint` passed; `rtk npm run build` passed. The test output included a non-fatal Vite WebSocket warning that local port 24678 was already in use.

## Phase 12: Discovery, CLI, architecture, docs, and integration - complete with explicit FTD gate

- Registered `fortigate_to_checkpoint` as JSON offline export only: `destination_aware_available=false`, `deployment_available=false`. Added pair-owned CLI dispatch; target-config comparison is rejected. Updated migration discovery assertions and architecture boundary checks for the implemented package paths.
- Added `documentation/fortigate_to_checkpoint-migration.md`; updated the top-level README and conversion architecture README after implementation. FMC-managed FTD remains unregistered and unavailable pending a versioned FMC 7.7 writable OpenAPI schema. No FTD request body was guessed.
- Final integration commands and results: `rtk .venv\Scripts\python.exe -m compileall -q src tests` passed; `rtk .venv\Scripts\ruff.exe check src tests` passed; `rtk .venv\Scripts\python.exe -m pytest -q` passed (2350 passed, 1 skipped, 8 subtests passed); frontend `rtk npm test` passed (142 passed), `rtk npm run lint` passed, and `rtk npm run build` passed; `rtk git diff --check` passed.
- The checkout remains on `main`; no commit or push was made. Existing dirty and untracked work remains present.
- Not run: CI, production browser run for Check Point, live Check Point API/Gaia acceptance, native Junos/ASA/FTD acceptance, and FMC 7.7 schema validation. Earlier SRX/ASA browser checks recorded above do not substitute for these target checks.
- Next action: obtain the exact supported FMC 7.7 writable schema before considering Phase 9 implementation; keep Check Point destination comparison and all new-target live execution disabled until their separate gates are met.
