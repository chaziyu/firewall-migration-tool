# Offline workflow parity progress

Status: all five phases implemented and validated.

Scope: eight offline migration pairs. Preserve the existing FortiGate → PAN-OS changes and advanced candidate workflow. No deployment, commit or push.

## Phase 1
- Implemented: only real ASA dependency nodes receive edges; missing references retain blockers and downstream blocking. SRX generated status uses artifact dispositions; FTD counts empty requirement values.
- Checks: 11 ASA planning tests passed. Supplied FortiGate config prepares successfully: 10,164 items, READY_WITH_MANUAL_WORK, 16 port/name proposals.

## Phase 2
- Implemented: stable numbered FortiGate SRX ports, deterministic named-port ordering, preserved overrides and collisions; initial SRX preparation proposes automatically. PAN-OS SRX physical/unit/tag/zone proposals are wired into planning. Both ASA pairs expose partial port/name proposals while security levels remain explicit.
- Checks: 102 focused Python tests passed, including the new proposal regressions and signed web artifact flows.

## Phase 3
- Implemented: three visible offline stages; setup is editable inside review details; shared paginated preview proposes eligible rows by default and shows included/reused/excluded/blocked counts.
- Checks: production build, frontend tests and ESLint passed. Review pagination, scope filtering, explicit approval and reuse/exclusion status have focused regressions. Mobile checks exposed and fixed intrinsic grid sizing and long native-file tabs.

## Phase 4
- Completed all eight controller integrations. Target setup remains editable within Review conversion. Pair-local dependency/atomic expansion and native files are preserved.
- Added current-response guards to PAN-OS SRX. All pairs revoke approval/artifacts after context changes, including automatically normalized proposals. Retry retains a valid approval.
- Checks: 36 parity regressions passed, including each pair's actual approved selection, exclusions, retry, no-eligible output, late approval/build responses, populated FTD requirements and SRX reuse-only output. No offline pair gains device deployment.

## Phase 5
- Full Python suite: 2,974 passed, 1 skipped, 16 subtests passed (508.75 seconds).
- Latest affected Python suite after backend refinements: 283 passed; three additional proposal regressions then passed in a 13-test focused run. Final proposal-provenance and PAN-OS ASA/SRX web checks: 7 passed. Check Point prepare scope-discovery check: 4 passed.
- Python compileall, Ruff and git diff --check passed.
- Final frontend full suite: 244 passed. Final focused presentation/parity check after the SRX label adjustment: 40 passed. Final production build and ESLint passed.
- FortiGate → PAN-OS offline browser baseline passed: two approval requests, matching SHA-256; 2,000-object search 36.8 ms. Advanced destination browser baseline passed: one approval, two scoped overrides; 2,000-object search 32.2 ms. These use test fixtures and do not contact devices.
- Standalone final browser suite exited successfully with all 16 cases passing. All eight pairs passed mobile (390px) and desktop (1440px) browser checks: three stages, no device connection, default proposals, explicit approval, exclusions, partial status, no JavaScript errors, and exact preview/download/bundle bytes plus SHA-256 for every native file. Both supplied large-source runs passed at 390px, including explicit approval, exclusions where selectable, command preview/download/bundle byte equality and SHA-256. ASA review contains 10,164 items and remains partial; unsupported work is retained.
- Large-source command SHA-256: ASA `3bad248b344af8c51cf882b5a5f3e390596bc9a9c4e77801d68c381f8ce8c01d`; SRX `83c4936fc5242c95bf28276d6d38d07a710cbdda839af8cff30405ecfe93b45e`.
- Large workbook bundles require more than the default 30-second browser-test wait; the large-fixture check allows 120 seconds. Large real API responses are captured before being forwarded unchanged to avoid Chromium inspector-cache eviction.
- Temporary test servers were stopped after validation.
- Browser test server used an elevated in-process request limit to avoid interference between acceptance suites; production request limits are unchanged.

## Limits
- Offline conventions do not verify hardware availability or live behavior.
- Existing 11 modified files were present before this implementation and remain preserved. Branch main; no reset, commit, push or live-device access.
- No semantic conversion support was added. Unsupported source state, required attestations and existing-target completeness gates remain explicit.
- Large-source preparation and workbook bundles can take tens of seconds on this machine. No broad performance refactor was added.
- Vite continues to warn about the main bundle exceeding 500 kB; bundle splitting is outside this scope.
