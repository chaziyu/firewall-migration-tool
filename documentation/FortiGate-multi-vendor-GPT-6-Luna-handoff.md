# New-chat handoff: GPT-6 Luna, Extra High

Use this repository:
C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool

In the new chat, select GPT-6 Luna and Extra High reasoning in the model controls. Attach or reference the detailed plan below. No model change, new chat or implementation was started by preparing this handoff.

Detailed plan:
C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/FortiGate-multi-vendor-implementation-plan.md

The plan has 13 phases (0-12), inspected code pointers, exact proposed file paths, pair-owned mapping contracts, web/CLI contracts, vendor checkpoints, negative tests, release gates and context-recovery instructions. All proposed file names and APIs are explicitly marked as new; existing code must be rechecked before edits.

## Copy-ready opening prompt

Paste the following into the new chat when you want implementation to begin:

```text
Implement the detailed plan at:
C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/FortiGate-multi-vendor-implementation-plan.md

Repository:
C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool

Use the plan as the execution brief. Read it, AGENTS.md, applicable skills and C:/Users/ziyu.cha-c/.codex/RTK.md before editing. Inspect actual code through CodeGraph first when .codegraph exists. Reconcile any drift without regenerating the index.

Implement FortiGate migration to Juniper SRX, Cisco ASA, FMC-managed Cisco FTD and Check Point. Preserve existing FortiGate -> PAN-OS, PAN-OS -> FortiGate, source reporting and PAN-OS set-upload/deployment behavior.

Execute phases 0-12 in dependency order. Complete the SRX vertical slice first, then ASA, FMC FTD and Check Point. Validate each phase before proceeding. Do not stop after planning, registering labels, creating scaffolding or implementing objects alone.

At startup inspect the branch, actual git status, current symbols/callers/tests and existing runtimes. The checkout already contains important modified and untracked files. Preserve all pre-existing work. Do not reset, clean, stash, change branch, commit or push without my explicit request.

Keep conversion directional and pair-specific. Do not create a vendor-neutral IR, generic semantic migration schema or shared firewall model. Shared additions are limited to discovery, orchestration, integrity transport and presentation.

Keep extracted source immutable. Missing source fields remain unknown/not explicitly configured. Use FortiGate native relationships/derived views with provenance. Unrepresented central NAT, unknown matches, unsupported earlier rules and uncertain target behavior must stay visible and block unsafe dependent output.

Web exports need explicit current signed approval bound to the exact pair, source, target, options, operations and dependencies. Imported mappings are proposals only. Preview and downloads must use the same approved bytes. No new target may reach PAN-OS deployment transport.

New targets are reviewed offline exports, with destination-aware comparison only after its gate. Do not add live execution, commit, publish, install-policy, save-config or automatic policy assignment. FTD means FMC only in this plan. Its output is a reviewed API request specification with explicit response-ID bindings, not ASA CLI or a native FMC import file. Check Point management and Gaia outputs remain separate.

Do not guess target command syntax, API fields, versions or equivalence. Verify exact vendor baselines using repository references and official documentation. If one feature cannot be verified, keep it blocked, record the affected scope and continue independent work. Do not silently claim the feature is supported.

Maintain:
C:/Users/ziyu.cha-c/Documents/GitHub/firewall-migration-tool/documentation/FortiGate-multi-vendor-execution-progress.md

Record phase/checkpoint, changed paths, commands actually run, results, remaining blockers and next action. Read it on resumption. Keep customer source and credentials out of it.

Use the existing .venv Python and prefix shell commands with rtk. Run relevant native-path tests after every phase. At integration run Python compile/Ruff/full tests and frontend tests/lint/build. Verify git diff --check. Do not claim browser, live-device or CI validation without performing it.

Proceed autonomously within this scope. Ask only for information that actually blocks dependent work; continue independent phases where possible. Do not delegate to subagents or create other chats without my authorization.

The final report must list supported behavior per target, manual/blocked coverage, validation results and unrun checks. Preserve any unresolved feature limits honestly. Leave all implementation local unless I separately ask to publish.
```

## Before starting

- The prior chat performed a planning review and created Markdown documents only for this request.
- Historical test counts in the plan describe the earlier implementation session. They do not replace startup or post-change tests.
- Expect a dirty main checkout containing the reverse migration and separate PAN-OS upload work; inspect actual status rather than assuming ownership from file names.
- Do not interpret unavailable live firewalls as permission to weaken the offline equivalence checks.
- If you only want one milestone implemented, replace the execution range in the prompt with a specific phase/checkpoint and its prerequisites.

## Success check

The new chat should first report the detected baseline and the first implementation phase. Its output should be working, tested conversion flows, not another generic roadmap or four empty planner packages.

