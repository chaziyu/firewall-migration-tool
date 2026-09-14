# Firewall Migration Tool — frontend review

Reviewed 14 September 2026. Scope: improve the existing browser and desktop frontend while preserving the Python migration pipeline and API contracts.

1. **Project understanding**

   The product serves network engineers inspecting source firewall configurations, generating migration artifacts, and planning PAN-OS deployments. Its three existing workflows are configuration conversion, Excel extraction, and live migration. Accurate source context, explicit limitations, and reviewable results have priority over decorative presentation.

   The running interface is served by `src/fwmigrate/web.py`. Source parsers normalize configurations into the vendor-neutral IR, which feeds generators and reports. The desktop application embeds the same frontend and provides a file-save bridge. The served workspace does not integrate the separate identity, role, or durable-job modules into a login or saved-project interface.

2. **User flow**

   Entry: open the application → choose a workflow → select source/vendor → upload a backup or retrieve a supported live source → read inventory → inspect policy checks.

   Conversion: source review → choose whether to prune unused objects → generate ZIP → inspect the migration report and source workbook before importing.

   Extraction: source review → download Excel → inspect inventory and extraction warnings. No target selection or pruning option is needed.

   Live migration: source review → PAN-OS target connection → diagnostics → dry-run plan → inspect output → explicit confirmation and server approval → streamed execution → state/audit downloads. The displayed removal operation concerns Terraform-managed resources, not restoration of a device snapshot.

   Loading, parse errors, empty inventories, export failures, save cancellation, and interrupted deployment streams are separate states. Source changes invalidate the review and output messages. Target/pruning changes invalidate the conversion result. Switching workflow preserves the selected source.

3. **Existing project assessment**

   **Keep:** Flask/Jinja partials, vanilla JavaScript, local assets and fonts, light/dark preferences, semantic controls, keyboard navigation, source-request cancellation, deployment confirmation, and the desktop download bridge.

   **Improve:** review depth, text readability, progress state, error recovery, export feedback, and copy about generated artifacts.

   **Remove:** promotional sidebar content, decorative entrance animations, unnecessary surface gradients/shadows, unused policy state in the main script, and wording that describes generated Terraform as production-ready or a computed plan as verified.

   **Add:** a shared source-review partial, bounded/searchable policy presentation, findings from existing optimizer counts, a retry control, persistent output feedback, and browser regression checks.

4. **Functional requirements**

   Inventory values come from `/api/preview`; the UI adds no invented counts or compatibility scores. Object totals include addresses, address groups, services, and service groups. Findings describe the checks actually returned by the endpoint.

   The policy endpoint returns at most the first 50 policies. The UI states the displayed and total counts, preserves returned order, and searches only that subset. Fields are inserted as text. The explicit `<IR_ANY>` sentinel is displayed as “Any”; missing values remain “Not reported.” Action and enabled/disabled state remain separate.

   A failed preview can retry the same source. Export feedback records the filename, source context, result, and review task. A late response cannot attach a result to a different source or changed conversion options. Source configuration and credentials are not written to browser storage.

   Only FortiGate and PAN-OS live retrieval are offered in the UI. The inspected Cisco, Check Point, and Juniper adapters contain placeholder extraction data. Their live panels explain the limitation and direct users to file upload. This is a frontend availability restriction; backend adapter remediation remains separate work.

5. **Recommended technology stack**

   Keep Flask and Jinja: they already serve the workspace and compose the required HTML partials. Keep vanilla JavaScript for requests, state, downloads, and streams; a presentation module now owns source-review rendering. Keep plain CSS and custom properties for shared layout and theme tokens. These choices preserve desktop packaging and avoid adding a frontend runtime or build step. [Flask template documentation](https://flask.palletsprojects.com/en/stable/tutorial/templates/)

   Browser verification uses the workspace's existing Playwright Core installation as development tooling. It is not an application dependency.

6. **Design direction and lightweight design system**

   A restrained technical workspace fits repeated inspection of configuration data. Forest-green navigation identifies the application; orange identifies primary actions. Neutral flat surfaces, dividers, and aligned rows keep attention on content. Findings and result messages use text and a restrained status border rather than color alone.

   Typography: locally bundled DM Sans for interface text; Space Grotesk for titles; system monospace for configuration values. Body text uses 14px/1.55, supporting text targets 12px, section titles use 18px, and page titles scale from 26–35px. Weights are primarily 400/500/600. No remote font requests are required.

   Spacing tokens: 4, 8, 12, 16, 24, and 32px. The main content retains a 1510px maximum width, a desktop context column, and approximately 32px desktop padding. Surfaces use the existing modest 4/7/10/14px radius scale; primary sections use 7px. Shadows are reserved for layered feedback/dialogs rather than every section.

   Layout changes at the existing 1220, 1020, 760, and 480px breakpoints. The context column stacks, navigation becomes horizontal, forms become single-column, and policy data scrolls within a labelled table region. Controls have larger minimum interaction sizes. Important review content remains available on mobile.

   Motion is limited to interaction/loading feedback. Decorative page reveals were removed. Reduced-motion preferences continue to disable animation and smooth scrolling. [MDN reduced-motion documentation](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@media/prefers-reduced-motion)

7. **Proposed and implemented architecture**

   `templates/index.html`: application shell, workflow navigation, progress, and source context.

   `templates/partials/source_configuration.html`: vendor selection, upload/live retrieval, source status, and retry.

   `templates/partials/source_review.html`: inventory metrics, findings, policy disclosure/filter/table, and conversion pruning choice.

   `templates/partials/exports.html`: bundle/Excel descriptions, actions, and persistent results. `live_migration.html` retains target connection, diagnostics, plan/apply/removal controls, and the execution log.

   `static/source-review.js`: presentation and filtering of the existing preview response. `static/app.js`: existing orchestration with source-aware export state and workflow updates. `style.css` and `themes.css`: shared styling and palettes. No routes, database models, parsers, generators, or deployment endpoints were changed.

8. **Risks and limits**

   Parsing is not target compatibility validation. A plan being generated is not a security-equivalence assessment. The backend can reject artifact generation for NAT requiring target-specific validation; the interface preserves and displays that error. Excel remains available for review.

   The policy preview is partial when there are more than 50 rules. Optimizer counts are not a complete extraction-coverage report. The frontend's source-availability list must be updated when the placeholder live adapters are properly implemented and verified.

   Existing authentication, persistence, backend adapter, and deployment limitations should not be hidden by account screens, project-history mockups, synthetic dashboards, or claims of migration readiness. The prebuilt executable has not been rebuilt by this frontend source change.

9. **Implementation order and validation**

   Implemented in order: hierarchy/copy → source-review presentation → retry and result state → responsive/readability refinements → automated and visual verification.

   Validation: 12 focused Flask web tests passed. The full Python suite reported 226 passed, 2 skipped, and 45 failures caused by missing `examples/` fixtures. All 45 failing tests reproduced with the original `HEAD` source, using an isolated source snapshot.

   The committed `tests/frontend/workspace.cjs` passed all 10 scenario groups: keyboard/guide focus, actual source-policy inspection, real ZIP/Excel downloads, backend NAT rejection, inline errors and stale responses, source retry, bounded preview and safe text rendering, unsupported-live-source guidance, and mocked plan/confirmation/approval ordering. Responsive checks covered all three workflows in both themes at widths of 1440, 1024, 768, 390, and 320px, with no document overflow or uncaught JavaScript errors.

   The existing theme checks also passed system preference changes, saved choice/reload, reset persistence, storage unavailability, and 18 workflow/theme/mobile combinations. A legacy external mock script still expects download errors in the global banner; the committed browser check verifies their new location beside the export action.

   Run browser checks against a locally running app with `node tests/frontend/workspace.cjs`. Make `playwright-core` available to Node (the current workspace has it in `../frontend-qa/node_modules`, usable through `NODE_PATH`). Optional environment variables are `FWM_QA_URL`, `CHROME_PATH`, and `FWM_QA_OUTPUT`. Device and Terraform routes are intercepted; only source preview and file exports reach the local application. Run Python checks with `python -m pytest tests/test_web.py -q` or `python -m pytest tests/ -q`.
