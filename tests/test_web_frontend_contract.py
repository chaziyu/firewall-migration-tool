from pathlib import Path

from fwmigrate.web import create_app


APP_JS = Path(__file__).parents[1] / "src" / "fwmigrate" / "static" / "app.js"
STYLE_CSS = Path(__file__).parents[1] / "src" / "fwmigrate" / "static" / "style.css"


def _app_js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _style_css() -> str:
    return STYLE_CSS.read_text(encoding="utf-8")


def _between(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def test_source_report_html_exposes_completeness_schedules_and_references():
    client = create_app({"TESTING": True}).test_client()
    html = client.get("/legacy").get_data(as_text=True)

    assert 'id="report-source-meta"' in html
    assert 'data-report-section="schedules"' in html
    assert 'data-report-section="references"' in html
    assert 'class="report-tabs" role="tablist"' in html
    assert 'id="report-detail-modal" class="report-detail-modal hidden" aria-hidden="true"' in html


def test_excel_frontend_always_sends_source_vendor_with_cached_preview():
    js = _app_js()
    block = _between(
        js,
        "// 8b. Vendor-native Excel source report",
        "// 9. Mode B: Target Authentication Switcher & Diagnostics",
    )

    vendor_line = 'formData.append("source_vendor", selectedSourceVendor);'
    file_guard = "if (currentFile) {"
    assert vendor_line in block
    assert block.index(vendor_line) < block.index(file_guard)


def test_source_preview_readiness_is_not_gated_by_migration_review():
    js = _app_js()
    block = _between(
        js,
        "async function fetchMigrationPreview()",
        "// =========================================================================\n  // 8. Mode A:",
    )

    assert "sourceReady = true;" in block
    assert "await loadMigrationReviewForReadySource(currentPreviewId);" in block
    assert block.index("sourceReady = true;") < block.index(
        "await loadMigrationReviewForReadySource(currentPreviewId);"
    )
    assert "await loadMigrationReview(currentPreviewId);" not in block


def test_collection_preview_uses_normalized_summary_and_preserves_partial_reporting():
    js = _app_js()
    block = _between(
        js,
        "async function applyCollectionPreview",
        "async function importSnapshot",
    )

    assert "detachLocalFile();" in block
    assert "setSourceContext({" in block
    assert "status: data.collection?.status || null" in block
    assert "warnings: data.collection?.warnings || []" in block
    assert "updateSourceOverview(currentReport)" in block
    assert "summary.rules" not in block
    assert "sourceReady = true;" in block
    assert block.index("sourceReady = true;") < block.index(
        "await loadMigrationReviewForReadySource(currentPreviewId);"
    )


def test_entering_collection_mode_does_not_clear_current_source():
    js = _app_js()

    assert 'if (mode === "collect" && activeMode !== "collect") clearSource();' not in js


def test_report_capability_lookup_fails_open_for_file_reporting():
    js = _app_js()

    assert (
        'tabReport?.classList.toggle("hidden", '
        'vendorCapabilities[selectedSourceVendor]?.web_report === false);'
    ) in js


def test_source_report_search_is_debounced_and_cached():
    js = _app_js()

    assert "const reportSearchIndex = new WeakMap();" in js
    assert "reportSearchText(row).includes(search)" in js
    assert "reportSearchTimer = setTimeout(() => {" in js


def test_report_workspace_exposes_compact_source_controls_and_tab_counts():
    client = create_app({"TESTING": True}).test_client()
    html = client.get("/legacy").get_data(as_text=True)

    assert 'id="source-configuration-card"' in html
    assert 'id="btn-report-change-source"' in html
    assert 'class="report-source-context"' in html
    assert 'data-report-count="policies"' in html
    assert 'data-report-count="validation"' in html
    assert "No reported entries in this section." in html


def test_report_frontend_collapses_ready_source_only_in_report_mode():
    js = _app_js()

    assert "let sourcePanelExpanded = true;" in js
    assert 'activeMode === "report" && sourceReady && !sourcePanelExpanded' in js
    assert "sourcePanelExpanded = false;" in js
    assert 'sourceConfigurationCard?.scrollIntoView({ block: "start", behavior: "smooth" });' in js


def test_report_frontend_distinguishes_empty_section_from_filtered_results():
    js = _app_js()
    block = _between(
        js,
        "function renderReportTable()",
        "function renderValidationSummary()",
    )

    assert '"No entries match the current filters."' in block
    assert '"No reported entries in this section."' in block


def test_report_validation_rows_keep_details_and_offer_explicit_target_navigation():
    js = _app_js()
    block = _between(
        js,
        "function renderReportTable()",
        "function renderValidationSummary()",
    )

    assert 'tr.addEventListener("click", () => {' in block
    assert "showReportDetails(row, tr);" in block
    assert 'button.textContent = "View object →";' in block
    assert "navigateToValidationTarget(row);" in block


def test_report_tables_use_compact_list_previews_and_sticky_identity_columns():
    js = _app_js()

    assert "function reportTableCell(value)" in js
    assert 'return `${value.slice(0, 2).join(", ")}  +${value.length - 2}`;' in js
    assert "const REPORT_STICKY_IDENTITY = {" in js
    assert 'th.classList.add("report-cell-sticky", "report-cell-identity");' in js


def test_report_overview_uses_primary_and_secondary_metric_groups():
    js = _app_js()
    block = _between(
        js,
        "function renderOverviewMetric",
        "function syncWorkspace()",
    )

    assert '"report-summary-primary"' in block
    assert '"report-summary-secondary"' in block
    assert 'affordance.textContent = "View →";' in block
    assert '"Scope metadata was not reported."' in block



def test_report_search_projection_excludes_secret_bearing_fields():
    js = _app_js()
    block = _between(
        js,
        "const REPORT_SENSITIVE_KEY",
        "function sourceOverviewCounts",
    )

    assert "raw_extra" in block
    assert "password" in block
    assert "credential" in block
    assert "private.?key" in block
    assert "psk" in block
    assert "safeReportSearchValues" in block
    assert "Object.entries(row)" in block
    assert "Object.values(row)" not in block


def test_report_validation_groups_share_scope_severity_and_search_filters():
    js = _app_js()

    assert "function filteredReportRows(section" in js
    assert 'filteredReportRows("validation", { includeValidationGroup: false })' in js
    assert 'if (scope && (row.scope || row.vdom) !== scope) return false;' in js
    assert 'if (section === "validation" && severity && row.severity !== severity) return false;' in js


def test_report_section_navigation_clears_section_specific_search():
    js = _app_js()

    assert "if (nextSection !== activeReportSection && reportSearch) reportSearch.value = \"\";" in js
    assert "if (nextObjectSection !== activeObjectSection && reportSearch) reportSearch.value = \"\";" in js


def test_report_rows_use_roving_keyboard_focus():
    js = _app_js()
    block = _between(
        js,
        "function setActiveReportRow",
        "function renderValidationSummary",
    )

    assert "tr.tabIndex = visibleIndex === 0 ? 0 : -1;" in block
    assert '"ArrowUp", "ArrowDown", "Home", "End"' in block
    assert "row.tabIndex = selected ? 0 : -1;" in block


def test_report_inspector_is_nonmodal_on_desktop_and_modal_on_narrow_screens():
    js = _app_js()
    css = _style_css()

    assert 'function reportDetailIsModal()' in js
    assert 'window.matchMedia("(max-width: 700px)").matches' in js
    assert 'setAttribute("aria-modal", String(modal))' in js
    assert "detailOpen && reportDetailIsModal()" in js
    assert "pointer-events: none;" in css
    assert "pointer-events: auto;" in css


def test_report_table_keeps_only_horizontal_identity_sticky():
    css = _style_css()
    header_block = _between(css, ".report-table th {", ".report-table tbody tr {")

    assert "position: sticky" not in header_block
    assert ".report-table .report-cell-sticky" in css
    assert "left: 0;" in css


def test_report_policy_and_nat_identity_preserve_source_order_context():
    js = _app_js()

    assert 'policies: [["__identity", "Policy", "identity"]' in js
    assert 'nat: [["__identity", "Policy", "identity"]' in js
    assert '["policies", "nat"].includes(columnKey)' in js
    assert '" · Source order preserved"' in js


def test_report_zero_severity_counts_and_explicit_disabled_state_are_neutral():
    js = _app_js()

    assert 'const emphasizedTone = tone && count(value) > 0 ? tone : "";' in js
    assert '["disabled", "inactive", "shutdown"].includes(token)' in js
    assert 'if (token === "failed") return "danger";' in js


def test_report_detail_renderer_preserves_nested_structure_without_secret_fields():
    js = _app_js()
    block = _between(
        js,
        "function appendReportDetailValue",
        "function openReportDetailModal",
    )

    assert 'if (REPORT_SENSITIVE_KEY.test(key)) return false;' in block
    assert 'typeof value === "object"' in block
    assert 'const nested = document.createElement("dl");' in block
    assert "appendReportDetailValue(detail, nestedValue, nestedKey);" in block


def test_report_source_context_is_not_a_generic_live_region():
    client = create_app({"TESTING": True}).test_client()
    html = client.get("/legacy").get_data(as_text=True)

    assert '<div class="report-source-context" id="report-source-meta"></div>' in html
    assert 'id="btn-report-change-source"' in html
    assert 'aria-controls="source-configuration-card"' in html
