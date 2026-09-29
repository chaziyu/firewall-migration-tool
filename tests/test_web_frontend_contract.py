from pathlib import Path

from fwmigrate.web import create_app


APP_JS = Path(__file__).parents[1] / "src" / "fwmigrate" / "static" / "app.js"


def _app_js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _between(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def test_source_report_html_exposes_completeness_schedules_and_references():
    client = create_app({"TESTING": True}).test_client()
    html = client.get("/").get_data(as_text=True)

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
    html = client.get("/").get_data(as_text=True)

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

    assert 'tr.addEventListener("click", () => showReportDetails(row, tr));' in block
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
