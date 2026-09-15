from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.report.migration_report import MigrationReporter
from tests.fixture_paths import (
    FORTIGATE_P0_EDGE_CASES_FIXTURE,
    FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE,
)


def test_fortigate_report_matches_p0_source_counts():
    result = extract_fortigate_config(
        FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE.read_text(encoding="utf-8")
    )
    summary = MigrationReporter(
        result.canonical_ir,
        extraction_result=result,
    ).generate_json_summary()["migration_critical_configuration"]

    assert summary["interfaces"] == 3
    assert summary["zones"] == 1
    assert summary["addresses"] == 3
    assert summary["address_groups"] == 2
    assert summary["services"] == 2
    assert summary["service_groups"] == 1
    assert summary["schedules"] == 2
    assert summary["policies"] == 2
    assert summary["vips"] == 1
    assert summary["ip_pools"] == 2
    assert summary["static_routes"] == 1
    assert summary["unresolved_dependencies"] == 0
    assert summary["status_counts"]["NORMALIZED"] > 0


def test_fortigate_report_exposes_edge_blockers_and_reference_context():
    result = extract_fortigate_config(
        FORTIGATE_P0_EDGE_CASES_FIXTURE.read_text(encoding="utf-8")
    )
    reporter = MigrationReporter(result.canonical_ir, extraction_result=result)
    summary = reporter.generate_json_summary()["migration_critical_configuration"]
    report = reporter.generate_report()

    assert summary["unresolved_dependencies"] == 1
    assert summary["blocked_by_unresolved_dependency"] == 1
    assert summary["generation_blockers"] > 0
    assert "Migration Critical Configuration" in report
    assert "MISSING_ADDRESS" in report
    assert "Expected Type" in report
