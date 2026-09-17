import pytest

from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.report.migration_summary import MigrationSummary
from tests.fixture_paths import (
    FORTIGATE_P0_EDGE_CASES_FIXTURE,
    FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE,
    VENDOR_FIXTURES,
)


def test_summary_uses_canonical_counts_and_extraction_safety():
    result = extract_fortigate_config(
        FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE.read_text(encoding="utf-8")
    )
    summary = MigrationSummary(
        result.canonical_ir,
        target_vendor="palo_alto",
        extraction_result=result,
    ).generate_json_summary()

    assert summary["source_vendor"] == result.canonical_ir.metadata.source_vendor
    assert summary["target_vendor"] == "palo_alto"
    assert summary["canonical_counts"]["interfaces"] == 3
    assert summary["canonical_counts"]["security_policies"] == 2
    assert summary["canonical_counts"]["schedules"] == 2
    assert summary["source_fidelity"]["source_sections"] > 0
    assert summary["extraction_status_counts"]["NORMALIZED"] > 0


def test_summary_preserves_unresolved_dependencies_and_blockers():
    result = extract_fortigate_config(
        FORTIGATE_P0_EDGE_CASES_FIXTURE.read_text(encoding="utf-8")
    )
    summary = MigrationSummary(
        result.canonical_ir,
        extraction_result=result,
    ).generate_json_summary()

    assert summary["unresolved_dependencies"] == 1
    assert summary["migration_critical_configuration"]["blocked_by_unresolved_dependency"] == 1
    assert summary["generation_blockers"] > 0
    assert summary["generation_blocking_reasons"]


@pytest.mark.parametrize("source_vendor", VENDOR_FIXTURES)
def test_summary_is_available_for_every_registered_source_fixture(source_vendor):
    parser = PluginRegistry.get_parser(source_vendor)
    result = parser.extract(
        VENDOR_FIXTURES[source_vendor].read_text(encoding="utf-8")
    )
    summary = MigrationSummary(
        result.canonical_ir,
        target_vendor="palo_alto",
        extraction_result=result,
    ).generate_json_summary()

    assert summary["source_vendor"] == result.canonical_ir.metadata.source_vendor
    assert set(summary["canonical_counts"]) >= {
        "interfaces",
        "zones",
        "addresses",
        "address_groups",
        "services",
        "service_groups",
        "schedules",
        "security_policies",
        "nat_rules",
        "routes",
        "vpn_tunnels",
    }
    assert sum(summary["extraction_status_counts"].values()) == len(result.inventory_items)
