import pytest

from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction import ExtractionResult
from tests.fixture_paths import VENDOR_FIXTURES


# sections, coverage, inventory, unsupported, dependencies
EXPECTED_ACCOUNTING = {
    "fortigate": (10, 0, 5, 0, 23),
    "palo_alto": (11, 0, 15, 0, 3),
    "cisco_asa": (20, 0, 39, 2, 0),
    "cisco_ftd": (2, 0, 8, 0, 0),
    "checkpoint": (7, 8, 8, 0, 9),
    "juniper_srx": (6, 0, 6, 0, 11),
}
# extraction safe, complete, review; canonical IR safe, review
EXPECTED_SAFETY = {
    "fortigate": (False, False, True, False, True),
    "palo_alto": (True, True, True, True, True),
    "cisco_asa": (True, True, False, True, False),
    "cisco_ftd": (True, True, False, True, False),
    "checkpoint": (False, False, True, False, True),
    "juniper_srx": (True, True, False, True, False),
}


@pytest.fixture(scope="module", autouse=True)
def _register_plugins():
    register_builtin_plugins()


@pytest.mark.parametrize("source_vendor", VENDOR_FIXTURES)
def test_current_extraction_accounting_and_safety(source_vendor):
    result = PluginRegistry.get_parser(source_vendor).extract(
        VENDOR_FIXTURES[source_vendor].read_text(encoding="utf-8")
    )

    assert isinstance(result, ExtractionResult)
    assert (
        len(result.source_sections),
        len(result.coverage),
        len(result.inventory_items),
        len(result.unsupported_items),
        len(result.dependencies),
    ) == EXPECTED_ACCOUNTING[source_vendor]
    assert (
        result.generation_safe,
        result.migration_complete,
        result.requires_manual_review,
        result.canonical_ir.generation_safe,
        result.canonical_ir.requires_manual_review,
    ) == EXPECTED_SAFETY[source_vendor]
    assert all(section.status for section in result.source_sections)
