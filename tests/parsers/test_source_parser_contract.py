import pytest

from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry
from tests.fixture_paths import VENDOR_FIXTURES


@pytest.fixture(scope="module", autouse=True)
def _register_plugins():
    register_builtin_plugins()


@pytest.mark.parametrize("source_vendor", VENDOR_FIXTURES)
def test_parse_is_canonical_ir_projection(source_vendor):
    content = VENDOR_FIXTURES[source_vendor].read_text(encoding="utf-8")
    parser = PluginRegistry.get_parser(source_vendor)
    parsed = parser.parse(content)
    extracted = parser.extract(content).canonical_ir

    assert parsed.model_dump(exclude={"metadata": {"migration_timestamp"}}) == (
        extracted.model_dump(exclude={"metadata": {"migration_timestamp"}})
    )


@pytest.mark.parametrize("source_vendor", VENDOR_FIXTURES)
def test_extraction_and_ir_safety_are_synchronized(source_vendor):
    result = PluginRegistry.get_parser(source_vendor).extract(
        VENDOR_FIXTURES[source_vendor].read_text(encoding="utf-8")
    )

    assert result.generation_safe == result.canonical_ir.generation_safe
    assert result.requires_manual_review == result.canonical_ir.requires_manual_review
    assert result.blocking_reasons == result.canonical_ir.generation_blocking_reasons
