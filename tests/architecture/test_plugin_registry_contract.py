import pytest

from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.plugins import PluginSpec, PluginType
from fwmigrate.core.registry import PluginRegistrationError, PluginRegistry


def test_builtin_specs_are_unique_and_registration_is_idempotent():
    register_builtin_plugins()
    parsers = PluginRegistry.list_parsers()
    generators = PluginRegistry.list_generators()

    assert len({spec.vendor_id for spec in parsers}) == len(parsers)
    assert len({spec.vendor_id for spec in generators}) == len(generators)
    assert {spec.vendor_id for spec in parsers} == {
        "fortigate", "palo_alto", "cisco_asa", "cisco_ftd", "checkpoint", "juniper_srx"
    }
    assert {spec.vendor_id for spec in generators} == {
        "palo_alto", "fortigate", "cisco_asa", "checkpoint", "juniper_srx"
    }
    assert PluginRegistry.get_parser_spec("FORTINET").vendor_id == "fortigate"
    assert PluginRegistry.get_generator_spec("panos").vendor_id == "palo_alto"
    before = (len(parsers), len(generators))
    register_builtin_plugins()
    assert (len(PluginRegistry.list_parsers()), len(PluginRegistry.list_generators())) == before


def test_metadata_listing_does_not_instantiate(monkeypatch):
    class NoInit:
        def __init__(self):
            raise AssertionError("metadata listing instantiated a plugin")

    spec = PluginSpec(
        "contract_parser", "Contract Parser", PluginType.SOURCE_PARSER,
        NoInit, supported_extensions=(".cfg",),
    )
    monkeypatch.setitem(PluginRegistry._parser_specs, "contract_parser", spec)
    assert PluginRegistry.list_source_vendors()[-1]["vendor_id"] == "contract_parser"


def test_conflicting_registration_fails(monkeypatch):
    class First:
        pass

    class Second:
        pass

    vendor_id = "contract_conflict"
    first = PluginSpec(vendor_id, "First", PluginType.SOURCE_PARSER, First)
    second = PluginSpec(vendor_id, "Second", PluginType.SOURCE_PARSER, Second)
    monkeypatch.setitem(PluginRegistry._parser_specs, vendor_id, first)
    with pytest.raises(PluginRegistrationError):
        PluginRegistry.register_parser(second)


def test_checkpoint_pipeline_does_not_rebind_extractor_at_import_time():
    from fwmigrate.parsers.checkpoint import extract_checkpoint_config
    from fwmigrate.parsers.checkpoint.extractor import parse_gaia_configuration

    assert extract_checkpoint_config.__module__.endswith("checkpoint.extractor")
    assert parse_gaia_configuration.__module__.endswith("checkpoint.gaia_scope_policy")
