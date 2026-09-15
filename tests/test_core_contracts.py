import pytest
from pydantic import ValidationError

from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.errors import IRSchemaError
from fwmigrate.ir.io import dump_ir_json, load_ir_json
from fwmigrate.ir import IRConfig, IRMetadata


def test_plugin_registration_is_unique_and_repeatable():
    register_builtin_plugins()
    before = {
        "parsers": [spec.vendor_id for spec in PluginRegistry.list_parsers()],
        "generators": [spec.vendor_id for spec in PluginRegistry.list_generators()],
    }
    register_builtin_plugins()

    assert len(before["parsers"]) == len(set(before["parsers"]))
    assert len(before["generators"]) == len(set(before["generators"]))
    assert before == {
        "parsers": [spec.vendor_id for spec in PluginRegistry.list_parsers()],
        "generators": [spec.vendor_id for spec in PluginRegistry.list_generators()],
    }


@pytest.mark.parametrize("invalid", ["[]", "null", '{"metadata": []}'])
def test_ir_serialization_round_trips_and_rejects_invalid_input(invalid):
    ir = IRConfig(metadata=IRMetadata(hostname="FW", source_vendor="fortigate"))
    restored = load_ir_json(dump_ir_json(ir))

    assert restored == ir
    with pytest.raises((IRSchemaError, ValidationError)):
        load_ir_json(invalid)
