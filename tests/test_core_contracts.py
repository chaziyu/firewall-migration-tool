from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry


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
