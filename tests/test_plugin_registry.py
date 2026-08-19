import pytest
import fg2pan.parsers
import fg2pan.generators
from fg2pan.core.registry import PluginRegistry
from fg2pan.ir.core import IRConfig, IRMetadata

def test_plugin_registry_discovery():
    sources = PluginRegistry.list_source_vendors()
    vendor_ids = [s['vendor_id'] for s in sources]
    assert 'fortigate' in vendor_ids
    assert 'cisco_asa' in vendor_ids
    assert 'checkpoint' in vendor_ids
    assert 'juniper_srx' in vendor_ids

    targets = PluginRegistry.list_target_vendors()
    target_ids = [t['vendor_id'] for t in targets]
    assert 'palo_alto' in target_ids
    assert 'fortigate' in target_ids

def test_plugin_registry_get_parser():
    fg_parser = PluginRegistry.get_parser('fortigate')
    assert fg_parser.vendor_id == 'fortigate'
    assert fg_parser.display_name == 'Fortinet FortiGate'

    asa_parser = PluginRegistry.get_parser('cisco_asa')
    assert asa_parser.vendor_id == 'cisco_asa'

    cp_parser = PluginRegistry.get_parser('checkpoint')
    assert cp_parser.vendor_id == 'checkpoint'

    srx_parser = PluginRegistry.get_parser('juniper_srx')
    assert srx_parser.vendor_id == 'juniper_srx'

    with pytest.raises(KeyError):
        PluginRegistry.get_parser('unknown_vendor')

def test_plugin_registry_get_generator():
    pan_gen = PluginRegistry.get_generator('palo_alto')
    assert pan_gen.vendor_id == 'palo_alto'

    fg_gen = PluginRegistry.get_generator('fortigate')
    assert fg_gen.vendor_id == 'fortigate'

    with pytest.raises(KeyError):
        PluginRegistry.get_generator('unknown_target')
