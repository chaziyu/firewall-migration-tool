from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import _compatible


def test_redundant_source_interface_is_not_assumed_to_be_aggregate():
    source = SimpleNamespace(type="redundant", vlanid=None)
    target = SimpleNamespace(interface_family="aggregate-ethernet", tag=None)
    assert _compatible(source, target) is False
