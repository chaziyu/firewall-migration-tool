import pytest

from fwmigrate.collection.cisco_asa import CiscoASACollector
from fwmigrate.collection.registry import SourceCollectorRegistry


def test_registry_register_get_list():
    registry = SourceCollectorRegistry()
    collector = CiscoASACollector()
    registry.register(collector)
    assert registry.get("CISCO_ASA") is collector
    assert registry.list() == (collector,)
    with pytest.raises(ValueError):
        registry.register(CiscoASACollector())
