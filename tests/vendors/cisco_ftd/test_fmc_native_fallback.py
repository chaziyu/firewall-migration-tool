import json

from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser



def test_unknown_safe_resource_uses_native_fallback():
    config = CiscoFMCBundleParser(json.dumps({"source": "fmc-rest-api", "objects": {
        "hosts": [{"id": "host-1", "name": "Known", "value": "192.0.2.1"}],
        "futurething": [{"id": "future-1", "name": "Future", "setting": "safe"}],
    }})).parse_source()
    assert [item.source_id for item in config.network_addresses] == ["host-1"]
    future = next(item for item in config.native_resources if item.source_id == "future-1")
    assert future.source_attributes["resource_type"] == "futurething"
    assert future.raw_extra["setting"] == "safe"
