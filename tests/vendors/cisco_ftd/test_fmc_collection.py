import json
import sys
from types import SimpleNamespace

from fwmigrate.collection.cisco_ftd import CiscoFTDCollector


class Response:
    def __init__(self, data=None, headers=None):
        self._data, self.headers = data or {}, headers or {}
        self.content = json.dumps(self._data).encode()

    def raise_for_status(self): pass
    def json(self): return self._data


def test_fmc_collector_collects_device_owned_routes_and_dhcp_read_only(monkeypatch):
    calls = []

    class Session:
        headers = {}
        verify = None
        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "secret", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})
        def get(self, url, **kwargs):
            calls.append(url)
            if url.endswith("/devices/devicerecords"):
                return Response({"items": [{"id": "device-1", "name": "FTD"}], "paging": {"total": 1}})
            if url.endswith("/devices/devicerecords/device-1"):
                return Response({"id": "device-1", "name": "FTD"})
            if url.endswith("/routing/staticroutes"):
                return Response({"items": [{"id": "route-1", "name": "default"}], "paging": {"total": 1}})
            if url.endswith("/routing/staticroutes/route-1"):
                return Response({"id": "route-1", "name": "default"})
            if url.endswith("/dhcp/dhcpserver"):
                return Response({"id": "dhcp-1", "name": "DHCP"})
            return Response({"items": [], "paging": {"total": 0}})
        def close(self): pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)
    assert bundle["devices"][0]["resources"]["static_routes"][0]["id"] == "route-1"
    assert bundle["devices"][0]["resources"]["dhcp_servers"][0]["id"] == "dhcp-1"
    assert any("device-1/routing/staticroutes" in url for url in calls)
    assert any("device-1/dhcp/dhcpserver" in url for url in calls)
