import json

from fwmigrate.collection.cisco_ftd import CiscoFTDCollector


class Response:
    def __init__(self, data=None, headers=None):
        self._data, self.headers = data or {}, headers or {}
        self.content = json.dumps(self._data).encode()

    def raise_for_status(self): pass
    def json(self): return self._data


def test_fmc_collector_collects_device_owned_routes_and_dhcp_read_only():
    calls = []

    class Session:
        headers = {}
        verify = None
        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "secret", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})
        def get(self, url, **kwargs):
            calls.append(url)
            path = url.split("?", 1)[0]
            if path.endswith("/devices/devicerecords"):
                return Response({"items": [{"id": "device-1", "name": "FTD"}], "paging": {"total": 1}})
            if path.endswith("/devices/devicerecords/device-1"):
                return Response({"id": "device-1", "name": "FTD"})
            if path.endswith("/routing/ipv4staticroutes"):
                return Response({"items": [{"id": "route-1", "name": "default", "selectedNetworks": [],
                    "interfaceName": "Null0"}], "paging": {"total": 1}})
            if path.endswith("/dhcp/dhcpserver"):
                return Response({"id": "dhcp-1", "name": "DHCP"})
            if path.endswith("/policy/intrusionpolicies"):
                return Response({"items": [{"id": "ips-1", "name": "IPS"}], "paging": {"total": 1}})
            return Response({"items": [], "paging": {"total": 0}})
        def close(self): pass

    collector = CiscoFTDCollector(session_factory=Session)
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)
    assert bundle["devices"][0]["resources"]["ipv4_static_routes"][0]["id"] == "route-1"
    assert bundle["devices"][0]["resources"]["dhcp_servers"][0]["id"] == "dhcp-1"
    assert any("device-1/routing/ipv4staticroutes" in url for url in calls)
    assert any("device-1/dhcp/dhcpserver" in url for url in calls)
    assert any("routing/ipv4staticroutes?expanded=true" in url for url in calls)
    assert not any("/routing/staticroutes" in url for url in calls)
    assert any("object/networkaddresses?expanded=true" in url for url in calls)
    from urllib.parse import parse_qs, urlparse
    filters = [parse_qs(urlparse(url).query).get("filter", []) for url in calls if "intrusionrules" in url]
    assert ["overrides:true;ipspolicy:ips-1"] in filters


def test_fmc_detail_fetch_uses_endpoint_fields_and_keeps_query_parameters():
    calls = []

    class Session:
        def get(self, url, **kwargs):
            calls.append(url)
            if "networkaddresses?expanded=true" in url:
                return Response({"items": [{"id": "net-1", "name": "inside", "type": "Network", "description": "brief"}],
                                 "paging": {"total": 1}})
            return Response({"id": "net-1", "name": "inside", "type": "Network", "value": "10.0.0.0/24"})

    collector = CiscoFTDCollector(session_factory=Session)
    items, complete = collector._pages(Session(), "https://fmc:443", "/api/fmc_config/v1/domain/d1/object/networkaddresses?expanded=true")
    assert complete
    assert items[0]["value"] == "10.0.0.0/24"
    assert calls[0].endswith("/networkaddresses?expanded=true")
    assert calls[1].endswith("/networkaddresses/net-1?expanded=true")


def test_fmc_access_rule_with_unrelated_extra_field_still_fetches_details():
    calls = []

    class Session:
        def get(self, url, **kwargs):
            calls.append(url)
            if "/accessrules?expanded=true" in url:
                return Response({"items": [{"id": "rule-1", "name": "Allow", "type": "AccessRule", "description": "short"}],
                                 "paging": {"total": 1}})
            return Response({"id": "rule-1", "name": "Allow", "action": "ALLOW"})

    items, complete = CiscoFTDCollector()._pages(Session(), "https://fmc:443",
        "/api/fmc_config/v1/domain/d1/policy/accesspolicies/acp-1/accessrules?expanded=true")
    assert complete and items[0]["action"] == "ALLOW"
    assert calls[1].endswith("/accessrules/rule-1?expanded=true")


def test_fmc_detail_failure_marks_family_partial_and_does_not_claim_success():
    class Session:
        def get(self, url, **kwargs):
            if url.endswith("networkaddresses?expanded=true"):
                return Response({"items": [{"id": "net-1", "name": "inside", "type": "Network"}],
                                 "paging": {"total": 1}})
            raise RuntimeError("detail failed")

    target, parts = {}, []
    CiscoFTDCollector()._collect_family(Session(), "https://fmc:443", "/api/fmc_config/v1/domain/d1/object/networkaddresses?expanded=true",
        target, "networkaddresses", parts)
    assert target["networkaddresses"] == [{"id": "net-1", "name": "inside", "type": "Network"}]
    assert parts[0].status == "PARTIAL" and not parts[0].complete
