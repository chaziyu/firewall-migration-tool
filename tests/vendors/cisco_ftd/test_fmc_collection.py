import json
import pytest

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
    items, complete, reason = collector._pages(Session(), "https://fmc:443", "/api/fmc_config/v1/domain/d1/object/networkaddresses?expanded=true")
    assert complete
    assert reason is None
    assert items[0]["value"] == "10.0.0.0/24"
    assert calls[0].endswith("/networkaddresses?expanded=true")
    assert calls[1].endswith("/networkaddresses/net-1?expanded=true")


def test_fmc_group_detail_distinguishes_missing_members_from_explicit_empty_members():
    calls = []

    class Session:
        def get(self, url, **kwargs):
            calls.append(url)
            if "networkgroups?expanded=true" in url:
                return Response({"items": [{"id": "g1", "name": "Group"},
                                           {"id": "g2", "name": "Empty", "objects": []}],
                                 "paging": {"total": 2}})
            return Response({"id": "g1", "name": "Group", "objects": []})

    items, complete, reason = CiscoFTDCollector()._pages(Session(), "https://fmc:443",
        "/api/fmc_config/v1/domain/d1/object/networkgroups?expanded=true")
    assert complete and reason is None
    assert [item["objects"] for item in items] == [[], []]
    assert len(calls) == 2


def test_fmc_access_rule_with_unrelated_extra_field_still_fetches_details():
    calls = []

    class Session:
        def get(self, url, **kwargs):
            calls.append(url)
            if "/accessrules?expanded=true" in url:
                return Response({"items": [{"id": "rule-1", "name": "Allow", "type": "AccessRule", "description": "short"}],
                                 "paging": {"total": 1}})
            return Response({"id": "rule-1", "name": "Allow", "action": "ALLOW"})

    items, complete, reason = CiscoFTDCollector()._pages(Session(), "https://fmc:443",
        "/api/fmc_config/v1/domain/d1/policy/accesspolicies/acp-1/accessrules?expanded=true")
    assert complete and items[0]["action"] == "ALLOW"
    assert reason is None
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
    assert parts[0].failure_reason == "API_ERROR"


def test_fmc_pages_follow_paging_next_until_total_is_collected():
    calls = []

    class Session:
        def get(self, url, **kwargs):
            calls.append(url)
            if "offset=1" in url:
                return Response({"items": [{"id": "second"}], "paging": {"total": 2}})
            return Response({"items": [{"id": "first"}], "paging": {
                "total": 2, "next": {"href": "/api/items?offset=1"}}})

    items, complete, reason = CiscoFTDCollector()._pages(Session(), "https://fmc:443", "/api/items")
    assert [item["id"] for item in items] == ["first", "second"]
    assert complete and len(calls) == 2
    assert reason is None


def test_fmc_pages_mark_incomplete_when_total_exceeds_collected_items():
    class Session:
        def get(self, url, **kwargs):
            return Response({"items": [{"id": "first"}], "paging": {"total": 2}})

    items, complete, reason = CiscoFTDCollector()._pages(Session(), "https://fmc:443", "/api/items")
    assert items == [{"id": "first"}]
    assert not complete
    assert reason == "INCOMPLETE_PAGINATION"


def test_fmc_pages_reject_cross_host_pagination_url():
    class Session:
        def get(self, url, **kwargs):
            return Response({"items": [{"id": "first"}], "paging": {
                "total": 2, "next": {"href": "https://evil.example/api/items?page=2"}}})

    items, complete, reason = CiscoFTDCollector()._pages(Session(), "https://fmc:443", "/api/items")
    assert items == [{"id": "first"}]
    assert not complete
    assert reason == "MALFORMED_RESPONSE"


@pytest.mark.parametrize(("paging", "reason"), [
    ({}, "INCOMPLETE_PAGINATION"),
    ({"total": 1, "next": "bad"}, "INCOMPLETE_PAGINATION"),
    ({"total": 1, "next": {"href": 4}}, "INCOMPLETE_PAGINATION"),
])
def test_fmc_pages_require_valid_pagination_metadata(paging, reason):
    class Session:
        def get(self, url, **kwargs):
            return Response({"items": [{"id": "first"}], "paging": paging})

    items, complete, failure = CiscoFTDCollector()._pages(Session(), "https://fmc:443", "/api/items")
    assert items == [{"id": "first"}]
    assert not complete and failure == reason


def test_fmc_pages_detect_repeated_pagination_url():
    class Session:
        def get(self, url, **kwargs):
            return Response({"items": [{"id": "same"}], "paging": {
                "total": 3, "next": {"href": "/api/items"}}})

    items, complete, reason = CiscoFTDCollector()._pages(Session(), "https://fmc:443", "/api/items")
    assert [item["id"] for item in items] == ["same"]
    assert not complete and reason == "PAGINATION_LOOP"


def test_fmc_pages_classify_http_and_malformed_response_failures():
    class HTTPError(Exception):
        response = object()

    class HttpSession:
        def get(self, url, **kwargs):
            raise HTTPError("private detail")

    class MalformedSession:
        def get(self, url, **kwargs):
            return Response(["unexpected"])

    collector = CiscoFTDCollector()
    assert collector._pages(HttpSession(), "https://fmc:443", "/api/items")[2] == "HTTP_API_ERROR"
    assert collector._pages(MalformedSession(), "https://fmc:443", "/api/items")[2] == "MALFORMED_RESPONSE"


def test_fmc_auth_credentials_and_access_token_never_enter_collected_source():
    sentinels = ("user-secret", "password-secret", "token-secret")

    class Session:
        headers = {}
        verify = None

        def post(self, url, **kwargs):
            assert kwargs["auth"] == sentinels[:2]
            return Response(headers={"X-auth-access-token": sentinels[2],
                                     "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    collector = CiscoFTDCollector(session_factory=Session)
    source = collector.collect(collector.validate_options({"host": "fmc", "username": sentinels[0],
        "password": sentinels[1]}))
    evidence = json.dumps((source.source_text, source.metadata, source.parts, source.warnings), default=str)
    assert all(secret not in evidence for secret in sentinels)
