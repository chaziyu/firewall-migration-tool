import json
import sys
from types import SimpleNamespace

from fwmigrate.collection.cisco_ftd import CiscoFTDCollector
from fwmigrate.collection.contracts import CollectionStatus
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter


class Response:
    def __init__(self, data=None, headers=None):
        self._data = data or {}
        self.headers = headers or {}
        self.content = json.dumps(self._data).encode()

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def test_fmc_pagination_bundle_and_read_only_requests(monkeypatch):
    calls = []

    class Session:
        headers = {}
        verify = None

        def post(self, url, **kwargs):
            calls.append(("POST", url))
            return Response(headers={"X-auth-access-token": "do-not-save", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            calls.append(("GET", url))
            if url.endswith("/hosts/h1"):
                return Response({"id": "h1", "name": "first", "value": "192.0.2.1"})
            if url.endswith("/hosts/h2"):
                return Response({"id": "h2", "name": "second", "value": "192.0.2.2", "password": "do-not-save"})
            if url.endswith("/hosts"):
                return Response({"items": [{"id": "h1", "name": "first"}], "paging": {"next": {"href": url + "?offset=1"}, "total": 2}})
            if url.endswith("/hosts?offset=1"):
                return Response({"items": [{"id": "h2", "name": "second", "password": "do-not-save"}], "paging": {"total": 2}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            calls.append(("CLOSE", ""))

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)
    assert source.status == CollectionStatus.SUCCESS
    assert bundle["format"] == "cisco-fmc-rest-export-v1"
    assert len(bundle["objects"]["hosts"]) == 2
    assert "do-not-save" not in source.source_text
    assert all(method == "GET" for method, _ in calls[1:-1])
    assert CiscoFTDSourceReporter().analyze_source(source.source_text)


def test_fmc_partial_endpoint_failure_keeps_usable_source(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            if url.endswith("/networks"):
                raise TimeoutError("secret-password")
            return Response({"items": [{"id": "h1", "name": "host", "value": "192.0.2.1"}] if url.endswith("/hosts") else [], "paging": {"total": 1 if url.endswith("/hosts") else 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    source = CiscoFTDCollector().collect(CiscoFTDCollector().validate_options({"host": "fmc", "username": "u", "password": "p"}))
    assert source.status == CollectionStatus.PARTIAL
    assert any(part.name == "networks" and not part.complete for part in source.parts)
    assert "secret-password" not in str(source)


def test_fmc_failed_later_page_keeps_first_page(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            if url.endswith("/hosts?offset=1"):
                raise TimeoutError("connection-secret")
            if url.endswith("/hosts"):
                return Response({"items": [{"id": "h1", "name": "host", "value": "192.0.2.1"}],
                                 "paging": {"next": {"href": url + "?offset=1"}, "total": 2}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    assert source.status == CollectionStatus.PARTIAL
    assert json.loads(source.source_text)["objects"]["hosts"][0]["name"] == "host"
    assert any(part.name == "hosts" and not part.complete and part.count == 1 for part in source.parts)


def test_fmc_nat_rule_sections_preserve_order(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            if url.endswith("/ftdnatpolicies"):
                return Response({"items": [{"id": "p1", "name": "NAT", "type": "FTDNatPolicy", "description": "policy"}], "paging": {"total": 1}})
            if url.endswith("/manualnatrules"):
                return Response({"items": [{"id": "m1", "section": "BEFORE_AUTO"}, {"id": "m2", "section": "AFTER_AUTO"}], "paging": {"total": 2}})
            if url.endswith("/autonatrules"):
                return Response({"items": [{"id": "a1", "section": "AUTO"}], "paging": {"total": 1}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    policy = json.loads(source.source_text)["nat_policies"][0]
    assert [policy["manual_rules_before_auto"][0]["id"], policy["auto_rules"][0]["id"], policy["manual_rules_after_auto"][0]["id"]] == ["m1", "a1", "m2"]
