import json
import sys
from types import SimpleNamespace

from fwmigrate.collection.cisco_ftd import CiscoFTDCollector
from fwmigrate.collection.contracts import CollectionPart, CollectionStatus
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
    parts = {part.name: part for part in source.parts}
    assert (parts["hosts"].status, parts["hosts"].complete, parts["hosts"].count) == ("SUCCESS", True, 2)
    assert (parts["networks"].status, parts["networks"].complete, parts["networks"].count) == ("EMPTY", True, 0)
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
    part = next(part for part in source.parts if part.name == "networks")
    assert (part.status, part.complete, part.count) == ("FAILED", False, 0)
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
    part = next(part for part in source.parts if part.name == "hosts")
    assert (part.status, part.complete, part.count) == ("PARTIAL", False, 1)


def test_fmc_total_endpoint_failure_is_failed_with_zero_count():
    class Session:
        def get(self, *args, **kwargs):
            raise TimeoutError("private transport detail")

    parts = []
    CiscoFTDCollector()._collect_family(Session(), "https://fmc", "/hosts", {}, "hosts", parts)
    assert parts == [CollectionPart("hosts", "FAILED", False, 0)]


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


def test_fmc_collects_device_interfaces_separately_from_zones_and_groups(monkeypatch):
    calls = []

    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d0","name":"Global"}]'})

        def get(self, url, **kwargs):
            calls.append(url)
            if url.endswith("/object/securityzones/z1"):
                return Response({"id": "z1", "name": "inside", "type": "SecurityZone"})
            if url.endswith("/object/interfacegroups/g1"):
                return Response({"id": "g1", "name": "trusted-group", "type": "InterfaceGroup"})
            if url.endswith("/devices/devicerecords"):
                return Response({"items": [{"id": "d1", "name": "ftd-1", "type": "DeviceRecord", "model": "FTD"}], "paging": {"total": 1}})
            if url.endswith("/d1/ftdallinterfaces"):
                return Response({"items": [
                    {"id": "if0", "name": "GigabitEthernet0/0", "type": "PhysicalInterface", "physicalName": "eth0"},
                    {"id": "if1", "name": "GigabitEthernet0/1", "type": "PhysicalInterface", "physicalName": "eth1"},
                ], "paging": {"total": 2}})
            if url.endswith("/object/securityzones"):
                return Response({"items": [{"id": "z1", "name": "inside", "type": "SecurityZone", "interfaces": []}], "paging": {"total": 1}})
            if url.endswith("/object/interfacegroups"):
                return Response({"items": [{"id": "g1", "name": "trusted-group", "type": "InterfaceGroup", "interfaces": []}], "paging": {"total": 1}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)

    assert bundle["objects"]["securityzones"][0]["name"] == "inside"
    assert bundle["objects"]["interfacegroups"][0]["name"] == "trusted-group"
    assert [item["name"] for item in bundle["devices"][0]["resources"]["ftd_interfaces"]] == [
        "GigabitEthernet0/0", "GigabitEthernet0/1"]
    assert "interfaces" not in bundle["objects"]
    assert any(url.endswith("/devices/devicerecords/d1/ftdallinterfaces") for url in calls)
    assert not any(url.endswith("/object/interfaceobjects") for url in calls)


def test_fmc_device_interface_failure_is_device_scoped_and_partial(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d0","name":"Global"}]'})

        def get(self, url, **kwargs):
            if url.endswith("/devices/devicerecords"):
                return Response({"items": [
                    {"id": "d1", "name": "ftd-1", "type": "DeviceRecord", "model": "FTD"},
                    {"id": "d2", "name": "ftd-2", "type": "DeviceRecord", "model": "FTD"},
                ], "paging": {"total": 2}})
            if url.endswith("/d1/ftdallinterfaces"):
                raise TimeoutError("interface request failed")
            if url.endswith("/d2/ftdallinterfaces"):
                return Response({"items": [{"id": "if2", "name": "GigabitEthernet0/0", "physicalName": "eth0"}], "paging": {"total": 1}})
            if url.endswith("/object/hosts"):
                return Response({"items": [{"id": "h1", "name": "usable"}], "paging": {"total": 1}})
            if url.endswith("/object/securityzones"):
                return Response({"items": [{"id": "z1", "name": "inside", "interfaces": ["GigabitEthernet0/0"]}], "paging": {"total": 1}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)
    assert source.status == CollectionStatus.PARTIAL
    assert bundle["devices"][0]["resources"]["ftd_interfaces"] == []
    assert bundle["devices"][1]["resources"]["ftd_interfaces"][0]["name"] == "GigabitEthernet0/0"
    assert any(part.name == "device/d1/ftd_interfaces" and not part.complete for part in source.parts)
    analysis = CiscoFTDSourceReporter().analyze_source(source.source_text)
    assert analysis.derived.source_plane_completeness["interfaces"] == "partial"
    assert next(item for item in analysis.derived.unresolved_references if item.field == "interfaces").status == "AMBIGUOUS"


def test_fmc_access_rules_request_expanded_fields(monkeypatch):
    calls = []

    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            calls.append(("GET", url))
            if url.endswith("/policy/accesspolicies/policy-1"):
                return Response({"id": "policy-1", "name": "Policy"})
            if url.endswith("/policy/accesspolicies"):
                return Response({"items": [{"id": "policy-1", "name": "Policy"}], "paging": {"total": 1}})
            if "/accessrules?expanded=true" in url:
                return Response({"items": [{
                    "id": "rule-1", "name": "Allow-Web", "enabled": True, "action": "ALLOW",
                    "sourcePorts": {"objects": [{"id": "src-port", "name": "Client"}]},
                    "destinationPorts": {"objects": [{"id": "dst-port", "name": "HTTPS"}]},
                }], "paging": {"total": 1}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    rule = json.loads(source.source_text)["access_policies"][0]["rules"][0]

    assert any("/accessrules?expanded=true" in url for _, url in calls)
    assert rule["sourcePorts"]["objects"][0]["id"] == "src-port"
    assert rule["destinationPorts"]["objects"][0]["id"] == "dst-port"
    assert all(method == "GET" for method, _ in calls)


def test_fmc_access_rule_later_page_failure_keeps_rules_and_marks_partial(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            if url.endswith("/policy/accesspolicies/policy-1"):
                return Response({"id": "policy-1", "name": "Policy"})
            if url.endswith("/policy/accesspolicies"):
                return Response({"items": [{"id": "policy-1", "name": "Policy"}], "paging": {"total": 1}})
            if "/accessrules?expanded=true&offset=1" in url:
                raise TimeoutError("transport-secret")
            if "/accessrules?expanded=true" in url:
                return Response({"items": [{
                    "id": "rule-1", "name": "Allow-Web", "enabled": True, "action": "ALLOW",
                    "sourceNetworks": {"objects": [{"id": "network-1", "name": "Web"}]},
                }], "paging": {"next": {"href": url + "&offset=1"}, "total": 2}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)

    assert source.status == CollectionStatus.PARTIAL
    assert bundle["access_policies"][0]["rules"][0]["id"] == "rule-1"
    assert any(part.name == "access_rules/policy-1" and not part.complete and part.count == 1 for part in source.parts)
    assert "transport-secret" not in source.source_text
