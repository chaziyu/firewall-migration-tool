import json
from io import BytesIO
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
            path = url.split("?", 1)[0]
            if path.endswith("/networkaddresses/h1"):
                return Response({"id": "h1", "name": "first", "type": "Host", "value": "192.0.2.1"})
            if path.endswith("/networkaddresses/h2"):
                return Response({"id": "h2", "name": "second", "type": "Host", "value": "192.0.2.2", "password": "do-not-save"})
            if path.endswith("/networkaddresses") and "offset=1" not in url:
                return Response({"items": [{"id": "h1", "name": "first"}], "paging": {"next": {"href": url + "&offset=1"}, "total": 2}})
            if path.endswith("/networkaddresses") and "offset=1" in url:
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
    assert len(bundle["objects"]["networkaddresses"]) == 2
    parts = {part.name: part for part in source.parts}
    assert (parts["networkaddresses"].status, parts["networkaddresses"].complete, parts["networkaddresses"].count) == ("SUCCESS", True, 2)
    assert (parts["networkgroups"].status, parts["networkgroups"].complete, parts["networkgroups"].count) == ("EMPTY", True, 0)
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
            if url.split("?", 1)[0].endswith("/networkaddresses"):
                raise TimeoutError("secret-password")
            items = [{"id": "z1", "name": "inside"}] if url.split("?", 1)[0].endswith("/object/securityzones") else []
            return Response({"items": items, "paging": {"total": len(items)}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    source = CiscoFTDCollector().collect(CiscoFTDCollector().validate_options({"host": "fmc", "username": "u", "password": "p"}))
    assert source.status == CollectionStatus.PARTIAL
    part = next(part for part in source.parts if part.name == "networkaddresses")
    assert (part.status, part.complete, part.count) == ("FAILED", False, 0)
    assert "secret-password" not in str(source)


def test_fmc_failed_later_page_keeps_first_page(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            path = url.split("?", 1)[0]
            if path.endswith("/networkaddresses") and "offset=1" in url:
                raise TimeoutError("connection-secret")
            if path.endswith("/networkaddresses"):
                return Response({"items": [{"id": "h1", "name": "host", "type": "Host", "value": "192.0.2.1"}],
                                 "paging": {"next": {"href": url + "&offset=1"}, "total": 2}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    assert source.status == CollectionStatus.PARTIAL
    assert json.loads(source.source_text)["objects"]["networkaddresses"][0]["name"] == "host"
    part = next(part for part in source.parts if part.name == "networkaddresses")
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
            path = url.split("?", 1)[0]
            if path.endswith("/policy/accesspolicies/policy-1"):
                return Response({"id": "policy-1", "name": "Policy"})
            if path.endswith("/policy/accesspolicies"):
                return Response({"items": [{"id": "policy-1", "name": "Policy", "defaultAction": {"id": "default-1"}}], "paging": {"total": 1}})
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
            path = url.split("?", 1)[0]
            if path.endswith("/policy/accesspolicies/policy-1"):
                return Response({"id": "policy-1", "name": "Policy"})
            if path.endswith("/policy/accesspolicies"):
                return Response({"items": [{"id": "policy-1", "name": "Policy", "defaultAction": {"id": "default-1"}}], "paging": {"total": 1}})
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


def test_fmc_expanded_selected_coverage_keeps_device_and_policy_ownership(monkeypatch):
    calls = []

    class Session:
        headers = {}
        verify = None

        def post(self, url, **kwargs):
            calls.append(("POST", url))
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            calls.append(("GET", url))
            data = []
            if url.endswith("/devices/devicerecords"):
                data = [{"id": "dev-1", "name": "edge", "type": "DeviceRecord", "model": "FTD"}]
            elif url.endswith("/routing/virtualrouters"):
                data = [{"id": "vr-1", "name": "blue", "interfaces": [{"name": "inside"}]}]
            elif url.split("?", 1)[0].endswith("/routing/virtualrouters/vr-1/staticroutes"):
                data = [{"id": "route-1", "name": "default-v6", "type": "IPv6StaticRoute", "destination": "::/0"}]
            elif url.split("?", 1)[0].endswith("/object/networkaddresses"):
                data = [{"id": "addr-1", "name": "vpn-client", "type": "Host", "value": "192.0.2.8"}]
            elif url.endswith("/object/ipv4addresspools"):
                data = [{"id": "pool-1", "name": "ra-pool", "range": "192.0.2.8-192.0.2.20"}]
            elif url.endswith("/policy/intrusionpolicies"):
                data = [{"id": "ips-1", "name": "IPS", "description": "configured policy"}]
            elif "/intrusionrulegroups?" in url:
                data = [{"id": "group-1", "name": "local-overrides", "rules": [{"id": "sig-1", "action": "DROP"}]}]
            elif "/intrusionrules?" in url and "overrides=true" in url:
                data = []
            elif "/intrusionrules?" in url:
                data = [{"id": "sig-1", "gid": 1, "sid": 50, "action": "DROP", "enabled": True}]
            elif url.endswith("/policy/ftds2svpns"):
                data = [{"id": "s2s-1", "name": "branch", "description": "configured topology"}]
            elif url.endswith("/s2s-1/endpoints"):
                data = [{"id": "endpoint-1", "ikeSettings": {"id": "ike-1"}}]
            elif url.endswith("/s2s-1/ikesettings?expanded=true"):
                data = [{"id": "ike-1", "ikeVersion": "IKEv2"}]
            elif url.endswith("/s2s-1/ipsecsettings?expanded=true"):
                data = [{"id": "ipsec-1", "proposal": "AES256"}]
            elif url.endswith("/s2s-1/advancedsettings?expanded=true"):
                data = [{"id": "adv-1", "rekey": 3600}]
            elif url.endswith("/policy/ravpns"):
                data = [{"id": "ra-1", "name": "remote", "description": "configured topology"}]
            elif url.endswith("/ra-1/connectionprofiles?expanded=true"):
                data = [{"id": "profile-1", "name": "staff", "realm": {"id": "realm-1"}}]
            elif url.endswith("/ra-1/addressassignmentsettings?expanded=true"):
                data = [{"id": "assign-1", "ipv4AddressPool": {"id": "pool-1"}}]
            elif url.split("?", 1)[0].endswith("/policy/accesspolicies"):
                data = [{"id": "acp-1", "name": "ACP", "description": "configured policy", "defaultAction": {"id": "default-1"}}]
            elif url.endswith("/acp-1/defaultactions?expanded=true"):
                data = [{"id": "default-1", "action": "BLOCK"}]
            elif "/policy/prefilterpolicies" in url and "defaultactions" not in url:
                data = [{"id": "prefilter-1", "name": "Prefilter", "description": "test"}]
            elif url.endswith("/prefilter-1/defaultactions?expanded=true"):
                data = [{"id": "prefilter-default-1", "action": "BLOCK"}]
            elif "/policy/networkanalysispolicies" in url and "inspector" not in url:
                data = [{"id": "nap-1", "name": "Network Analysis", "description": "test"}]
            elif url.endswith("/nap-1/inspectorconfigs?expanded=true"):
                data = [{"id": "inspector-1", "name": "httpInspect", "description": "test"}]
            elif url.endswith("/nap-1/inspectoroverrideconfigs?expanded=true"):
                data = [{"id": "override-1", "name": "httpInspect", "enabled": False, "description": "test"}]
            return Response({"items": data, "paging": {"total": len(data)}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)

    assert bundle["devices"][0]["id"] == "dev-1"
    assert any("prefilter-1/defaultactions" in url for method, url in calls if method == "GET"), [url for method, url in calls if method == "GET" and "prefilter" in url]
    vr = bundle["devices"][0]["resources"]["virtual_routers"][0]
    assert vr["id"] == "vr-1" and vr["resources"]["static_routes"][0]["id"] == "route-1"
    assert bundle["objects"]["intrusionpolicies"][0]["rules"][0]["sid"] == 50
    assert bundle["objects"]["s2svpns"][0]["ike_settings"][0]["id"] == "ike-1"
    assert bundle["objects"]["ravpns"][0]["address_assignment_settings"][0]["id"] == "assign-1"
    assert bundle["access_policies"][0]["default_actions"][0]["id"] == "default-1"
    assert bundle["objects"]["prefilterpolicies"][0]["default_actions"][0]["id"] == "prefilter-default-1"
    assert bundle["objects"]["networkanalysispolicies"][0]["inspectorconfigs"][0]["id"] == "inspector-1"
    assert bundle["objects"]["networkanalysispolicies"][0]["inspectoroverrideconfigs"][0]["id"] == "override-1"
    assert bundle["coverage"]["fmc_cli_users"]["status"] == "UNAVAILABLE"
    parts = {part.name for part in source.parts}
    assert "device/dev-1/virtual_router/vr-1/static_routes" in parts
    assert "intrusionpolicies/ips-1/rules" in parts
    assert "s2svpns/s2s-1/ike_settings" in parts
    assert "ravpns/ra-1/address_assignment_settings" in parts
    assert "accesspolicies/acp-1/default_actions" in parts
    assert "networkanalysispolicies/nap-1/inspectorconfigs" in parts
    assert all("/domain/d1/" in url for method, url in calls if method == "GET")
    assert all(method == "GET" for method, _ in calls[1:])

    analysis = CiscoFTDSourceReporter().analyze_source(source.source_text)
    assert analysis.config.routes[0].virtual_router == "blue"
    assert any(item.source_attributes.get("parent_policy_id") == "ra-1"
               for item in analysis.config.ra_vpn_address_assignment_settings)
    assert any(item.source_attributes.get("parent_policy_id") == "acp-1"
               and item.action == "BLOCK" for item in analysis.config.access_control_default_actions)
    assert any(item.source_attributes.get("parent_policy_id") == "prefilter-1"
               for item in analysis.config.prefilter_default_actions)
    assert analysis.derived is not None and analysis.validation is not None
    assert isinstance(CiscoFTDSourceReporter().build_preview(analysis), dict)
    workbook = BytesIO()
    CiscoFTDSourceReporter().export_excel(analysis, workbook)
    assert workbook.getvalue().startswith(b"PK")


def test_fmc_device_intrusion_and_vpn_failures_keep_successful_source(monkeypatch):
    class Session:
        headers = {}
        verify = None

        def post(self, *args, **kwargs):
            return Response(headers={"X-auth-access-token": "token", "DOMAINS": '[{"uuid":"d1","name":"Global"}]'})

        def get(self, url, **kwargs):
            if url.endswith("/devices/devicerecords"):
                return Response({"items": [{"id": "dev-1", "name": "edge", "model": "FTD"}], "paging": {"total": 1}})
            if url.split("?", 1)[0].endswith("/dev-1/routing/ipv6staticroutes"):
                raise TimeoutError("device-resource-secret")
            if url.endswith("/dev-1/ftdallinterfaces"):
                return Response({"items": [{"id": "if-1", "name": "inside", "type": "PhysicalInterface", "physicalName": "eth0"}], "paging": {"total": 1}})
            if url.endswith("/policy/intrusionpolicies"):
                return Response({"items": [{"id": "ips-1", "name": "IPS", "description": "policy"}], "paging": {"total": 1}})
            if url.endswith("/intrusionrules?expanded=true"):
                raise TimeoutError("intrusion-child-secret")
            if url.endswith("/policy/ftds2svpns"):
                return Response({"items": [{"id": "vpn-1", "name": "S2S", "description": "topology"}], "paging": {"total": 1}})
            if url.endswith("/vpn-1/endpoints"):
                raise TimeoutError("vpn-child-secret")
            if url.split("?", 1)[0].endswith("/object/networkaddresses"):
                return Response({"items": [{"id": "addr-1", "name": "server", "type": "Host", "value": "192.0.2.1"}], "paging": {"total": 1}})
            return Response({"items": [], "paging": {"total": 0}})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CiscoFTDCollector()
    source = collector.collect(collector.validate_options({"host": "fmc", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)
    failed = {part.name for part in source.parts if not part.complete}

    assert source.status == CollectionStatus.PARTIAL
    assert "device/dev-1/ipv6_static_routes" in failed
    assert "intrusionpolicies/ips-1/rules" in failed
    assert "s2svpns/vpn-1/endpoints" in failed
    assert bundle["objects"]["networkaddresses"][0]["id"] == "addr-1"
    assert bundle["devices"][0]["resources"]["ftd_interfaces"][0]["id"] == "if-1"
    assert "device-resource-secret" not in source.source_text
    assert "intrusion-child-secret" not in source.source_text
    assert "vpn-child-secret" not in source.source_text
    analysis = CiscoFTDSourceReporter().analyze_source(source.source_text)
    assert analysis.config.network_addresses[0].source_id == "addr-1"
    assert any(item["source_path"] == "intrusionpolicies/ips-1/rules" for item in analysis.config.unsupported_evidence)
