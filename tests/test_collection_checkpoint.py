import json
import sys
from types import SimpleNamespace

from fwmigrate.collection.checkpoint import CheckPointCollector
from fwmigrate.vendors.checkpoint.models import CollectionStatus as CPStatus
from fwmigrate.vendors.checkpoint.r81_commands import R81CommandSpec
from fwmigrate.vendors.checkpoint.source_report import CheckPointSourceReporter


class Response:
    content = b"{}"

    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


def test_checkpoint_bundle_keeps_command_status_and_gaia_separate(monkeypatch):
    commands = []
    disconnected = []

    class Session:
        headers = {}
        verify = True

        def post(self, url, **kwargs):
            command = url.split("/")[-1]
            commands.append(command)
            if command == "login":
                return Response({"sid": "do-not-save"})
            if command == "logout":
                return Response({})
            shape = "rulebase" if command.endswith("rulebase") else "objects"
            return Response({shape: [{"uid": "uid-1", "name": "obj"}] if command == "show-hosts" else [], "from": 1, "to": 1 if command == "show-hosts" else 0, "total": 1 if command == "show-hosts" else 0})

        def close(self):
            disconnected.append("api")

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: SimpleNamespace(
        send_command=lambda *args, **kwargs: "set interface eth0 ipv4-address 192.0.2.1 mask-length 24",
        disconnect=lambda: disconnected.append("gaia"))))
    collector = CheckPointCollector()
    source = collector.collect(collector.validate_options({"host": "mgmt", "username": "u", "password": "p",
                                                         "domain": "D", "package": "P", "layer": "L", "gateway": "G",
                                                         "gaia_host": "gaia", "gaia_username": "u", "gaia_password": "p"}))
    bundle = json.loads(source.source_text)
    assert "do-not-save" not in source.source_text
    assert bundle["gaia_responses"] and bundle["responses"]
    assert bundle["collection_completeness"]["show-hosts|domain=D"]["status"] == CPStatus.SUCCESS_WITH_DATA.value
    host_response = next(item for item in bundle["responses"] if item["command"] == "show-hosts")
    assert host_response["domain"] == "D"
    assert not any(host_response.get(key) for key in ("package", "layer", "gateway"))
    nat_response = next(item for item in bundle["responses"] if item["command"] == "show-nat-rulebase")
    layer_response = next(item for item in bundle["responses"] if item["command"] == "show-access-rulebase")
    assert nat_response["package"] == "P" and nat_response.get("layer") is None
    assert layer_response["layer"] == "L" and layer_response["package"] == "P"
    assert bundle["management_server"] == "mgmt"
    assert bundle["requested_scope"] == {"domain": "D", "package": "P", "layer": "L", "gateway": "G"}
    assert set(commands[1:-1]).isdisjoint({"publish", "install-policy", "delete"})
    assert disconnected == ["gaia", "api"] or disconnected == ["api", "gaia"]
    assert CheckPointSourceReporter().analyze_source(source.source_text)


def test_checkpoint_pagination_and_permission_failure(monkeypatch):
    from fwmigrate.collection import checkpoint as module
    monkeypatch.setattr(module, "R81_COMMAND_REGISTRY", {
        "show-hosts": R81CommandSpec("show-hosts", required=True),
        "show-networks": R81CommandSpec("show-networks"),
    })
    requests_seen = []

    class Denied(Exception):
        response = SimpleNamespace(status_code=403)

    class Session:
        headers = {}
        verify = None

        def post(self, url, **kwargs):
            command = url.split("/")[-1]
            if command == "login":
                return Response({"sid": "session-secret"})
            if command == "logout":
                return Response({})
            requests_seen.append((command, kwargs["json"].get("offset")))
            if command == "show-networks":
                raise Denied("secret-password")
            offset = kwargs["json"]["offset"]
            return Response({"objects": [{"uid": str(offset)}], "from": offset + 1, "to": offset + 1, "total": 2})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CheckPointCollector()
    source = collector.collect(collector.validate_options({"host": "mgmt", "username": "u", "password": "p"}))
    bundle = json.loads(source.source_text)
    assert requests_seen == [("show-hosts", 0), ("show-hosts", 1), ("show-networks", 0)]
    assert bundle["collection_completeness"]["show-hosts"]["complete"] is True
    assert bundle["collection_completeness"]["show-networks"]["status"] == CPStatus.PERMISSION_DENIED.value
    assert source.status.value == "PARTIAL"
    assert "session-secret" not in source.source_text
    assert "secret-password" not in str(source)


def test_gaia_failure_is_not_empty_source(monkeypatch):
    from fwmigrate.collection import checkpoint as module
    monkeypatch.setattr(module, "R81_COMMAND_REGISTRY", {"show-hosts": R81CommandSpec("show-hosts", required=True)})

    class Session:
        headers = {}
        verify = None

        def post(self, url, **kwargs):
            if url.endswith("login"):
                return Response({"sid": "secret-session"})
            if url.endswith("logout"):
                return Response({})
            return Response({"objects": [{"uid": "h1", "name": "host"}], "from": 1, "to": 1, "total": 1})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: (_ for _ in ()).throw(TimeoutError("secret-password"))))
    collector = CheckPointCollector()
    source = collector.collect(collector.validate_options({"host": "mgmt", "username": "u", "password": "p",
                                                         "gaia_host": "gaia", "gaia_username": "u", "gaia_password": "p"}))
    assert source.status.value == "PARTIAL"
    assert json.loads(source.source_text)["gaia_responses"][0]["collection_status"] == "TRANSPORT_ERROR"
    assert "secret-password" not in source.source_text


def test_checkpoint_inconsistent_pagination_is_partial(monkeypatch):
    from fwmigrate.collection import checkpoint as module
    monkeypatch.setattr(module, "R81_COMMAND_REGISTRY", {"show-hosts": R81CommandSpec("show-hosts", required=True)})

    class Session:
        headers = {}
        verify = None

        def post(self, url, **kwargs):
            if url.endswith("login"):
                return Response({"sid": "sid"})
            if url.endswith("logout"):
                return Response({})
            return Response({"objects": [{"uid": "h1", "name": "host"}], "from": 2, "to": 2, "total": 2})

        def close(self):
            pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    collector = CheckPointCollector()
    source = collector.collect(collector.validate_options({"host": "mgmt", "username": "u", "password": "p"}))
    assert source.status.value == "PARTIAL"
    assert json.loads(source.source_text)["collection_completeness"]["show-hosts"]["complete"] is False


def test_inline_rulebase_collection_is_recursive_and_scoped(monkeypatch):
    from fwmigrate.collection import checkpoint as module
    from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle, CheckPointResponse
    spec = R81CommandSpec("show-access-rulebase", expected_response_shape="rulebase", scope_type="ACCESS_LAYER", required=True)
    monkeypatch.setattr(module, "R81_COMMAND_REGISTRY", {"show-access-rulebase": spec})
    requests_seen = []

    class Session:
        headers = {}
        def post(self, url, **kwargs):
            payload = kwargs["json"]
            requests_seen.append(payload)
            if payload["name"] == "root":
                return Response({"uid": "root-uid", "name": "root", "rulebase": [
                    {"type": "access-rule", "uid": "parent-rule", "inline-layer": {"uid": "child-uid"}},
                ], "from": 1, "to": 1, "total": 1})
            return Response({"uid": "child-uid", "name": "child", "rulebase": [], "from": 1, "to": 0, "total": 0})

    collector = CheckPointCollector()
    bundle = CheckPointExportBundle()
    bundle.responses.append(CheckPointResponse(command="show-access-layers", data={"objects": [
        {"uid": "child-uid", "name": "child"},
    ]}))
    parts = []
    collector._collect_command(Session(), "https://mgmt/web_api/", "show-access-rulebase", spec,
                               ("name", "root"), bundle, parts, {"domain": "D", "package": "P", "layer": "root"})
    assert [item["name"] for item in requests_seen] == ["root", "child"]
    child = bundle.responses[-1]
    assert child.parent_layer_uid == "root-uid" and child.parent_rule_uid == "parent-rule"
    assert "show-access-rulebase|domain=D|package=P|layer=root" in bundle.collection_completeness
    assert "show-access-rulebase|domain=D|package=P|layer=child" in bundle.collection_completeness


def test_full_details_is_limited_to_marked_commands(monkeypatch):
    from fwmigrate.collection import checkpoint as module
    monkeypatch.setattr(module, "R81_COMMAND_REGISTRY", {
        "show-hosts": R81CommandSpec("show-hosts", details_level_full=True),
        "show-services-tcp": R81CommandSpec("show-services-tcp"),
    })
    payloads = []

    class Session:
        headers = {}
        def post(self, url, **kwargs):
            if url.endswith("login"): return Response({"sid": "sid"})
            if url.endswith("logout"): return Response({})
            payloads.append(kwargs["json"])
            return Response({"objects": [], "from": 0, "to": 0, "total": 0})
        def close(self): pass

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(Session=Session))
    CheckPointCollector().collect(CheckPointCollector().validate_options({"host": "mgmt", "username": "u", "password": "p"}))
    assert payloads[0]["details-level"] == "full"
    assert "details-level" not in payloads[1]
