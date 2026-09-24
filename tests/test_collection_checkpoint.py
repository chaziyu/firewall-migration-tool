import json
from types import SimpleNamespace

from fwmigrate.collection.checkpoint import CheckPointCollector, _classify_management_error
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle, CheckPointResponse, CollectionStatus as CPStatus
from fwmigrate.vendors.checkpoint.r81_commands import R81CommandSpec, R81_COMMAND_REGISTRY


class Response:
    content = b"{}"

    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.headers = {}
        self.verify = None
        self.closed = False

    def post(self, url, **kwargs):
        return self.handler(url.split("/")[-1], kwargs)

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, output=""):
        self.output = output
        self.disconnected = False

    def send_command(self, *args, **kwargs):
        return self.output

    def disconnect(self):
        self.disconnected = True


def api_factory(handler, sessions=None):
    def factory():
        session = FakeSession(handler)
        if sessions is not None:
            sessions.append(session)
        return session
    return factory


def connection_factory(connection):
    return lambda **kwargs: connection


def options(**extra):
    return CheckPointCollector().validate_options({"host": "mgmt", "username": "u", "password": "p", **extra})


def test_checkpoint_bundle_keeps_command_status_and_gaia_separate():
    commands, sessions = [], []
    gaia = FakeConnection("set interface eth0 ipv4-address 192.0.2.1 mask-length 24")

    def handle(command, kwargs):
        commands.append(command)
        if command == "login": return Response({"sid": "do-not-save"})
        if command == "logout": return Response({})
        shape = "rulebase" if command.endswith("rulebase") else "objects"
        items = [{"uid": "uid-1", "name": "obj"}] if command == "show-hosts" else []
        return Response({shape: items, "from": 1, "to": len(items), "total": len(items)})

    registry = {
        "show-hosts": R81CommandSpec("show-hosts", required=True),
        "show-packages": R81CommandSpec("show-packages", required=True),
        "show-access-layers": R81CommandSpec("show-access-layers"),
        "show-nat-rulebase": R81CommandSpec("show-nat-rulebase", expected_response_shape="rulebase", scope_type="PACKAGE", required=True),
        "show-access-rulebase": R81CommandSpec("show-access-rulebase", expected_response_shape="rulebase", scope_type="ACCESS_LAYER", required=True),
    }
    collector = CheckPointCollector(api_factory(handle, sessions), connection_factory(gaia), registry)
    source = collector.collect(collector.validate_options({"host": "mgmt", "username": "u", "password": "p",
        "domain": "D", "package": "P", "layer": "L", "gateway": "G", "gaia_host": "gaia",
        "gaia_username": "u", "gaia_password": "p"}))
    bundle = json.loads(source.source_text)
    assert "do-not-save" not in source.source_text
    assert bundle["gaia_responses"] and bundle["responses"]
    assert bundle["collection_completeness"]["show-hosts|domain=D"]["status"] == CPStatus.SUCCESS_WITH_DATA.value
    host = next(item for item in bundle["responses"] if item["command"] == "show-hosts")
    assert host["domain"] == "D" and not any(host.get(key) for key in ("package", "layer", "gateway"))
    nat = next(item for item in bundle["responses"] if item["command"] == "show-nat-rulebase")
    layer = next(item for item in bundle["responses"] if item["command"] == "show-access-rulebase")
    assert nat["package"] == "P" and nat.get("layer") is None
    assert layer["layer"] == "L" and layer.get("package") is None
    assert bundle["management_server"] == "mgmt"
    assert bundle["requested_scope"] == {"domain": "D", "package": "P", "layer": "L", "gateway": "G"}
    assert commands[0] == "login" and commands[-1] == "logout"
    assert set(commands[1:-1]).isdisjoint({"publish", "install-policy", "delete"})
    assert gaia.disconnected and sessions[0].closed


def test_checkpoint_pagination_and_permission_failure():
    requests_seen = []

    class Denied(Exception):
        response = SimpleNamespace(status_code=403)

    def handle(command, kwargs):
        if command == "login": return Response({"sid": "session-secret"})
        if command == "logout": return Response({})
        requests_seen.append((command, kwargs["json"].get("offset")))
        if command == "show-networks": raise Denied("secret-password")
        offset = kwargs["json"]["offset"]
        return Response({"objects": [{"uid": str(offset)}], "from": offset + 1, "to": offset + 1, "total": 2})

    registry = {"show-hosts": R81CommandSpec("show-hosts", required=True), "show-networks": R81CommandSpec("show-networks")}
    source = CheckPointCollector(api_factory(handle), command_registry=registry).collect(options())
    bundle = json.loads(source.source_text)
    assert requests_seen == [("show-hosts", 0), ("show-hosts", 1), ("show-networks", 0)]
    assert bundle["collection_completeness"]["show-hosts"]["complete"] is True
    assert bundle["collection_completeness"]["show-networks"]["status"] == CPStatus.PERMISSION_DENIED.value
    assert source.status.value == "PARTIAL"
    assert "session-secret" not in source.source_text and "secret-password" not in str(source)


def test_gaia_failure_is_not_empty_source_and_api_closes():
    sessions = []

    def handle(command, kwargs):
        if command == "login": return Response({"sid": "secret-session"})
        if command == "logout": return Response({})
        return Response({"objects": [{"uid": "h1", "name": "host"}], "from": 1, "to": 1, "total": 1})

    def fail_gaia(**kwargs):
        raise TimeoutError("secret-password")

    collector = CheckPointCollector(api_factory(handle, sessions), fail_gaia,
                                    {"show-hosts": R81CommandSpec("show-hosts", required=True)})
    source = collector.collect(collector.validate_options({"host": "mgmt", "username": "u", "password": "p",
        "gaia_host": "gaia", "gaia_username": "u", "gaia_password": "p"}))
    assert source.status.value == "PARTIAL"
    assert json.loads(source.source_text)["gaia_responses"][0]["collection_status"] == "TRANSPORT_ERROR"
    assert "secret-password" not in source.source_text and sessions[0].closed


def test_checkpoint_inconsistent_pagination_is_partial():
    def handle(command, kwargs):
        if command == "login": return Response({"sid": "sid"})
        if command == "logout": return Response({})
        return Response({"objects": [{"uid": "h1", "name": "host"}], "from": 2, "to": 2, "total": 2})

    collector = CheckPointCollector(api_factory(handle), command_registry={"show-hosts": R81CommandSpec("show-hosts", required=True)})
    source = collector.collect(options())
    assert source.status.value == "PARTIAL"
    assert json.loads(source.source_text)["collection_completeness"]["show-hosts"]["complete"] is False


def test_inline_rulebase_collection_is_recursive_and_scoped():
    spec = R81CommandSpec("show-access-rulebase", expected_response_shape="rulebase", scope_type="ACCESS_LAYER", required=True)
    requests_seen = []

    def handle(command, kwargs):
        payload = kwargs["json"]
        requests_seen.append(payload)
        if payload["name"] == "root":
            return Response({"uid": "root-uid", "name": "root", "rulebase": [
                {"type": "access-rule", "uid": "parent-rule", "inline-layer": {"uid": "child-uid"}},
            ], "from": 1, "to": 1, "total": 1})
        return Response({"uid": "child-uid", "name": "child", "rulebase": [], "from": 1, "to": 0, "total": 0})

    collector = CheckPointCollector(command_registry={"show-access-rulebase": spec})
    bundle = CheckPointExportBundle()
    bundle.responses.append(CheckPointResponse(command="show-access-layers", data={"objects": [{"uid": "child-uid", "name": "child"}]}))
    parts = []
    collector._collect_command(FakeSession(handle), "https://mgmt/web_api/", "show-access-rulebase", spec,
        ("name", "root"), bundle, parts, {"domain": "D", "package": "P", "layer": "root"})
    assert [item["name"] for item in requests_seen] == ["root", "child"]
    child = bundle.responses[-1]
    assert child.parent_layer_uid == "root-uid" and child.parent_rule_uid == "parent-rule"
    assert "show-access-rulebase|domain=D|layer=root" in bundle.collection_completeness
    assert "show-access-rulebase|domain=D|layer=child" in bundle.collection_completeness


def test_full_details_is_limited_to_marked_commands():
    payloads = []

    def handle(command, kwargs):
        if command in {"login", "logout"}: return Response({"sid": "sid"} if command == "login" else {})
        payloads.append(kwargs["json"])
        return Response({"objects": [], "from": 0, "to": 0, "total": 0})

    registry = {"show-hosts": R81CommandSpec("show-hosts", details_level_full=True),
                "show-services-tcp": R81CommandSpec("show-services-tcp")}
    CheckPointCollector(api_factory(handle), command_registry=registry).collect(options())
    assert payloads[0]["details-level"] == "full" and "details-level" not in payloads[1]


def test_scope_discovery_and_explicit_selection():
    package_calls, layer_calls = [], []

    def handle(command, kwargs):
        if command == "login": return Response({"sid": "sid"})
        if command == "logout": return Response({})
        payload = kwargs["json"]
        if command == "show-packages": return Response({"objects": [{"name": "P1"}, {"name": "P2"}]})
        if command == "show-access-layers": return Response({"objects": [{"name": "L1"}, {"name": "L2"}]})
        if command == "show-nat-rulebase":
            package_calls.append(payload["package"])
            return Response({"rulebase": [], "from": 1, "to": 0, "total": 0})
        if command == "show-access-rulebase":
            layer_calls.append(payload["name"])
            return Response({"rulebase": [], "from": 1, "to": 0, "total": 0})
        return Response({"objects": []})

    registry = {
        "show-packages": R81CommandSpec("show-packages", required=True),
        "show-access-layers": R81CommandSpec("show-access-layers"),
        "show-nat-rulebase": R81CommandSpec("show-nat-rulebase", expected_response_shape="rulebase", scope_type="PACKAGE", required=True),
        "show-access-rulebase": R81CommandSpec("show-access-rulebase", expected_response_shape="rulebase", scope_type="ACCESS_LAYER", required=True),
    }
    collector = CheckPointCollector(api_factory(handle), command_registry=registry)
    bundle = json.loads(collector.collect(options()).source_text)
    assert package_calls == ["P1", "P2"] and layer_calls == ["L1", "L2"]
    assert all(f"show-nat-rulebase|package={name}" in bundle["collection_completeness"] for name in package_calls)
    assert all(f"show-access-rulebase|layer={name}" in bundle["collection_completeness"] for name in layer_calls)
    package_calls.clear(); layer_calls.clear()
    collector.collect(options(package="P2", layer="L1"))
    assert package_calls == ["P2"] and layer_calls == ["L1"]


def test_management_error_classifier_requires_confirmed_capability_evidence():
    class ApiFailure(Exception):
        response = SimpleNamespace(status_code=400)

    class Forbidden(Exception):
        response = SimpleNamespace(status_code=403)

    assert _classify_management_error(Forbidden()) == CPStatus.PERMISSION_DENIED
    assert _classify_management_error(ApiFailure()) == CPStatus.API_ERROR
    assert _classify_management_error(ValueError("bad response")) == CPStatus.API_ERROR
    assert _classify_management_error(TimeoutError()) == CPStatus.TRANSPORT_ERROR


def test_selected_package_discovers_its_layers_without_labeling_layer_scope_as_package():
    bundle = CheckPointExportBundle.model_validate({"responses": [
        {"command": "show-packages", "domain": "Domain A", "data": {"objects": [{"name": "Package A", "access-layers": [{"uid": "l1"}, {"name": "Layer B"}]}]}},
        {"command": "show-access-layers", "domain": "Domain A", "data": {"objects": [
            {"uid": "l1", "name": "Layer A"}, {"uid": "l2", "name": "Layer B"},
            {"uid": "l3", "name": "Unrelated"},
        ]}},
    ]})
    options = {"package": "Package A", "layer": None, "domain": "Domain A"}
    spec = R81_COMMAND_REGISTRY["show-access-rulebase"]

    assert CheckPointCollector._plan_selectors("show-access-rulebase", spec, bundle, options) == [
        ("name", "Layer A"), ("name", "Layer B"),
    ]
    scope = CheckPointCollector._response_scope(spec, options, ("name", "Layer A"))
    assert scope == {"domain": "Domain A", "layer": "Layer A"}
    assert CheckPointCollector._operation_key("show-access-rulebase", scope) == "show-access-rulebase|domain=Domain A|layer=Layer A"
