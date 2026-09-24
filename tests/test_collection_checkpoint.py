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
    assert bundle["collection_completeness"]["show-hosts"]["status"] == CPStatus.SUCCESS_WITH_DATA.value
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
