import sys
import json
import pytest
from types import SimpleNamespace

from fwmigrate.collection.cisco_asa import CiscoASACollector


@pytest.mark.parametrize("multi_context", [False, True])
def test_asa_collector_snapshot_round_trip(monkeypatch, multi_context):
    from fwmigrate.collection.snapshot import make_snapshot, parse_snapshot

    responses = {"show mode": "Security context mode: multiple" if multi_context else "Security context mode: single",
                 "changeto system": "", "show running-config": "hostname asa\ncontext blue\n",
                 "changeto context blue": ""}
    session = SimpleNamespace(send_command=lambda command, **kwargs: responses[command], disconnect=lambda: None)
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: session))
    source = CiscoASACollector().collect({"host": "asa", "port": 22, "username": "u", "password": "p"})
    imported = parse_snapshot(json.dumps(make_snapshot(source)).encode())
    assert imported == source


@pytest.mark.parametrize("response", ["ERROR: Command authorization failed", "% Invalid input detected", "Permission denied"])
def test_asa_command_errors_are_failed_acquisition(monkeypatch, response):
    from fwmigrate.collection.contracts import CollectionError

    calls = []
    session = SimpleNamespace(send_command=lambda command, **kwargs: "Security context mode: single" if command == "show mode" else response,
                              disconnect=lambda: calls.append("disconnect"))
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: session))
    with pytest.raises(CollectionError):
        CiscoASACollector().collect({"host": "asa", "port": 22, "username": "u", "password": "p"})
    assert calls == ["disconnect"]


def test_rejected_context_switch_does_not_collect_under_wrong_owner(monkeypatch):
    commands = []

    def send(command, **kwargs):
        commands.append(command)
        return {"show mode": "Security context mode: multiple", "changeto system": "",
                "show running-config": "hostname system\ncontext blue\n",
                "changeto context blue": "ERROR: context not found"}[command]

    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs:
        SimpleNamespace(send_command=send, disconnect=lambda: None)))
    source = CiscoASACollector().collect({"host": "asa", "port": 22, "username": "u", "password": "p"})
    assert source.status.value == "PARTIAL"
    assert commands.count("show running-config") == 1
    assert "changeto context blue" not in source.source_text
    assert source.parts[-1].status == "FAILED"


def test_multi_context_collection_keeps_each_context_and_reports_partial_results(monkeypatch):
    commands = []

    class Session:
        def send_command(self, command, **kwargs):
            commands.append(command)
            responses = {
                "show mode": "Security context mode: multiple",
                "changeto system": "",
                "show running-config": "hostname system\ncontext admin\n config-url disk0:/admin.cfg\ncontext blue\n config-url disk0:/blue.cfg\n",
                "changeto context admin": "",
            }
            if command == "show running-config" and commands.count(command) == 2:
                return "hostname admin\n"
            if command == "show running-config" and commands.count(command) == 3:
                raise TimeoutError("sensitive transport detail")
            return responses[command]

        def disconnect(self):
            commands.append("disconnect")

    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: Session()))
    collector = CiscoASACollector()
    source = collector.collect(collector.validate_options({"host": "asa", "username": "user", "password": "secret"}))

    assert source.status.value == "PARTIAL"
    assert "changeto system\nhostname system" in source.source_text
    assert "changeto context admin\nhostname admin" in source.source_text
    assert "changeto context blue" not in source.source_text
    assert "sensitive transport detail" not in str(source)
    assert source.metadata == {"multi_context": True}
    assert [(part.name, part.complete) for part in source.parts] == [
        ("system/running-config", True), ("contexts", True),
        ("context/admin/running-config", True), ("context/blue/running-config", False),
    ]
    assert commands[-2:] == ["changeto system", "disconnect"]
