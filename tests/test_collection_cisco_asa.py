import sys
from types import SimpleNamespace

from fwmigrate.collection.cisco_asa import CiscoASACollector


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
