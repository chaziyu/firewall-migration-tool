import sys
from types import SimpleNamespace

import pytest

from fwmigrate.collection.juniper_srx import JuniperSRXCollector
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter


def test_juniper_set_collection_preserves_context_and_disconnects(monkeypatch):
    calls = []
    content = 'set groups G system host-name branch\nset apply-groups G\nset logical-systems LS interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\ndeactivate security policies from-zone a to-zone b policy p\nset system root-authentication encrypted-password do-not-save\nset security ike gateway g pre-shared-key ascii also-do-not-save'
    connection = SimpleNamespace(send_command=lambda command, **kwargs: calls.append(command) or content,
                                 disconnect=lambda: calls.append("disconnect"))
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: connection))
    source = JuniperSRXCollector().collect({"host": "192.0.2.1", "port": 22, "username": "u", "password": "p"})
    assert calls == ["show configuration | display set", "disconnect"]
    assert "deactivate security" in source.source_text
    assert "logical-systems LS" in source.source_text
    assert "do-not-save" not in source.source_text
    assert "pre-shared-key ascii [REDACTED]" in source.source_text
    assert JuniperSRXSourceReporter().analyze_source(source.source_text)


def test_juniper_empty_output_disconnects(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=lambda **kwargs: SimpleNamespace(send_command=lambda *args, **kwargs: "", disconnect=lambda: calls.append(1))))
    with pytest.raises(Exception):
        JuniperSRXCollector().collect({"host": "h", "port": 22, "username": "u", "password": "p"})
    assert calls == [1]
