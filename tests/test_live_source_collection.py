from __future__ import annotations

import hashlib
import io

import pytest

from fwmigrate.collectors.fortigate import FortiGateSSHCollector
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.report.excel_exporter import IRExcelExporter

import fwmigrate.parsers  # noqa: F401


FORTIGATE_CONFIG = """config system global
    set hostname \"FG-LIVE-TEST\"
end
config firewall address
    edit \"host1\"
        set subnet 10.0.0.1 255.255.255.255
    next
end
"""


class FakeStream:
    def __init__(self, value: str):
        self.value = value

    def read(self):
        return self.value.encode("utf-8")


class FakeSSHClient:
    def __init__(self, config_text: str = FORTIGATE_CONFIG, config_stderr: str = ""):
        self.config_text = config_text
        self.config_stderr = config_stderr
        self.closed = False
        self.connect_kwargs = None
        self.commands = []

    def load_system_host_keys(self):
        pass

    def set_missing_host_key_policy(self, _policy):
        pass

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs

    def exec_command(self, command, timeout=None, get_pty=False):
        self.commands.append((command, timeout, get_pty))
        if command == "get system status":
            stdout = "Version: FortiGate-VM64 v7.4.6\nHostname: FG-LIVE-TEST\n"
            return None, FakeStream(stdout), FakeStream("")
        if command == "show full-configuration":
            return None, FakeStream(self.config_text), FakeStream(self.config_stderr)
        raise AssertionError(f"unexpected command: {command}")

    def close(self):
        self.closed = True


def test_fortigate_collector_preserves_raw_snapshot_and_checksum():
    fake = FakeSSHClient()
    collector = FortiGateSSHCollector(
        host="192.0.2.10",
        username="admin",
        password="secret",
        ssh_client_factory=lambda: fake,
    )

    snapshot = collector.collect()

    assert snapshot.complete is True
    assert snapshot.raw_config == FORTIGATE_CONFIG
    assert snapshot.hostname == "FG-LIVE-TEST"
    assert snapshot.software_version == "FortiGate-VM64 v7.4.6"
    assert snapshot.commands_executed == ["get system status", "show full-configuration"]
    assert snapshot.sha256 == hashlib.sha256(FORTIGATE_CONFIG.encode("utf-8")).hexdigest()
    assert fake.commands[1][2] is False, "full configuration must use a non-PTY channel to avoid pager truncation"
    assert fake.closed is True


def test_fortigate_collector_fails_closed_on_pager_marker():
    fake = FakeSSHClient(config_text=FORTIGATE_CONFIG + "\n--More--\n")
    snapshot = FortiGateSSHCollector(
        host="192.0.2.10",
        username="admin",
        password="secret",
        ssh_client_factory=lambda: fake,
    ).collect()

    assert snapshot.complete is False
    assert any("Paging markers" in error for error in snapshot.errors)


def test_live_snapshot_extracts_to_ir_and_excel_without_conversion():
    openpyxl = pytest.importorskip("openpyxl")
    snapshot = FortiGateSSHCollector(
        host="192.0.2.10",
        username="admin",
        password="secret",
        ssh_client_factory=lambda: FakeSSHClient(),
    ).collect()
    extraction = PluginRegistry.get_parser("fortigate").extract(snapshot.raw_config)

    assert extraction.canonical_ir.metadata.hostname == "FG-LIVE-TEST"
    assert any(address.name == "host1" for address in extraction.canonical_ir.addresses)
    assert extraction.source_sections
    assert all(section.status is not None for section in extraction.source_sections)

    workbook_bytes = IRExcelExporter(
        extraction.canonical_ir,
        extraction_result=extraction,
    ).generate()
    workbook = openpyxl.load_workbook(io.BytesIO(workbook_bytes), read_only=True)
    assert "Source Inventory" in workbook.sheetnames
    assert "Extraction Coverage" in workbook.sheetnames
    assert "Addresses" in workbook.sheetnames
