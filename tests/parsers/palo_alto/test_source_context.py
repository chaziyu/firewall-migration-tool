from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


FIXTURES = Path(__file__).parents[2] / "fixtures"
STANDALONE = FIXTURES / "example_palo_alto.xml"
PANORAMA = FIXTURES / "palo_alto" / "integrated_panorama.xml"


def _records(path: Path):
    return {record.name: record for record in build_panos_config(path.read_text()).source_inventory}


def test_standalone_vsys_and_local_rulebase_keep_device_context():
    records = _records(STANDALONE)

    server = records["Server_Web"]
    rule = records["Allow_LAN_To_Web"]
    assert server.scope.kind == "vsys"
    assert server.scope.name == "vsys1"
    assert server.scope.device_name == "localhost.localdomain"
    assert rule.rulebase_position == "local"


def test_shared_and_device_group_scopes_are_explicit_and_not_inherited():
    records = _records(PANORAMA)

    assert records["shared-net"].scope.kind == "shared"
    assert records["shared-net"].scope.name == "shared"
    assert records["shared-pre"].rulebase_position == "pre"
    assert records["shared-post"].rulebase_position == "post"

    assert records["parent-pre"].scope.device_group == "parent"
    assert records["parent-pre"].scope.parent_device_group is None
    assert records["child-pre"].scope.device_group == "child"
    assert records["child-pre"].scope.parent_device_group == "parent"
    assert records["child-post"].rulebase_position == "post"
    assert records["vsys1"].scope.device_serial == "serial-child"
    assert records["vsys1"].scope.device_group == "child"

    child_names = {
        name for name, record in records.items() if record.scope.device_group == "child"
    }
    assert "child-pre" in child_names
    assert "child-post" in child_names
    assert "parent-pre" not in child_names
    assert "shared-net" not in child_names


def test_sibling_devices_do_not_leak_vsys_context_or_scope_identity():
    config = build_panos_config(
        """<config><devices>
          <entry name="fw-a"><vsys><entry name="vsys1"><address><entry name="a"/></address></entry></vsys></entry>
          <entry name="fw-b"><vsys><entry name="vsys1"><address><entry name="b"/></address></entry></vsys></entry>
        </devices></config>"""
    )
    records = {record.name: record for record in config.source_inventory}

    assert records["a"].scope.device_name == "fw-a"
    assert records["b"].scope.device_name == "fw-b"
    identities = {
        pan_scope_identity(record.scope)
        for record in records.values()
        if record.scope.kind == "vsys"
    }
    assert len(identities) == 2


def test_scope_identity_prefers_serial_without_encoding_parent_hierarchy():
    scope = PANScope(
        kind="vsys",
        name="vsys1",
        device_name="panorama",
        device_serial="serial-child",
        device_group="child",
        parent_device_group="parent",
    )

    assert pan_scope_identity(scope) == "vsys:vsys1:device:serial-child"
