import pytest
from pathlib import Path

from fwmigrate.vendors.palo_alto.native import load_pan_source as native_load_pan_source
from fwmigrate.vendors.palo_alto.native import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.vendors.palo_alto.xml_loader import load_pan_source


PANORAMA_FIXTURE = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml"


def test_scope_identity_qualifies_vsys_by_device_and_serial():
    first = PANScope(kind="vsys", name="vsys1", device_name="fw-a", vsys="vsys1")
    second = PANScope(kind="vsys", name="vsys1", device_name="fw-b", vsys="vsys1")
    managed = PANScope(
        kind="vsys", name="vsys1", device_name="panorama", device_serial="SERIAL-1", vsys="vsys1"
    )

    assert pan_scope_identity(first) != pan_scope_identity(second)
    assert pan_scope_identity(managed) == "vsys:vsys1:device:SERIAL-1"
    assert pan_scope_identity(PANScope(kind="shared", name="shared")) == "shared:shared"


def test_rulebase_position_belongs_to_each_record():
    config = build_panos_config(
        """<config><devices>
          <entry name="fw-a"><vsys><entry name="vsys1">
            <pre-rulebase><security><rules><entry name="pre"/></rules></security></pre-rulebase>
            <rulebase><security><rules><entry name="local"/></rules></security></rulebase>
            <post-rulebase><security><rules><entry name="post"/></rules></security></post-rulebase>
          </entry></vsys></entry>
          <entry name="fw-b"><vsys><entry name="vsys1"><address><entry name="same"/></address></entry></vsys></entry>
        </devices></config>"""
    )

    positions = {record.name: record.rulebase_position for record in config.records}
    assert positions["pre"] == "pre"
    assert positions["local"] == "local"
    assert positions["post"] == "post"
    assert all(not hasattr(scope, "rulebase_position") for scope in config.scopes)
    assert len({pan_scope_identity(scope) for scope in config.scopes if scope.kind == "vsys"}) == 2


def test_xml_loader_preserves_supported_input_forms_and_compatibility_export():
    wrapped = "<response><result><config version='11.1'><devices><entry name='fw'/></devices></config></result></response>"
    document = load_pan_source(wrapped)

    assert document.root.tag == "config"
    assert document.source_version == "11.1"
    assert native_load_pan_source is load_pan_source

    with pytest.raises(ValueError, match="Empty configuration input"):
        load_pan_source("  ")
    with pytest.raises(ValueError, match="Malformed XML input"):
        load_pan_source("<config>")
    with pytest.raises(ValueError, match="CLI 'set'"):
        load_pan_source("set deviceconfig system hostname fw")


def test_walker_keeps_panorama_device_group_and_managed_serial_contexts_separate():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = build_panos_config(PANORAMA_FIXTURE.read_text())
    by_name = {record.name: record for record in config.records}

    assert by_name["shared-pre"].scope.kind == "shared"
    assert by_name["parent-pre"].scope.device_group == "parent"
    assert by_name["child-pre"].scope.device_group == "child"
    assert by_name["child-pre"].scope.parent_device_group == "parent"
    assert by_name["vsys1"].scope.device_serial == "serial-child"
    assert by_name["vsys1"].scope.device_group == "child"
    assert by_name["child-pre"].rulebase_position == "pre"
    assert by_name["child-post"].rulebase_position == "post"
