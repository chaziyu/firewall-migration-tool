from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def test_shared_device_group_and_nested_scopes_remain_explicit():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml"
    records = {item.name: item for item in build_panos_config(path.read_text()).source_inventory}
    assert records["shared-net"].scope.kind == "shared"
    assert records["parent-pre"].scope.device_group == "parent"
    assert records["child-pre"].scope.parent_device_group == "parent"


def test_template_and_template_stack_owners_remain_distinct():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "template_scope.xml"
    config = build_panos_config(path.read_text())
    interfaces = config.interfaces
    assert len(interfaces) == 3
    assert {(item.scope.kind, item.scope.name) for item in interfaces} == {
        ("template", "template-a"), ("template", "template-b"), ("template-stack", "stack-a")
    }
    assert len({pan_scope_identity(item.scope) for item in interfaces}) == 3
    assert {record.scope.kind for record in config.source_inventory if record.source_path.endswith("ethernet/entry")} == {"template", "template-stack"}
    topology = build_derived_views(config).interface_topology
    assert len([item for item in topology if item.interface == "ethernet1/1"]) == 3


def test_same_named_vsys_on_different_devices_have_distinct_scope_identity():
    config = build_panos_config("""<config><devices>
      <entry name='fw-a' serial='serial-a'><vsys><entry name='vsys1'><address><entry name='same'><ip-netmask>192.0.2.1</ip-netmask></entry></address><rulebase><security><rules><entry name='rule-a'><source><member>same</member></source></entry></rules></security></rulebase></entry></vsys></entry>
      <entry name='fw-b' serial='serial-b'><vsys><entry name='vsys1'><address><entry name='same'><ip-netmask>192.0.2.2</ip-netmask></entry></address><rulebase><security><rules><entry name='rule-b'><source><member>same</member></source></entry></rules></security></rulebase></entry></vsys></entry>
    </devices></config>""")
    addresses = config.addresses
    assert len(addresses) == 2
    assert addresses[0].scope.vsys == addresses[1].scope.vsys == "vsys1"
    assert {item.scope.device_serial for item in addresses} == {"serial-a", "serial-b"}
    assert pan_scope_identity(addresses[0].scope) != pan_scope_identity(addresses[1].scope)
    resolutions = {item.owner_name: item for item in build_derived_views(config).reference_resolutions if item.owner_family == "policy" and item.owner_field == "source"}
    assert resolutions["rule-a"].status == resolutions["rule-b"].status == "RESOLVED"
    assert resolutions["rule-a"].resolved_target_scope.device_serial == "serial-a"
    assert resolutions["rule-b"].resolved_target_scope.device_serial == "serial-b"
