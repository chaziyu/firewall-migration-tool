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
