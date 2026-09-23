from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_shared_device_group_and_nested_scopes_remain_explicit():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml"
    records = {item.name: item for item in build_panos_config(path.read_text()).source_inventory}
    assert records["shared-net"].scope.kind == "shared"
    assert records["parent-pre"].scope.device_group == "parent"
    assert records["child-pre"].scope.parent_device_group == "parent"
