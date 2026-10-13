from copy import deepcopy

from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config


def test_native_dhcp_split_scope_family_and_references():
    config = JuniperSRXParser("\n".join([
        "set interfaces ge-0/0/0 unit 0",
        "set routing-instances RI1 instance-type virtual-router",
        "set system services dhcp-local-server group LOCAL family inet interface ge-0/0/0.0",
        "set system services dhcp-local-server group V6 family inet6 interface ge-0/0/0.0",
        "set access address-assignment pool P1 family inet range R1 low 10.0.0.10",
        "set access address-assignment pool P1 family inet range R1 high 10.0.0.20",
        "set access address-assignment pool P1 family inet host H1 hardware-address aa:bb:cc:dd:ee:ff",
        "set access address-assignment pool P1 family inet host H1 ip-address 10.0.0.5",
        "set access address-assignment pool P1 family inet dhcp-attributes router 10.0.0.1",
        "set access address-assignment pool P1 family inet dhcp-attributes name-server [ 1.1.1.1 8.8.8.8 ]",
        "set access address-assignment pool P1 family inet6 range R6 low 2001:db8::10",
        "set access address-assignment pool P1 link P2",
        "set routing-instances RI1 access address-assignment pool P1 family inet range R1 low 192.0.2.10",
        "set routing-instances RI1 system services dhcp-local-server group LOCAL family inet interface ge-0/0/0.0",
        "set system services dhcp pool 10.0.0.0/24 address-range low 10.0.0.2",
    ])).extract_source()
    dhcp = config.get_context().dhcp
    root_pool = dhcp.address_assignment_pools["root||P1"]
    assert root_pool.families["inet"].ranges["R1"].model_dump() | {"source_attributes": {}} == {
        "name": "R1", "low": "10.0.0.10", "high": "10.0.0.20", "source_attributes": {}
    }
    assert root_pool.families["inet"].hosts["H1"].ip_address == "10.0.0.5"
    assert root_pool.families["inet"].dhcp_attributes.name_servers == ["1.1.1.1", "8.8.8.8"]
    assert set(root_pool.families) == {"inet", "inet6"}
    assert dhcp.address_assignment_pools["RI1||P1"].routing_instance == "RI1"
    assert {group.family for group in dhcp.local_servers.values()} == {"inet", "inet6"}
    assert len(dhcp.legacy.commands) == 1
    assert root_pool.families["inet"].dhcp_attributes.lease_time is None
    before = deepcopy(config)
    derived = build_juniper_derived_views(config)
    validate_juniper_config(config, derived)
    assert config == before
    assert any(item.source_field == "link" and item.result == "UNRESOLVED" for item in derived.dependencies)


def test_dhcp_relay_preserves_routing_instance_contract():
    source = "\n".join([
        "set interfaces ge-0/0/0 unit 0",
        "set routing-instances RI1 instance-type virtual-router",
        "set routing-instances RI1 system services dhcp-relay group RELAY routing-instance RI1",
        "set routing-instances RI1 system services dhcp-relay group RELAY interface ge-0/0/0.0",
    ])
    config = JuniperSRXParser(source).extract_source()
    before = deepcopy(config)
    group = config.get_context().dhcp.relay_groups["RI1||RELAY"]
    derived = build_juniper_derived_views(config)
    assert group.routing_instance == "RI1"
    assert all(item.result == "RESOLVED" for item in derived.dependencies
               if item.source_object == "RELAY" and item.source_path == "system services dhcp-relay")
    validation = validate_juniper_config(config, derived)
    assert not [item for item in validation.errors if item.object_name == "RELAY"]
    assert config == before

    from io import BytesIO

    from openpyxl import load_workbook

    from fwmigrate.vendors.juniper_srx.export.excel import export_juniper_excel
    from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source

    output = BytesIO()
    export_juniper_excel(extract_juniper_source(source), output)
    output.seek(0)
    rows = list(load_workbook(output, read_only=True)["DHCP Relay Groups"].values)
    assert rows[1] == ("root", "RELAY", "RI1", "['ge-0/0/0.0']", "[]")
