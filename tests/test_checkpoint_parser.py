from pathlib import Path
from fg2pan.core.registry import PluginRegistry
from fg2pan.ir.enums import AddressType, PolicyAction

def test_checkpoint_parser_full_config():
    example_path = Path(__file__).parent.parent / "examples" / "example_checkpoint.json"
    with open(example_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("checkpoint")
    ir = parser.parse(content)

    assert ir.metadata.hostname == "CP-Enterprise-Gateway"
    assert ir.metadata.source_vendor == "checkpoint"

    # Check Addresses
    addr_names = [a.name for a in ir.addresses]
    assert "Host_ERP_Database" in addr_names
    assert "Net_Corporate_Users" in addr_names
    assert "Range_DHCP_Pool" in addr_names

    host_addr = next(a for a in ir.addresses if a.name == "Host_ERP_Database")
    assert host_addr.type == AddressType.HOST
    assert "10.50.1.20" in host_addr.value

    net_addr = next(a for a in ir.addresses if a.name == "Net_Corporate_Users")
    assert net_addr.type == AddressType.NETWORK
    assert "10.20.0.0/16" in net_addr.value

    # Check Address Groups
    assert len(ir.address_groups) == 1
    assert ir.address_groups[0].name == "Grp_Finance_Servers"
    assert "Host_ERP_Database" in ir.address_groups[0].members

    # Check Services
    assert any(s.name == "svc_custom_app_8443" for s in ir.services)

    # Check Policies
    assert len(ir.policies) == 2
    allow_rule = next(p for p in ir.policies if p.name == "Allow_Corporate_To_ERP")
    assert allow_rule.action == PolicyAction.ALLOW
    assert "Net_Corporate_Users" in allow_rule.source

    deny_rule = next(p for p in ir.policies if p.name == "Block_Guest_To_Finance")
    assert deny_rule.action == PolicyAction.DENY

    # Check NAT
    assert len(ir.nat_rules) == 1
