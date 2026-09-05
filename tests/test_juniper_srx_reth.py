from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_reth_member_and_redundancy_group_are_source_preserved():
    content = """
    set interfaces reth0 redundant-ether-options redundancy-group 1
    set interfaces reth0 unit 0 family inet address 203.0.113.1/24
    set interfaces ge-0/0/0 gigether-options redundant-parent reth0
    set chassis cluster cluster-id 1 node 0 reboot
    set chassis cluster redundancy-group 1 node 0 priority 100
    """
    cfg = JuniperSRXParser(content).parse_raw().contexts["root"]
    assert cfg.interfaces["reth0"].redundancy_group == "1"
    assert cfg.interfaces["ge-0/0/0"].redundant_parent == "reth0"
    assert cfg.source_attributes["chassis_cluster"]["cluster-id_1_node_0_reboot"]
    out = JuniperSRXParser(content).transform_to_ir()
    reth = next(i for i in out.interfaces if i.name == "reth0.0")
    assert reth.ip == "203.0.113.1/24"
    assert reth.source_attributes["junos_redundancy_group"] == "1"

