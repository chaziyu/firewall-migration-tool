from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_chassis_cluster_interface_monitor_is_scoped_to_redundancy_group():
    cfg = JuniperSRXParser("""
    set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 255
    set chassis cluster redundancy-group 1 threshold 200
    """).parse_raw()

    group = cfg.contexts["root"].chassis_cluster.redundancy_groups["1"]
    assert group.interface_monitors["ge-0/0/0"]["interface"] == "ge-0/0/0"
    assert group.interface_monitors["ge-0/0/0"]["weight"] == 255
    assert group.threshold == 200
    assert group.interface_monitors["ge-0/0/0"]["source_attributes"]["raw"]
