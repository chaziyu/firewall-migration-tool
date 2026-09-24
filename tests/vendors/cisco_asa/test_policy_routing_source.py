from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def test_policy_route_cost_and_path_monitor_are_separate_from_sla_track():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 policy-route cost 25
 policy-route path-monitoring 192.0.2.1
""").parse_raw()
    interface = config.interfaces[0]
    assert interface.policy_route_cost == "25"
    monitor = interface.policy_route_path_monitors[0]
    assert (monitor.mode, monitor.peer, monitor.source_order) == ("peer", "192.0.2.1", 3)
    assert config.tracks == [] and config.sla_monitors == []
