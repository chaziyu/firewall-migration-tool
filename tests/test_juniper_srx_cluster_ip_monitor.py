import pytest

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def parse_line(line):
    parser = JuniperSRXParser(line)
    result = parser.extract()
    group = parser.config.contexts["root"].chassis_cluster.redundancy_groups["1"]
    return parser, result, group


def test_ip_monitoring_combined_configuration_merges_target():
    parser, result, group = parse_line("\n".join([
        "set chassis cluster redundancy-group 1 ip-monitoring global-weight 255",
        "set chassis cluster redundancy-group 1 ip-monitoring global-threshold 100",
        "set chassis cluster redundancy-group 1 ip-monitoring retry-interval 3",
        "set chassis cluster redundancy-group 1 ip-monitoring retry-count 10",
        "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.1.1.10 weight 100",
        "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.1.1.10 interface reth1.0 secondary-ip-address 10.1.1.101",
    ]))
    monitor = group.ip_monitoring
    assert (monitor.global_threshold, monitor.global_weight, monitor.retry_count, monitor.retry_interval) == (100, 255, 10, 3)
    assert len(monitor.targets) == 1
    assert monitor.targets[0].interface == "reth1.0"
    assert monitor.targets[0].secondary_ip_address == "10.1.1.101"
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.EXTRACT_ONLY
    assert monitor.targets[0].source_attributes["raw"]


@pytest.mark.parametrize("setting,value", [
    ("global-threshold", "0"), ("global-threshold", "255"),
    ("global-weight", "0"), ("global-weight", "255"),
    ("retry-count", "5"), ("retry-count", "15"),
    ("retry-interval", "1"), ("retry-interval", "30"),
])
def test_ip_monitoring_numeric_boundaries(setting, value):
    _, result, group = parse_line(f"set chassis cluster redundancy-group 1 ip-monitoring {setting} {value}")
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.EXTRACT_ONLY
    assert getattr(group.ip_monitoring, setting.replace("-", "_")) == int(value)


@pytest.mark.parametrize("line", [
    "set chassis cluster redundancy-group 1 ip-monitoring global-threshold 256",
    "set chassis cluster redundancy-group 1 ip-monitoring retry-count 4",
    "set chassis cluster redundancy-group 1 ip-monitoring retry-count abc",
    "set chassis cluster redundancy-group 1 ip-monitoring retry-interval 31",
    "set chassis cluster redundancy-group 1 ip-monitoring family inet 999.1.1.1 weight 100",
    "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.1.1.10 weight 256",
    "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.1.1.10 interface reth1.0 secondary-ip-address 2001:db8::1",
])
def test_ip_monitoring_invalid_values_are_parse_errors(line):
    _, result, _ = parse_line(line)
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.PARSE_ERROR


def test_ip_monitoring_unknown_child_is_partial_and_preserved():
    _, result, group = parse_line("set chassis cluster redundancy-group 1 ip-monitoring unknown-option foo")
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert group.ip_monitoring.source_attributes["unknown"]


def test_ip_monitoring_deactivation_does_not_create_active_target():
    parser = JuniperSRXParser("deactivate chassis cluster redundancy-group 1 ip-monitoring family inet 10.1.1.10")
    result = parser.extract()
    assert "1" not in parser.config.contexts["root"].chassis_cluster.redundancy_groups
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.NORMALIZED


def test_interface_monitor_behavior_is_unchanged():
    cfg = JuniperSRXParser("set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 100").parse_raw()
    group = cfg.contexts["root"].chassis_cluster.redundancy_groups["1"]
    assert group.interface_monitors["ge-0/0/0"]["weight"] == 100
