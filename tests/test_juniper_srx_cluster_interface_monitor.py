import pytest

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_chassis_cluster_interface_monitor_is_scoped_to_redundancy_group():
    cfg = JuniperSRXParser(
        "set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 100"
    ).parse_raw()

    group = cfg.contexts["root"].chassis_cluster.redundancy_groups["1"]
    assert group.interface_monitors["ge-0/0/0"]["interface"] == "ge-0/0/0"
    assert group.interface_monitors["ge-0/0/0"]["weight"] == 100
    assert "threshold" not in group.interface_monitors["ge-0/0/0"]
    assert group.interface_monitors["ge-0/0/0"]["source_attributes"]["raw"]


@pytest.mark.parametrize("weight", [0, 255])
def test_chassis_cluster_interface_monitor_accepts_weight_boundaries(weight):
    cfg = JuniperSRXParser(
        f"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight {weight}"
    ).parse_raw()

    monitor = cfg.contexts["root"].chassis_cluster.redundancy_groups["1"].interface_monitors["ge-0/0/0"]
    assert monitor["weight"] == weight


@pytest.mark.parametrize("weight", ["256", "not-a-number"])
def test_chassis_cluster_interface_monitor_rejects_invalid_weight(weight):
    parser = JuniperSRXParser(
        f"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight {weight}"
    )
    result = parser.extract()

    monitor = parser.config.contexts["root"].chassis_cluster.redundancy_groups["1"].interface_monitors["ge-0/0/0"]
    command = result.inventory_items[0].commands[0]
    assert "weight" not in monitor
    assert command.status == ExtractionStatus.PARSE_ERROR
    assert monitor["source_attributes"]["raw"]


def test_chassis_cluster_interface_monitor_threshold_child_is_partial_source_only():
    parser = JuniperSRXParser(
        "set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 threshold 200"
    )
    result = parser.extract()

    monitor = parser.config.contexts["root"].chassis_cluster.redundancy_groups["1"].interface_monitors["ge-0/0/0"]
    command = result.inventory_items[0].commands[0]
    assert "threshold" not in monitor
    assert command.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert command.requires_manual_review is True
    assert monitor["source_attributes"]["raw"]
