import pytest

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def parse_lines(*lines):
    parser = JuniperSRXParser("\n".join(lines))
    result = parser.extract()
    groups = parser.config.contexts["root"].chassis_cluster.redundancy_groups
    return parser, result, groups


@pytest.mark.parametrize("option,minimum,maximum", [
    ("delay", 1, 21600), ("limit", 1, 50), ("period", 1, 1400),
])
def test_preempt_ranges(option, minimum, maximum):
    _, result, groups = parse_lines(f"set chassis cluster redundancy-group 1 preempt {option} {minimum}")
    assert getattr(groups["1"].preempt, option) == minimum
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.EXTRACT_ONLY
    _, result, groups = parse_lines(f"set chassis cluster redundancy-group 1 preempt {option} {maximum}")
    assert getattr(groups["1"].preempt, option) == maximum
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.EXTRACT_ONLY


@pytest.mark.parametrize("line", [
    "set chassis cluster redundancy-group 1 preempt delay 0",
    "set chassis cluster redundancy-group 1 preempt delay 21601",
    "set chassis cluster redundancy-group 1 preempt delay abc",
    "set chassis cluster redundancy-group 1 preempt limit 0",
    "set chassis cluster redundancy-group 1 preempt limit 51",
    "set chassis cluster redundancy-group 1 preempt period 0",
    "set chassis cluster redundancy-group 1 preempt period 1401",
    "set chassis cluster redundancy-group 1 preempt period abc",
])
def test_invalid_preempt_values_are_parse_errors(line):
    _, result, _ = parse_lines(line)
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.PARSE_ERROR


def test_preempt_merges_repeated_statements_and_preserves_metadata():
    _, result, groups = parse_lines(
        "set chassis cluster redundancy-group 1 preempt",
        "set chassis cluster redundancy-group 1 preempt delay 60",
        "set chassis cluster redundancy-group 1 preempt limit 10",
        "set chassis cluster redundancy-group 1 preempt period 300",
    )
    preempt = groups["1"].preempt
    assert (preempt.enabled, preempt.delay, preempt.limit, preempt.period) == (True, 60, 10, 300)
    assert preempt.source_attributes["raw"]
    assert len(result.inventory_items[0].commands) == 4


@pytest.mark.parametrize("line", [
    "set chassis cluster redundancy-group 0 preempt",
    "set chassis cluster redundancy-group 0 preempt delay 10",
    "set chassis cluster redundancy-group 0 preempt limit 5",
    "set chassis cluster redundancy-group 0 preempt period 300",
])
def test_preempt_is_rejected_for_rg0(line):
    _, result, groups = parse_lines(line)
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.PARSE_ERROR
    assert groups["0"].preempt is None
    assert groups["0"].source_attributes["invalid"]


@pytest.mark.parametrize("group,value,valid", [("0", 300, True), ("0", 1800, True), ("0", 299, False), ("0", 1801, False), ("1", 0, True), ("1", 1800, True), ("1", 1801, False), ("2", 0, True)])
def test_hold_down_interval_uses_group_aware_ranges(group, value, valid):
    _, result, groups = parse_lines(f"set chassis cluster redundancy-group {group} hold-down-interval {value}")
    command = result.inventory_items[0].commands[0]
    assert (command.status != ExtractionStatus.PARSE_ERROR) is valid
    assert (groups[group].hold_down_interval == value) is valid


@pytest.mark.parametrize("value,valid", [(1, True), (16, True), (0, False), (17, False), ("abc", False)])
def test_gratuitous_arp_count_range(value, valid):
    _, result, groups = parse_lines(f"set chassis cluster redundancy-group 1 gratuitous-arp-count {value}")
    command = result.inventory_items[0].commands[0]
    assert (command.status != ExtractionStatus.PARSE_ERROR) is valid
    assert (groups["1"].gratuitous_arp_count == value) is valid


def test_unknown_preempt_child_is_partial_and_preserved():
    _, result, groups = parse_lines("set chassis cluster redundancy-group 1 preempt unsupported-option foo")
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert groups["1"].preempt.source_attributes["unknown"]


def test_deactivation_does_not_leave_effective_failover_settings():
    _, result, groups = parse_lines(
        "set chassis cluster redundancy-group 1 preempt",
        "set chassis cluster redundancy-group 1 preempt delay 300",
        "deactivate chassis cluster redundancy-group 1 preempt",
    )
    assert groups["1"].preempt.enabled is False
    assert groups["1"].preempt.delay is None
    assert result.inventory_items[-1].commands[0].status == ExtractionStatus.NORMALIZED

    _, _, groups = parse_lines(
        "set chassis cluster redundancy-group 1 preempt",
        "set chassis cluster redundancy-group 1 preempt delay 300",
        "deactivate chassis cluster redundancy-group 1 preempt delay",
    )
    assert groups["1"].preempt.delay is None


@pytest.mark.parametrize("setting", ["hold-down-interval", "gratuitous-arp-count"])
def test_deactivated_scalar_setting_is_not_effective(setting):
    value = 30 if setting == "hold-down-interval" else 4
    _, _, groups = parse_lines(
        f"set chassis cluster redundancy-group 1 {setting} {value}",
        f"deactivate chassis cluster redundancy-group 1 {setting}",
    )
    assert "1" not in groups or getattr(groups["1"], setting.replace("-", "_")) is None
