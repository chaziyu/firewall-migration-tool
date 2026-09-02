from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _config(value: str) -> str:
    return f"""
config system interface
    edit "port1"
        set monitor-bandwidth {value}
    next
end
"""


def _ir_interface(value: str):
    return FGToIRTransformer(
        parse_fortigate_config(_config(value))
    ).transform().interfaces[0]


def test_monitor_bandwidth_is_typed_and_source_preserved():
    interface = parse_fortigate_config(_config("enable")).interfaces[0]

    assert interface.monitor_bandwidth == "enable"
    assert interface.source_attributes["monitor_bandwidth"] == "enable"


def test_monitor_bandwidth_enable_normalizes_true():
    assert _ir_interface("enable").source_monitor_bandwidth is True


def test_monitor_bandwidth_disable_normalizes_false():
    assert _ir_interface("disable").source_monitor_bandwidth is False


def test_valid_monitor_bandwidth_does_not_add_review_reason():
    interface = _ir_interface("enable")

    assert not any(
        "monitor-bandwidth" in reason.lower()
        or "monitor_bandwidth" in reason.lower()
        for reason in interface.review_reasons
    )


def test_invalid_monitor_bandwidth_is_preserved_and_requires_review():
    interface = _ir_interface("unexpected")

    assert interface.source_monitor_bandwidth is None
    assert interface.source_attributes["monitor_bandwidth"] == "unexpected"
    assert any("monitor" in reason.lower() for reason in interface.review_reasons)
