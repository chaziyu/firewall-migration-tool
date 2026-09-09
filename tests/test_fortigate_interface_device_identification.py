import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _config(value: str) -> str:
    return f"""
config system interface
    edit "port1"
        set device-identification {value}
    next
end
"""


def _transform(value: str):
    return FGToIRTransformer(parse_fortigate_config(_config(value))).transform().interfaces[0]


def test_interface_device_identification_is_typed_and_preserved():
    interface = parse_fortigate_config(_config("enable")).interfaces[0]

    assert interface.device_identification == "enable"
    assert interface.source_attributes["device_identification"] == "enable"


@pytest.mark.parametrize("value", ["enable", "disable"])
def test_device_identification_maps_to_ir_without_unmodeled_review(value):
    interface = _transform(value)

    assert interface.source_device_identification == value
    assert interface.source_attributes["device_identification"] == value
    assert not any(
        "device_identification" in reason or "device-identification" in reason
        for reason in interface.review_reasons
    )


def test_unknown_device_identification_requires_review():
    interface = _transform("unknown")

    assert interface.source_device_identification is None
    assert interface.source_attributes["device_identification"] == "unknown"
    assert interface.requires_manual_review is True
    assert any("device_identification" in reason for reason in interface.review_reasons)
