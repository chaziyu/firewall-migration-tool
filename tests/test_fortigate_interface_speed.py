import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _config(speed: str) -> str:
    return f"""
config system interface
    edit "port1"
        set type physical
        set speed {speed}
    next
end
"""


def test_fortigate_interface_speed_is_typed():
    interface = parse_fortigate_config(_config("10000full")).interfaces[0]

    assert interface.speed == "10000full"
    assert interface.source_attributes["speed"] == "10000full"


@pytest.mark.parametrize(
    ("raw_speed", "expected_speed", "expected_duplex"),
    [
        ("auto", "auto", "auto"),
        ("100full", "100", "full"),
        ("100half", "100", "half"),
        ("1000full", "1000", "full"),
        ("1000auto", "1000", "auto"),
        ("5000auto", "5000", "auto"),
        ("10000full", "10000", "full"),
        ("10000auto", "10000", "auto"),
        ("100Gfull", "100000", "full"),
        ("10000sr", "10000", None),
    ],
)
def test_fortigate_interface_speed_normalization(
    raw_speed,
    expected_speed,
    expected_duplex,
):
    interface = FGToIRTransformer(
        parse_fortigate_config(_config(raw_speed))
    ).transform().interfaces[0]

    assert interface.source_speed == expected_speed
    assert interface.source_duplex == expected_duplex


def test_known_fortigate_interface_speed_does_not_require_review():
    interface = FGToIRTransformer(
        parse_fortigate_config(_config("10000full"))
    ).transform().interfaces[0]

    assert interface.requires_manual_review is False
    assert not any("speed" in reason.lower() for reason in interface.review_reasons)


def test_unknown_fortigate_interface_speed_requires_review():
    interface = FGToIRTransformer(
        parse_fortigate_config(_config("future-hardware-speed"))
    ).transform().interfaces[0]

    assert interface.source_speed is None
    assert interface.source_attributes["speed"] == "future-hardware-speed"
    assert interface.requires_manual_review is True
    assert any("speed" in reason.lower() for reason in interface.review_reasons)
