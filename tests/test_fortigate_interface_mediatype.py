from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _config(value: str) -> str:
    return f"""
config system interface
    edit "x1"
        set vdom "root"
        set type physical
        set mediatype {value}
    next
end
"""


def test_mediatype_is_typed_and_preserved_in_source_attributes():
    interface = parse_fortigate_config(_config("sr-lr")).interfaces[0]

    assert interface.mediatype == "sr-lr"
    assert interface.source_attributes["mediatype"] == "sr-lr"


def test_mediatype_maps_to_ir_and_keeps_source_fidelity():
    interface = FGToIRTransformer(
        parse_fortigate_config(_config("sr-lr"))
    ).transform().interfaces[0]

    assert interface.source_media_type == "sr-lr"
    assert interface.source_attributes["mediatype"] == "sr-lr"


def test_mediatype_does_not_create_an_unmodeled_review_reason():
    interface = FGToIRTransformer(
        parse_fortigate_config(_config("sr-lr"))
    ).transform().interfaces[0]

    assert not any("mediatype" in reason.lower() for reason in interface.review_reasons)


def test_unknown_hardware_specific_mediatype_is_preserved():
    interface = FGToIRTransformer(
        parse_fortigate_config(_config("vendor-new-optic"))
    ).transform().interfaces[0]

    assert interface.source_media_type == "vendor-new-optic"
    assert interface.source_attributes["mediatype"] == "vendor-new-optic"
