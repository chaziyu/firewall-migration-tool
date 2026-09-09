from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_dedicated_to_is_parsed_preserved_and_reviewed():
    config = '''\
config system interface
    edit "mgmt1"
        set ip 10.0.0.1 255.255.255.0
        set dedicated-to management
    next
end
'''
    parsed = parse_fortigate_config(config)
    source = parsed.interfaces[0]
    interface = FGToIRTransformer(parsed).transform().interfaces[0]

    assert source.dedicated_to == "management"
    assert source.source_attributes["dedicated_to"] == "management"
    assert interface.source_dedicated_to == "management"
    assert interface.requires_manual_review is True
    assert any(
        "management" in reason.lower() and "dedicated" in reason.lower()
        for reason in interface.review_reasons
    )
    assert not any(
        "unmodeled top-level interface setting 'dedicated-to'" in reason.lower()
        for reason in interface.review_reasons
    )


def test_unrecognized_dedicated_to_is_preserved_and_reviewed():
    config = '''\
config system interface
    edit "port1"
        set dedicated-to some-new-mode
    next
end
'''
    parsed = parse_fortigate_config(config)
    interface = FGToIRTransformer(parsed).transform().interfaces[0]

    assert interface.source_dedicated_to == "some-new-mode"
    assert interface.source_attributes["dedicated_to"] == "some-new-mode"
    assert interface.requires_manual_review is True
