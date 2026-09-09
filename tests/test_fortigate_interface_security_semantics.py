from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _transform(config: str):
    parsed = parse_fortigate_config(config)
    return parsed, FGToIRTransformer(parsed).transform().interfaces[0]


def _interface(setting: str) -> str:
    return f'''\
config system interface
    edit "vpn1"
        set ip 10.0.0.1 255.255.255.0
        set type tunnel
        {setting}
    next
end
'''


def test_src_check_enable_and_disable_are_modeled_but_reviewed():
    parsed, enabled = _transform(_interface("set src-check enable"))
    assert parsed.interfaces[0].src_check == "enable"
    assert enabled.source_src_check is True
    assert any("source-ip" in reason.lower() for reason in enabled.review_reasons)

    _, disabled = _transform(_interface("set src-check disable"))
    assert disabled.source_src_check is False
    assert disabled.requires_manual_review is True


def test_invalid_src_check_is_preserved_and_reviewed():
    parsed, interface = _transform(_interface("set src-check unexpected"))
    assert parsed.interfaces[0].src_check == "unexpected"
    assert interface.source_src_check is None
    assert interface.source_attributes["src_check"] == "unexpected"
    assert interface.requires_manual_review is True


def test_ike_saml_server_resolution_and_review():
    config = '''
config user saml
    edit "corp-saml"
    next
end
''' + _interface('set ike-saml-server "corp-saml"')
    parsed, interface = _transform(config)
    assert parsed.interfaces[0].ike_saml_server == "corp-saml"
    assert interface.source_ike_saml_server == "corp-saml"
    assert interface.source_ike_saml_server_resolved is True
    assert interface.requires_manual_review is True
    assert any("ike/saml" in reason.lower() for reason in interface.review_reasons)


def test_missing_ike_saml_server_is_unresolved():
    _, interface = _transform(_interface('set ike-saml-server "missing-saml"'))
    assert interface.source_ike_saml_server_resolved is False
    assert any("missing-saml" in reason for reason in interface.review_reasons)
