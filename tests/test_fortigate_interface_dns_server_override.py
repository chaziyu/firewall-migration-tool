from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _interface(extra=""):
    config = f'''\
config system interface
    edit "wan1"
        set ip 10.0.0.1 255.255.255.0
{extra}
    next
end
'''
    parsed = parse_fortigate_config(config)
    return parsed.interfaces[0], FGToIRTransformer(parsed).transform().interfaces[0]


def test_dns_server_override_is_preserved_and_normalized():
    source, interface = _interface("        set dns-server-override enable")

    assert source.dns_server_override == "enable"
    assert source.source_attributes["dns_server_override"] == "enable"
    assert interface.source_dns_server_override is True
    assert interface.requires_manual_review is False


def test_dns_server_override_disable_normalizes_false():
    _, interface = _interface("        set dns-server-override disable")

    assert interface.source_dns_server_override is False


def test_dns_server_override_absent_is_none():
    _, interface = _interface()

    assert interface.source_dns_server_override is None


def test_dns_server_override_invalid_value_is_preserved_and_reviewed():
    source, interface = _interface("        set dns-server-override unexpected")

    assert interface.source_dns_server_override is None
    assert source.source_attributes["dns_server_override"] == "unexpected"
    assert any("dns" in reason.lower() for reason in interface.review_reasons)
