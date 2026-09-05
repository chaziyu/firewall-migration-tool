from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_ssl_proxy_keeps_references_without_key_material():
    c = JuniperSRXParser("set services ssl proxy profile p server-certificate cert1 private-key SECRET").parse_raw()
    p = c.contexts["root"].ssl_proxy_profiles["p"]
    assert "cert1" in p.references and "SECRET" not in str(p.model_dump())
