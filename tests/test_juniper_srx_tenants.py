from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def test_tenant_contexts_are_isolated_and_malformed_prefixes_do_not_root_parse():
    content = """
    set security zones security-zone trust description root
    set logical-systems LS1 security zones security-zone trust description ls
    set tenants TSYS1 security zones security-zone trust description t1
    set tenants TSYS2 security zones security-zone trust description t2
    set tenants
    set tenants TSYS1
    """
    parser = JuniperSRXParser(content)
    result = parser.extract()

    assert parser.config.contexts["root"].zones["trust"].description == "root"
    assert parser.config.contexts["LS1"].zones["trust"].description == "ls"
    assert parser.config.contexts["TSYS1"].zones["trust"].description == "t1"
    assert parser.config.contexts["TSYS2"].zones["trust"].description == "t2"
    assert any("Malformed tenants context prefix" in item.reason for item in result.unsupported_items)


def test_tenant_provenance_and_security_profile_binding_are_preserved():
    parser = JuniperSRXParser("set tenants TSYS1 security-profile SP1\n")
    result = parser.extract()
    context = parser.config.contexts["TSYS1"]

    assert context.context_type == "tenant"
    assert context.security_profile == "SP1"
    assert context.source_attributes["security_profile"]["name"] == "SP1"
    assert result.source_sections[0].path == "tenants TSYS1 security-profile"


def test_tenant_activation_does_not_affect_other_contexts():
    parser = JuniperSRXParser("""
    set tenants TSYS1 security zones security-zone trust description t1
    set tenants TSYS2 security zones security-zone trust description t2
    set security zones security-zone trust description root
    deactivate tenants TSYS1 security zones security-zone trust
    """)
    parser.extract()

    assert parser.config.contexts["TSYS1"].zones["trust"].source_attributes["disabled"] is True
    assert parser.config.contexts["TSYS2"].zones["trust"].disabled is False
    assert parser.config.contexts["root"].zones["trust"].disabled is False
