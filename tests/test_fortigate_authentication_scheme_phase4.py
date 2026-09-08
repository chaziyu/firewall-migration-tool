from fwmigrate.parsers.fortigate import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_authentication_scheme_typed_fields_and_backend_references() -> None:
    content = """
config user domain-controller
    edit "DC1"
    next
end
config user fsso
    edit "FSSO1"
    next
end
config user krb-keytab
    edit "KRB1"
    next
end
config user saml
    edit "SAML1"
    next
end
config vpn certificate ca
    edit "SSH_CA"
    next
end
config user ldap
    edit "LDAP1"
    next
end
config user radius
    edit "RADIUS1"
    next
end
config authentication scheme
    edit "SCHEME1"
        set domain-controller "DC1"
        set fsso-agent-for-ntlm "FSSO1"
        set fsso-guest enable
        set kerberos-keytab "KRB1"
        set method negotiate fsso
        set negotiate-ntlm enable
        set require-tfa enable
        set saml-server "SAML1"
        set saml-timeout 300
        set ssh-ca "SSH_CA"
        set user-cert enable
        set user-database "LDAP1" local "RADIUS1"
        set future-field preserve-me
    next
end
"""

    parsed = parse_fortigate_config(content)
    scheme = parsed.authentication_schemes[0]
    assert scheme.domain_controller == "DC1"
    assert scheme.fsso_agent_for_ntlm == "FSSO1"
    assert scheme.fsso_guest == "enable"
    assert scheme.kerberos_keytab == "KRB1"
    assert scheme.method == ["negotiate", "fsso"]
    assert scheme.negotiate_ntlm == "enable"
    assert scheme.require_tfa == "enable"
    assert scheme.saml_server == "SAML1"
    assert scheme.saml_timeout == 300
    assert scheme.ssh_ca == "SSH_CA"
    assert scheme.user_cert == "enable"
    assert scheme.user_database == ["LDAP1", "local", "RADIUS1"]
    assert scheme.extra_settings["future_field"] == "preserve-me"

    extraction = extract_fortigate_config(content)
    ir_scheme = extraction.canonical_ir.authentication_schemes[0]
    assert ir_scheme.source_attributes["method"] == ["negotiate", "fsso"]
    assert ir_scheme.source_attributes["user_database"] == ["LDAP1", "local", "RADIUS1"]
    assert ir_scheme.resolved_user_databases == ["LDAP1", "local"]
    assert ir_scheme.unresolved_user_databases == ["RADIUS1"]

    dependencies = [
        dependency
        for dependency in extraction.dependencies
        if dependency.source_path == "authentication scheme"
    ]
    by_reference = {dependency.reference: dependency for dependency in dependencies}
    assert by_reference["DC1"].target_path == "user domain-controller"
    assert by_reference["FSSO1"].target_path == "user fsso"
    assert by_reference["KRB1"].target_path == "user krb-keytab"
    assert by_reference["SAML1"].target_path == "user saml"
    assert by_reference["SSH_CA"].target_path == "vpn certificate ca"
    assert by_reference["LDAP1"].target_path == "user ldap"
    assert by_reference["local"].target_path == "fortigate built-in local user database"
    assert by_reference["RADIUS1"].result == "UNRESOLVED"
    assert by_reference["RADIUS1"].expected_type == "user ldap"


def test_authentication_scheme_invalid_cli_values_are_preserved_for_review() -> None:
    long_name = "x" * 36
    content = f'''\
config authentication scheme
    edit "SCHEME1"
        set fsso-guest invalid
        set method negotiate invalid-method
        set saml-server "{long_name}"
        set saml-timeout 29
        set user-database local "{'y' * 80}"
    next
end
'''

    scheme = parse_fortigate_config(content).authentication_schemes[0]
    assert scheme.fsso_guest is None
    assert scheme.method == ["negotiate"]
    assert scheme.saml_server is None
    assert scheme.saml_timeout is None
    assert scheme.user_database == ["local"]
    assert scheme.extra_settings == {
        "unparsed_fsso_guest": "invalid",
        "unparsed_method": ["invalid-method"],
        "unparsed_saml_server": long_name,
        "unparsed_saml_timeout": 29,
        "unparsed_user_database": ["y" * 80],
    }
