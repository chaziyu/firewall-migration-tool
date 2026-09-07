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
        set user-database "LDAP1" local
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
    assert scheme.user_database == ["LDAP1", "local"]
    assert scheme.extra_settings["future_field"] == "preserve-me"

    dependencies = [
        dependency
        for dependency in extract_fortigate_config(content).dependencies
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
