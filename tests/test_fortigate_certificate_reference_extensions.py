from fwmigrate.parsers.fortigate import extract_fortigate_config


def test_certificate_consumers_resolve_against_their_certificate_family() -> None:
    result = extract_fortigate_config(
        """
config vpn certificate local
    edit "LOCAL"
    next
end
config vpn certificate ca
    edit "CA"
    next
end
config vpn certificate remote
    edit "REMOTE"
    next
end
config system global
    set admin-server-cert "LOCAL"
end
config user setting
    set auth-cert "LOCAL"
    set auth-ca-cert "CA"
end
config user ldap
    edit "LDAP"
        set ca-cert "CA"
    next
end
config user saml
    edit "SAML"
        set cert "LOCAL"
        set idp-cert "REMOTE"
    next
end
config vpn ssl settings
    set servercert "LOCAL"
end
config firewall vip
    edit "VIP"
        set ssl-certificate "LOCAL"
    next
end
config firewall ssl-ssh-profile
    edit "SSL"
        set caname "CA"
        set server-cert "LOCAL"
    next
end
"""
    )

    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.expected_type.startswith("vpn certificate")
    ]
    assert dependencies
    assert all(dependency.result == "RESOLVED" for dependency in dependencies)
    assert {dependency.expected_type for dependency in dependencies} >= {
        "vpn certificate local",
        "vpn certificate ca",
        "vpn certificate remote",
    }
