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
config user peer
    edit "PEER"
        set ca "CA"
    next
end
config user saml
    edit "SAML"
        set cert "LOCAL"
        set idp-cert "REMOTE"
    next
end
config system saml
    set cert "LOCAL"
    set idp-cert "REMOTE"
end
config vpn ssl settings
    set servercert "LOCAL"
end
config firewall vip
    edit "VIP"
        set ssl-certificate "LOCAL"
    next
end
config firewall access-proxy
    edit "PROXY"
        set certificate "LOCAL"
        set ssl-certificate "LOCAL"
    next
end
config firewall access-proxy-virtual-host
    edit "VHOST"
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

    certificate_dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.expected_type.startswith("vpn certificate")
    ]
    assert certificate_dependencies
    assert all(dependency.result == "RESOLVED" for dependency in certificate_dependencies)
    assert {dependency.expected_type for dependency in certificate_dependencies} >= {
        "vpn certificate local",
        "vpn certificate ca",
        "vpn certificate remote",
    }


def test_certificate_references_do_not_cross_vdoms() -> None:
    result = extract_fortigate_config(
        """
config vdom
    edit "tenant-a"
        config vpn certificate local
            edit "SHARED"
            next
        end
        config vpn ssl settings
            set servercert "SHARED"
        end
    next
    edit "tenant-b"
        config vpn certificate local
            edit "OTHER"
            next
        end
        config vpn ssl settings
            set servercert "SHARED"
        end
    next
end
"""
    )

    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "vpn ssl settings"
        and dependency.source_field == "servercert"
    ]
    assert [(d.source_context, d.reference, d.result) for d in dependencies] == [
        ("tenant-a", "SHARED", "RESOLVED"),
        ("tenant-b", "SHARED", "UNRESOLVED"),
    ]
