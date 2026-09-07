"""FortiGate certificate-consumer dependency extensions.

Keep certificate namespaces explicit so local, CA, and remote certificate
references are validated against the correct FortiOS object family.
"""

from __future__ import annotations

from typing import Dict, Set, Tuple


CERTIFICATE_REFERENCE_RULES: Dict[Tuple[str, str], str] = {
    ("firewall vip", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy", "certificate"): "vpn certificate local",
    ("firewall access-proxy", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy6", "certificate"): "vpn certificate local",
    ("firewall access-proxy6", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy-virtual-host", "certificate"): "vpn certificate local",
    ("firewall access-proxy-virtual-host", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy virtual-host", "certificate"): "vpn certificate local",
    ("firewall access-proxy virtual-host", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy6 virtual-host", "certificate"): "vpn certificate local",
    ("firewall access-proxy6 virtual-host", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy realservers", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy6 realservers", "ssl-certificate"): "vpn certificate local",
    ("firewall ssl-ssh-profile", "caname"): "vpn certificate ca",
    ("firewall ssl-ssh-profile", "server-cert"): "vpn certificate local",
    ("system global", "admin-server-cert"): "vpn certificate local",
    ("user setting", "auth-cert"): "vpn certificate local",
    ("user setting", "auth-ca-cert"): "vpn certificate ca",
    ("user ldap", "ca-cert"): "vpn certificate ca",
    ("user peer", "ca"): "vpn certificate ca",
    ("user saml", "cert"): "vpn certificate local",
    ("user saml", "idp-cert"): "vpn certificate remote",
    ("system saml", "cert"): "vpn certificate local",
    ("system saml", "idp-cert"): "vpn certificate remote",
    ("vpn ssl settings", "servercert"): "vpn certificate local",
}

CERTIFICATE_TARGET_SECTIONS: Dict[Tuple[str, str], Set[str]] = {
    key: {value} for key, value in CERTIFICATE_REFERENCE_RULES.items()
}


def install_certificate_reference_support(dependencies_module) -> None:
    """Install certificate reference rules without replacing dependency logic."""

    dependencies_module.REFERENCE_RULES.update(CERTIFICATE_REFERENCE_RULES)
    dependencies_module.REFERENCE_TARGET_SECTIONS.update(CERTIFICATE_TARGET_SECTIONS)
