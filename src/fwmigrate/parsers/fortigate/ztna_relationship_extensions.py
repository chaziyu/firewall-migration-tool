"""FortiGate ZTNA/access-proxy relationship validation.

The parser already retains the relevant FortiOS objects and reference fields.
This extension makes those relationships explicit in dependency accounting so
missing or cross-VDOM references are surfaced instead of silently accepted.
"""

from __future__ import annotations

from typing import Any, Dict, Set, Tuple


# Source field -> canonical FortiGate source family used for DependencyRecord
# expected_type. Exact allowed target sections are defined separately below.
ZTNA_REFERENCE_RULES: Dict[Tuple[str, str], str] = {
    # Access-proxy parents (IPv4 and IPv6 variants share the same semantics).
    ("firewall access-proxy", "interface"): "system interface",
    ("firewall access-proxy", "srcintf"): "system interface",
    ("firewall access-proxy", "certificate"): "vpn certificate local",
    ("firewall access-proxy", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy", "auth-method"): "authentication scheme",
    ("firewall access-proxy", "auth-rule"): "authentication rule",
    ("firewall access-proxy", "auth-virtual-host"): "firewall access-proxy-virtual-host",
    ("firewall access-proxy", "service"): "firewall service custom",
    ("firewall access-proxy", "ssl-vpn-web-portal"): "vpn ssl web portal",
    ("firewall access-proxy6", "interface"): "system interface",
    ("firewall access-proxy6", "srcintf"): "system interface",
    ("firewall access-proxy6", "certificate"): "vpn certificate local",
    ("firewall access-proxy6", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy6", "auth-method"): "authentication scheme",
    ("firewall access-proxy6", "auth-rule"): "authentication rule",
    ("firewall access-proxy6", "auth-virtual-host"): "firewall access-proxy-virtual-host",
    ("firewall access-proxy6", "service"): "firewall service custom",
    ("firewall access-proxy6", "ssl-vpn-web-portal"): "vpn ssl web portal",

    # Standalone access-proxy virtual hosts.
    ("firewall access-proxy-virtual-host", "access-proxy"): "firewall access-proxy",
    ("firewall access-proxy-virtual-host", "certificate"): "vpn certificate local",
    ("firewall access-proxy-virtual-host", "ssl-certificate"): "vpn certificate local",
    ("firewall access-proxy-virtual-host", "interface"): "system interface",
    ("firewall access-proxy-virtual-host", "auth-method"): "authentication scheme",
    ("firewall access-proxy-virtual-host", "auth-portal"): "firewall auth-portal",

    # Authentication rules can select one or more authentication schemes.
    ("authentication rule", "active-auth-method"): "authentication scheme",
    ("authentication rule", "auth-method"): "authentication scheme",
}


ZTNA_REFERENCE_TARGET_SECTIONS: Dict[Tuple[str, str], Set[str]] = {
    # Interfaces remain context-scoped; zones are not treated as generic
    # aliases for access-proxy interface references.
    ("firewall access-proxy", "interface"): {"system interface"},
    ("firewall access-proxy", "srcintf"): {"system interface"},
    ("firewall access-proxy6", "interface"): {"system interface"},
    ("firewall access-proxy6", "srcintf"): {"system interface"},
    ("firewall access-proxy-virtual-host", "interface"): {"system interface"},

    # Access-proxy TLS identity is a locally configured certificate. Do not
    # infer CA/remote certificates as interchangeable target types.
    ("firewall access-proxy", "certificate"): {"vpn certificate local"},
    ("firewall access-proxy", "ssl-certificate"): {"vpn certificate local"},
    ("firewall access-proxy6", "certificate"): {"vpn certificate local"},
    ("firewall access-proxy6", "ssl-certificate"): {"vpn certificate local"},
    ("firewall access-proxy-virtual-host", "certificate"): {"vpn certificate local"},
    ("firewall access-proxy-virtual-host", "ssl-certificate"): {"vpn certificate local"},

    ("firewall access-proxy", "auth-method"): {"authentication scheme"},
    ("firewall access-proxy6", "auth-method"): {"authentication scheme"},
    ("firewall access-proxy-virtual-host", "auth-method"): {"authentication scheme"},
    ("authentication rule", "active-auth-method"): {"authentication scheme"},
    ("authentication rule", "auth-method"): {"authentication scheme"},

    ("firewall access-proxy", "auth-rule"): {"authentication rule"},
    ("firewall access-proxy6", "auth-rule"): {"authentication rule"},
    ("firewall access-proxy", "auth-virtual-host"): {"firewall access-proxy-virtual-host"},
    ("firewall access-proxy6", "auth-virtual-host"): {"firewall access-proxy-virtual-host"},
    ("firewall access-proxy-virtual-host", "access-proxy"): {
        "firewall access-proxy",
        "firewall access-proxy6",
    },
    ("firewall access-proxy-virtual-host", "auth-portal"): {"firewall auth-portal"},

    ("firewall access-proxy", "service"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall access-proxy6", "service"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall access-proxy", "ssl-vpn-web-portal"): {"vpn ssl web portal"},
    ("firewall access-proxy6", "ssl-vpn-web-portal"): {"vpn ssl web portal"},
}


def install_ztna_relationship_support(dependencies_module: Any) -> None:
    """Install context-scoped ZTNA dependency rules on the shared registry."""

    for key, expected_type in ZTNA_REFERENCE_RULES.items():
        dependencies_module.REFERENCE_RULES[key] = expected_type

    for key, target_sections in ZTNA_REFERENCE_TARGET_SECTIONS.items():
        dependencies_module.REFERENCE_TARGET_SECTIONS[key] = set(target_sections)
