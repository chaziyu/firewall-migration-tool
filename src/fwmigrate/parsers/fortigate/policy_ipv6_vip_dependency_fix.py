"""FortiOS 7.4.6 firewall-policy IPv6 VIP dependency correction.

Fortinet's FortiOS 7.4.6 documentation shows IPv6 VIP objects being selected
through ``dstaddr6`` in ``config firewall policy``. IPv6 VIP groups represent
collections of those IPv6 VIP objects for policy use. Keep the correction
strictly destination-scoped: ``srcaddr6`` remains limited to Address6 and
Address6-group objects.
"""

from typing import Any


POLICY_DSTADDR6_TARGETS = {
    "firewall address6",
    "firewall addrgrp6",
    "firewall vip6",
    "firewall vipgrp6",
}


def install_policy_ipv6_vip_dependency_fix(dependencies_module: Any) -> None:
    """Allow verified IPv6 VIP/VIP-group policy destination references."""

    key = ("firewall policy", "dstaddr6")
    existing_targets = set(
        dependencies_module.REFERENCE_TARGET_SECTIONS.get(key, set())
    )
    dependencies_module.REFERENCE_TARGET_SECTIONS[key] = (
        existing_targets | POLICY_DSTADDR6_TARGETS
    )
