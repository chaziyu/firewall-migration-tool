"""FortiGate source-model builders grouped by responsibility."""

from typing import Any

from .common import prepare_section
from .objects import build_objects
from .policy_nat import build_policy_nat
from .routing_vpn import build_routing_vpn
from .security import build_security


def build_model(parser: Any, section_path: str, attributes: dict[str, Any]) -> bool:
    """Run the domain builders and report whether one consumed the section."""

    if section_path in {
        "firewall shaper per-ip-shaper",
        "firewall shaping-profile",
        "firewall ippool_grp",
    } and build_objects(parser, section_path, attributes):
        return True
    if prepare_section(parser, section_path, attributes):
        return True
    return (
        build_objects(parser, section_path, attributes)
        or build_policy_nat(parser, section_path, attributes)
        or build_routing_vpn(parser, section_path, attributes)
        or build_security(parser, section_path, attributes)
    )
