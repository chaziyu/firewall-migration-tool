from __future__ import annotations

from typing import Any

from ..models import CheckPointResponse
from .common import SemanticKind, infer_semantic_kind, record, values


def bucket(response: CheckPointResponse, value: dict[str, Any]) -> str:
    command = response.command.lower()
    if command == "show-domains": return "domains"
    if command == "show-packages": return "packages"
    if command == "show-access-layers": return "access_layers"
    if command == "show-access-rulebase": return "access_rules"
    if command == "show-nat-rulebase": return "nat_rules"
    if "vpn-community" in command: return "vpn_communities"
    if "https" in command: return "https_inspection"
    if "threat" in command: return "threat_prevention"
    if response.command.startswith("gaia/"):
        if "route" in command: return "gaia_routes"
        if "pbr" in command or "policy-based" in command: return "pbr"
        if "ntp" in command or "dns" in command: return "dns_ntp"
        if "cluster" in command: return "cluster_state"
        if "management" in command or "access" in command: return "management_access"
        return "gaia_interfaces"
    kind = infer_semantic_kind(value.get("type"), value.get("name"))
    if kind in {SemanticKind.ADDRESS, SemanticKind.SECURITY_ZONE}: return "network_objects"
    if kind in {SemanticKind.ADDRESS_GROUP, SemanticKind.SERVICE_GROUP, SemanticKind.APPLICATION_GROUP, SemanticKind.TIME_GROUP}: return "groups"
    if kind == SemanticKind.SERVICE: return "services"
    if kind in {SemanticKind.APPLICATION, SemanticKind.APPLICATION_CATEGORY}: return "applications"
    if kind == SemanticKind.TIME: return "schedules"
    if any(part in command for part in ("identity", "user", "ldap", "radius")): return "identity_objects"
    if kind == SemanticKind.INSTALL_TARGET: return "gateways"
    return "network_objects"


def extract_object_records(response: CheckPointResponse) -> list[tuple[str, Any]]:
    return [(bucket(response, value), record(response, value, index)) for index, value in enumerate(values(response), 1)]
