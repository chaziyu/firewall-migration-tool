"""Check Point VPN community and gateway extraction."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import IRVPNCommunity, IRVPNGateway
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def _first(data: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if data.get(key) not in (None, "", []):
            return data[key]
    return None


def _items(response: CheckPointResponse) -> Iterable[Dict[str, Any]]:
    objects = response.data.get("objects", response.data.get("communities", []))
    if isinstance(objects, dict):
        objects = list(objects.values())
    return (item for item in objects if isinstance(item, dict)) if isinstance(objects, list) else ()


def _refs(value: Any) -> List[str]:
    values = value if isinstance(value, list) else [value]
    result = []
    for item in values:
        if isinstance(item, dict):
            item = item.get("uid") or item.get("name") or item.get("reference")
        if item not in (None, ""):
            result.append(str(item))
    return list(dict.fromkeys(result))


def _settings(obj: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(obj)
    for key in ("encryption", "encryption-settings", "ike", "ike-settings", "ipsec", "ipsec-settings", "vpn-settings", "remote-access"):
        nested = obj.get(key)
        if isinstance(nested, dict):
            result.update(nested)
    return result


def extract_vpn(
    responses: List[CheckPointResponse],
) -> Tuple[List[IRVPNCommunity], List[IRVPNGateway], List[SourceInventoryItem], List[UnsupportedItem]]:
    communities: List[IRVPNCommunity] = []
    gateways: List[IRVPNGateway] = []
    inventory: List[SourceInventoryItem] = []
    unsupported: List[UnsupportedItem] = []
    for response in responses:
        command = canonicalize_command(response.command)
        if command not in {
            "show-vpn-communities-meshed", "show-vpn-communities-star",
            "show-vpn-communities-remote-access", "show-gateways-and-servers",
            "show-simple-gateways", "show-simple-clusters",
        }:
            continue
        for obj in _items(response):
            attrs = _settings(obj)
            uid = obj.get("uid")
            name = str(obj.get("name") or uid or "<unnamed>")
            context = response.domain or "global"
            if command in {"show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters"}:
                main = _first(attrs, "main-ip-address", "main-ip", "ipv4-address", "ip-address")
                vpn = _first(attrs, "vpn", "vpn-settings", "vpn-properties")
                vpn_attrs = vpn if isinstance(vpn, dict) else {}
                certs = _refs(_first(vpn_attrs, "certificate", "certificate-reference", "certificate-references"))
                membership = _refs(_first(vpn_attrs, "communities", "community-membership", "community-members"))
                record = IRVPNGateway(
                    name=name, uid=uid, source_context=context, main_ip=main,
                    vpn_enabled=_first(vpn_attrs, "enabled", "vpn-enabled"),
                    topology=_first(vpn_attrs, "topology"),
                    encryption_domain=_first(vpn_attrs, "encryption-domain", "encryption-domain-type"),
                    certificate_references=certs, community_membership=membership,
                    source_attributes=sanitize_source_attributes(obj),
                )
                gateways.append(record)
                source_type = "checkpoint-vpn-gateway"
            else:
                kind = command.rsplit("-", 1)[-1]
                members = _refs(_first(attrs, "member-gateways", "members", "gateway-members"))
                centers = _refs(_first(attrs, "center-gateways", "centers", "center"))
                satellites = _refs(_first(attrs, "satellite-gateways", "satellites", "satellite"))
                secret = _first(attrs, "shared-secret-reference", "shared-secret", "pre-shared-key", "psk")
                secret_ref = None
                if isinstance(secret, dict):
                    secret_ref = secret.get("uid") or secret.get("name") or secret.get("reference")
                elif isinstance(secret, str) and secret.startswith(("uid:", "ref:", "cert:")):
                    secret_ref = secret
                record = IRVPNCommunity(
                    name=name, uid=uid, source_context=context, community_type=kind,
                    member_gateways=members, center_gateways=centers, satellite_gateways=satellites,
                    tunnel_sharing=_first(attrs, "tunnel-sharing", "tunnel-sharing-mode"),
                    ike_version=_first(attrs, "ike-version", "ike-version-mode"),
                    encryption_algorithm=_first(attrs, "encryption-algorithm", "encryption"),
                    integrity_hash=_first(attrs, "integrity", "hash", "hash-algorithm"),
                    dh_group=_first(attrs, "dh-group", "diffie-hellman-group"),
                    lifetime=_first(attrs, "lifetime", "lifetime-seconds"),
                    pfs=_first(attrs, "pfs", "perfect-forward-secrecy"),
                    nat_traversal=_first(attrs, "nat-traversal", "nat-t"),
                    shared_secret_reference=str(secret_ref) if secret_ref else None,
                    certificate_reference=next(iter(_refs(_first(attrs, "certificate", "certificate-reference"))), None),
                    office_mode=_first(attrs, "office-mode", "office-mode-settings"),
                    authentication_methods=_refs(_first(attrs, "authentication-methods", "authentication")),
                    allowed_users=_refs(_first(attrs, "allowed-users", "users")),
                    allowed_groups=_refs(_first(attrs, "allowed-groups", "user-groups", "groups")),
                    client_settings=dict(_first(attrs, "client-settings") or {}) if isinstance(_first(attrs, "client-settings"), dict) else {},
                    source_attributes=sanitize_source_attributes(obj),
                )
                communities.append(record)
                source_type = "checkpoint-vpn-community"
            if command not in {"show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters"}:
                inventory.append(SourceInventoryItem(
                    domain=context, source_path=f"checkpoint/{command}", name=name, source_id=uid,
                    source_type=source_type, source_context=context,
                    source_attributes=sanitize_source_attributes(obj),
                    status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
                    notes=["vpn-semantics-require-target-review"],
                ))
    return communities, gateways, inventory, unsupported
