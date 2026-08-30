"""Check Point Management gateway topology and Security Zone extraction."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.ir.core import IRInterface, IRZone
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, SemanticKind


class SourceGatewayTopology(BaseModel):
    topology: Optional[str] = None
    security_zone: Optional[Any] = None
    anti_spoofing: Optional[bool] = None
    settings: Dict[str, Any] = Field(default_factory=dict)


class SourceGatewayInterface(BaseModel):
    name: str
    ipv4_address: Optional[str] = None
    ipv4_network_mask: Optional[str] = None
    ipv6_address: Optional[str] = None
    topology: SourceGatewayTopology = Field(default_factory=SourceGatewayTopology)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class SourceGateway(BaseModel):
    uid: Optional[str] = None
    name: str
    source_type: str
    interfaces: List[SourceGatewayInterface] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


def _zone_label(raw: Any, resolver: CheckPointObjectResolver, domain: str) -> Optional[str]:
    if raw in (None, False, ""):
        return None
    if raw is True:
        return None
    resolution = resolver.resolve(raw, domain=domain)
    if resolution.resolved and resolution.name:
        return resolution.name
    if isinstance(raw, dict):
        return str(raw.get("name") or raw.get("uid") or "") or None
    return str(raw)


def _interface_zone(obj: Dict[str, Any], resolver: CheckPointObjectResolver, domain: str) -> Optional[str]:
    direct = obj.get("security-zone")
    settings = obj.get("security-zone-settings")
    if isinstance(settings, dict):
        for key in ("specific-zone", "specific-security-zone", "security-zone", "zone"):
            if settings.get(key) not in (None, ""):
                return _zone_label(settings[key], resolver, domain)
        if settings.get("auto-calculated") is True:
            return None
    return _zone_label(direct, resolver, domain)


def _management_ip(obj: Dict[str, Any]) -> Optional[str]:
    address = obj.get("ipv4-address")
    mask = obj.get("ipv4-network-mask")
    prefix = obj.get("ipv4-mask-length")
    if not address:
        return None
    try:
        if prefix is None and mask:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        if prefix is None:
            return None
        ipaddress.IPv4Address(str(address))
        return f"{address}/{int(prefix)}"
    except (ValueError, TypeError):
        return None


def extract_gateway_topology(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
    gaia_interfaces: Optional[List[IRInterface]] = None,
) -> Tuple[List[IRInterface], List[IRZone], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Merge Management topology (authoritative for zones) with Gaia OS interfaces."""
    interfaces_by_name = {item.name: item for item in (gaia_interfaces or [])}
    zones_by_name: Dict[str, IRZone] = {}
    inventory: List[SourceInventoryItem] = []
    unsupported: List[UnsupportedItem] = []

    for response in responses:
        command = canonicalize_command(response.command)
        objects = response.data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        domain = response.domain or "global"
        if command == "show-security-zones" or command.endswith("/objects-dictionary"):
            for obj in objects:
                if not isinstance(obj, dict) or str(obj.get("type") or "").lower() != "security-zone":
                    continue
                name = obj.get("name")
                uid = obj.get("uid")
                status = ExtractionStatus.NORMALIZED if name else ExtractionStatus.PARSE_ERROR
                if name:
                    zones_by_name.setdefault(name, IRZone(
                        name=name, description=obj.get("comments"), source_attributes=dict(obj),
                    ))
                    resolver.set_object_normalization(
                        str(uid or name), name, status, semantic_kind=SemanticKind.SECURITY_ZONE,
                        domain=domain,
                    )
                inventory.append(SourceInventoryItem(
                    domain=domain, source_path=f"checkpoint/{command}",
                    name=name or f"<unnamed:{uid or len(inventory)}>", source_id=uid,
                    source_type="security-zone", source_attributes=dict(obj), status=status,
                    requires_manual_review=not bool(name), notes=[] if name else ["missing-security-zone-name"],
                ))

        if command != "show-gateways-and-servers":
            continue
        for obj in objects:
            if not isinstance(obj, dict):
                inventory.append(SourceInventoryItem(
                    domain=domain, source_path=f"checkpoint/{command}", name="<malformed-gateway>",
                    source_type="malformed-gateway", source_attributes={"raw_value": repr(obj)},
                    status=ExtractionStatus.PARSE_ERROR, requires_manual_review=True,
                ))
                continue
            gateway_name = str(obj.get("name") or f"<unnamed:{obj.get('uid') or len(inventory)}>")
            raw_interfaces = obj.get("interfaces", [])
            if isinstance(raw_interfaces, dict):
                raw_interfaces = raw_interfaces.get("objects", [])
            gateway_notes: List[str] = []
            for raw_interface in raw_interfaces if isinstance(raw_interfaces, list) else []:
                if not isinstance(raw_interface, dict) or not raw_interface.get("name"):
                    gateway_notes.append("malformed-gateway-interface")
                    continue
                name = str(raw_interface["name"])
                managed_ip = _management_ip(raw_interface)
                zone = _interface_zone(raw_interface, resolver, domain)
                interface = interfaces_by_name.get(name)
                if interface is None:
                    interface = IRInterface(
                        name=name, ip=managed_ip, zone=zone,
                        interface_type=raw_interface.get("interface-type"),
                        source_attributes={"checkpoint-management-topology": dict(raw_interface)},
                    )
                    interfaces_by_name[name] = interface
                else:
                    conflicts: List[str] = []
                    if managed_ip and interface.ip and managed_ip != interface.ip:
                        conflicts.append("gaia-management-ip-conflict")
                    if interface.zone and zone and interface.zone != zone:
                        conflicts.append("gaia-management-zone-conflict")
                    if zone:
                        interface.zone = zone
                    interface.source_attributes["checkpoint-management-topology"] = dict(raw_interface)
                    if conflicts:
                        interface.requires_manual_review = True
                        interface.parse_errors.extend(conflicts)
                        gateway_notes.extend(f"{name}:{reason}" for reason in conflicts)
                if zone:
                    zone_obj = zones_by_name.setdefault(zone, IRZone(name=zone))
                    if name not in zone_obj.interfaces:
                        zone_obj.interfaces.append(name)

            inventory.append(SourceInventoryItem(
                domain=domain, source_path=f"checkpoint/{command}", name=gateway_name,
                source_id=obj.get("uid"), source_type=str(obj.get("type") or "gateway-server"),
                source_attributes=dict(obj),
                status=ExtractionStatus.PARTIALLY_NORMALIZED if gateway_notes else ExtractionStatus.EXTRACT_ONLY,
                requires_manual_review=bool(gateway_notes), notes=gateway_notes,
            ))

    return list(interfaces_by_name.values()), list(zones_by_name.values()), inventory, unsupported
