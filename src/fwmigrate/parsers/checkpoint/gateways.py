"""Check Point Management gateway topology and Security Zone extraction."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.ir.core import (
    IRCheckpointInterfaceContext,
    IRCheckpointSICMetadata,
    IRInterface,
    IRZone,
)
from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, ResolutionResult, SemanticKind


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
    ipv6_network_prefix: Optional[str] = None
    topology: SourceGatewayTopology = Field(default_factory=SourceGatewayTopology)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class SourceGateway(BaseModel):
    uid: Optional[str] = None
    name: str
    source_type: str
    interfaces: List[SourceGatewayInterface] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


def _drop_sic_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _drop_sic_secrets(child)
            for key, child in value.items()
            if str(key).lower().replace("_", "-") not in {
                "sic-password", "activation-key", "one-time-password", "otp",
                "private-key", "private-key-data", "password", "passphrase",
            }
        }
    if isinstance(value, list):
        return [_drop_sic_secrets(item) for item in value]
    return value


def extract_sic_metadata(responses: List[CheckPointResponse]) -> List[IRCheckpointSICMetadata]:
    """Extract explicit SIC state only; reachability never implies SIC state."""
    result: List[IRCheckpointSICMetadata] = []
    for response in responses:
        if canonicalize_command(response.command) not in {"show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters"}:
            continue
        objects = response.data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        for obj in objects if isinstance(objects, list) else []:
            if not isinstance(obj, dict):
                continue
            sic = obj.get("sic") or obj.get("sic-status") or obj.get("sic_status")
            sic_obj = sic if isinstance(sic, dict) else {}
            explicit = sic is not None or any(key in obj for key in ("sic-certificate", "sic-certificate-uid", "sic-password", "activation-key"))
            if not explicit:
                continue
            cert = sic_obj.get("certificate") or obj.get("sic-certificate")
            cert_uid, cert_name, cert_fp = (None, None, None)
            if isinstance(cert, dict):
                cert_uid, cert_name, cert_fp = cert.get("uid"), cert.get("name"), cert.get("fingerprint")
            elif cert:
                cert_name = str(cert)
            result.append(IRCheckpointSICMetadata(
                gateway_uid=obj.get("uid"), gateway_name=obj.get("name"),
                sic_status=sic_obj.get("status") or (sic if isinstance(sic, str) else obj.get("sic-status")),
                sic_certificate_uid=cert_uid or obj.get("sic-certificate-uid"), sic_certificate_name=cert_name,
                sic_certificate_fingerprint=cert_fp, management_reference=obj.get("management-server") or obj.get("management-reference"),
                source_context=response.domain or "global", sic_credential_present=any(key in obj or key in sic_obj for key in ("sic-password", "activation-key", "one-time-password")),
                source_attributes=_drop_sic_secrets(sanitize_source_attributes({"source_command": response.command, "gateway": obj})),
            ))
    return result


def _zone_reference(obj: Dict[str, Any]) -> Any:
    settings = obj.get("security-zone-settings")
    if isinstance(settings, dict):
        for key in ("specific-zone", "specific-security-zone", "security-zone", "zone"):
            if settings.get(key) not in (None, ""):
                return settings[key]
        if settings.get("auto-calculated") is True:
            return None
    return obj.get("security-zone")


def _zone_label(
    raw: Any, resolver: CheckPointObjectResolver, domain: str,
) -> Optional[ResolutionResult]:
    if raw in (None, False, ""):
        return None
    if raw is True:
        return None
    resolution = resolver.resolve(raw, domain=domain)
    if (
        resolution.resolved
        and resolution.name
        and resolution.semantic_kind == SemanticKind.SECURITY_ZONE
    ):
        return resolution
    return None


def _interface_zone(
    obj: Dict[str, Any], resolver: CheckPointObjectResolver, domain: str,
) -> Optional[ResolutionResult]:
    resolution = _zone_label(_zone_reference(obj), resolver, domain)
    return resolution


def _management_ipv4(obj: Dict[str, Any]) -> Optional[str]:
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


def _management_ipv6(obj: Dict[str, Any]) -> Optional[str]:
    address = obj.get("ipv6-address") or obj.get("ipv6_address")
    mask = obj.get("ipv6-network-mask") or obj.get("ipv6_network_mask")
    prefix = obj.get("ipv6-mask-length")
    if prefix is None:
        prefix = obj.get("ipv6-prefix-length", obj.get("ipv6_prefix_length"))
    if prefix is None and mask:
        try:
            prefix = ipaddress.IPv6Network(f"::/{mask}").prefixlen
        except (ValueError, TypeError):
            return None
    if not address or prefix is None:
        return None
    try:
        ipaddress.IPv6Address(str(address))
        prefix = int(prefix)
        if not 0 <= prefix <= 128:
            raise ValueError
        return f"{address}/{prefix}"
    except (ValueError, TypeError):
        return None


def _management_ip(obj: Dict[str, Any]) -> Optional[str]:
    """Backward-compatible IPv4 helper used by older callers."""
    return _management_ipv4(obj)


def _virtual_system_id(*objects: Dict[str, Any]) -> Optional[int]:
    """Return an explicit Management-side VSID only when source evidence supplies one."""
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        for key in ("virtual-system-id", "virtual_system_id", "vsid"):
            if obj.get(key) is None:
                continue
            try:
                value = int(obj[key])
                return value if value >= 0 else None
            except (TypeError, ValueError):
                return None
    return None


def _gateway_references(obj: Dict[str, Any]) -> set[str]:
    refs = {
        str(value) for value in (obj.get("uid"), obj.get("name"))
        if value not in (None, "")
    }
    members = obj.get("members") or obj.get("member-gateways") or obj.get("cluster-members") or []
    for member in members if isinstance(members, list) else []:
        if isinstance(member, dict):
            refs.update(
                str(value) for value in (member.get("uid"), member.get("name"))
                if value not in (None, "")
            )
        elif member not in (None, ""):
            refs.add(str(member))
    return refs


def _interface_vsid(interface: IRInterface) -> Optional[int]:
    context = interface.checkpoint_context
    if context and context.virtual_system_id is not None:
        return context.virtual_system_id
    value = interface.source_attributes.get("virtual_system_id")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _interface_domain_matches(
    interface: IRInterface, domain: str, domain_uid: Optional[str],
) -> bool:
    context = interface.checkpoint_context
    if context and context.domain_uid and domain_uid:
        return context.domain_uid == domain_uid
    if context and context.domain_name and domain:
        return context.domain_name == domain
    provenance = interface.source_attributes.get("provenance", {})
    source_domain = provenance.get("domain") if isinstance(provenance, dict) else None
    return not source_domain or not domain or source_domain == domain


def _management_owner_matches(
    context: Optional[IRCheckpointInterfaceContext], gateway: Dict[str, Any],
) -> bool:
    if context is None:
        return True
    current_uid = gateway.get("uid")
    if context.management_gateway_uid and current_uid:
        return str(context.management_gateway_uid) == str(current_uid)
    current_name = gateway.get("name")
    return bool(
        context.management_gateway_name and current_name
        and str(context.management_gateway_name) == str(current_name)
    )


def _gaia_candidates(
    interfaces: List[IRInterface], name: str, management_vsid: Optional[int],
    gateway: Dict[str, Any], domain: str, domain_uid: Optional[str] = None,
) -> List[IRInterface]:
    refs = _gateway_references(gateway)
    candidates = [item for item in interfaces if item.name == name]
    candidates = [item for item in candidates if not (
        item.checkpoint_context
        and item.checkpoint_context.domain_uid
        and domain_uid
        and item.checkpoint_context.domain_uid != domain_uid
    )]
    candidates = [
        item for item in candidates
        if _interface_domain_matches(item, domain, domain_uid)
    ]
    if management_vsid is not None:
        candidates = [item for item in candidates if _interface_vsid(item) == management_vsid]

    matched: List[IRInterface] = []
    for candidate in candidates:
        context = candidate.checkpoint_context
        if context and (
            context.management_gateway_uid or context.management_gateway_name
        ) and not _management_owner_matches(context, gateway):
            continue
        gaia_owner = {
            str(value) for value in (
                context.gaia_gateway_name if context else None,
                context.gaia_cluster_member_name if context else None,
            ) if value not in (None, "")
        }
        if gaia_owner and not gaia_owner.intersection(refs):
            continue
        matched.append(candidate)
    return matched


def _set_management_context(
    interface: IRInterface, response: CheckPointResponse, gateway: Dict[str, Any],
    management_vsid: Optional[int],
) -> None:
    context = interface.checkpoint_context or IRCheckpointInterfaceContext()
    context.domain_uid = response.domain_uid or context.domain_uid
    context.domain_name = response.domain or response.domain_name or context.domain_name
    context.management_gateway_uid = gateway.get("uid") or context.management_gateway_uid
    context.management_gateway_name = gateway.get("name") or context.management_gateway_name
    context.management_gateway_type = gateway.get("type") or context.management_gateway_type
    if management_vsid is not None:
        context.virtual_system_id = management_vsid
    interface.checkpoint_context = context


def _append_review(interface: IRInterface, reason: str) -> None:
    interface.requires_manual_review = True
    interface.migration_status = "PARTIALLY_NORMALIZED"
    if reason not in interface.parse_errors:
        interface.parse_errors.append(reason)
    if reason not in interface.review_reasons:
        interface.review_reasons.append(reason)


def extract_gateway_topology(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
    gaia_interfaces: Optional[List[IRInterface]] = None,
) -> Tuple[List[IRInterface], List[IRZone], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Merge Management topology with Gaia without collapsing distinct VS contexts.

    Gaia is authoritative for persistent OS interface state. Management topology
    is authoritative for Security Zone, anti-spoofing and topology relations. A
    Management interface without explicit VSID is never used to arbitrarily pick
    one of multiple same-named Gaia interfaces from different virtual systems.
    """
    interfaces: List[IRInterface] = list(gaia_interfaces or [])
    zones_by_scope: Dict[Tuple[Optional[int], str], IRZone] = {}
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
                    zones_by_scope.setdefault((None, str(name)), IRZone(
                        name=str(name), description=obj.get("comments"), source_attributes=dict(obj),
                    ))
                    resolver.set_object_normalization(
                        str(uid or name), str(name), status, semantic_kind=SemanticKind.SECURITY_ZONE,
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
                managed_ip = _management_ipv4(raw_interface)
                managed_ipv6 = _management_ipv6(raw_interface)
                zone_resolution = _interface_zone(raw_interface, resolver, domain)
                zone = (
                    zone_resolution.canonical_name or zone_resolution.name
                    if zone_resolution else None
                )
                zone_reference = _zone_reference(raw_interface)
                unresolved_zone = zone_reference not in (None, False, "") and zone_resolution is None
                management_vsid = _virtual_system_id(raw_interface, obj)
                candidates = _gaia_candidates(
                    interfaces, name, management_vsid, obj, domain,
                    response.domain_uid,
                )

                if len(candidates) > 1 and management_vsid is None:
                    reason = "ambiguous-management-topology-across-virtual-systems"
                    gateway_notes.append(f"{name}:{reason}")
                    for candidate in candidates:
                        candidate.source_attributes.setdefault("checkpoint-management-topology-unscoped", []).append(dict(raw_interface))
                        _append_review(candidate, reason)
                    continue

                if len(candidates) > 1:
                    reason = "ambiguous-management-gateway-interface-correlation"
                    gateway_notes.append(f"{name}:{reason}")
                    for candidate in candidates:
                        candidate.source_attributes.setdefault("checkpoint-management-topology-ambiguous", []).append(dict(raw_interface))
                        _append_review(candidate, reason)
                    continue

                interface = candidates[0] if candidates else None
                if interface is None:
                    interface = IRInterface(
                        name=name, ip=managed_ip, zone=zone,
                        ipv6_address=managed_ipv6,
                        interface_type=raw_interface.get("interface-type"),
                        source_context=f"{domain}:{gateway_name}",
                        checkpoint_context=IRCheckpointInterfaceContext(
                            domain_uid=response.domain_uid,
                            domain_name=response.domain or response.domain_name,
                            management_gateway_uid=obj.get("uid"),
                            management_gateway_name=obj.get("name"),
                            management_gateway_type=obj.get("type"),
                            virtual_system_id=management_vsid,
                        ),
                        source_attributes={
                            "checkpoint-management-topology": dict(raw_interface),
                            "virtual_system_id": management_vsid,
                        },
                    )
                    interfaces.append(interface)
                else:
                    _set_management_context(interface, response, obj, management_vsid)
                    conflicts: List[str] = []
                    if managed_ip and interface.ip and managed_ip != interface.ip:
                        conflicts.append("gaia-management-ip-conflict")
                    if managed_ipv6 and interface.ipv6_address and managed_ipv6 != interface.ipv6_address:
                        conflicts.append("gaia-management-ipv6-conflict")
                    if interface.zone and zone and interface.zone != zone:
                        conflicts.append("gaia-management-zone-conflict")
                    # Gaia OS addressing is authoritative. Management addresses
                    # remain topology/conflict evidence and never overwrite it.
                    if zone:
                        interface.zone = zone
                    interface.source_attributes["checkpoint-management-topology"] = dict(raw_interface)
                    interface.source_attributes["management_ipv4"] = managed_ip
                    interface.source_attributes["management_ipv6"] = managed_ipv6
                    if management_vsid is not None:
                        interface.source_attributes["management_virtual_system_id"] = management_vsid
                    for reason in conflicts:
                        _append_review(interface, reason)
                        gateway_notes.append(f"{name}:{reason}")

                if unresolved_zone:
                    reason = "unresolved-security-zone-reference"
                    reference_id = (
                        zone_reference.get("uid") or zone_reference.get("name")
                        if isinstance(zone_reference, dict) else str(zone_reference)
                    )
                    interface.source_attributes["checkpoint-unresolved-security-zone"] = zone_reference
                    interface.source_attributes.setdefault("checkpoint-unresolved-zone-references", []).append(zone_reference)
                    _append_review(interface, reason)
                    gateway_notes.append(f"{name}:{reason}")
                    inventory.append(SourceInventoryItem(
                        domain=domain,
                        domain_uid=response.domain_uid,
                        domain_name=response.domain_name or response.domain,
                        source_path=f"checkpoint/{command}/interfaces/{name}/security-zone",
                        name=f"{gateway_name}:{name}:security-zone",
                        source_id=str(reference_id) if reference_id else None,
                        source_type="security-zone-reference",
                        source_attributes={
                            "gateway": gateway_name,
                            "interface": name,
                            "security_zone_reference": zone_reference,
                            "raw_interface": dict(raw_interface),
                        },
                        source_references=[str(reference_id)] if reference_id else [],
                        status=ExtractionStatus.PARTIALLY_NORMALIZED,
                        requires_manual_review=True,
                        notes=[reason],
                    ))

                if zone:
                    zone_key = (management_vsid, zone)
                    zone_obj = zones_by_scope.setdefault(zone_key, IRZone(
                        name=zone,
                        source_context=(
                            f"{response.domain or 'global'}:vsid={management_vsid}"
                            if management_vsid is not None else None
                        ),
                        source_attributes=(
                            {"virtual_system_id": management_vsid}
                            if management_vsid is not None else {}
                        ),
                    ))
                    member_key = f"{name}@vsid={management_vsid}" if management_vsid is not None else name
                    if member_key not in zone_obj.interfaces:
                        zone_obj.interfaces.append(member_key)

            is_cluster = "cluster" in str(obj.get("type") or "").lower()
            if is_cluster:
                members = obj.get("members") or obj.get("member-gateways") or obj.get("cluster-members") or []
                obj.setdefault("cluster-member-references", [
                    m.get("uid") or m.get("name") or str(m) if isinstance(m, dict) else str(m)
                    for m in members
                ])
                gateway_notes.append("cluster-topology-preserved")
            inventory.append(SourceInventoryItem(
                domain=domain, source_path=f"checkpoint/{command}", name=gateway_name,
                source_id=obj.get("uid"), source_type=str(obj.get("type") or "gateway-server"),
                source_attributes=dict(obj),
                status=ExtractionStatus.PARTIALLY_NORMALIZED if gateway_notes else ExtractionStatus.EXTRACT_ONLY,
                requires_manual_review=bool(gateway_notes), notes=gateway_notes,
            ))

    return interfaces, list(zones_by_scope.values()), inventory, unsupported
