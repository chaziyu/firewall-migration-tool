"""Registry-driven PAN-OS typed source extraction."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..schema_registry import PANPathSpec, match_path_spec
from ..source_context import PANWalkContext
from .address import extract_address
from .interface import extract_interface
from .vpn import extract_ipsec_tunnel
from .nat import extract_nat
from .policy import extract_default_security_rule, extract_security_rule
from .routing import extract_routing
from .schedule import extract_schedule
from .service import extract_service
from .zone import extract_zone
from ..model import PANSecurityProfileGroup, PANTag
from .common import source_fields, value, values
from .common import raw_extra, structured_xml_capture
from ..model.management_profile import MANAGEMENT_PROTOCOLS, PANInterfaceManagementProfile
from ..sanitization import sanitize_panos_attributes
from .extended import EXTRACTORS as EXTENDED_EXTRACTORS


def extract_security_profile_group(element, path, context, source_order, spec):
    extra, explicit = source_fields(element, spec)
    return PANSecurityProfileGroup(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, antivirus=values(element, "virus"), anti_spyware=values(element, "spyware"), vulnerability=values(element, "vulnerability"), url_filtering=values(element, "url-filtering"), file_blocking=values(element, "file-blocking"), wildfire_analysis=values(element, "wildfire-analysis"), data_filtering=values(element, "data-filtering"), gtp=values(element, "gtp"), sctp=values(element, "sctp"), ai_security=values(element, "ai-security"), disable_override=value(element, "disable-override"), raw_extra=extra, explicit_fields=explicit)


def extract_tag(element, path, context, source_order, spec):
    extra, explicit = source_fields(element, spec)
    return PANTag(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
                  color=value(element, "color"), comments=value(element, "comments"), raw_extra=extra, explicit_fields=explicit)


def extract_management_profile(element, path, context, source_order, spec):
    extra, explicit = source_fields(element, spec)
    protocols = {name: value(element, name) for name in MANAGEMENT_PROTOCOLS if element.find(name) is not None}
    explicit.difference_update(MANAGEMENT_PROTOCOLS)
    for name in (*MANAGEMENT_PROTOCOLS, 'permitted-ip'):
        nodes = element.findall(name)
        if len(nodes) > 1 or (name != 'permitted-ip' and any(list(node) or node.attrib for node in nodes)):
            extra[name] = [structured_xml_capture(node) for node in nodes]
    permitted = element.find('permitted-ip')
    permitted_ips = None
    if permitted is not None:
        permitted_ips = [entry.get('name') or '' for entry in permitted.findall('entry')]
        unknown = raw_extra(permitted, {'entry'})
        if unknown or any(list(entry) or set(entry.attrib) != {'name'} for entry in permitted):
            extra['permitted-ip'] = structured_xml_capture(permitted)
    if protocols:
        explicit.add('protocols')
    return PANInterfaceManagementProfile(name=element.get('name'), source_path='/'.join(path),
        scope=context.scope, source_order=source_order, protocols=protocols, permitted_ips=permitted_ips,
        raw_extra=sanitize_panos_attributes(extra), explicit_fields=explicit)


_EXTRACTORS = {
    "management_profile": ("management_profiles", extract_management_profile),
    "tag": ("tags", extract_tag),
    "address": ("addresses", extract_address),
    "address_group": ("address_groups", extract_address),
    "service": ("services", extract_service),
    "service_group": ("service_groups", extract_service),
    "schedule": ("schedules", extract_schedule),
    "security_rule": ("security_rules", extract_security_rule),
    "default_security_rule": ("default_security_rules", extract_default_security_rule),
    "nat_rule": ("nat_rules", extract_nat),
    "interface_import": ("interface_imports", extract_interface),
    "virtual_router_import": ("interface_imports", extract_interface),
    "zone": ("zones", extract_zone),
    "security_profile_group": ("security_profile_groups", extract_security_profile_group),
    "interface_unit": ("interface_units", extract_interface),
    "virtual_router": ("virtual_routers", extract_routing),
    "logical_router": ("logical_routers", extract_routing),
    "ipsec_tunnel": ("ipsec_tunnels", extract_ipsec_tunnel),
}
_EXTRACTORS.update(EXTENDED_EXTRACTORS)
_EXTRACTORS.update({"dhcp_interface": ("dhcp_servers", EXTENDED_EXTRACTORS["dhcp_server"][1]),
                    "local_user_database": ("local_users", EXTENDED_EXTRACTORS["local_user"][1])})
_EXTRACTORS.update({f"interface_{family}": ("interfaces", extract_interface) for family in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan")})


def registered_typed_collections() -> tuple[str, ...]:
    return tuple(sorted({collection for collection, _ in _EXTRACTORS.values()}))


def registered_typed_domains() -> frozenset[str]:
    return frozenset(_EXTRACTORS)


def extract_typed(
    element: ET.Element,
    path: tuple[str, ...],
    context: PANWalkContext,
    source_order: int,
) -> tuple[str, object] | None:
    spec: PANPathSpec | None = match_path_spec(path)
    if spec is None or spec.name not in _EXTRACTORS:
        return None
    collection, extractor = _EXTRACTORS[spec.name]
    model = extractor(element, path, context, source_order, spec)
    return (collection, model) if model is not None else None
