"""Registry-driven PAN-OS typed source extraction."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..schema_registry import PANPathSpec, match_path_spec
from ..source_context import PANWalkContext
from .address import extract_address
from .interface import extract_interface
from .nat import extract_nat
from .policy import extract_default_security_rule, extract_security_rule
from .routing import extract_routing
from .schedule import extract_schedule
from .service import extract_service


_EXTRACTORS = {
    "address": ("addresses", extract_address),
    "address_group": ("address_groups", extract_address),
    "service": ("services", extract_service),
    "service_group": ("service_groups", extract_service),
    "schedule": ("schedules", extract_schedule),
    "security_rule": ("security_rules", extract_security_rule),
    "default_security_rule": ("default_security_rules", extract_default_security_rule),
    "nat_rule": ("nat_rules", extract_nat),
    "interface_import": ("interface_imports", extract_interface),
    "interface_unit": ("interface_units", extract_interface),
    "virtual_router": ("virtual_routers", extract_routing),
    "logical_router": ("logical_routers", extract_routing),
}
_EXTRACTORS.update({f"interface_{family}": ("interfaces", extract_interface) for family in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan")})


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
