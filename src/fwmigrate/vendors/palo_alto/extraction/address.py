from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANAddress, PANAddressGroup
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, value, values


def extract_address(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    common = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if spec.name == "address":
        extra, explicit = source_fields(element, spec)
        return PANAddress(**common, ip_netmask=value(element, "ip-netmask"), ip_range=value(element, "ip-range"), ip_wildcard=value(element, "ip-wildcard"), fqdn=value(element, "fqdn"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if spec.name == "address_group":
        extra, explicit = source_fields(element, spec)
        for child_name, handled in (("static", {"member"}), ("dynamic", {"filter"})):
            child_extra = raw_extra(element.find(child_name), handled) if element.find(child_name) is not None else {}
            if child_extra:
                extra.setdefault("nested", {})[child_name] = child_extra
        dynamic = element.find("dynamic")
        return PANAddressGroup(**common, static_members=values(element, "static"), dynamic_filter=value(dynamic, "filter"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    return None
