from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANAddress, PANAddressGroup
from ..source_context import PANWalkContext
from .common import typed_fields, value, values


def extract_address(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int) -> object | None:
    kind = path[-2:] if len(path) >= 2 else ()
    common = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if kind == ("address", "entry"):
        extra, explicit = typed_fields(element, {"ip-netmask", "ip-range", "ip-wildcard", "fqdn", "description", "tag"})
        return PANAddress(**common, ip_netmask=value(element, "ip-netmask"), ip_range=value(element, "ip-range"), ip_wildcard=value(element, "ip-wildcard"), fqdn=value(element, "fqdn"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if kind == ("address-group", "entry"):
        extra, explicit = typed_fields(element, {"static", "dynamic", "description", "tag"})
        dynamic = element.find("dynamic")
        return PANAddressGroup(**common, static_members=values(element, "static"), dynamic_filter=value(dynamic, "filter"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    return None
