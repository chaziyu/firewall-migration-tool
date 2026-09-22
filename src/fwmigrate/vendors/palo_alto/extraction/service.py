from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANService, PANServiceGroup, PANServiceOverride, PANServiceProtocol
from ..source_context import PANWalkContext
from .common import typed_fields, value, values


def _override(element: ET.Element) -> PANServiceOverride | None:
    node = element.find("override")
    if node is None:
        return None
    source = next(iter(node), node)
    extra, explicit = typed_fields(source, {"timeout", "halfclose-timeout", "timewait-timeout"})
    names = {"halfclose-timeout": "halfclose_timeout", "timewait-timeout": "timewait_timeout"}
    return PANServiceOverride(timeout=value(source, "timeout"), halfclose_timeout=value(source, "halfclose-timeout"), timewait_timeout=value(source, "timewait-timeout"), raw_extra=extra, explicit_fields={names.get(item, item) for item in explicit})


def _protocol(element: ET.Element | None, name: str) -> PANServiceProtocol | None:
    if element is None:
        return None
    node = element.find(name)
    if node is None:
        return None
    extra, explicit = typed_fields(node, {"port", "source-port", "override"})
    return PANServiceProtocol(port=value(node, "port"), source_port=value(node, "source-port"), override=_override(node), raw_extra=extra, explicit_fields={"source_port" if item == "source-port" else item for item in explicit})


def extract_service(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int) -> object | None:
    kind = path[-2:] if len(path) >= 2 else ()
    common = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if kind == ("service", "entry"):
        extra, explicit = typed_fields(element, {"protocol", "description", "tag"})
        protocol = element.find("protocol")
        return PANService(**common, tcp=_protocol(protocol, "tcp"), udp=_protocol(protocol, "udp"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if kind == ("service-group", "entry"):
        extra, explicit = typed_fields(element, {"members", "description", "tag"})
        return PANServiceGroup(**common, members=values(element, "members"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    return None
