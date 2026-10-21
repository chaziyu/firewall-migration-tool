from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANService, PANServiceGroup, PANServiceOverride, PANServiceProtocol
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, typed_fields, value, values


def _override(element: ET.Element) -> PANServiceOverride | None:
    node = element.find("override")
    if node is None:
        return None
    children = list(node)
    source = children[0] if (len(children) == 1 and children[0].tag in {"yes", "no"}
                             and not (children[0].text or "").strip()) else node
    extra, explicit = typed_fields(source, {"timeout", "halfclose-timeout", "timewait-timeout"}, {"halfclose-timeout": "halfclose_timeout", "timewait-timeout": "timewait_timeout"})
    enabled = source.tag if source is not node and source.tag in {"yes", "no"} else None
    if enabled is not None:
        explicit.add("enabled")
        container_extra = raw_extra(node, {source.tag})
        if container_extra:
            extra["override"] = container_extra
    return PANServiceOverride(enabled=enabled, timeout=value(source, "timeout"), halfclose_timeout=value(source, "halfclose-timeout"), timewait_timeout=value(source, "timewait-timeout"), raw_extra=extra, explicit_fields=explicit)


def _protocol(element: ET.Element | None, name: str) -> PANServiceProtocol | None:
    if element is None:
        return None
    node = element.find(name)
    if node is None:
        return None
    extra, explicit = typed_fields(node, {"port", "source-port", "override"}, {"source-port": "source_port"})
    if len(node.findall("override")) > 1:
        extra["override"] = [raw_extra(item, set()) for item in node.findall("override")]
    return PANServiceProtocol(port=value(node, "port"), source_port=value(node, "source-port"), override=_override(node), raw_extra=extra, explicit_fields=explicit)


def extract_service(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    common = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if spec.name == "service":
        extra, explicit = source_fields(element, spec)
        explicit.discard("protocol")
        protocol = element.find("protocol")
        if protocol is not None:
            explicit.update({name for name in ("tcp", "udp") if protocol.find(name) is not None})
            protocol_extra = raw_extra(protocol, {"tcp", "udp"})
            if protocol_extra:
                extra["protocol"] = protocol_extra
        return PANService(**common, tcp=_protocol(protocol, "tcp"), udp=_protocol(protocol, "udp"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if spec.name == "service_group":
        extra, explicit = source_fields(element, spec)
        return PANServiceGroup(**common, members=values(element, "members"), description=value(element, "description"), tags=values(element, "tag"), disable_override=value(element, "disable-override"), raw_extra=extra, explicit_fields=explicit)
    return None
