from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANService, PANServiceGroup, PANServiceOverride, PANServiceProtocol
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import source_fields, typed_fields, value, values


def _override(element: ET.Element) -> PANServiceOverride | None:
    node = element.find("override")
    if node is None:
        return None
    source = next(iter(node), node)
    extra, explicit = typed_fields(source, {"timeout", "halfclose-timeout", "timewait-timeout"}, {"halfclose-timeout": "halfclose_timeout", "timewait-timeout": "timewait_timeout"})
    enabled = source.tag if source is not node and source.tag in {"yes", "no"} else None
    if enabled is not None:
        explicit.add("enabled")
    return PANServiceOverride(enabled=enabled, timeout=value(source, "timeout"), halfclose_timeout=value(source, "halfclose-timeout"), timewait_timeout=value(source, "timewait-timeout"), raw_extra=extra, explicit_fields=explicit)


def _protocol(element: ET.Element | None, name: str) -> PANServiceProtocol | None:
    if element is None:
        return None
    node = element.find(name)
    if node is None:
        return None
    extra, explicit = typed_fields(node, {"port", "source-port", "override"}, {"source-port": "source_port"})
    return PANServiceProtocol(port=value(node, "port"), source_port=value(node, "source-port"), override=_override(node), raw_extra=extra, explicit_fields=explicit)


def extract_service(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    common = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if spec.name == "service":
        extra, explicit = source_fields(element, spec)
        explicit.discard("protocol")
        protocol = element.find("protocol")
        if protocol is not None:
            explicit.update({name for name in ("tcp", "udp") if protocol.find(name) is not None})
        return PANService(**common, tcp=_protocol(protocol, "tcp"), udp=_protocol(protocol, "udp"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if spec.name == "service_group":
        extra, explicit = source_fields(element, spec)
        return PANServiceGroup(**common, members=values(element, "members"), description=value(element, "description"), tags=values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    return None
