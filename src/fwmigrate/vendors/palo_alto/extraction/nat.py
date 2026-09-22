from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANDestinationTranslation, PANDNSRewrite, PANDynamicDestinationTranslation, PANDynamicIPAndPortTranslation, PANStaticIPTranslation, PANNATRule
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, structured_xml_capture, typed_fields, value, values


def _source(element: ET.Element):
    node = element.find("source-translation")
    if node is None:
        return None
    dynamic = node.find("dynamic-ip-and-port")
    if dynamic is not None:
        interface = dynamic.find("interface-address")
        extra, explicit = typed_fields(dynamic, {"translated-address", "interface-address"}, {"translated-address": "translated_addresses"})
        explicit.discard("interface-address")
        if interface is not None:
            explicit.update(field for field, child in (("interface", "interface"), ("ip", "ip")) if interface.find(child) is not None)
        interface_extra = raw_extra(interface, {"interface", "ip"}) if interface is not None else {}
        if interface_extra:
            extra["interface-address"] = interface_extra
        return PANDynamicIPAndPortTranslation(translated_addresses=values(dynamic, "translated-address"), interface=value(interface, "interface"), ip=value(interface, "ip"), raw_extra=extra, explicit_fields=explicit)
    static = node.find("static-ip")
    if static is not None:
        extra, explicit = typed_fields(static, {"translated-address", "bi-directional"}, {"translated-address": "translated_address", "bi-directional": "bi_directional"})
        return PANStaticIPTranslation(translated_address=value(static, "translated-address"), bi_directional=value(static, "bi-directional"), raw_extra=extra, explicit_fields=explicit)
    return None


def _destination(element: ET.Element):
    node = element.find("destination-translation")
    if node is None:
        return None
    extra, explicit = typed_fields(node, {"translated-address", "translated-port"}, {"translated-address": "translated_address", "translated-port": "translated_port"})
    return PANDestinationTranslation(translated_address=value(node, "translated-address"), translated_port=value(node, "translated-port"), raw_extra=extra, explicit_fields=explicit)


def _dynamic_destination(element: ET.Element):
    node = element.find("dynamic-destination-translation")
    if node is None:
        return None
    rewrite = node.find("dns-rewrite")
    dns = None
    if rewrite is not None:
        branch = next(iter(rewrite), None)
        if branch is None:
            dns = PANDNSRewrite(enabled=None, explicit_fields=set())
        else:
            extra, explicit = typed_fields(branch, {"direction"})
            dns = PANDNSRewrite(enabled=branch.tag, direction=value(branch, "direction"), raw_extra=extra, explicit_fields={"enabled", *explicit})
    distribution = next(iter(node.find("distribution")), None) if node.find("distribution") is not None else None
    extra, explicit = typed_fields(node, {"translated-address", "distribution", "dns-rewrite"}, {"translated-address": "translated_addresses", "distribution": "distribution"})
    explicit.discard("dns-rewrite")
    if distribution is not None:
        extra["distribution"] = {distribution.tag: structured_xml_capture(distribution)}
    return PANDynamicDestinationTranslation(translated_addresses=values(node, "translated-address"), distribution=distribution.tag if distribution is not None else None, dns_rewrite=dns, raw_extra=extra, explicit_fields=explicit)


def extract_nat(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    extra, explicit = source_fields(element, spec)
    return PANNATRule(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, rulebase_position=context.rulebase_position, from_zones=values(element, "from"), to_zones=values(element, "to"), source=values(element, "source"), destination=values(element, "destination"), service=value(element, "service"), disabled=value(element, "disabled"), active_active_device_binding=value(element, "active-active-device-binding"), source_translation=_source(element), destination_translation=_destination(element), dynamic_destination_translation=_dynamic_destination(element), raw_extra=extra, explicit_fields=explicit)
