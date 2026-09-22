from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANZone
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import source_fields, value, values


def extract_zone(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANZone:
    extra, explicit = source_fields(element, spec)
    network = element.find("network")
    members = None
    if network is not None:
        members = [item.text.strip() for item in network.iter("member") if item.text]
    return PANZone(
        name=element.get("name"), source_path="/".join(path), scope=context.scope,
        source_order=source_order, members=members,
        network_type=value(element, "network-type"),
        zone_protection_profile=value(element, "zone-protection-profile"),
        packet_buffer_protection=value(element, "packet-buffer-protection"),
        network_inspection=value(element, "network-inspection"),
        pre_nat_user_identification=value(element, "pre-nat-user-identification"),
        pre_nat_device_identification=value(element, "pre-nat-device-identification"),
        pre_nat_source_policy_lookup=value(element, "pre-nat-source-policy-lookup"),
        pre_nat_source_ip_downstream=value(element, "pre-nat-source-ip-downstream"),
        log_setting=value(element, "log-setting"), user_identification=value(element, "user-identification"),
        device_identification=value(element, "device-identification"),
        user_acl_include=values(element, "user-acl-include"), user_acl_exclude=values(element, "user-acl-exclude"),
        device_acl_include=values(element, "device-acl-include"), device_acl_exclude=values(element, "device-acl-exclude"),
        raw_extra=extra, explicit_fields=explicit,
    )
