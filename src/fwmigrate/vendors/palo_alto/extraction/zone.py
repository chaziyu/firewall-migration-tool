from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANZone
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, value, values


def extract_zone(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANZone:
    extra, explicit = source_fields(element, spec)
    network = element.find("network")
    network_type = value(element, "network-type")
    members = None
    network_fields = {
        "zone-protection-profile": "zone_protection_profile",
        "enable-packet-buffer-protection": "packet_buffer_protection",
        "net-inspection": "network_inspection",
        "log-setting": "log_setting",
    }
    pre_nat_fields = {
        "enable-prenat-user-identification": "pre_nat_user_identification",
        "enable-prenat-device-identification": "pre_nat_device_identification",
        "enable-prenat-source-policy-lookup": "pre_nat_source_policy_lookup",
        "enable-prenat-source-ip-downstream": "pre_nat_source_ip_downstream",
    }
    for tag, field in (("enable-user-identification", "user_identification"), ("enable-device-identification", "device_identification")):
        selected_value = value(element, tag)
        if selected_value is not None:
            setattr_value = selected_value
            explicit.add(field)
        else:
            setattr_value = None
        if field == "user_identification":
            user_identification = setattr_value
        else:
            device_identification = setattr_value
    user_identification = user_identification or value(element, "user-identification")
    device_identification = device_identification or value(element, "device-identification")

    if network is not None:
        branch = next((child for child in network if child.tag in {"tap", "virtual-wire", "layer2", "layer3", "tunnel"}), None)
        if branch is not None:
            network_type = branch.tag
            explicit.add("network_type")
            members = [(item.text or item.get("name") or "").strip() for item in branch.findall("member")]
        for tag, field in network_fields.items():
            if network.find(tag) is not None:
                explicit.add(field)
        prenat = network.find("prenat-identification")
        if prenat is not None:
            for tag, field in pre_nat_fields.items():
                if prenat.find(tag) is not None:
                    explicit.add(field)
        known = set(network_fields) | {"prenat-identification", "tap", "virtual-wire", "layer2", "layer3", "tunnel"}
        nested_extra = raw_extra(network, known)
        if branch is not None:
            branch_extra = raw_extra(branch, {"member"})
            if branch_extra:
                nested_extra[branch.tag] = branch_extra
        if prenat is not None:
            unknown = raw_extra(prenat, set(pre_nat_fields))
            if unknown:
                nested_extra["prenat-identification"] = unknown
        for acl_tag in ("user-acl", "device-acl"):
            acl = element.find(acl_tag)
            if acl is not None:
                acl_extra = raw_extra(acl, {"include-list", "exclude-list"})
                if acl_extra:
                    extra[acl_tag] = acl_extra
        if nested_extra:
            extra["network"] = nested_extra

    acl_values = {}
    for acl_tag, prefix in (("user-acl", "user_acl"), ("device-acl", "device_acl")):
        acl = element.find(acl_tag)
        for leaf in ("include-list", "exclude-list"):
            field = f"{prefix}_{'include' if leaf == 'include-list' else 'exclude'}"
            selected = values(acl, leaf)
            legacy = values(element, field.replace("_", "-"))
            acl_values[field] = selected if selected is not None else legacy
            if selected is not None:
                explicit.add(field)

    def network_value(field, legacy_tag):
        tag = next(tag for tag, mapped in network_fields.items() if mapped == field)
        return value(network, tag) if network is not None and value(network, tag) is not None else value(element, legacy_tag)

    def prenat_value(field, legacy_tag):
        tag = next(tag for tag, mapped in pre_nat_fields.items() if mapped == field)
        prenat = network.find("prenat-identification") if network is not None else None
        return value(prenat, tag) if prenat is not None and value(prenat, tag) is not None else value(element, legacy_tag)

    return PANZone(
        name=element.get("name"), source_path="/".join(path), scope=context.scope,
        source_order=source_order, members=members,
        network_type=network_type,
        zone_protection_profile=network_value("zone_protection_profile", "zone-protection-profile"),
        packet_buffer_protection=network_value("packet_buffer_protection", "packet-buffer-protection"),
        network_inspection=network_value("network_inspection", "network-inspection"),
        pre_nat_user_identification=prenat_value("pre_nat_user_identification", "pre-nat-user-identification"),
        pre_nat_device_identification=prenat_value("pre_nat_device_identification", "pre-nat-device-identification"),
        pre_nat_source_policy_lookup=prenat_value("pre_nat_source_policy_lookup", "pre-nat-source-policy-lookup"),
        pre_nat_source_ip_downstream=prenat_value("pre_nat_source_ip_downstream", "pre-nat-source-ip-downstream"),
        log_setting=network_value("log_setting", "log-setting"), user_identification=user_identification,
        device_identification=device_identification,
        user_acl_include=acl_values["user_acl_include"], user_acl_exclude=acl_values["user_acl_exclude"],
        device_acl_include=acl_values["device_acl_include"], device_acl_exclude=acl_values["device_acl_exclude"],
        raw_extra=extra, explicit_fields=explicit,
    )
