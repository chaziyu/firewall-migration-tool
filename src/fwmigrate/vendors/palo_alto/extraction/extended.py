from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..model import (
    PANAdministrator, PANAdminRole, PANGlobalProtectGateway,
    PANGlobalProtectPortal, PANIKECryptoProfile, PANIKEGateway,
    PANIPsecCryptoProfile, PANLocalUser, PANLocalUserGroup, PANGroupMapping,
    PANSDWANErrorCorrectionProfile, PANSDWANInterfaceProfile,
    PANSDWANPathQualityProfile, PANSDWANRule, PANSDWANSaaSQualityProfile,
    PANSDWANTrafficDistributionLink, PANSDWANTrafficDistributionProfile, PANVulnerabilityProfile,
)
from ..model.security_profile import PANBlockIPAction, PANVulnerabilityException, PANVulnerabilityRule
from ..model.administration import PANAdminRolePermission
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, secret_leaf_exists, source_fields
from .vpn import extract_ipsec_tunnel
from .dhcp import extract_dhcp
from .globalprotect import extract_gateway, extract_portal
from ..model.vpn import PANIPsecProxyID


def _text(node: ET.Element) -> str | None:
    return (node.text or "").strip() or None


def _value(node: ET.Element, tag: str) -> Any:
    child = node.find(tag)
    if child is None:
        return None
    members = child.findall("member")
    if members:
        return [_text(item) or item.get("name") or "" for item in members]
    if len(child) == 0:
        return _text(child)
    return {item.tag: (_text(item) if len(item) == 0 else _value(child, item.tag)) for item in child}


def _named(cls, element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec, *, secret_fields=()):
    extra, explicit = source_fields(element, spec)
    fields = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order,
              "raw_extra": extra, "explicit_fields": explicit}
    for field in cls.model_fields:
        if field in fields or field in {"raw_extra", "explicit_fields", "name", "source_path", "scope", "source_order"}:
            continue
        tag = {"password_configured": "password", "pre_shared_key_configured": "pre-shared-key"}.get(field, field.replace("_", "-"))
        if field in secret_fields:
            fields[field] = secret_leaf_exists(element, tag, f"{tag}/member")
        else:
            value = _value(element, tag)
            if value is not None and not isinstance(value, dict):
                fields[field] = value
    return cls(**fields)


def extract_named(cls, *, secret_fields=()):
    def extract(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
        return _named(cls, element, path, context, source_order, spec, secret_fields=secret_fields)
    return extract


def extract_vulnerability(element, path, context, source_order, spec):
    item = _named(PANVulnerabilityProfile, element, path, context, source_order, spec)
    for child_tag, model in (("rules", PANVulnerabilityRule), ("exceptions", PANVulnerabilityException)):
        child = element.find(child_tag)
        if child is None:
            continue
        entries = []
        setattr(item, child_tag, entries)
        for entry in child.findall("entry"):
            exception = child_tag == "exceptions"
            known = {"threat-name", "host", "vendor-ids", "severities", "category", "action", "block-ip", "packet-capture"}
            if exception:
                known.update({"time-interval", "time-threshold", "time-track-by", "exempt-ips", "exempt-ip"})
            extra = raw_extra(entry, known)
            fields = ("name", "threat_name", "host", "vendor_ids", "severities", "category", "action", "packet_capture")
            if exception:
                fields += ("time_interval", "time_threshold", "time_track_by")
            data = {field: _value(entry, field.replace("_", "-")) for field in fields}
            block_ip = entry.find("block-ip")
            if block_ip is not None:
                data["block_ip"] = _extract_block_ip(block_ip)
            if exception:
                data["exempt_ips"] = _exempt_ips(entry)
            data = {key: value for key, value in data.items() if value is not None}
            data["name"] = entry.get("name")
            data["raw_extra"] = extra
            data["explicit_fields"] = {child.tag.replace("-", "_") for child in entry if child.tag in known}
            if block_ip is not None:
                data["explicit_fields"].add("block_ip")
            entries.append(model(**data))
    return item


def _extract_block_ip(element):
    known = {"track-by", "duration"}
    return PANBlockIPAction(
        track_by=_value(element, "track-by"), duration=_value(element, "duration"),
        raw_extra=raw_extra(element, known),
        explicit_fields={child.tag.replace("-", "_") for child in element if child.tag in known},
    )


def _exempt_ips(element):
    for tag in ("exempt-ips", "exempt-ip"):
        value = _value(element, tag)
        if value is None:
            continue
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return list(value.values())
        return [value]
    return None


def extract_admin_role(element, path, context, source_order, spec):
    item = _named(PANAdminRole, element, path, context, source_order, spec)
    section = element.find("permissions")
    if section is None:
        return item
    item.permissions = []
    for entry in section.findall("entry"):
        item.permissions.append(PANAdminRolePermission(
            channel=_value(entry, "channel"), permission_path=_value(entry, "permission-path"), setting=_value(entry, "setting"), value=_value(entry, "value")))
    return item


def extract_ipsec_proxy(element):
    return PANIPsecProxyID(
        name=element.get("name"), address_family=_value(element, "address-family"),
        local=_proxy_value(element, "local"), remote=_proxy_value(element, "remote"),
        protocol=_proxy_value(element, "protocol"), protocol_number=_proxy_value(element, "protocol-number"),
        local_port=_proxy_value(element, "local-port"), remote_port=_proxy_value(element, "remote-port"),
        raw_extra=raw_extra(element, {"address-family", "local", "remote", "protocol", "protocol-number", "local-port", "remote-port"}),
        explicit_fields={child.tag.replace("-", "_") for child in element if child.tag in {"address-family", "local", "remote", "protocol", "protocol-number", "local-port", "remote-port"}},
    )


def _proxy_value(element, tag):
    value = _value(element, tag)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def extract_ipsec(element, path, context, source_order, spec):
    item = extract_ipsec_tunnel(element, path, context, source_order, spec)
    manual = element.find("manual-key")
    item.manual_key_configured = manual is not None
    auto_key = element.find("auto-key")
    proxy_ids = []
    for family, tag in (("ipv4", "proxy-id"), ("ipv6", "proxy-id-v6")):
        for entry in auto_key.findall(f"{tag}/entry") if auto_key is not None else ():
            proxy = extract_ipsec_proxy(entry)
            if proxy.address_family is None:
                proxy.address_family = family
                proxy.explicit_fields.add("address_family")
            proxy_ids.append(proxy)
    item.proxy_ids = proxy_ids or None
    return item


def extract_traffic_distribution(element, path, context, source_order, spec):
    item = _named(PANSDWANTrafficDistributionProfile, element, path, context, source_order, spec)
    section = element.find("link")
    if section is None:
        return item
    item.links = []
    for entry in section.findall("entry"):
        known = {"link-tag", "weight"}
        item.links.append(PANSDWANTrafficDistributionLink(
            link_tag=_value(entry, "link-tag"),
            weight=_value(entry, "weight"),
            raw_extra=raw_extra(entry, known),
            explicit_fields={child.tag.replace("-", "_") for child in entry if child.tag in known},
        ))
    return item


EXTRACTORS = {
    "vulnerability_profile": ("vulnerability_profiles", extract_vulnerability),
    "administrator": ("administrators", extract_named(PANAdministrator, secret_fields=("password_configured",))),
    "admin_role": ("admin_roles", extract_admin_role),
    "ike_gateway": ("ike_gateways", extract_named(PANIKEGateway, secret_fields=("pre_shared_key_configured",))),
    "ike_crypto_profile": ("ike_crypto_profiles", extract_named(PANIKECryptoProfile)),
    "ipsec_crypto_profile": ("ipsec_crypto_profiles", extract_named(PANIPsecCryptoProfile)),
    "ipsec_tunnel": ("ipsec_tunnels", extract_ipsec),
    "dhcp_server": ("dhcp_servers", extract_dhcp),
    "sdwan_interface_profile": ("sdwan_interface_profiles", extract_named(PANSDWANInterfaceProfile)),
    "sdwan_path_quality_profile": ("sdwan_path_quality_profiles", extract_named(PANSDWANPathQualityProfile)),
    "sdwan_traffic_distribution_profile": ("sdwan_traffic_distribution_profiles", extract_traffic_distribution),
    "sdwan_saas_quality_profile": ("sdwan_saas_quality_profiles", extract_named(PANSDWANSaaSQualityProfile)),
    "sdwan_error_correction_profile": ("sdwan_error_correction_profiles", extract_named(PANSDWANErrorCorrectionProfile)),
    "sdwan_rule": ("sdwan_rules", extract_named(PANSDWANRule)),
    "local_user": ("local_users", extract_named(PANLocalUser, secret_fields=("password_configured",))),
    "local_user_group": ("local_user_groups", extract_named(PANLocalUserGroup)),
    "group_mapping": ("group_mappings", extract_named(PANGroupMapping)),
    "globalprotect_portal": ("globalprotect_portals", extract_portal),
    "globalprotect_gateway": ("globalprotect_gateways", extract_gateway),
}
