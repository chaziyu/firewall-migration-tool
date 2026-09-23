from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..model import (
    PANAdministrator, PANAdminRole, PANDHCPServer, PANGlobalProtectGateway,
    PANGlobalProtectPortal, PANIKECryptoProfile, PANIKEGateway,
    PANIPsecCryptoProfile, PANLocalUser, PANLocalUserGroup, PANGroupMapping,
    PANSDWANErrorCorrectionProfile, PANSDWANInterfaceProfile,
    PANSDWANPathQualityProfile, PANSDWANRule, PANSDWANSaaSQualityProfile,
    PANSDWANTrafficDistributionProfile, PANVulnerabilityProfile,
)
from ..model.security_profile import PANVulnerabilityException, PANVulnerabilityRule
from ..model.administration import PANAdminRolePermission
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import secret_leaf_exists, source_fields
from .vpn import extract_ipsec_tunnel
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
    item.rules = []
    item.exceptions = []
    for child in element:
        if child.tag not in {"rules", "exceptions"}:
            continue
        target = item.rules if child.tag == "rules" else item.exceptions
        for entry in child.findall("entry"):
            data = {field: _value(entry, field.replace("_", "-")) for field in ("name", "threat_name", "host", "vendor_ids", "severities", "category", "action", "packet_capture", "time_interval", "time_threshold", "time_track_by", "exempt_ips")}
            data = {key: value for key, value in data.items() if value is not None}
            target.append((PANVulnerabilityRule if child.tag == "rules" else PANVulnerabilityException)(**data))
    return item


def extract_admin_role(element, path, context, source_order, spec):
    item = _named(PANAdminRole, element, path, context, source_order, spec)
    item.permissions = []
    for entry in element.findall("permissions/entry"):
        item.permissions.append(PANAdminRolePermission(
            channel=_value(entry, "channel"), permission_path=_value(entry, "permission-path"), setting=_value(entry, "setting"), value=_value(entry, "value")))
    return item


def extract_ipsec_proxy(element):
    return PANIPsecProxyID(name=element.get("name"), address_family=_value(element, "address-family"), local=_value(element, "local"), remote=_value(element, "remote"), protocol=_value(element, "protocol"), protocol_number=_value(element, "protocol-number"), local_port=_value(element, "local-port"), remote_port=_value(element, "remote-port"))


def extract_ipsec(element, path, context, source_order, spec):
    item = extract_ipsec_tunnel(element, path, context, source_order, spec)
    manual = element.find("manual-key")
    item.manual_key_configured = manual is not None
    item.proxy_ids = [extract_ipsec_proxy(entry) for entry in element.findall("proxy-id/entry")]
    return item


def extract_dhcp(element, path, context, source_order, spec):
    item = _named(PANDHCPServer, element, path, context, source_order, spec)
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
    "sdwan_traffic_distribution_profile": ("sdwan_traffic_distribution_profiles", extract_named(PANSDWANTrafficDistributionProfile)),
    "sdwan_saas_quality_profile": ("sdwan_saas_quality_profiles", extract_named(PANSDWANSaaSQualityProfile)),
    "sdwan_error_correction_profile": ("sdwan_error_correction_profiles", extract_named(PANSDWANErrorCorrectionProfile)),
    "sdwan_rule": ("sdwan_rules", extract_named(PANSDWANRule)),
    "local_user": ("local_users", extract_named(PANLocalUser, secret_fields=("password_configured",))),
    "local_user_group": ("local_user_groups", extract_named(PANLocalUserGroup)),
    "group_mapping": ("group_mappings", extract_named(PANGroupMapping)),
    "globalprotect_portal": ("globalprotect_portals", extract_named(PANGlobalProtectPortal)),
    "globalprotect_gateway": ("globalprotect_gateways", extract_named(PANGlobalProtectGateway)),
}
