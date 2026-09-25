from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes

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
from .common import raw_extra, secret_leaf_exists, source_fields, structured_xml_capture
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


_FIELD_ALIASES = {
    "password_configured": ("phash", "password"),
    "group_object_attributes": ("group-object-attributes",), "group_member_attributes": ("group-member-attributes",),
    "group_name_attributes": ("group-name-attributes",), "user_object_attributes": ("user-object-attributes",),
    "user_name_attributes": ("user-name-attributes",), "user_email_attributes": ("user-email-attributes",),
    "group_email_attributes": ("group-email-attributes",), "container_object_attributes": ("container-object-attributes",),
    "ldap_serial_number_check": ("ldap-serial-number-check",), "alternate_username_1": ("alternate-username-1",),
    "alternate_username_2": ("alternate-username-2",), "alternate_username_3": ("alternate-username-3",),
    "last_modify_attribute": ("last-modify-attribute",),
}


def _named(cls, element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec, *, secret_fields=(), secret_paths=None):
    extra, explicit = source_fields(element, spec)
    mapped_fields = {target: source for source, target in spec.field_map.items()}
    explicit.update(field for field, aliases in _FIELD_ALIASES.items() if any(element.find(tag) is not None for tag in aliases))
    explicit = {name.replace("-", "_") for name in explicit if name.replace("-", "_") in cls.model_fields}
    fields = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order,
              "raw_extra": extra, "explicit_fields": explicit}
    for field in cls.model_fields:
        if field in fields or field in {"raw_extra", "explicit_fields", "name", "source_path", "scope", "source_order"}:
            continue
        tags = tuple(tag for tag in dict.fromkeys((mapped_fields.get(field), *_FIELD_ALIASES.get(field, ()), {"pre_shared_key_configured": "pre-shared-key"}.get(field), field.replace("_", "-"))) if tag)
        if field in secret_fields:
            paths = (secret_paths or {}).get(field, tags)
            present = secret_leaf_exists(element, *paths)
            fields[field] = True if present else None
            if present:
                explicit.add(field)
        else:
            for tag in tags:
                if not tag:
                    continue
                value = _value(element, tag)
                if value is not None and not isinstance(value, dict):
                    fields[field] = value
                    break
    return cls(**fields)


def extract_named(cls, *, secret_fields=()):
    def extract(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
        return _named(cls, element, path, context, source_order, spec, secret_fields=secret_fields)
    return extract


def extract_ike_gateway(element, path, context, source_order, spec):
    item = _named(PANIKEGateway, element, path, context, source_order, spec, secret_fields=("pre_shared_key_configured",))
    item.explicit_fields.discard("authentication")
    paths = {
        "local_interface": ("local-address/interface",), "local_ip": ("local-address/ip",),
        "ike_version": ("protocol/version",),
        "ikev1_exchange_mode": ("protocol/ikev1/exchange-mode",),
        "ikev1_crypto_profile": ("protocol/ikev1/ike-crypto-profile",),
        "ikev2_crypto_profile": ("protocol/ikev2/ike-crypto-profile",),
        "ikev2_require_cookie": ("protocol/ikev2/require-cookie",),
        "ikev1_dpd_enabled": ("protocol/ikev1/dpd/enable",),
        "ikev1_dpd_interval": ("protocol/ikev1/dpd/interval",),
        "ikev1_dpd_retry": ("protocol/ikev1/dpd/retry",),
        "ikev2_dpd_enabled": ("protocol/ikev2/dpd/enable",),
        "ikev2_dpd_interval": ("protocol/ikev2/dpd/interval",),
        "nat_traversal": ("protocol-common/nat-traversal/enable",),
        "nat_traversal_keepalive": ("protocol-common/nat-traversal/keep-alive-interval",),
        "nat_traversal_udp_checksum": ("protocol-common/nat-traversal/udp-checksum-enable",),
        "passive_mode": ("protocol-common/passive-mode",),
        "fragmentation": ("protocol-common/fragmentation/enable",),
    }
    for field, alternatives in paths.items():
        for source_path in alternatives:
            if element.find(source_path) is not None:
                setattr(item, field, _value(element, source_path))
                item.explicit_fields.add(field)
                break
    peer = element.find("peer-address")
    if peer is not None:
        branch = next(iter(peer), None)
        if branch is not None:
            item.peer_address_type = branch.tag
            item.peer_address = _text(branch)
            item.explicit_fields.update({"peer_address_type", "peer_address"})
    authentication = element.find("authentication")
    if authentication is not None:
        item.raw_extra["authentication"] = sanitize_source_attributes(structured_xml_capture(authentication))
        branch = next(iter(authentication), None)
        if branch is not None:
            item.authentication_method = branch.tag
            item.explicit_fields.add("authentication_method")
    for field, tag in (("local_id", "local-id"), ("peer_id", "peer-id")):
        node = element.find(tag)
        if node is not None:
            if len(node) == 0:
                setattr(item, field, _text(node))
                item.explicit_fields.add(field)
            else:
                item.raw_extra[tag] = sanitize_source_attributes(structured_xml_capture(node))
    if any(element.find(source_path) is not None for source_path in ("pre-shared-key", "authentication/pre-shared-key", "authentication/pre-shared-key/key")):
        item.pre_shared_key_configured = True
        item.explicit_fields.add("pre_shared_key_configured")
    return item


def extract_ike_crypto(element, path, context, source_order, spec):
    item = _named(PANIKECryptoProfile, element, path, context, source_order, spec)
    for field, tag in (("encryption_algorithms", "encryption"), ("authentication_algorithms", "authentication"), ("dh_groups", "dh-group")):
        node = element.find(tag)
        if node is not None:
            setattr(item, field, [_text(member) or "" for member in node.findall("member")])
            item.explicit_fields.add(field)
    lifetime = element.find("lifetime")
    branch = next(iter(lifetime), None) if lifetime is not None else None
    if branch is not None:
        item.lifetime_unit, item.lifetime_value = branch.tag, _text(branch)
        item.explicit_fields.update({"lifetime_unit", "lifetime_value"})
    if element.find("authentication-multiple") is not None:
        item.authentication_multiple = _value(element, "authentication-multiple")
        item.explicit_fields.add("authentication_multiple")
    return item


def extract_ipsec_crypto(element, path, context, source_order, spec):
    item = _named(PANIPsecCryptoProfile, element, path, context, source_order, spec)
    for field, tag in (("esp_encryption", "esp/encryption"), ("esp_authentication", "esp/authentication"), ("ah_authentication", "ah/authentication")):
        node = element.find(tag)
        if node is not None:
            setattr(item, field, [_text(member) or "" for member in node.findall("member")])
            item.explicit_fields.add(field)
    for field, tag in (("dh_group", "dh-group"), ("protocol", "protocol")):
        node = element.find(tag)
        if node is not None and len(node) == 0:
            setattr(item, field, _text(node))
            item.explicit_fields.add(field)
        elif node is not None:
            item.raw_extra[tag] = sanitize_source_attributes(structured_xml_capture(node))
    lifetime = element.find("lifetime")
    branch = next(iter(lifetime), None) if lifetime is not None else None
    if branch is not None:
        item.lifetime_unit, item.lifetime_value = branch.tag, _text(branch)
        item.explicit_fields.update({"lifetime_unit", "lifetime_value"})
    return item


def extract_vulnerability(element, path, context, source_order, spec):
    item = _named(PANVulnerabilityProfile, element, path, context, source_order, spec)
    for child_tag, model in (("rules", PANVulnerabilityRule), ("threat-exception", PANVulnerabilityException), ("exceptions", PANVulnerabilityException)):
        if child_tag == "exceptions" and element.find("threat-exception") is not None:
            continue
        child = element.find(child_tag)
        if child is None:
            continue
        entries = []
        field_name = "exceptions" if child_tag != "rules" else "rules"
        setattr(item, field_name, entries)
        for entry in child.findall("entry"):
            exception = child_tag != "rules"
            known = {"threat-name", "host", "vendor-id", "severity", "category", "action", "packet-capture"}
            if exception:
                known.update({"time-interval", "time-threshold", "time-track-by", "time-attribute", "exempt-ips", "exempt-ip"})
            extra = raw_extra(entry, known)
            fields = ("threat_name", "host", "category", "packet_capture")
            data = {field: _value(entry, field.replace("_", "-")) for field in fields}
            if exception:
                time_attribute = entry.find("time-attribute")
                if time_attribute is not None:
                    data.update(time_interval=_value(time_attribute, "interval"), time_threshold=_value(time_attribute, "threshold"), time_track_by=_value(time_attribute, "track-by"))
                    time_extra = raw_extra(time_attribute, {"interval", "threshold", "track-by"})
                    if time_extra:
                        extra["time-attribute"] = time_extra
                for field, tag in (("time_interval", "time-interval"), ("time_threshold", "time-threshold"), ("time_track_by", "time-track-by")):
                    data[field] = data.get(field) or _value(entry, tag)
            data["vendor_ids"] = _value(entry, "vendor-id")
            data["severities"] = _value(entry, "severity")
            action = entry.find("action")
            branch = next(iter(action), None) if action is not None else None
            if branch is not None:
                data["action"] = branch.tag
            elif action is not None:
                data["action"] = _text(action)
            block_ip = action.find("block-ip") if action is not None else None
            if block_ip is not None:
                data["block_ip"] = _extract_block_ip(block_ip)
            if action is not None:
                action_extra = raw_extra(action, {branch.tag} if branch is not None and branch.tag in {"default", "allow", "alert", "drop", "reset-client", "reset-server", "reset-both", "block-ip"} else set())
                if action_extra:
                    extra["action"] = action_extra
            if exception:
                data["exempt_ips"] = _exempt_ips(entry)
            data = {key: value for key, value in data.items() if value is not None}
            data["name"] = entry.get("name")
            data["raw_extra"] = extra
            explicit_map = {"vendor-id": "vendor_ids", "severity": "severities", "exempt-ip": "exempt_ips", "exempt-ips": "exempt_ips"}
            data["explicit_fields"] = {explicit_map.get(child.tag, child.tag.replace("-", "_")) for child in entry if child.tag in known and child.tag != "time-attribute"}
            if exception:
                time_attribute = entry.find("time-attribute")
                if time_attribute is not None:
                    data["explicit_fields"].update(f"time_{field.replace('-', '_')}" for field in ("interval", "threshold", "track-by") if time_attribute.find(field) is not None)
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
    role = element.find("role")
    if role is not None:
        item.permissions = []
        known_scopes = {"device", "panorama", "device-group"}
        known_channels = {"webui", "xmlapi", "restapi", "cli"}
        unknown = {}
        for scope in role:
            if scope.tag not in known_scopes:
                unknown[scope.tag] = sanitize_source_attributes(structured_xml_capture(scope))
                continue
            if item.role_scope is None:
                item.role_scope = scope.tag
                item.explicit_fields.add("role_scope")
            elif item.role_scope != scope.tag:
                unknown[scope.tag] = sanitize_source_attributes(structured_xml_capture(scope))
                continue
            for channel in scope:
                if channel.tag not in known_channels:
                    unknown.setdefault(scope.tag, {})[channel.tag] = sanitize_source_attributes(structured_xml_capture(channel))
                    continue
                def walk(node, parents=()):
                    if not len(node):
                        value = _text(node)
                        if value is not None:
                            item.permissions.append(PANAdminRolePermission(channel=channel.tag, permission_path="/".join(parents) or None, setting=node.tag, value=value))
                        else:
                            unknown.setdefault(scope.tag, {}).setdefault(channel.tag, {})[node.tag] = value
                        return
                    for child in node:
                        walk(child, (*parents, node.tag))
                for leaf in channel:
                    walk(leaf)
        if unknown:
            item.raw_extra["role"] = unknown
        item.explicit_fields.add("permissions")
        return item
    section = element.find("permissions")
    if section is None:
        return item
    item.permissions = []
    for entry in section.findall("entry"):
        item.permissions.append(PANAdminRolePermission(
            channel=_value(entry, "channel"), permission_path=_value(entry, "permission-path"), setting=_value(entry, "setting"), value=_value(entry, "value")))
    return item


def extract_administrator(element, path, context, source_order, spec):
    item = _named(PANAdministrator, element, path, context, source_order, spec, secret_fields=("password_configured",), secret_paths={"password_configured": ("password", "phash")})
    role_based = element.find("permissions/role-based")
    if role_based is None:
        return item
    for branch in role_based:
        if branch.tag in {"devicereader", "deviceadmin", "superreader", "superuser"}:
            item.role_type = "built-in"
            item.built_in_role = branch.tag
            item.explicit_fields.update({"role_type", "built_in_role"})
        elif branch.tag == "custom":
            item.role_type = "custom"
            item.explicit_fields.add("role_type")
            item.raw_extra["permissions"] = {"role-based": {"custom": sanitize_source_attributes(structured_xml_capture(branch))}}
        elif branch.tag == "role-type":
            item.role_type = _text(branch)
            item.explicit_fields.add("role_type")
    return item


def extract_ipsec_proxy(element):
    protocol, protocol_number, nested_local_port, nested_remote_port, protocol_extra = _extract_proxy_protocol(element.find("protocol"))
    extra = raw_extra(element, {"address-family", "local", "remote", "protocol", "protocol-number", "local-port", "remote-port"})
    if protocol_extra:
        extra["protocol"] = protocol_extra
    explicit = {child.tag.replace("-", "_") for child in element if child.tag in {"address-family", "local", "remote", "protocol", "protocol-number", "local-port", "remote-port"}}
    if protocol_number is not None:
        explicit.add("protocol_number")
    if nested_local_port is not None:
        explicit.add("local_port")
    if nested_remote_port is not None:
        explicit.add("remote_port")
    return PANIPsecProxyID(
        name=element.get("name"), address_family=_value(element, "address-family"),
        local=_proxy_value(element, "local"), remote=_proxy_value(element, "remote"),
        protocol=protocol if element.find("protocol") is not None and len(element.find("protocol")) else _proxy_value(element, "protocol"),
        protocol_number=protocol_number or _proxy_value(element, "protocol-number"),
        local_port=nested_local_port or _proxy_value(element, "local-port"), remote_port=nested_remote_port or _proxy_value(element, "remote-port"),
        raw_extra=extra,
        explicit_fields=explicit,
    )


def _extract_proxy_protocol(node):
    if node is None:
        return None, None, None, None, {}
    branch = next(iter(node), None)
    if branch is None:
        return _text(node), None, None, None, {}
    if branch.tag in {"tcp", "udp"}:
        branch_extra = raw_extra(branch, {"local-port", "remote-port"})
        extra = {branch.tag: branch_extra} if branch_extra else {}
        return branch.tag, None, _value(branch, "local-port"), _value(branch, "remote-port"), extra
    if branch.tag == "any":
        return "any", None, None, None, raw_extra(branch, set())
    if branch.tag == "number":
        return None, _text(branch), None, None, {}
    return None, None, None, None, {branch.tag: structured_xml_capture(branch)}


def _proxy_value(element, tag):
    value = _value(element, tag)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def extract_ipsec(element, path, context, source_order, spec):
    item = extract_ipsec_tunnel(element, path, context, source_order, spec)
    manual = element.find("manual-key")
    if manual is not None:
        item.manual_key_configured = True
        item.explicit_fields.add("manual_key_configured")
    auto_key = element.find("auto-key")
    proxy_ids = []
    for family, tag in (("ipv4", "proxy-id"), ("ipv6", "proxy-id-v6")):
        for entry in auto_key.findall(f"{tag}/entry") if auto_key is not None else ():
            proxy = extract_ipsec_proxy(entry)
            if proxy.address_family is None:
                proxy.address_family = family
            proxy_ids.append(proxy)
    item.proxy_ids = proxy_ids or None
    return item


def extract_traffic_distribution(element, path, context, source_order, spec):
    item = _named(PANSDWANTrafficDistributionProfile, element, path, context, source_order, spec)
    if element.find("traffic-distribution") is not None:
        item.distribution_mode = _value(element, "traffic-distribution")
        item.explicit_fields.add("distribution_mode")
    section = element.find("link-tags")
    if section is None:
        section = element.find("link")
    if section is None:
        return item
    item.links = []
    item.explicit_fields.add("links")
    for entry in section.findall("entry"):
        known = {"link-tag", "weight"}
        item.links.append(PANSDWANTrafficDistributionLink(
            link_tag=_value(entry, "link-tag") or entry.get("name"),
            weight=_value(entry, "weight"),
            raw_extra=raw_extra(entry, known),
            explicit_fields={child.tag.replace("-", "_") for child in entry if child.tag in known} | ({"link_tag"} if entry.get("name") else set()),
        ))
    return item


def extract_path_quality(element, path, context, source_order, spec):
    item = _named(PANSDWANPathQualityProfile, element, path, context, source_order, spec)
    for metric, prefix in (("latency", "latency"), ("pkt-loss", "packet_loss"), ("jitter", "jitter")):
        for leaf in ("threshold", "sensitivity"):
            source_path = f"metric/{metric}/{leaf}"
            if element.find(source_path) is not None:
                field = f"{prefix}_{leaf}"
                setattr(item, field, _value(element, source_path))
                item.explicit_fields.add(field)
    return item


def extract_sdwan_rule(element, path, context, source_order, spec):
    item = _named(PANSDWANRule, element, path, context, source_order, spec)
    item.rulebase_position = context.rulebase_position
    for field, source_path in (("traffic_distribution_profile", "action/traffic-distribution-profile"), ("nat_session_failover_action", "action/app-failover-for-nat-sessions")):
        if element.find(source_path) is not None:
            setattr(item, field, _value(element, source_path))
            item.explicit_fields.add(field)
    return item


def extract_sdwan_mode(cls):
    def extract(element, path, context, source_order, spec):
        item = _named(cls, element, path, context, source_order, spec)
        mode = element.find("monitor-mode" if cls is PANSDWANSaaSQualityProfile else "mode")
        branch = next(iter(mode), None) if mode is not None else None
        if branch is not None:
            field = "monitor_mode" if cls is PANSDWANSaaSQualityProfile else "mode"
            setattr(item, field, branch.tag)
            item.explicit_fields.add(field)
            item.raw_extra[mode.tag] = raw_extra(mode, set())
        return item
    return extract


EXTRACTORS = {
    "vulnerability_profile": ("vulnerability_profiles", extract_vulnerability),
    "administrator": ("administrators", extract_administrator),
    "administrator_mgt_config": ("administrators", extract_administrator),
    "admin_role": ("admin_roles", extract_admin_role),
    "ike_gateway": ("ike_gateways", extract_ike_gateway),
    "ike_crypto_profile": ("ike_crypto_profiles", extract_ike_crypto),
    "ipsec_crypto_profile": ("ipsec_crypto_profiles", extract_ipsec_crypto),
    "ipsec_tunnel": ("ipsec_tunnels", extract_ipsec),
    "dhcp_server": ("dhcp_servers", extract_dhcp),
    "sdwan_interface_profile": ("sdwan_interface_profiles", extract_named(PANSDWANInterfaceProfile)),
    "sdwan_path_quality_profile": ("sdwan_path_quality_profiles", extract_path_quality),
    "sdwan_traffic_distribution_profile": ("sdwan_traffic_distribution_profiles", extract_traffic_distribution),
    "sdwan_saas_quality_profile": ("sdwan_saas_quality_profiles", extract_sdwan_mode(PANSDWANSaaSQualityProfile)),
    "sdwan_error_correction_profile": ("sdwan_error_correction_profiles", extract_sdwan_mode(PANSDWANErrorCorrectionProfile)),
    "sdwan_rule": ("sdwan_rules", extract_sdwan_rule),
    "local_user": ("local_users", extract_named(PANLocalUser, secret_fields=("password_configured",))),
    "local_user_database_compat": ("local_users", extract_named(PANLocalUser, secret_fields=("password_configured",))),
    "local_user_group": ("local_user_groups", extract_named(PANLocalUserGroup)),
    "local_user_group_compat": ("local_user_groups", extract_named(PANLocalUserGroup)),
    "group_mapping": ("group_mappings", extract_named(PANGroupMapping)),
    "globalprotect_portal": ("globalprotect_portals", extract_portal),
    "globalprotect_gateway": ("globalprotect_gateways", extract_gateway),
    "globalprotect_portal_selected": ("globalprotect_portals", extract_portal),
    "globalprotect_gateway_selected": ("globalprotect_gateways", extract_gateway),
}
EXTRACTORS.update({f"{name}_cli": EXTRACTORS[name] for name in ("sdwan_interface_profile", "sdwan_path_quality_profile", "sdwan_traffic_distribution_profile", "sdwan_saas_quality_profile", "sdwan_error_correction_profile")})
