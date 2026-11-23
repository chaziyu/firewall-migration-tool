from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..model import (
    PANAdministrator, PANAdminRole, PANIKECryptoProfile, PANIKEGateway,
    PANIPsecCryptoProfile, PANLocalUser, PANLocalUserGroup, PANGroupMapping,
    PANSDWANErrorCorrectionProfile, PANSDWANInterfaceProfile,
    PANSDWANPathQualityProfile, PANSDWANRule, PANSDWANSaaSQualityProfile,
    PANSDWANTrafficDistributionLink, PANSDWANTrafficDistributionProfile, PANVulnerabilityProfile,
)
from ..model.extended_sections import (
    PANSystemSettings, PANHAConfig, PANDeviceSetupSetting,
    PANQoSRule, PANPBFRule, PANDecryptionRule, PANTunnelInspectRule,
    PANAppOverrideRule, PANAuthenticationRule, PANDoSRule,
    PANApplicationGroup, PANRegion, PANDynamicUserGroup,
    PANHIPObject, PANHIPProfile, PANExternalList, PANCustomURLCategory,
    PANDataPattern, PANCustomThreat,
    PANAntivirusProfile, PANAntiSpywareProfile, PANURLFilteringProfile,
    PANFileBlockingProfile, PANWildFireProfile, PANDataFilteringProfile,
    PANDoSProtectionProfile, PANDecryptionProfile, PANLogForwardingProfile,
    PANAuthenticationProfile, PANAuthenticationSequence,
    PANVLAN, PANVirtualWire, PANGRETunnel, PANDNSProxy,
    PANQoSInterface, PANQoSProfile,
    PANZoneProtectionProfile, PANMonitorProfile, PANLLDPProfile, PANBFDProfile,
    PANGlobalProtectClientlessApp, PANGlobalProtectClientlessAppGroup, PANGlobalProtectMDM,
    PANRadiusServerProfile, PANLDAPServerProfile, PANTACPlusServerProfile,
    PANKerberosServerProfile, PANSAMLIdPServerProfile, PANMFAServerProfile,
    PANCertificate, PANSSLTLSServiceProfile,
    PANSyslogServerProfile, PANEmailServerProfile, PANSNMPTrapServerProfile,
    PANHTTPServerProfile, PANNetflowServerProfile,
    PANPasswordComplexity, PANPasswordProfile, PANUserIDAgent,
    PANDeviceObject, PANSCPServerProfile, PANSSHServerProfile,
    PANUserIDSetting, PANLogSettingCategory,
)
from ..sanitization import sanitize_panos_attributes
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
    if manual is not None and any(node.tag == "key" for node in manual.iter()):
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


def _entry_list_capture(container: ET.Element) -> list[dict[str, Any]]:
    rows = []
    for entry in container.findall("entry"):
        captured = structured_xml_capture(entry)
        row = {"name": entry.get("name")}
        if isinstance(captured, dict):
            row.update(captured)
        elif captured:
            row["value"] = captured
        rows.append(sanitize_panos_attributes(row))
    return rows


def extract_structured(
    cls,
    *,
    dict_fields: dict[str, str] | None = None,
    entry_list_fields: dict[str, str] | None = None,
    secret_fields: tuple[str, ...] = (),
    secret_paths: dict[str, tuple[str, ...]] | None = None,
    rulebase: bool = False,
    default_name: str | None = None,
    static_attrs: dict[str, Any] | None = None,
):
    dict_fields = dict_fields or {}
    entry_list_fields = entry_list_fields or {}

    def extract(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
        item = _named(
            cls, element, path, context, source_order, spec,
            secret_fields=secret_fields, secret_paths=secret_paths,
        )
        if default_name is not None and not item.name:
            item.name = default_name
        if rulebase and "rulebase_position" in cls.model_fields:
            item.rulebase_position = context.rulebase_position
        if static_attrs:
            for attr, val in static_attrs.items():
                if attr in cls.model_fields:
                    setattr(item, attr, val)
        for tag, target in dict_fields.items():
            node = element.find(tag)
            if node is not None and target in cls.model_fields:
                captured = structured_xml_capture(node)
                setattr(item, target, sanitize_panos_attributes(captured) if isinstance(captured, dict) else {"value": sanitize_panos_attributes(captured)})
                item.explicit_fields.add(target)
        for tag, target in entry_list_fields.items():
            node = element.find(tag)
            if node is not None and target in cls.model_fields:
                setattr(item, target, _entry_list_capture(node))
                item.explicit_fields.add(target)
        return item
    return extract


def extract_system_settings(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
    extractor = extract_structured(
        PANSystemSettings,
        default_name="system",
        dict_fields={
            "dns-setting": "dns_setting",
            "ntp-servers": "ntp_servers",
            "service": "service",
            "route": "route",
            "panorama": "panorama",
            "snmp-setting": "snmp_setting",
        },
    )
    item = extractor(element, path, context, source_order, spec)
    type_node = element.find("type")
    if type_node is not None:
        branch = next(iter(type_node), None)
        item.type = branch.tag if branch is not None else _text(type_node)
        item.explicit_fields.add("type")
    perm = element.find("permitted-ip")
    if perm is not None:
        item.permitted_ip = [entry.get("name") or _text(entry) or "" for entry in perm.findall("entry")]
        item.explicit_fields.add("permitted_ip")
    return item


def extract_pbf_rule(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
    item = _named(PANPBFRule, element, path, context, source_order, spec)
    item.rulebase_position = context.rulebase_position
    sym = element.find("enforce-symmetric-return")
    if sym is not None:
        item.enforce_symmetric_return = sanitize_panos_attributes(structured_xml_capture(sym)) if len(sym) else {"enabled": _text(sym)}
        item.explicit_fields.add("enforce_symmetric_return")
    from_node = element.find("from")
    if from_node is not None:
        zones_node = from_node.find("zone")
        if zones_node is not None:
            item.from_zones = [_text(m) or m.get("name") or "" for m in zones_node.findall("member")]
            item.explicit_fields.add("from_zones")
        intf_node = from_node.find("interface")
        if intf_node is not None:
            item.from_interfaces = [_text(m) or m.get("name") or "" for m in intf_node.findall("member")]
            item.explicit_fields.add("from_interfaces")
        from_extra = raw_extra(from_node, {"zone", "interface"})
        if from_extra:
            item.raw_extra["from"] = from_extra
    action_node = element.find("action")
    if action_node is not None:
        branch = next(iter(action_node), None)
        if branch is not None:
            item.action = branch.tag
            item.explicit_fields.add("action")
            if branch.tag == "forward":
                egress = branch.find("egress-interface")
                if egress is not None:
                    item.egress_interface = _text(egress)
                    item.explicit_fields.add("egress_interface")
                nh_node = branch.find("nexthop")
                if nh_node is not None:
                    ip_addr = nh_node.find("ip-address")
                    item.nexthop = _text(ip_addr) if ip_addr is not None else _text(nh_node)
                    item.explicit_fields.add("nexthop")
                fwd_extra = raw_extra(branch, {"egress-interface", "nexthop"})
                if fwd_extra:
                    item.raw_extra["action"] = {"forward": fwd_extra}
        elif _text(action_node):
            item.action = _text(action_node)
            item.explicit_fields.add("action")
    return item


def extract_external_list(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
    item = _named(PANExternalList, element, path, context, source_order, spec, secret_fields=("password_configured",), secret_paths={"password_configured": ("type/*/password", "password")})
    type_node = element.find("type")
    if type_node is not None:
        item.type = sanitize_panos_attributes(structured_xml_capture(type_node))
        item.explicit_fields.add("type")
        branch = next(iter(type_node), None)
        if branch is not None:
            if branch.find("url") is not None:
                item.url = _text(branch.find("url"))
                item.explicit_fields.add("url")
            if branch.find("certificate-profile") is not None:
                item.certificate_profile = _text(branch.find("certificate-profile"))
                item.explicit_fields.add("certificate_profile")
            if branch.find("recurring") is not None:
                item.recurring = sanitize_panos_attributes(structured_xml_capture(branch.find("recurring")))
                item.explicit_fields.add("recurring")
            if branch.find("auth/username") is not None:
                item.username = _text(branch.find("auth/username"))
                item.explicit_fields.add("username")
            if branch.find("auth/password") is not None:
                item.password_configured = True
                item.explicit_fields.add("password_configured")
    return item


def extract_vlan(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
    item = _named(PANVLAN, element, path, context, source_order, spec)
    vi_node = element.find("virtual-interface")
    if vi_node is not None:
        item.virtual_interface = _value(vi_node, "interface") or _text(vi_node)
        item.explicit_fields.add("virtual_interface")
    mac_node = element.find("mac")
    if mac_node is not None:
        item.mac = _entry_list_capture(mac_node)
        item.explicit_fields.add("mac")
    return item


def extract_dns_proxy(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
    item = extract_structured(
        PANDNSProxy,
        dict_fields={"cache": "cache", "tcp-queries": "tcp_queries"},
        entry_list_fields={"domain-servers": "domain_servers"},
    )(element, path, context, source_order, spec)
    default_node = element.find("default")
    if default_node is not None:
        item.default_primary = _value(default_node, "primary")
        item.default_secondary = _value(default_node, "secondary")
        if item.default_primary is not None:
            item.explicit_fields.add("default_primary")
        if item.default_secondary is not None:
            item.explicit_fields.add("default_secondary")
    return item


def extract_mfa_server(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec):
    item = _named(PANMFAServerProfile, element, path, context, source_order, spec, secret_fields=("secret_configured",), secret_paths={"secret_configured": ("mfa-vendor-type/*/secret", "mfa-config/*/secret", "secret")})
    mvt = element.find("mfa-vendor-type")
    if mvt is not None:
        branch = next(iter(mvt), None)
        item.mfa_vendor_type = branch.tag if branch is not None else _text(mvt)
        item.explicit_fields.add("mfa_vendor_type")
    cfg = element.find("mfa-config")
    if cfg is not None:
        item.mfa_config = sanitize_panos_attributes(structured_xml_capture(cfg))
        item.explicit_fields.add("mfa_config")
    return item


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
    "local_user_group": ("local_user_groups", extract_named(PANLocalUserGroup)),
    "local_user_group_compat": ("local_user_groups", extract_named(PANLocalUserGroup)),
    "group_mapping": ("group_mappings", extract_named(PANGroupMapping)),
    "globalprotect_portal": ("globalprotect_portals", extract_portal),
    "globalprotect_gateway": ("globalprotect_gateways", extract_gateway),
    "globalprotect_portal_selected": ("globalprotect_portals", extract_portal),
    "globalprotect_gateway_selected": ("globalprotect_gateways", extract_gateway),
    "system_settings": ("system_settings", extract_system_settings),
    "ha_config": ("ha_configs", extract_structured(PANHAConfig, default_name="high-availability", dict_fields={"mode": "mode", "group": "group", "interface": "interface", "election-option": "election_option", "state-synchronization": "state_synchronization", "monitoring": "monitoring"})),
    "device_setup_setting": ("device_setup_settings", extract_structured(PANDeviceSetupSetting, default_name="setting", dict_fields={"config": "config", "management": "management", "wildfire": "wildfire", "tcp": "tcp", "session": "session", "logging": "logging", "ctd": "ctd", "application": "application", "alarm": "alarm", "user-id-collector": "user_id_collector"})),
    "qos_rule": ("qos_rules", extract_structured(PANQoSRule, rulebase=True, dict_fields={"dscp-marking": "dscp_marking"})),
    "pbf_rule": ("pbf_rules", extract_pbf_rule),
    "decryption_rule": ("decryption_rules", extract_structured(PANDecryptionRule, rulebase=True, dict_fields={"type": "type"})),
    "tunnel_inspect_rule": ("tunnel_inspect_rules", extract_structured(PANTunnelInspectRule, rulebase=True)),
    "app_override_rule": ("app_override_rules", extract_structured(PANAppOverrideRule, rulebase=True)),
    "authentication_rule": ("authentication_rules", extract_structured(PANAuthenticationRule, rulebase=True)),
    "dos_rule": ("dos_rules", extract_structured(PANDoSRule, rulebase=True, dict_fields={"action": "action", "protection": "protection"})),
    "application_group": ("application_groups", extract_named(PANApplicationGroup)),
    "region": ("regions", extract_structured(PANRegion, dict_fields={"geo-location": "geo_location"})),
    "dynamic_user_group": ("dynamic_user_groups", extract_named(PANDynamicUserGroup)),
    "hip_object": ("hip_objects", extract_structured(PANHIPObject, dict_fields={"host-info": "host_info", "network-info": "network_info", "patch-management": "patch_management", "disk-backup": "disk_backup", "disk-encryption": "disk_encryption", "mobile-device": "mobile_device", "certificate": "certificate"})),
    "hip_profile": ("hip_profiles", extract_named(PANHIPProfile)),
    "external_list": ("external_lists", extract_external_list),
    "custom_url_category": ("custom_url_categories", extract_named(PANCustomURLCategory)),
    "data_pattern": ("data_patterns", extract_structured(PANDataPattern, dict_fields={"pattern-type": "pattern_type"})),
    "custom_threat_vulnerability": ("custom_threats", extract_structured(PANCustomThreat, dict_fields={"default-action": "default_action"}, static_attrs={"threat_type": "vulnerability"})),
    "custom_threat_spyware": ("custom_threats", extract_structured(PANCustomThreat, dict_fields={"default-action": "default_action"}, static_attrs={"threat_type": "spyware"})),
    "antivirus_profile": ("antivirus_profiles", extract_structured(PANAntivirusProfile, entry_list_fields={"decoder": "decoders", "application": "applications", "threat-exception": "threat_exceptions"})),
    "anti_spyware_profile": ("anti_spyware_profiles", extract_structured(PANAntiSpywareProfile, dict_fields={"botnet-domains": "botnet_domains"}, entry_list_fields={"rules": "rules", "threat-exception": "threat_exceptions"})),
    "url_filtering_profile": ("url_filtering_profiles", extract_structured(PANURLFilteringProfile, dict_fields={"credential-enforcement": "credential_enforcement"})),
    "file_blocking_profile": ("file_blocking_profiles", extract_structured(PANFileBlockingProfile, entry_list_fields={"rules": "rules"})),
    "wildfire_profile": ("wildfire_profiles", extract_structured(PANWildFireProfile, entry_list_fields={"rules": "rules"})),
    "data_filtering_profile": ("data_filtering_profiles", extract_structured(PANDataFilteringProfile, entry_list_fields={"rules": "rules"})),
    "dos_protection_profile": ("dos_protection_profiles", extract_structured(PANDoSProtectionProfile, dict_fields={"flood": "flood", "resource": "resource"})),
    "decryption_profile": ("decryption_profiles", extract_structured(PANDecryptionProfile, dict_fields={"ssl-forward-proxy": "ssl_forward_proxy", "ssl-inbound-proxy": "ssl_inbound_proxy", "ssl-no-proxy": "ssl_no_proxy", "ssl-protocol-settings": "ssl_protocol_settings", "ssh-proxy": "ssh_proxy"})),
    "log_forwarding_profile": ("log_forwarding_profiles", extract_structured(PANLogForwardingProfile, entry_list_fields={"match-list": "match_list"})),
    "authentication_profile": ("authentication_profiles", extract_structured(PANAuthenticationProfile, dict_fields={"method": "method", "single-sign-on": "single_sign_on", "lockout": "lockout", "multi-factor-auth": "multi_factor_auth"})),
    "authentication_sequence": ("authentication_sequences", extract_named(PANAuthenticationSequence)),
    "vlan": ("vlans", extract_vlan),
    "virtual_wire": ("virtual_wires", extract_structured(PANVirtualWire, dict_fields={"link-state-pass-through": "link_state_pass_through", "multicast-firewalling": "multicast_firewalling"})),
    "gre_tunnel": ("gre_tunnels", extract_structured(PANGRETunnel, dict_fields={"local-address": "local_address", "peer-address": "peer_address", "keep-alive": "keep_alive"})),
    "dns_proxy": ("dns_proxies", extract_dns_proxy),
    "qos_interface": ("qos_interfaces", extract_structured(PANQoSInterface, dict_fields={"regular-traffic": "regular_traffic", "tunnel-traffic": "tunnel_traffic"})),
    "qos_profile": ("qos_profiles", extract_structured(PANQoSProfile, dict_fields={"class-bandwidth-type": "class_bandwidth_type"})),
    "zone_protection_profile": ("zone_protection_profiles", extract_structured(PANZoneProtectionProfile, dict_fields={"flood": "flood"}, entry_list_fields={"scan": "scan"})),
    "monitor_profile": ("monitor_profiles", extract_named(PANMonitorProfile)),
    "lldp_profile": ("lldp_profiles", extract_structured(PANLLDPProfile, dict_fields={"option-tlvs": "option_tlvs"})),
    "bfd_profile": ("bfd_profiles", extract_named(PANBFDProfile)),
    "gp_clientless_app": ("gp_clientless_apps", extract_named(PANGlobalProtectClientlessApp)),
    "gp_clientless_app_group": ("gp_clientless_app_groups", extract_named(PANGlobalProtectClientlessAppGroup)),
    "gp_mdm": ("gp_mdms", extract_named(PANGlobalProtectMDM)),
    "radius_server_profile": ("radius_server_profiles", extract_structured(PANRadiusServerProfile, dict_fields={"protocol": "protocol"}, entry_list_fields={"server": "servers"}, secret_fields=("secret_configured",), secret_paths={"secret_configured": ("server/entry/secret", "secret")})),
    "ldap_server_profile": ("ldap_server_profiles", extract_structured(PANLDAPServerProfile, entry_list_fields={"server": "servers"}, secret_fields=("bind_password_configured",), secret_paths={"bind_password_configured": ("bind-password",)})),
    "tacplus_server_profile": ("tacplus_server_profiles", extract_structured(PANTACPlusServerProfile, entry_list_fields={"server": "servers"}, secret_fields=("secret_configured",), secret_paths={"secret_configured": ("server/entry/secret", "secret")})),
    "kerberos_server_profile": ("kerberos_server_profiles", extract_structured(PANKerberosServerProfile, entry_list_fields={"server": "servers"})),
    "saml_idp_server_profile": ("saml_idp_server_profiles", extract_named(PANSAMLIdPServerProfile)),
    "mfa_server_profile": ("mfa_server_profiles", extract_mfa_server),
    "certificate": ("certificates", extract_named(PANCertificate, secret_fields=("private_key_configured",))),
    "ssl_tls_service_profile": ("ssl_tls_service_profiles", extract_structured(PANSSLTLSServiceProfile, dict_fields={"protocol-settings": "protocol_settings"})),
    "syslog_server_profile": ("syslog_server_profiles", extract_structured(PANSyslogServerProfile, entry_list_fields={"server": "servers"})),
    "email_server_profile": ("email_server_profiles", extract_structured(PANEmailServerProfile, entry_list_fields={"server": "servers"})),
    "snmptrap_server_profile": ("snmptrap_server_profiles", extract_structured(PANSNMPTrapServerProfile, dict_fields={"version": "version"})),
    "http_server_profile": ("http_server_profiles", extract_structured(PANHTTPServerProfile, entry_list_fields={"server": "servers"})),
    "netflow_server_profile": ("netflow_server_profiles", extract_structured(PANNetflowServerProfile, dict_fields={"template-refresh-rate": "template_refresh_rate"}, entry_list_fields={"server": "servers"})),
    "password_complexity": ("password_complexities", extract_structured(PANPasswordComplexity, default_name="password-complexity")),
    "password_profile": ("password_profiles", extract_named(PANPasswordProfile)),
    "user_id_agent": ("user_id_agents", extract_named(PANUserIDAgent)),
    "device_object_shared": ("device_objects", extract_named(PANDeviceObject)),
    "device_object_vsys": ("device_objects", extract_named(PANDeviceObject)),
    "scp_server_profile": ("scp_server_profiles", extract_structured(PANSCPServerProfile, entry_list_fields={"server": "servers"}, secret_fields=("password_configured",), secret_paths={"password_configured": ("password", "server/entry/password")})),
    "ssh_server_profile": ("ssh_server_profiles", extract_structured(PANSSHServerProfile, entry_list_fields={"server": "servers"}, secret_fields=("password_configured",), secret_paths={"password_configured": ("password", "server/entry/password")})),
    "user_identification": ("user_id_settings", lambda el, p, c, o, s: PANUserIDSetting(name="user-identification", setting_type="user-identification", source_path="/".join(p), scope=c.scope, source_order=o, settings=sanitize_panos_attributes(structured_xml_capture(el)) if len(el) else None, raw_extra={}, explicit_fields={"setting_type", "settings"} if len(el) else {"setting_type"})),
    "user_id_collector": ("user_id_settings", lambda el, p, c, o, s: PANUserIDSetting(name="user-id-collector", setting_type="user-id-collector", source_path="/".join(p), scope=c.scope, source_order=o, settings=sanitize_panos_attributes(structured_xml_capture(el)) if len(el) else None, raw_extra={}, explicit_fields={"setting_type", "settings"} if len(el) else {"setting_type"})),
    "log_system_setting": ("log_setting_categories", extract_structured(PANLogSettingCategory, default_name="system", entry_list_fields={"match-list": "match_list"}, static_attrs={"category": "system"})),
    "log_config_setting": ("log_setting_categories", extract_structured(PANLogSettingCategory, default_name="config", entry_list_fields={"match-list": "match_list"}, static_attrs={"category": "config"})),
    "log_threat_setting": ("log_setting_categories", extract_structured(PANLogSettingCategory, default_name="threat", entry_list_fields={"match-list": "match_list"}, static_attrs={"category": "threat"})),
    "log_traffic_setting": ("log_setting_categories", extract_structured(PANLogSettingCategory, default_name="traffic", entry_list_fields={"match-list": "match_list"}, static_attrs={"category": "traffic"})),
    "log_wildfire_setting": ("log_setting_categories", extract_structured(PANLogSettingCategory, default_name="wildfire", entry_list_fields={"match-list": "match_list"}, static_attrs={"category": "wildfire"})),
    "log_userid_setting": ("log_setting_categories", extract_structured(PANLogSettingCategory, default_name="userid", entry_list_fields={"match-list": "match_list"}, static_attrs={"category": "userid"})),
}
EXTRACTORS.update({f"{name}_cli": EXTRACTORS[name] for name in ("sdwan_interface_profile", "sdwan_path_quality_profile", "sdwan_traffic_distribution_profile", "sdwan_saas_quality_profile", "sdwan_error_correction_profile")})
