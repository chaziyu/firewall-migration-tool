"""Source-only extraction for PAN-OS GlobalProtect configuration."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Any, Optional

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import (
    IRGlobalProtectAppSetting, IRGlobalProtectClientAuthentication,
    IRGlobalProtectExternalGateway, IRGlobalProtectGateway,
    IRGlobalProtectGatewayPriorityRule, IRGlobalProtectGatewayRole,
    IRGlobalProtectNetworkGateway, IRGlobalProtectPortal,
    IRGlobalProtectPortalClientConfig, IRGlobalProtectPortalRootCA,
    IRGlobalProtectRemoteUserTunnelConfig,
)

from .extraction import record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope, PANSourceObject
from .xml_utils import member_texts, structured_xml_capture, text_or_none


def _scope_context(scope: PANScope) -> str:
    return f"{scope.kind}:{scope.name}:device:{scope.device_serial}" if scope.device_serial else f"{scope.kind}:{scope.name}"


def _scope_attributes(scope: PANScope) -> dict[str, Any]:
    attrs = {"pan_scope_kind": scope.kind, "pan_scope_name": scope.name}
    if scope.device_serial:
        attrs["pan_scope_device_serial"] = scope.device_serial
    if scope.device_name:
        attrs["pan_scope_device_name"] = scope.device_name
    if scope.vsys:
        attrs["pan_scope_vsys"] = scope.vsys
    return attrs


def _safe_capture(node: Optional[ET.Element]) -> dict[str, Any]:
    return sanitize_source_attributes({"pan_source_entry": structured_xml_capture(node)}) if node is not None else {}


def _first_text(node: Optional[ET.Element], *paths: str) -> Optional[str]:
    for path in paths:
        value = text_or_none(node, path)
        if value is not None:
            return value
    return None


def _members(node: Optional[ET.Element], *paths: str) -> list[str]:
    for path in paths:
        values = member_texts(node, path)
        if values:
            return values
    return []


def _values(node: Optional[ET.Element], *paths: str) -> list[str]:
    for path in paths:
        values = member_texts(node, path) or member_texts(node, f"{path}/member")
        if values:
            return values
        entries = node.findall(f"{path}/entry") if node is not None else []
        values = [entry.get("name") or (entry.text or "").strip() for entry in entries]
        values = [value for value in values if value]
        if values:
            return values
    for path in paths:
        value = text_or_none(node, path)
        if value is not None:
            return [value]
    return []


def _strict_yes_no(node: Optional[ET.Element], *paths: str) -> tuple[Optional[bool], Optional[str]]:
    value = _first_text(node, *paths, *(f"{path}/{suffix}" for path in paths for suffix in ("enabled", "enable", "value")))
    if value is None:
        return None, None
    if value.lower() in {"yes", "no"}:
        return value.lower() == "yes", None
    return None, f"malformed-yes-no:{value}"


def _int_value(node: Optional[ET.Element], field: str, *paths: str) -> tuple[Optional[int], Optional[str]]:
    value = _first_text(node, *paths)
    if value is None:
        return None, None
    try:
        return int(value), None
    except ValueError:
        return None, f"malformed-{field}:{value}"


def _record_object(extraction, domain: str, path: str, scope: PANScope, name: Optional[str], attrs: dict[str, Any], notes: list[str]) -> None:
    if name:
        record_extract_only(extraction, domain, path, scope, name, attrs, notes, requires_manual_review=True)
    else:
        record_parse_error(extraction, domain, path, scope, attributes=attrs, notes=["PAN-OS GlobalProtect object is missing its required name.", *notes])


def _register(resolver, name: str, kind: str, path: str, scope: PANScope, item: Any) -> None:
    resolver.register_object(PANSourceObject(name=name, kind=kind, domain="global-protect", source_path=path, scope=scope, ir_object=item), kind)


def _client_auth(parent: ET.Element, scope: PANScope, owner: str, extraction) -> tuple[list[IRGlobalProtectClientAuthentication], list[str]]:
    entries = (
        parent.findall("./client-auth/entry")
        or parent.findall("./client-authentication/entry")
        or parent.findall("./authentication/client-auth/entry")
    )
    result: list[IRGlobalProtectClientAuthentication] = []
    reasons: list[str] = []
    for entry in entries:
        name = entry.get("name")
        os_values = _values(entry, "./os", "./operating-system", "./operating-systems")
        attrs = {**_safe_capture(entry), **_scope_attributes(scope)}
        item_reasons: list[str] = []
        item = IRGlobalProtectClientAuthentication(
            name=name or "<unnamed>", os=", ".join(os_values) if os_values else None,
            authentication_profile=_first_text(entry, "./authentication-profile"),
            authentication_message=_first_text(entry, "./authentication-message", "./message"),
            username_label=_first_text(entry, "./username-label"),
            password_label=_first_text(entry, "./password-label"),
            review_reasons=item_reasons, source_attributes=sanitize_source_attributes(attrs),
        )
        if not name:
            item_reasons.append("missing-name")
        result.append(item)
        path = f"{owner}/client-auth/entry" if owner else "global-protect/client-auth/entry"
        _record_object(extraction, "global-protect/client-auth", path, scope, name, attrs, item_reasons)
    return result, reasons


def _validate_ip_pool(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return True
        if "-" in value:
            start_text, end_text = (part.strip() for part in value.split("-", 1))
            start, end = ipaddress.ip_address(start_text), ipaddress.ip_address(end_text)
            return start.version == end.version and int(start) <= int(end)
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _literal_or_address_reference(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_priority_rules(node: ET.Element, scope: PANScope, owner_reasons: list[str]) -> list[IRGlobalProtectGatewayPriorityRule]:
    entries = node.findall("./priority-rule/entry") or node.findall("./priority-rules/entry")
    result = []
    for entry in entries:
        name = entry.get("name") or "priority"
        priority, reason = _int_value(entry, "priority", "./priority")
        attrs = {**_safe_capture(entry), **_scope_attributes(scope)}
        if reason:
            owner_reasons.append(reason)
            attrs["pan_malformed_priority"] = _first_text(entry, "./priority")
        result.append(IRGlobalProtectGatewayPriorityRule(name=name, priority=priority, source_attributes=attrs))
    return result


def _parse_external_gateway(node: ET.Element, scope: PANScope, owner_reasons: list[str]) -> IRGlobalProtectExternalGateway:
    name = node.get("name") or "<unnamed>"
    manual, reason = _strict_yes_no(node, "./manual")
    if reason:
        owner_reasons.append(reason)
    attrs = {**_safe_capture(node), **_scope_attributes(scope)}
    return IRGlobalProtectExternalGateway(
        name=name,
        ipv4=_first_text(node, "./ipv4", "./ip-address/ipv4"),
        ipv6=_first_text(node, "./ipv6", "./ip-address/ipv6"),
        manual=manual,
        priority_rules=_parse_priority_rules(node, scope, owner_reasons),
        source_attributes=attrs,
    )


def _parse_app_settings(node: ET.Element, scope: PANScope, owner_reasons: list[str]) -> list[IRGlobalProtectAppSetting]:
    result = []
    entries = node.findall("./gp-app-config/entry")
    for order, entry in enumerate(entries):
        name = entry.get("name") or "<unnamed>"
        values = _values(entry, "./value", "./values/member", "./member")
        if not values and text_or_none(entry, ".") is not None:
            values = [text_or_none(entry, ".") or ""]
        safe_values = sanitize_source_attributes({name: values}).get(name, values)
        if isinstance(safe_values, str):
            safe_values = [safe_values]
        attrs = {**_safe_capture(entry), **_scope_attributes(scope)}
        result.append(IRGlobalProtectAppSetting(name=name, values=safe_values, source_order=order, source_attributes=attrs))
    return result


def _parse_portal_client_config(node: ET.Element, scope: PANScope, extraction, portal_name: str) -> IRGlobalProtectPortalClientConfig:
    reasons: list[str] = []
    external_nodes = node.findall("./external-gateway/entry") or node.findall("./external-gateways/entry")
    external_gateways = [_parse_external_gateway(item, scope, reasons) for item in external_nodes]
    generate_cookie, reason = _strict_yes_no(node, "./authentication-override/generate-cookie")
    if reason: reasons.append(reason)
    hip_collect, reason = _strict_yes_no(node, "./hip-collection/collect-data", "./hip-collect-data")
    if reason: reasons.append(reason)
    parsed_ints: dict[str, Optional[int]] = {}
    for field, paths in {
        "max_agent_user_overrides": ("./agent-user-override/max-agent-user-overrides", "./max-agent-user-overrides"),
        "agent_user_override_timeout": ("./agent-user-override/timeout", "./agent-user-override-timeout"),
        "hip_max_wait_time": ("./hip-collection/max-wait-time", "./hip-max-wait-time"),
        "mdm_enrollment_port": ("./mdm-enrollment-port",),
    }.items():
        parsed_ints[field], reason = _int_value(node, field, *paths)
        if reason:
            reasons.append(reason)
    values: dict[str, Any] = {
        "name": node.get("name") or "<unnamed>",
        "source_users": _values(node, "./source-user", "./source-users"),
        "operating_systems": _values(node, "./os", "./operating-system", "./operating-systems"),
        "external_gateways": external_gateways,
        "external_gateway_cutoff_time": _first_text(node, "./external-gateway-priority-cutoff-time", "./external-gateway-cutoff-time"),
        "authentication_override_generate_cookie": generate_cookie,
        "max_agent_user_overrides": parsed_ints["max_agent_user_overrides"],
        "agent_user_override_timeout": parsed_ints["agent_user_override_timeout"],
        "hip_collect_data": hip_collect,
        "hip_max_wait_time": parsed_ints["hip_max_wait_time"],
        "app_settings": _parse_app_settings(node, scope, reasons),
        "portal_2fa": _strict_yes_no(node, "./portal-2fa")[0],
        "manual_only_gateway_2fa": _strict_yes_no(node, "./manual-only-gateway-2fa")[0],
        "internal_gateway_2fa": _strict_yes_no(node, "./internal-gateway-2fa")[0],
        "auto_discovery_external_gateway_2fa": _strict_yes_no(node, "./auto-discovery-external-gateway-2fa")[0],
        "mdm_enrollment_port": parsed_ints["mdm_enrollment_port"],
    }
    for field, paths in {
        "portal_2fa": ("./portal-2fa",),
        "manual_only_gateway_2fa": ("./manual-only-gateway-2fa",),
        "internal_gateway_2fa": ("./internal-gateway-2fa",),
        "auto_discovery_external_gateway_2fa": ("./auto-discovery-external-gateway-2fa",),
    }.items():
        _, reason = _strict_yes_no(node, *paths)
        if reason: reasons.append(reason)
    save = _first_text(node, "./save-user-credentials")
    if save is not None:
        try: values["save_user_credentials"] = int(save)
        except ValueError: values["save_user_credentials"] = save
    attrs = {**_safe_capture(node), **_scope_attributes(scope)}
    values.update(review_reasons=reasons, source_attributes=attrs)
    item = IRGlobalProtectPortalClientConfig(**values)
    path = f"global-protect/portal-client-config/entry"
    _record_object(extraction, "global-protect/portal-client-config", path, scope, node.get("name"), attrs, reasons)
    return item


def _parse_portal(entry: ET.Element, scope: PANScope, extraction, resolver) -> Optional[IRGlobalProtectPortal]:
    name = entry.get("name")
    path = f"global-protect/global-protect-portal/entry"
    attrs = {**_safe_capture(entry), **_scope_attributes(scope)}
    if not name:
        _record_object(extraction, "global-protect/global-protect-portal", path, scope, None, attrs, [])
        return None
    config = entry.find("./portal-config")
    if config is None:
        config = entry
    reasons: list[str] = []
    client_auth, _ = _client_auth(config, scope, "global-protect/global-protect-portal/entry", extraction)
    client_config_root = config.find("./client-config")
    client_configs = [_parse_portal_client_config(item, scope, extraction, name) for item in (client_config_root.findall("./entry") if client_config_root is not None else config.findall("./client-config/entry"))]
    root_ca_root = config.find("./root-ca")
    if root_ca_root is None:
        root_ca_root = config.find("./root-ca-certificates")
    root_cas: list[IRGlobalProtectPortalRootCA] = []
    for ca in root_ca_root.findall("./entry") if root_ca_root is not None else []:
        certificate = _first_text(ca, "./certificate") or ca.get("name")
        if not certificate:
            reasons.append("missing-root-ca-certificate")
            continue
        install, reason = _strict_yes_no(ca, "./install-in-cert-store")
        if reason: reasons.append(reason)
        root_cas.append(IRGlobalProtectPortalRootCA(certificate=certificate, install_in_cert_store=install,
            review_reasons=[reason] if reason else [], source_attributes={**_safe_capture(ca), **_scope_attributes(scope)}))
    local = config.find("./local-address")
    local_ipv4 = _first_text(local, "./ip/ipv4", "./ipv4")
    local_ipv6 = _first_text(local, "./ip/ipv6", "./ipv6")
    portal = IRGlobalProtectPortal(
        name=name, source_context=_scope_context(scope),
        local_interface=_first_text(local, "./interface") if local is not None else None,
        local_ipv4=local_ipv4, local_ipv6=local_ipv6,
        ssl_tls_service_profile=_first_text(config, "./ssl-tls-service-profile"),
        custom_login_page=_first_text(config, "./custom-login-page"),
        custom_home_page=_first_text(config, "./custom-home-page"),
        client_authentication=client_auth, client_configs=client_configs, root_ca_certificates=root_cas,
        has_agent_user_override_key=entry.find("./agent-user-override-key") is not None,
        review_reasons=reasons, source_attributes=attrs,
    )
    extraction.canonical_ir.global_protect_portals.append(portal)
    _unsupported_children(config, {
        "local-address", "ssl-tls-service-profile", "custom-login-page", "custom-home-page",
        "client-auth", "client-authentication", "client-config", "root-ca", "root-ca-certificates",
    }, "global-protect/global-protect-portal/entry/portal-config", scope, extraction)
    _unsupported_children(entry, {"agent-user-override-key", "portal-config"}, "global-protect/global-protect-portal/entry", scope, extraction)
    _register(resolver, name, "globalprotect-portal", path, scope, portal)
    _record_object(extraction, "global-protect/global-protect-portal", path, scope, name, attrs, reasons)
    return portal


def _parse_role(entry: ET.Element, scope: PANScope, owner_reasons: list[str]) -> IRGlobalProtectGatewayRole:
    values = {}
    for field, paths in {
        "login_lifetime_days": ("./login-lifetime", "./login-lifetime-days"),
        "inactivity_logout_hours": ("./inactivity-logout", "./inactivity-logout-hours"),
        "disconnect_on_idle_minutes": ("./disconnect-on-idle", "./disconnect-on-idle-minutes"),
    }.items():
        value, reason = _int_value(entry, field, *paths)
        values[field] = value
        if reason: owner_reasons.append(reason)
    return IRGlobalProtectGatewayRole(name=entry.get("name") or "<unnamed>", **values,
        source_attributes={**_safe_capture(entry), **_scope_attributes(scope)})


def _parse_remote_tunnel(entry: ET.Element, scope: PANScope, extraction) -> IRGlobalProtectRemoteUserTunnelConfig:
    reasons: list[str] = []
    pools = _values(entry, "./ip-pool", "./ip-pools")
    for pool in pools:
        if not _validate_ip_pool(pool):
            reasons.append(f"malformed-ip-pool:{pool}")
    includes = _values(entry, "./split-tunnel/access-route", "./split-tunnel/access-routes", "./access-route")
    excludes = _values(entry, "./split-tunnel/exclude-route", "./split-tunnel/exclude-routes", "./exclude-route")
    framed, reason = _strict_yes_no(entry, "./retrieve-framed-ip-address")
    if reason: reasons.append(reason)
    direct, reason = _strict_yes_no(entry, "./no-direct-access-to-local-network")
    if reason: reasons.append(reason)
    item = IRGlobalProtectRemoteUserTunnelConfig(
        name=entry.get("name") or "<unnamed>",
        source_users=_values(entry, "./source-user", "./source-users"),
        operating_systems=_values(entry, "./os", "./operating-system", "./operating-systems"),
        ip_pools=pools, split_include_routes=includes, split_exclude_routes=excludes,
        retrieve_framed_ip_address=framed, no_direct_access_to_local_network=direct,
        review_reasons=reasons, source_attributes={**_safe_capture(entry), **_scope_attributes(scope)},
    )
    _record_object(extraction, "global-protect/remote-user-tunnel-config", "global-protect/remote-user-tunnel-config/entry", scope, entry.get("name"), item.source_attributes, reasons)
    return item


def _parse_gateway(entry: ET.Element, scope: PANScope, extraction, resolver) -> Optional[IRGlobalProtectGateway]:
    name = entry.get("name")
    path = "global-protect/global-protect-gateway/entry"
    attrs = {**_safe_capture(entry), **_scope_attributes(scope)}
    if not name:
        _record_object(extraction, "global-protect/global-protect-gateway", path, scope, None, attrs, [])
        return None
    config = entry.find("./gateway-config")
    if config is None:
        config = entry
    reasons: list[str] = []
    client_auth, _ = _client_auth(config, scope, "global-protect/global-protect-gateway/entry", extraction)
    role_root = config.find("./roles")
    roles = [_parse_role(role, scope, reasons) for role in role_root.findall("./entry") if role_root is not None] if role_root is not None else []
    tunnel_root = config.find("./remote-user-tunnel-config")
    if tunnel_root is None:
        tunnel_root = config.find("./remote-user-tunnel-configuration")
    tunnels = [_parse_remote_tunnel(item, scope, extraction) for item in tunnel_root.findall("./entry") if tunnel_root is not None] if tunnel_root is not None else []
    gateway = IRGlobalProtectGateway(
        name=name, source_context=_scope_context(scope),
        ssl_tls_service_profile=_first_text(config, "./ssl-tls-service-profile"),
        tunnel_mode=_strict_yes_no(config, "./tunnel-mode")[0],
        remote_user_tunnel=_first_text(config, "./remote-user-tunnel"), roles=roles,
        client_authentication=client_auth, remote_user_tunnel_configs=tunnels,
        review_reasons=reasons, source_attributes=attrs,
    )
    _, reason = _strict_yes_no(config, "./tunnel-mode")
    if reason: gateway.review_reasons.append(reason)
    extraction.canonical_ir.global_protect_gateways.append(gateway)
    _unsupported_children(config, {
        "ssl-tls-service-profile", "tunnel-mode", "remote-user-tunnel", "roles",
        "client-auth", "client-authentication", "remote-user-tunnel-config",
        "remote-user-tunnel-configuration",
    }, "global-protect/global-protect-gateway/entry/gateway-config", scope, extraction)
    _unsupported_children(entry, {"gateway-config"}, "global-protect/global-protect-gateway/entry", scope, extraction)
    _register(resolver, name, "globalprotect-gateway", path, scope, gateway)
    _record_object(extraction, "global-protect/global-protect-gateway", path, scope, name, attrs, gateway.review_reasons)
    return gateway


def _parse_network_gateway(entry: ET.Element, scope: PANScope, extraction, resolver) -> Optional[IRGlobalProtectNetworkGateway]:
    name = entry.get("name")
    path = "network/tunnel/global-protect-gateway/entry"
    attrs = {**_safe_capture(entry), **_scope_attributes(scope)}
    if not name:
        _record_object(extraction, "network/tunnel/global-protect-gateway", path, scope, None, attrs, [])
        return None
    reasons: list[str] = []
    exclude, reason = _strict_yes_no(entry, "./exclude-video-traffic/enabled", "./exclude-video-traffic")
    if reason: reasons.append(reason)
    third_party, reason = _strict_yes_no(entry, "./third-party-client/enable", "./third-party-client/enabled")
    if reason: reasons.append(reason)
    inherited, reason = _strict_yes_no(entry, "./client-dns/dns-suffix-inherited", "./dns-suffix-inherited")
    if reason: reasons.append(reason)
    password = entry.find("./third-party-client/group-password") is not None or entry.find("./group-password") is not None
    ip_pools = _values(entry, "./ip-pool", "./ip-pools")
    for pool in ip_pools:
        if not _validate_ip_pool(pool):
            reasons.append(f"malformed-ip-pool:{pool}")
    item = IRGlobalProtectNetworkGateway(
        name=name, source_context=_scope_context(scope),
        local_interface=_first_text(entry, "./local-address/interface", "./local-interface"),
        local_ipv4=_first_text(entry, "./local-address/ip/ipv4", "./local-address/ipv4", "./local-address/ip"),
        local_ipv6=_first_text(entry, "./local-address/ip/ipv6", "./local-address/ipv6"),
        tunnel_interface=_first_text(entry, "./tunnel-interface"),
        ip_pools=ip_pools,
        client_dns_primary=_first_text(entry, "./client-dns/primary", "./client-dns/primary-dns"),
        client_dns_secondary=_first_text(entry, "./client-dns/secondary", "./client-dns/secondary-dns"),
        dns_suffixes=_values(entry, "./client-dns/dns-suffix", "./dns-suffix"),
        dns_suffix_inherited=inherited, exclude_video_traffic_enabled=exclude,
        third_party_client_enabled=third_party,
        third_party_group_name=_first_text(entry, "./third-party-client/group-name", "./group-name"),
        third_party_group_password_configured=password, review_reasons=reasons, source_attributes=attrs,
    )
    extraction.canonical_ir.global_protect_network_gateways.append(item)
    _register(resolver, name, "globalprotect-network-gateway", path, scope, item)
    _record_object(extraction, "network/tunnel/global-protect-gateway", path, scope, name, attrs, reasons)
    return item


def _unsupported_children(parent: Optional[ET.Element], known: set[str], prefix: str, scope: PANScope, extraction, domain: str = "global-protect") -> None:
    if parent is None:
        return
    for child in parent:
        if child.tag in known:
            continue
        if len(child) == 0 and not (child.text or "").strip():
            continue
        entries = child.findall("./entry") or [child]
        for entry in entries:
            record_unsupported(
                extraction, domain, f"{prefix}/{child.tag}", scope,
                entry.get("name") or child.get("name") or child.tag,
                {"pan_source_entry": structured_xml_capture(entry)},
                notes=[f"Unhandled PAN-OS GlobalProtect subtree: {child.tag}"],
            )


def extract_globalprotect_scope(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    container = root.find("./global-protect")
    if container is None:
        return
    portals = container.findall("./global-protect-portal/entry")
    gateways = container.findall("./global-protect-gateway/entry")
    for entry in portals:
        _parse_portal(entry, scope, extraction, resolver)
    for entry in gateways:
        _parse_gateway(entry, scope, extraction, resolver)
    _unsupported_children(container, {"global-protect-portal", "global-protect-gateway"}, "global-protect", scope, extraction)


def extract_globalprotect_network(scope: PANScope, network_root: ET.Element, extraction, resolver) -> None:
    tunnel = network_root.find("./tunnel")
    if tunnel is None:
        return
    entries = tunnel.findall("./global-protect-gateway/entry")
    for entry in entries:
        _parse_network_gateway(entry, scope, extraction, resolver)
        _unsupported_children(entry, {
            "local-address", "local-interface", "tunnel-interface", "ip-pool", "ip-pools", "client-dns",
            "dns-suffix", "dns-suffix-inherited", "exclude-video-traffic", "third-party-client",
            "group-password", "group-name",
        }, "network/tunnel/global-protect-gateway/entry", scope, extraction, domain="network")


def _scope_from_item(item: Any) -> PANScope:
    attrs = item.source_attributes
    return PANScope(kind=attrs.get("pan_scope_kind") or (item.source_context or "vsys:vsys1").split(":", 1)[0],
                    name=attrs.get("pan_scope_name") or (item.source_context or "vsys:vsys1").split(":", 2)[1],
                    device_serial=attrs.get("pan_scope_device_serial"), device_name=attrs.get("pan_scope_device_name"),
                    vsys=attrs.get("pan_scope_vsys"))


def _resolve(resolver, name: Optional[str], kind: str, scope: PANScope):
    return resolver.resolve(name, kind, scope) if name else None


def _resolve_interface(item: Any, name: Optional[str], resolver, extraction):
    if not name:
        return None
    scope = _scope_from_item(item)
    obj = resolver.resolve(name, "interface", scope)
    if obj:
        return obj
    if scope.device_serial or scope.device_name:
        device_name = scope.device_name or scope.device_serial
        device_scope = PANScope(kind="device", name=device_name, device_name=device_name, device_serial=scope.device_serial or device_name)
        obj = resolver.resolve(name, "interface", device_scope)
        if obj:
            return obj
    candidates = [interface for interface in extraction.canonical_ir.interfaces if interface.name == name]
    if scope.device_serial:
        candidates = [interface for interface in candidates if interface.source_attributes.get("pan_device_serial") == scope.device_serial]
    return candidates[0] if len(candidates) == 1 else None


def _resolve_address_value(obj: Any) -> Optional[str]:
    ir_object = getattr(obj, "ir_object", obj)
    return getattr(ir_object, "subnet", None) or getattr(ir_object, "fqdn", None) or getattr(ir_object, "ip_range_start", None)


def finalize_globalprotect_references(extraction, resolver) -> None:
    ir = extraction.canonical_ir
    for portal in ir.global_protect_portals:
        scope = _scope_from_item(portal)
        for auth in portal.client_authentication:
            obj = _resolve(resolver, auth.authentication_profile, "authentication-profile", scope)
            auth.authentication_profile_resolved = obj is not None
            if obj:
                auth.resolved_authentication_profile = obj.canonical_name or obj.name
            elif auth.authentication_profile:
                auth.review_reasons.append("unresolved-authentication-profile")
        for field, kind, label in (("ssl_tls_service_profile", "ssl-tls-service-profile", "ssl_tls_service_profile"),):
            obj = _resolve(resolver, getattr(portal, field), kind, scope)
            setattr(portal, f"{label}_resolved", obj is not None)
            if obj: setattr(portal, f"resolved_{label}", obj.canonical_name or obj.name)
            elif getattr(portal, field): portal.review_reasons.append("unresolved-ssl-tls-service-profile")
        interface = _resolve_interface(portal, portal.local_interface, resolver, extraction)
        portal.local_interface_resolved = interface is not None
        if interface: portal.resolved_local_interface = getattr(interface, "name", None) or interface.canonical_name
        elif portal.local_interface: portal.review_reasons.append("unresolved-local-interface")
        token = portal.local_ipv4 or portal.local_ipv6
        if token:
            if _literal_or_address_reference(token):
                portal.local_address_resolved, portal.resolved_local_address = True, token
            else:
                obj = resolver.resolve(token, "address-reference", scope)
                portal.local_address_resolved = obj is not None
                if obj:
                    portal.resolved_local_address = obj.canonical_name or obj.name
                    portal.source_attributes["pan_resolved_local_address_value"] = _resolve_address_value(obj)
                else: portal.review_reasons.append("unresolved-local-address")
        for ca in portal.root_ca_certificates:
            obj = _resolve(resolver, ca.certificate, "certificate", scope)
            ca.certificate_resolved = obj is not None
            if obj: ca.resolved_certificate = obj.canonical_name or obj.name
            else: ca.review_reasons.append("unresolved-certificate")
        for config in portal.client_configs:
            for gateway in config.external_gateways:
                pass
    for gateway in ir.global_protect_gateways:
        scope = _scope_from_item(gateway)
        for auth in gateway.client_authentication:
            obj = _resolve(resolver, auth.authentication_profile, "authentication-profile", scope)
            auth.authentication_profile_resolved = obj is not None
            if obj: auth.resolved_authentication_profile = obj.canonical_name or obj.name
            elif auth.authentication_profile: auth.review_reasons.append("unresolved-authentication-profile")
        obj = _resolve(resolver, gateway.ssl_tls_service_profile, "ssl-tls-service-profile", scope)
        gateway.ssl_tls_service_profile_resolved = obj is not None
        if obj: gateway.resolved_ssl_tls_service_profile = obj.canonical_name or obj.name
        elif gateway.ssl_tls_service_profile: gateway.review_reasons.append("unresolved-ssl-tls-service-profile")
        interface = _resolve_interface(gateway, gateway.remote_user_tunnel, resolver, extraction)
        gateway.remote_user_tunnel_resolved = interface is not None
        if interface: gateway.resolved_remote_user_tunnel = getattr(interface, "name", None) or interface.canonical_name
        elif gateway.remote_user_tunnel: gateway.review_reasons.append("unresolved-remote-user-tunnel")
        for config in gateway.remote_user_tunnel_configs:
            for field, resolved_field, unresolved_field in (("split_include_routes", "resolved_split_include_routes", "unresolved_split_include_routes"), ("split_exclude_routes", "resolved_split_exclude_routes", "unresolved_split_exclude_routes")):
                for token in getattr(config, field):
                    if _literal_or_address_reference(token):
                        getattr(config, resolved_field).append(token)
                        continue
                    obj = resolver.resolve(token, "address-reference", scope)
                    if obj:
                        getattr(config, resolved_field).append(obj.canonical_name or obj.name)
                        config.source_attributes.setdefault("pan_resolved_route_values", {})[token] = _resolve_address_value(obj)
                    else:
                        getattr(config, unresolved_field).append(token)
                        config.review_reasons.append(f"unresolved-split-route:{token}")
    for gateway in ir.global_protect_network_gateways:
        interface = _resolve_interface(gateway, gateway.local_interface, resolver, extraction)
        gateway.local_interface_resolved = interface is not None
        if interface: gateway.resolved_local_interface = getattr(interface, "name", None) or interface.canonical_name
        elif gateway.local_interface: gateway.review_reasons.append("unresolved-local-interface")
        interface = _resolve_interface(gateway, gateway.tunnel_interface, resolver, extraction)
        gateway.tunnel_interface_resolved = interface is not None
        if interface: gateway.resolved_tunnel_interface = getattr(interface, "name", None) or interface.canonical_name
        elif gateway.tunnel_interface: gateway.review_reasons.append("unresolved-tunnel-interface")
