from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..model import (
    PANGlobalProtectClientlessVPN,
    PANGlobalProtectGateway,
    PANGlobalProtectGatewayClientAuth,
    PANGlobalProtectPortal,
    PANGlobalProtectPortalClientConfig,
    PANGlobalProtectPortalGateway,
    PANGlobalProtectRemoteUserTunnel,
)
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, structured_xml_capture


def _text(element: ET.Element | None) -> str | None:
    return (element.text or "").strip() or None if element is not None else None


def _value(element: ET.Element | None, tag: str) -> str | None:
    return _text(element.find(tag)) if element is not None else None


def _values(element: ET.Element | None, tag: str) -> list[str] | None:
    child = element.find(tag) if element is not None else None
    if child is None:
        return None
    members = child.findall("member")
    if members:
        return [_text(member) or member.get("name") or "" for member in members]
    entries = child.findall("entry")
    if entries:
        return [entry.get("name") or _text(entry) or "" for entry in entries]
    return [_text(child) or ""]


def _entries(element: ET.Element, tag: str) -> list[ET.Element] | None:
    section = element.find(tag)
    if section is None:
        return None
    entries = section.findall("entry")
    return entries or [section]


def _capture(element: ET.Element | None) -> dict[str, Any] | None:
    return sanitize_source_attributes(structured_xml_capture(element)) if element is not None else None


def _nested_metadata(element: ET.Element, known: set[str], field_map: dict[str, str] | None = None) -> tuple[dict[str, Any], set[str]]:
    return raw_extra(element, known), {(field_map or {}).get(child.tag, child.tag.replace("-", "_")) for child in element if child.tag in known}


def _portal_gateway(element: ET.Element) -> PANGlobalProtectPortalGateway:
    known = {"gateway-type", "gateway", "priority"}
    extra, explicit = _nested_metadata(element, known)
    return PANGlobalProtectPortalGateway(
        gateway_type=_value(element, "gateway-type"), gateway=_value(element, "gateway"), priority=_value(element, "priority"),
        raw_extra=extra, explicit_fields=explicit,
    )


def _client_config(element: ET.Element) -> PANGlobalProtectPortalClientConfig:
    known = {"internal-host-detection", "authentication-override", "agent-ui-settings", "hip-collection-settings", "agent-configuration", "app-configuration", "agent-ui", "hip-collection", "agent-config", "gp-app-config", "gateways"}
    extra, explicit = _nested_metadata(element, known, {"internal-host-detection": "internal_host_detection"})
    detection = element.find("internal-host-detection")
    gateways = _entries(element, "gateways")
    if detection is not None:
        if detection.find("ip-address") is not None or detection.find("ip") is not None:
            explicit.add("internal_host_detection_ip")
        if detection.find("hostname") is not None:
            explicit.add("internal_host_detection_hostname")
    selected_tags = (("authentication-override", "authentication_override"), ("agent-ui", "agent_ui_settings"), ("agent-ui-settings", "agent_ui_settings"), ("hip-collection", "hip_collection_settings"), ("hip-collection-settings", "hip_collection_settings"), ("agent-config", "agent_configuration"), ("agent-configuration", "agent_configuration"), ("gp-app-config", "app_configuration"), ("app-configuration", "app_configuration"))
    for tag, field in selected_tags:
        if element.find(tag) is not None:
            explicit.add(field)
    explicit.intersection_update(PANGlobalProtectPortalClientConfig.model_fields)
    if gateways is not None:
        explicit.add("gateways")
    return PANGlobalProtectPortalClientConfig(
        name=element.get("name"),
        internal_host_detection_ip=_value(detection, "ip-address") or _value(detection, "ip"),
        internal_host_detection_hostname=_value(detection, "hostname"),
        authentication_override=_capture(element.find("authentication-override")),
        agent_ui_settings=_capture(element.find("agent-ui") if element.find("agent-ui") is not None else element.find("agent-ui-settings")),
        hip_collection_settings=_capture(element.find("hip-collection") if element.find("hip-collection") is not None else element.find("hip-collection-settings")),
        agent_configuration=_capture(element.find("agent-config") if element.find("agent-config") is not None else element.find("agent-configuration")),
        app_configuration=_capture(element.find("gp-app-config") if element.find("gp-app-config") is not None else element.find("app-configuration")),
        gateways=[_portal_gateway(entry) for entry in gateways] if gateways is not None else None,
        raw_extra=extra, explicit_fields=explicit,
    )


def _clientless_vpn(element: ET.Element) -> PANGlobalProtectClientlessVPN:
    known = {"hostname", "security-zone", "login-lifetime", "inactivity-logout", "maximum-users", "max-user", "dns-proxy"}
    extra, explicit = _nested_metadata(element, known)
    login = element.find("login-lifetime")
    inactivity = element.find("inactivity-logout")
    login_unit = next((child.tag for child in login if child.tag in {"minutes", "hours"}), None) if login is not None else None
    inactivity_unit = next((child.tag for child in inactivity if child.tag in {"minutes", "hours"}), None) if inactivity is not None else None
    if login_unit:
        explicit.update({"login_lifetime", "login_lifetime_unit"})
    if inactivity_unit:
        explicit.update({"inactivity_logout", "inactivity_logout_unit"})
    if element.find("max-user") is not None:
        explicit.add("maximum_users")
    explicit.intersection_update(PANGlobalProtectClientlessVPN.model_fields)
    for node, unit, tag in ((login, login_unit, "login-lifetime"), (inactivity, inactivity_unit, "inactivity-logout")):
        if node is not None:
            unknown = raw_extra(node, {"minutes", "hours"})
            if unknown:
                extra[tag] = unknown
    return PANGlobalProtectClientlessVPN(
        hostname=_value(element, "hostname"), security_zone=_value(element, "security-zone"),
        login_lifetime=_value(login, login_unit) if login_unit else _value(element, "login-lifetime"), login_lifetime_unit=login_unit,
        inactivity_logout=_value(inactivity, inactivity_unit) if inactivity_unit else _value(element, "inactivity-logout"), inactivity_logout_unit=inactivity_unit,
        maximum_users=_value(element, "max-user") or _value(element, "maximum-users"), dns_proxy=_value(element, "dns-proxy"),
        raw_extra=extra, explicit_fields=explicit,
    )


def extract_portal(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANGlobalProtectPortal:
    extra, explicit = source_fields(element, spec)
    client_config = element.find("client-config")
    client_configs = _entries(client_config, "configs") if client_config is not None else None
    client_configs = client_configs if client_configs is not None else _entries(element, "client-config")
    clientless = element.find("clientless-vpn")
    if client_configs is not None:
        explicit.add("client_configs")
    if clientless is not None:
        explicit.add("clientless_vpn")
    return PANGlobalProtectPortal(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        ssl_tls_service_profile=_value(element, "ssl-tls-service-profile"), certificate_profile=_value(element, "certificate-profile"),
        clientless_vpn_enabled=_value(element, "clientless-vpn-enabled"),
        client_configs=[_client_config(item) for item in client_configs] if client_configs is not None else None,
        clientless_vpn=_clientless_vpn(clientless) if clientless is not None else None,
        raw_extra=extra, explicit_fields=explicit,
    )


def _client_auth(element: ET.Element) -> PANGlobalProtectGatewayClientAuth:
    known = {"operating-system", "os", "authentication-profile", "auto-retrieve-passcode"}
    extra, explicit = _nested_metadata(element, known, {"os": "operating_system"})
    return PANGlobalProtectGatewayClientAuth(
        name=element.get("name"), operating_system=_value(element, "os") or _value(element, "operating-system"),
        authentication_profile=_value(element, "authentication-profile"), auto_retrieve_passcode=_value(element, "auto-retrieve-passcode"),
        raw_extra=extra, explicit_fields=explicit,
    )


def _remote_user_tunnel(element: ET.Element) -> PANGlobalProtectRemoteUserTunnel:
    known = {"ip-pools", "ip-pool", "authentication-server-ip-pools", "authentication-server-ip-pool", "split-tunneling", "no-direct-access-to-local-network", "retrieve-framed-ip", "retrieve-framed-ip-address"}
    field_map = {"ip-pools": "ip_pools", "ip-pool": "ip_pools", "authentication-server-ip-pools": "authentication_server_ip_pools", "authentication-server-ip-pool": "authentication_server_ip_pools", "no-direct-access-to-local-network": "no_direct_access_to_local_network", "retrieve-framed-ip": "retrieve_framed_ip", "retrieve-framed-ip-address": "retrieve_framed_ip"}
    extra, explicit = _nested_metadata(element, known, field_map)
    split_tunneling = element.find("split-tunneling")
    if split_tunneling is not None:
        explicit.add("split_tunneling")
    return PANGlobalProtectRemoteUserTunnel(
        name=element.get("name"), ip_pools=_values(element, "ip-pools") or _values(element, "ip-pool"),
        authentication_server_ip_pools=_values(element, "authentication-server-ip-pools") or _values(element, "authentication-server-ip-pool"),
        split_tunneling=_capture(split_tunneling), no_direct_access_to_local_network=_value(element, "no-direct-access-to-local-network"),
        retrieve_framed_ip=_value(element, "retrieve-framed-ip-address") or _value(element, "retrieve-framed-ip"), raw_extra=extra, explicit_fields=explicit,
    )


def extract_gateway(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANGlobalProtectGateway:
    extra, explicit = source_fields(element, spec)
    selected = spec.name == "globalprotect_gateway_selected"
    client_authentication = _entries(element, "client-auth") or _entries(element, "client-authentication")
    remote_user_tunnels = _entries(element, "remote-user-tunnel-configs") or _entries(element, "remote-user-tunnel")
    if client_authentication is not None:
        explicit.add("client_authentication")
    if remote_user_tunnels is not None:
        explicit.add("remote_user_tunnels")
    local_address = element.find("local-address")
    local_interface = _value(local_address, "interface") if selected else _value(element, "local-interface")
    ip_address_family = _value(local_address, "ip-address-family") if selected else _value(element, "ip-address-family")
    if local_address is not None:
        if selected:
            explicit.discard("local_address")
        unknown = raw_extra(local_address, {"interface", "ip-address-family"})
        if unknown:
            extra["local-address"] = unknown
        if local_interface is not None:
            explicit.add("local_interface")
        if ip_address_family is not None:
            explicit.add("ip_address_family")
    return PANGlobalProtectGateway(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        tunnel_mode=_value(element, "tunnel-mode"), local_interface=local_interface,
        local_address=None if selected else _value(element, "local-address"), ip_address_family=ip_address_family,
        ssl_tls_service_profile=_value(element, "ssl-tls-service-profile"), certificate_profile=_value(element, "certificate-profile"),
        client_authentication=[_client_auth(item) for item in client_authentication] if client_authentication is not None else None,
        remote_user_tunnels=[_remote_user_tunnel(item) for item in remote_user_tunnels] if remote_user_tunnels is not None else None,
        raw_extra=extra, explicit_fields=explicit,
    )
