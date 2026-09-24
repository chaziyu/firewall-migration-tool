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
    known = {"internal-host-detection", "authentication-override", "agent-ui-settings", "hip-collection-settings", "agent-configuration", "app-configuration", "gateways"}
    extra, explicit = _nested_metadata(element, known, {"internal-host-detection": "internal_host_detection"})
    detection = element.find("internal-host-detection")
    gateways = _entries(element, "gateways")
    if detection is not None:
        if detection.find("ip-address") is not None or detection.find("ip") is not None:
            explicit.add("internal_host_detection_ip")
        if detection.find("hostname") is not None:
            explicit.add("internal_host_detection_hostname")
    for tag, field in (("authentication-override", "authentication_override"), ("agent-ui-settings", "agent_ui_settings"), ("hip-collection-settings", "hip_collection_settings"), ("agent-configuration", "agent_configuration"), ("app-configuration", "app_configuration")):
        if element.find(tag) is not None:
            explicit.add(field)
    if gateways is not None:
        explicit.add("gateways")
    return PANGlobalProtectPortalClientConfig(
        name=element.get("name"),
        internal_host_detection_ip=_value(detection, "ip-address") or _value(detection, "ip"),
        internal_host_detection_hostname=_value(detection, "hostname"),
        authentication_override=_capture(element.find("authentication-override")),
        agent_ui_settings=_capture(element.find("agent-ui-settings")),
        hip_collection_settings=_capture(element.find("hip-collection-settings")),
        agent_configuration=_capture(element.find("agent-configuration")),
        app_configuration=_capture(element.find("app-configuration")),
        gateways=[_portal_gateway(entry) for entry in gateways] if gateways is not None else None,
        raw_extra=extra, explicit_fields=explicit,
    )


def _clientless_vpn(element: ET.Element) -> PANGlobalProtectClientlessVPN:
    known = {"hostname", "security-zone", "login-lifetime", "inactivity-logout", "maximum-users", "dns-proxy"}
    extra, explicit = _nested_metadata(element, known)
    return PANGlobalProtectClientlessVPN(
        hostname=_value(element, "hostname"), security_zone=_value(element, "security-zone"),
        login_lifetime=_value(element, "login-lifetime"), inactivity_logout=_value(element, "inactivity-logout"),
        maximum_users=_value(element, "maximum-users"), dns_proxy=_value(element, "dns-proxy"),
        raw_extra=extra, explicit_fields=explicit,
    )


def extract_portal(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANGlobalProtectPortal:
    extra, explicit = source_fields(element, spec)
    client_configs = _entries(element, "client-config")
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
    known = {"operating-system", "authentication-profile", "auto-retrieve-passcode"}
    extra, explicit = _nested_metadata(element, known)
    return PANGlobalProtectGatewayClientAuth(
        name=element.get("name"), operating_system=_value(element, "operating-system"),
        authentication_profile=_value(element, "authentication-profile"), auto_retrieve_passcode=_value(element, "auto-retrieve-passcode"),
        raw_extra=extra, explicit_fields=explicit,
    )


def _remote_user_tunnel(element: ET.Element) -> PANGlobalProtectRemoteUserTunnel:
    known = {"ip-pools", "ip-pool", "authentication-server-ip-pools", "authentication-server-ip-pool", "split-tunneling", "no-direct-access-to-local-network", "retrieve-framed-ip"}
    field_map = {"ip-pools": "ip_pools", "ip-pool": "ip_pools", "authentication-server-ip-pools": "authentication_server_ip_pools", "authentication-server-ip-pool": "authentication_server_ip_pools", "no-direct-access-to-local-network": "no_direct_access_to_local_network", "retrieve-framed-ip": "retrieve_framed_ip"}
    extra, explicit = _nested_metadata(element, known, field_map)
    split_tunneling = element.find("split-tunneling")
    if split_tunneling is not None:
        explicit.add("split_tunneling")
    return PANGlobalProtectRemoteUserTunnel(
        name=element.get("name"), ip_pools=_values(element, "ip-pools") or _values(element, "ip-pool"),
        authentication_server_ip_pools=_values(element, "authentication-server-ip-pools") or _values(element, "authentication-server-ip-pool"),
        split_tunneling=_capture(split_tunneling), no_direct_access_to_local_network=_value(element, "no-direct-access-to-local-network"),
        retrieve_framed_ip=_value(element, "retrieve-framed-ip"), raw_extra=extra, explicit_fields=explicit,
    )


def extract_gateway(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANGlobalProtectGateway:
    extra, explicit = source_fields(element, spec)
    client_authentication = _entries(element, "client-authentication")
    remote_user_tunnels = _entries(element, "remote-user-tunnel")
    if client_authentication is not None:
        explicit.add("client_authentication")
    if remote_user_tunnels is not None:
        explicit.add("remote_user_tunnels")
    return PANGlobalProtectGateway(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        tunnel_mode=_value(element, "tunnel-mode"), local_interface=_value(element, "local-interface"),
        local_address=_value(element, "local-address"), ip_address_family=_value(element, "ip-address-family"),
        ssl_tls_service_profile=_value(element, "ssl-tls-service-profile"), certificate_profile=_value(element, "certificate-profile"),
        client_authentication=[_client_auth(item) for item in client_authentication] if client_authentication is not None else None,
        remote_user_tunnels=[_remote_user_tunnel(item) for item in remote_user_tunnels] if remote_user_tunnels is not None else None,
        raw_extra=extra, explicit_fields=explicit,
    )
