from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANIPsecTunnel
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import source_fields, value, values


def _scalar_or_member(element: ET.Element, tag: str) -> str | None:
    node = element.find(tag)
    if node is None:
        return None
    return (node.text or next((child.text for child in node if child.text), "")).strip() or None


def extract_ipsec_tunnel(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANIPsecTunnel:
    extra, explicit = source_fields(element, spec)
    auto_key = element.find("auto-key")
    crypto_profile = _scalar_or_member(auto_key, "ipsec-crypto-profile") if auto_key is not None else None
    crypto_profile = crypto_profile or value(element, "ipsec-crypto-profile")
    if auto_key is not None and auto_key.find("ipsec-crypto-profile") is not None:
        explicit.add("ipsec_crypto_profile")
    return PANIPsecTunnel(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        tunnel_interface=_scalar_or_member(element, "tunnel-interface"), ipsec_crypto_profile=crypto_profile,
        tunnel_monitor=value(element, "tunnel-monitor"), globalprotect_satellite=value(element, "global-protect-satellite"),
        ike_gateways=values(element.find("auto-key"), "ike-gateway"), raw_extra=extra, explicit_fields=explicit,
    )
