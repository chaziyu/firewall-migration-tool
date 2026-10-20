from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANIPsecTunnel
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, value


def _scalar_or_member(element: ET.Element, tag: str) -> str | None:
    node = element.find(tag)
    if node is None:
        return None
    return (node.text or next((child.text for child in node if child.text), "")).strip() or None


def extract_ipsec_tunnel(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANIPsecTunnel:
    extra, explicit = source_fields(element, spec)
    auto_key = element.find("auto-key")
    gateways = auto_key.find("ike-gateway") if auto_key is not None else None
    gateway_names = ([child.get("name") if child.tag == "entry" else (child.text or "").strip()
                      for child in gateways if child.tag in {"entry", "member"}]
                     if gateways is not None else None)
    if gateways is not None:
        explicit.add("ike_gateways")
    monitor = element.find("tunnel-monitor")
    monitor_fields = {"enable": "tunnel_monitor", "destination-ip": "tunnel_monitor_destination_ip",
                      "tunnel-monitor-profile": "tunnel_monitor_profile", "proxy-id": "tunnel_monitor_proxy_id"}
    monitor_values = {}
    if monitor is not None and len(monitor):
        explicit.discard("tunnel_monitor")
        for tag, field in monitor_fields.items():
            monitor_values[field] = value(monitor, tag)
            if monitor.find(tag) is not None:
                explicit.add(field)
        monitor_extra = raw_extra(monitor, set(monitor_fields))
        if monitor_extra:
            extra["tunnel-monitor"] = monitor_extra
    else:
        monitor_values["tunnel_monitor"] = value(element, "tunnel-monitor")
    crypto_profile = _scalar_or_member(auto_key, "ipsec-crypto-profile") if auto_key is not None else None
    crypto_profile = crypto_profile or value(element, "ipsec-crypto-profile")
    if auto_key is not None and auto_key.find("ipsec-crypto-profile") is not None:
        explicit.add("ipsec_crypto_profile")
    return PANIPsecTunnel(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        tunnel_interface=_scalar_or_member(element, "tunnel-interface"), ipsec_crypto_profile=crypto_profile,
        **monitor_values, globalprotect_satellite=value(element, "global-protect-satellite"),
        ike_gateways=gateway_names, raw_extra=extra, explicit_fields=explicit,
    )
