"""Source-only PAN-OS IKE/IPsec inventory."""

from __future__ import annotations

import copy
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import IRConfig, IRVPNPhase2, IRVPNTunnel

from .extraction import add_source_section, record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope, pan_scope_identity
from .xml_utils import member_texts, structured_xml_capture, text_or_none


def _entries(root: ET.Element | None, paths: tuple[str, ...]) -> Iterable[tuple[str, ET.Element]]:
    if root is None:
        return
    for path in paths:
        for entry in root.findall(path):
            yield path, entry


def _entry_names(root: ET.Element, path: str) -> list[str]:
    return [name for node in root.findall(path) if (name := node.get("name"))]


def _selected_ike_crypto_profile(
    version: str | None,
    ikev1_profile: str | None,
    ikev2_profile: str | None,
) -> str | None:
    normalized = (version or "").lower()
    if normalized == "ikev1":
        return ikev1_profile
    if normalized.startswith("ikev2"):
        return ikev2_profile

    configured = {value for value in (ikev1_profile, ikev2_profile) if value}
    return next(iter(configured)) if len(configured) == 1 else None


def _safe_source_capture(entry: ET.Element | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    captured = copy.deepcopy(entry)
    for parent in captured.iter():
        for child in list(parent):
            if child.tag in {"pre-shared-key", "psk"}:
                parent.remove(child)
    return structured_xml_capture(captured)


def _record(extraction, domain: str, path: str, scope: PANScope, name: str | None,
            attributes: dict, notes: list[str] | None = None) -> None:
    if not name:
        record_parse_error(extraction, domain, path, scope, None, attributes,
                           notes=["PAN-OS VPN object is missing its required name."])
    else:
        record_extract_only(extraction, domain, path, scope, name, attributes,
                            notes=notes or ["PAN-OS VPN configuration retained as source-only inventory."],
                            requires_manual_review=True)


def extract_vpn(network_root: ET.Element, scope: PANScope, extraction, ir: IRConfig) -> None:
    ike = network_root.find("./ike")
    ipsec = network_root.find("./ipsec")
    ike_profiles = list(_entries(ike, ("./crypto-profiles/ike-crypto-profiles/entry",
                                      "./crypto-profiles/ike/entry")))
    ipsec_profiles = list(_entries(ike, ("./crypto-profiles/ipsec-crypto-profiles/entry",
                                         "./crypto-profiles/ipsec/entry")))
    ipsec_profile_root = "network/ike"
    if not ipsec_profiles:
        ipsec_profiles = list(_entries(ipsec, ("./crypto-profiles/ipsec-crypto-profiles/entry",
                                               "./crypto-profiles/ipsec/entry")))
        ipsec_profile_root = "network/ipsec"
    gateways = list(_entries(ike, ("./gateway/entry", "./gateways/entry")))
    tunnels = list(_entries(network_root, ("./tunnel/ipsec/entry", "./ipsec/tunnel/entry",
                                            "./ipsec/tunnels/entry")))
    total = 0
    recognized_ike_children = {"crypto-profiles", "gateway", "gateways"}
    if ike is not None:
        unknown_ike = [child for child in ike if child.tag not in recognized_ike_children]
        for child in unknown_ike:
            record_unsupported(
                extraction, "vpn:ike", f"network/ike/{child.tag}", scope, child.tag,
                {"pan_source_entry": structured_xml_capture(child)},
                notes=[f"PAN-OS IKE subtree {child.tag} is not recognized by the source-only extractor."],
            )
            total += 1
        if not ike_profiles and not gateways and not unknown_ike:
            record_unsupported(
                extraction, "vpn:ike", "network/ike", scope, "ike",
                {"pan_source_entry": structured_xml_capture(ike)},
                notes=["PAN-OS IKE container has no recognized profiles or gateways."],
            )
            total += 1
    recognized_ipsec_children = {"crypto-profiles", "tunnel", "tunnels"}
    if ipsec is not None:
        unknown_ipsec = [child for child in ipsec if child.tag not in recognized_ipsec_children]
        for child in unknown_ipsec:
            record_unsupported(
                extraction, "vpn:ipsec", f"network/ipsec/{child.tag}", scope, child.tag,
                {"pan_source_entry": structured_xml_capture(child)},
                notes=[f"PAN-OS IPsec subtree {child.tag} is not recognized by the source-only extractor."],
            )
            total += 1
        if not ipsec_profiles and not tunnels and not unknown_ipsec:
            record_unsupported(
                extraction, "vpn:ipsec", "network/ipsec", scope, "ipsec",
                {"pan_source_entry": structured_xml_capture(ipsec)},
                notes=["PAN-OS IPsec container has no recognized profiles or tunnels."],
            )
            total += 1
    for path_prefix, entry in ike_profiles:
        name = entry.get("name")
        path = f"network/ike/{path_prefix.removeprefix('./')}/@name='{name}'"
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ike-crypto-profile",
            "pan_encryption": member_texts(entry, "./encryption/member"),
            "pan_hash": member_texts(entry, "./hash/member"),
            "pan_authentication": member_texts(entry, "./hash/member"),
            "pan_dh_groups": member_texts(entry, "./dh-group/member"),
            "pan_lifetime": structured_xml_capture(entry.find("./lifetime")),
            "pan_ike_encryption": member_texts(entry, "./encryption/member"),
            "pan_ike_hash": member_texts(entry, "./hash/member"),
            "pan_ike_dh_groups": member_texts(entry, "./dh-group/member"),
            "pan_ike_lifetime_seconds": text_or_none(entry, "./lifetime/seconds"),
            "pan_source_entry": structured_xml_capture(entry),
        })
        _record(extraction, "vpn:ike_crypto_profile", path, scope, name, attrs)
        total += 1
    for path_prefix, entry in ipsec_profiles:
        name = entry.get("name")
        path = f"{ipsec_profile_root}/{path_prefix.removeprefix('./')}/@name='{name}'"
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ipsec-crypto-profile",
            "pan_protocol": member_texts(entry, "./protocol/member"),
            "pan_encryption": member_texts(entry, "./esp/encryption/member"),
            "pan_authentication": member_texts(entry, "./esp/authentication/member"),
            "pan_pfs": structured_xml_capture(entry.find("./dh-group")),
            "pan_lifetime": structured_xml_capture(entry.find("./lifetime")),
            "pan_ipsec_esp_encryption": member_texts(entry, "./esp/encryption/member"),
            "pan_ipsec_esp_authentication": member_texts(entry, "./esp/authentication/member"),
            "pan_ipsec_dh_groups": member_texts(entry, "./dh-group/member"),
            "pan_source_entry": structured_xml_capture(entry),
        })
        _record(extraction, "vpn:ipsec_crypto_profile", path, scope, name, attrs)
        total += 1
    for path_prefix, entry in gateways:
        name = entry.get("name")
        path = f"network/ike/{path_prefix.removeprefix('./')}/@name='{name}'"
        ike_version = text_or_none(entry, "./protocol/version")
        ikev1_crypto_profile = text_or_none(entry, "./protocol/ikev1/ike-crypto-profile")
        ikev2_crypto_profile = text_or_none(entry, "./protocol/ikev2/ike-crypto-profile")
        crypto_profile = _selected_ike_crypto_profile(
            ike_version, ikev1_crypto_profile, ikev2_crypto_profile,
        )
        ikev1_dpd = structured_xml_capture(entry.find("./protocol/ikev1/dpd"))
        ikev2_dpd = structured_xml_capture(entry.find("./protocol/ikev2/dpd"))
        if ike_version == "ikev1":
            selected_dpd = ikev1_dpd
        elif (ike_version or "").startswith("ikev2"):
            selected_dpd = ikev2_dpd
        else:
            selected_dpd = ikev1_dpd or ikev2_dpd
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ike-gateway",
            "pan_ike_version": ike_version,
            "pan_local_interface": text_or_none(entry, "./local-address/interface"),
            "pan_local_address": text_or_none(entry, "./local-address/ip"),
            "pan_peer_address": text_or_none(entry, "./peer-address/ip") or text_or_none(entry, "./peer-address"),
            "pan_ipv6_local_address": text_or_none(entry, "./local-address/ipv6") or text_or_none(entry, "./local-address/ipv6-address"),
            "pan_ipv6_peer_address": text_or_none(entry, "./peer-address/ipv6") or text_or_none(entry, "./peer-address/ipv6-address"),
            "pan_local_id": structured_xml_capture(entry.find("./local-id")),
            "pan_peer_id": structured_xml_capture(entry.find("./peer-id")),
            "pan_authentication": _safe_source_capture(entry.find("./authentication")),
            "pan_ikev1_crypto_profile": ikev1_crypto_profile,
            "pan_ikev2_crypto_profile": ikev2_crypto_profile,
            "pan_crypto_profile": crypto_profile,
            "pan_certificate_profile": text_or_none(entry, "./authentication/certificate-profile"),
            "pan_passive_mode": text_or_none(entry, "./protocol-common/passive-mode"),
            "pan_nat_traversal": structured_xml_capture(entry.find("./protocol-common/nat-traversal")),
            "pan_fragmentation": structured_xml_capture(entry.find("./protocol-common/fragmentation")),
            "pan_ikev1_dpd": ikev1_dpd,
            "pan_ikev2_dpd": ikev2_dpd,
            "pan_dpd": selected_dpd,
            "pan_authentication_methods": member_texts(entry, "./authentication/method/member"),
            "pan_protocol_settings": structured_xml_capture(entry.find("./protocol-common")),
            "pan_source_entry": _safe_source_capture(entry),
        })
        _record(extraction, "vpn:ike_gateway", path, scope, name, attrs)
        if name:
            ir.vpn_tunnels.append(IRVPNTunnel(
                name=name,
                source_context=pan_scope_identity(scope),
                local_interface=attrs.get("pan_local_interface") or "",
                peer_address=attrs.get("pan_peer_address"),
                ike_version=attrs.get("pan_ike_version"),
                ike_crypto_profile=attrs.get("pan_crypto_profile"),
                has_psk=entry.find(".//pre-shared-key") is not None,
                migration_status="EXTRACT_ONLY",
                requires_manual_review=True,
                source_attributes=attrs,
            ))
        total += 1
    for path_prefix, entry in tunnels:
        name = entry.get("name")
        path = f"network/{path_prefix.removeprefix('./')}/@name='{name}'"
        ike_gateways = _entry_names(entry, "./auto-key/ike-gateway/entry")
        phase1 = ike_gateways[0] if len(ike_gateways) == 1 else ""
        crypto = text_or_none(entry, "./auto-key/ipsec-crypto-profile") or text_or_none(entry, "./ipsec-crypto-profile")
        tunnel_monitor = structured_xml_capture(entry.find("./tunnel-monitor"))
        tunnel_notes = (
            ["PAN-OS IPsec tunnel references multiple IKE gateways; phase1_name left blank."]
            if len(ike_gateways) > 1 else None
        )
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ipsec-tunnel",
            "pan_tunnel_interface": text_or_none(entry, "./tunnel-interface"),
            "pan_ike_gateway": phase1,
            "pan_ike_gateways": ike_gateways,
            "pan_ipsec_crypto_profile": crypto,
            "pan_keying_mode": "auto-key" if entry.find("./auto-key") is not None else (
                "manual-key" if entry.find("./manual-key") is not None else None
            ),
            "pan_protocol": text_or_none(entry, "./protocol"),
            "pan_ports": structured_xml_capture(entry.find("./ports")),
            "pan_anti_replay": structured_xml_capture(entry.find("./anti-replay")),
            "pan_copy_tos": text_or_none(entry, "./copy-tos"),
            "pan_tunnel_monitor": tunnel_monitor,
            "pan_tunnel_monitoring": tunnel_monitor,
            "pan_proxy_ids": structured_xml_capture(entry.find("./auto-key/proxy-id")),
            "pan_fragmentation_settings": structured_xml_capture(entry.find("./fragmentation")),
            "pan_source_entry": _safe_source_capture(entry),
        })
        _record(extraction, "vpn:ipsec_tunnel", path, scope, name, attrs, notes=tunnel_notes)
        if name:
            ir.vpn_phase2.append(IRVPNPhase2(
                name=name, source_context=pan_scope_identity(scope), phase1_name=phase1,
                proposals=[crypto] if crypto else [],
                source_address_type=text_or_none(entry, "./proxy-id/source/ipv6") and "ipv6" or None,
                destination_address_type=text_or_none(entry, "./proxy-id/destination/ipv6") and "ipv6" or None,
                source_subnet=text_or_none(entry, "./proxy-id/source/ipv6") or text_or_none(entry, "./proxy-id/source-ipv6"),
                destination_subnet=text_or_none(entry, "./proxy-id/destination/ipv6") or text_or_none(entry, "./proxy-id/destination-ipv6"),
                source_attributes=attrs, migration_status="EXTRACT_ONLY",
                requires_manual_review=True,
            ))
        total += 1
    if total:
        add_source_section(
            extraction, "network/vpn", ExtractionStatus.EXTRACT_ONLY,
            total, total, 0, "extract_vpn",
            source_context=f"{scope.kind}:{scope.name}",
        )
