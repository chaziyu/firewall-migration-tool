"""Source-only PAN-OS IKE/IPsec inventory."""

from __future__ import annotations

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
    ipsec_profiles = list(_entries(ipsec, ("./crypto-profiles/ipsec-crypto-profiles/entry",
                                           "./crypto-profiles/ipsec/entry")))
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
            "pan_authentication": member_texts(entry, "./authentication/member"),
            "pan_dh_groups": member_texts(entry, "./dh-group/member"),
            "pan_lifetime": structured_xml_capture(entry.find("./lifetime")),
            "pan_source_entry": structured_xml_capture(entry),
        })
        _record(extraction, "vpn:ike_crypto_profile", path, scope, name, attrs)
        total += 1
    for path_prefix, entry in ipsec_profiles:
        name = entry.get("name")
        path = f"network/ipsec/{path_prefix.removeprefix('./')}/@name='{name}'"
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ipsec-crypto-profile",
            "pan_protocol": member_texts(entry, "./protocol/member"),
            "pan_encryption": member_texts(entry, "./esp/encryption/member"),
            "pan_authentication": member_texts(entry, "./esp/authentication/member"),
            "pan_pfs": structured_xml_capture(entry.find("./dh-group")),
            "pan_lifetime": structured_xml_capture(entry.find("./lifetime")),
            "pan_source_entry": structured_xml_capture(entry),
        })
        _record(extraction, "vpn:ipsec_crypto_profile", path, scope, name, attrs)
        total += 1
    for path_prefix, entry in gateways:
        name = entry.get("name")
        path = f"network/ike/{path_prefix.removeprefix('./')}/@name='{name}'"
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ike-gateway",
            "pan_ike_version": text_or_none(entry, "./protocol/common") or text_or_none(entry, "./protocol"),
            "pan_local_interface": text_or_none(entry, "./local-address/interface"),
            "pan_local_address": text_or_none(entry, "./local-address/ip"),
            "pan_peer_address": text_or_none(entry, "./peer-address/ip") or text_or_none(entry, "./peer-address"),
            "pan_local_id": structured_xml_capture(entry.find("./local-id")),
            "pan_peer_id": structured_xml_capture(entry.find("./peer-id")),
            "pan_authentication": structured_xml_capture(entry.find("./authentication")),
            "pan_crypto_profile": text_or_none(entry, "./protocol/ike-crypto-profile"),
            "pan_certificate_profile": text_or_none(entry, "./authentication/certificate-profile"),
            "pan_passive_mode": text_or_none(entry, "./passive-mode"),
            "pan_nat_traversal": structured_xml_capture(entry.find("./protocol/nat-traversal"))
                or structured_xml_capture(entry.find("./nat-traversal")),
            "pan_fragmentation": structured_xml_capture(entry.find("./protocol/fragmentation"))
                or structured_xml_capture(entry.find("./fragmentation")),
            "pan_dpd": structured_xml_capture(entry.find("./protocol/dpd"))
                or structured_xml_capture(entry.find("./dpd")),
            "pan_source_entry": structured_xml_capture(entry),
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
        phase1 = text_or_none(entry, "./auto-key/ike-gateway") or text_or_none(entry, "./ike-gateway") or ""
        crypto = text_or_none(entry, "./auto-key/ipsec-crypto-profile") or text_or_none(entry, "./ipsec-crypto-profile")
        attrs = sanitize_source_attributes({
            "pan_vpn_kind": "ipsec-tunnel",
            "pan_tunnel_interface": text_or_none(entry, "./tunnel-interface"),
            "pan_ike_gateway": phase1,
            "pan_ipsec_crypto_profile": crypto,
            "pan_keying_mode": "auto-key" if entry.find("./auto-key") is not None else (
                "manual-key" if entry.find("./manual-key") is not None else None
            ),
            "pan_protocol": text_or_none(entry, "./protocol"),
            "pan_ports": structured_xml_capture(entry.find("./ports")),
            "pan_anti_replay": structured_xml_capture(entry.find("./anti-replay")),
            "pan_copy_tos": text_or_none(entry, "./copy-tos"),
            "pan_tunnel_monitoring": structured_xml_capture(entry.find("./tunnel-monitoring")),
            "pan_proxy_ids": structured_xml_capture(entry.find("./auto-key/proxy-id")),
            "pan_source_entry": structured_xml_capture(entry),
        })
        _record(extraction, "vpn:ipsec_tunnel", path, scope, name, attrs)
        if name:
            ir.vpn_phase2.append(IRVPNPhase2(
                name=name, source_context=pan_scope_identity(scope), phase1_name=phase1,
                proposals=[crypto] if crypto else [],
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
