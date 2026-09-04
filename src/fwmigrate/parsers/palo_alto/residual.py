"""Path-level residual accounting for PAN-OS XML."""

from __future__ import annotations

from typing import Iterable
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_unsupported, record_vendor_extension
from .management_access import SYSTEM_PATHS
from .system_settings import SYSTEM_SETTINGS_HANDLED_CHILDREN
from .source_model import PANScope
from .xml_utils import structured_xml_capture


class PANResidualExtractor:
    POLICY_CONTAINERS = ("rulebase", "pre-rulebase", "post-rulebase")
    HANDLED_POLICY_FAMILIES = {
        "security", "nat", "default-security-rules", "decryption",
        "application-override", "authentication", "pbf", "qos", "dos",
        "tunnel-inspect", "tunnel-inspection", "sdwan", "network-packet-broker",
    }
    HANDLED_SCOPE_CHILDREN = {
        "zone", "address", "address-group", "service", "service-group",
        "schedule", "application", "application-group", "application-filter",
        "tag", "profile-group", "external-dynamic-list", "profiles",
        "security-profiles", "template", "template-stack", "ike", "ipsec",
        "region", "regions", "device-id", "device-id-objects", "device-identification",
        "device-objects", "import", *POLICY_CONTAINERS,
    }
    VENDOR_EXTENSION_CHILDREN = {"property", "setting", "log-settings", "reports"}
    HANDLED_INTERFACE_FAMILIES = {
        "ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan",
    }

    @staticmethod
    def _entries(node: ET.Element) -> Iterable[ET.Element]:
        entries = node.findall("./rules/entry")
        if entries:
            return entries
        entries = node.findall("./entry")
        return entries or [node]

    @staticmethod
    def extract_policy_residuals(scope: PANScope, search_root: ET.Element, extraction) -> None:
        for container_name in PANResidualExtractor.POLICY_CONTAINERS:
            container = search_root.find(f"./{container_name}")
            if container is None:
                continue
            for family in container:
                if family.tag in PANResidualExtractor.HANDLED_POLICY_FAMILIES:
                    continue
                entries = list(PANResidualExtractor._entries(family))
                for index, entry in enumerate(entries):
                    name = entry.get("name") or family.tag
                    suffix = f"/rules/entry[@name='{name}']" if entry.tag == "entry" else ""
                    path = f"{container_name}/{family.tag}{suffix}"
                    record_unsupported(
                        extraction, f"policy:{family.tag}", path, scope, name,
                        {"pan_source_entry": structured_xml_capture(entry),
                         "pan_rulebase_position": container_name,
                         "pan_source_rule_index": index},
                        notes=[f"PAN-OS {family.tag} policy extraction is not implemented."],
                    )
                add_source_section(
                    extraction, f"{container_name}/{family.tag}", ExtractionStatus.UNSUPPORTED,
                    len(entries), len(entries), 0,
                    "PANResidualExtractor.extract_policy_residuals",
                    source_context=f"{scope.kind}:{scope.name}",
                )

    @staticmethod
    def extract_scope_residuals(scope: PANScope, search_root: ET.Element, extraction) -> None:
        for child in search_root:
            if child.tag in PANResidualExtractor.HANDLED_SCOPE_CHILDREN:
                continue
            status = (
                ExtractionStatus.VENDOR_EXTENSION
                if child.tag in PANResidualExtractor.VENDOR_EXTENSION_CHILDREN
                else ExtractionStatus.UNSUPPORTED
            )
            entries = list(PANResidualExtractor._entries(child))
            for entry in entries:
                name = entry.get("name") or child.tag
                path = f"{child.tag}/entry[@name='{name}']" if entry.tag == "entry" else child.tag
                recorder = record_vendor_extension if status == ExtractionStatus.VENDOR_EXTENSION else record_unsupported
                recorder(
                    extraction, child.tag, path, scope, name,
                    {"pan_source_entry": structured_xml_capture(entry)},
                    notes=[f"Unhandled PAN-OS source subtree: {child.tag}."],
                )
            add_source_section(
                extraction, child.tag, status, len(entries), len(entries), 0,
                "PANResidualExtractor.extract_scope_residuals",
                source_context=f"{scope.kind}:{scope.name}",
            )

    @staticmethod
    def extract_network_residuals(scope: PANScope, network_root: ET.Element, extraction) -> None:
        for child in network_root:
            if child.tag == "profiles":
                # Interface management profiles have a dedicated source-only
                # extractor.  Keep other network profile families visible.
                for profile_family in child:
                    if profile_family.tag == "interface-management-profile":
                        continue
                    path = f"network/profiles/{profile_family.tag}"
                    entries = list(PANResidualExtractor._entries(profile_family))
                    for entry in entries:
                        name = entry.get("name") or profile_family.tag
                        entry_path = (
                            f"{path}/entry[@name='{name}']"
                            if entry.tag == "entry" else path
                        )
                        record_unsupported(
                            extraction, "network", entry_path, scope, name,
                            {"pan_source_entry": structured_xml_capture(entry)},
                            notes=[f"PAN-OS network profile family {profile_family.tag} is not implemented."],
                        )
                    if entries:
                        add_source_section(
                            extraction, path, ExtractionStatus.UNSUPPORTED,
                            len(entries), len(entries), 0,
                            "PANResidualExtractor.extract_network_residuals",
                            source_context=f"{scope.kind}:{scope.name}",
                        )
                continue
            if child.tag in {"virtual-router", "logical-router"}:
                # Advanced routing nests all meaningful configuration below
                # logical-router/entry/vrf/entry.  Treat each VRF as its own
                # context so valid VRFs are not misreported as unsupported
                # logical-router children.
                for routing_entry in child.findall("./entry"):
                    router_name = routing_entry.get("name") or "<unnamed>"
                    contexts = [(routing_entry, f"network/{child.tag}/entry[@name='{router_name}']")]
                    if child.tag == "logical-router":
                        contexts = [
                            (vrf, f"network/logical-router/entry[@name='{router_name}']/vrf/entry[@name='{vrf.get('name') or '<unnamed>'}']")
                            for vrf in routing_entry.findall("./vrf/entry")
                        ]
                        if not contexts:
                            contexts = [(routing_entry, f"network/logical-router/entry[@name='{router_name}']")]
                    for context_node, context_path in contexts:
                        for routing_child in context_node:
                            if routing_child.tag in {"routing-table", "interface", "admin-dists", "protocol", "routing-protocol"}:
                                continue
                            path = f"{context_path}/{routing_child.tag}"
                            record_unsupported(
                                extraction, "network", path, scope, router_name,
                                {"pan_source_entry": structured_xml_capture(routing_child)},
                                notes=[f"PAN-OS {child.tag} routing child {routing_child.tag} is not normalized."],
                            )
                continue
            if child.tag in {"ike", "ipsec"}:
                # Dedicated VPN extraction retains the complete sanitized
                # object subtree.  Unknown descendants are therefore visible
                # in that source-only record instead of being double-counted
                # as an unrelated network residual.
                continue
            if child.tag == "interface":
                for family in child:
                    if family.tag in PANResidualExtractor.HANDLED_INTERFACE_FAMILIES:
                        continue
                    path = f"network/interface/{family.tag}"
                    record_unsupported(
                        extraction, "interfaces", path, scope, family.tag,
                        {"pan_source_entry": structured_xml_capture(family)},
                        notes=[f"PAN-OS interface family {family.tag} is not implemented."],
                    )
                continue
            path = f"network/{child.tag}"
            record_unsupported(
                extraction, "network", path, scope, child.tag,
                {"pan_source_entry": structured_xml_capture(child)},
                notes=[f"PAN-OS network subtree {child.tag} is not normalized."],
            )
            add_source_section(
                extraction, path, ExtractionStatus.UNSUPPORTED, 1, 1, 0,
                "PANResidualExtractor.extract_network_residuals",
                source_context=f"{scope.kind}:{scope.name}",
            )

    @staticmethod
    def extract_device_system_residuals(
        scope: PANScope, device_root: ET.Element, extraction
    ) -> None:
        system_root = device_root.find("./deviceconfig/system")
        if system_root is None:
            return

        handled = set(SYSTEM_PATHS) | SYSTEM_SETTINGS_HANDLED_CHILDREN
        for child in system_root:
            if child.tag in handled:
                continue
            path = f"deviceconfig/system/{child.tag}"
            entries = list(PANResidualExtractor._entries(child))
            for entry in entries:
                name = entry.get("name") or child.tag
                entry_path = (
                    f"{path}/entry[@name='{name}']"
                    if entry.tag == "entry" else path
                )
                record_unsupported(
                    extraction, "deviceconfig", entry_path, scope, name,
                    {"pan_source_entry": structured_xml_capture(entry)},
                    notes=[f"Unhandled PAN-OS device system subtree: {child.tag}."],
                )
            add_source_section(
                extraction, path, ExtractionStatus.UNSUPPORTED,
                len(entries), len(entries), 0,
                "PANResidualExtractor.extract_device_system_residuals",
                source_context=f"{scope.kind}:{scope.name}",
            )

    # Backward-compatible alias used by older callers.
    extract_residual_scope = extract_scope_residuals
