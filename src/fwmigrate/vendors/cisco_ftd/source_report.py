"""Cisco FTD vendor-native source extraction and reporting entry point."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, SourceSectionResult
from fwmigrate.extraction.sanitize import sanitize_raw_text

from .derived import FTDDerivedViews, build_ftd_derived_views
from .model import CiscoFTDConfig, CiscoFTDInterfaceSource, CiscoFTDRoute
from .cli.parser import CiscoFTDParser
from .validation import FTDValidationResult, validate_ftd_config


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_raw_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    fields = getattr(type(value), "model_fields", None)
    if fields is not None:
        for name in fields:
            setattr(value, name, _sanitize(getattr(value, name)))
    return value


@dataclass(frozen=True)
class FTDSourceResult:
    config: CiscoFTDConfig
    source_sections: list[Any]
    inventory_items: list[Any]
    unsupported_items: list[Any]
    derived: FTDDerivedViews
    validation: FTDValidationResult


def _text_source(text: str, zone_mapping: dict[str, str] | None) -> CiscoFTDConfig:
    config = CiscoFTDParser(text, zone_mapping=zone_mapping).parse_raw()
    config.input_source_type = config.source_plane = "ftd-text-evidence"
    config.source_metadata = {"authoritative": "device CLI/text evidence"}
    config.source_interfaces = [CiscoFTDInterfaceSource(
        name=item.name, source_plane="ftd-text-evidence", raw_extra={"raw_lines": item.raw_lines},
        interface_type=item.interface_type, address=item.ip, zone=zone_mapping.get(item.nameif, zone_mapping.get(item.name))
        if zone_mapping else None,
    ) for item in config.interfaces]
    config.routes = [CiscoFTDRoute(
        name=item.name, source_plane="ftd-text-evidence", raw_extra={"raw_line": item.raw_line},
        interface=item.interface, destination=item.destination, gateway=item.gateway,
    ) for item in config.static_routes]
    return config


def _inventory(config: CiscoFTDConfig) -> list[SourceInventoryItem]:
    def nat_rules(policy):
        for rules in (policy.manual_rules_before_auto, policy.auto_rules, policy.manual_rules_after_auto,
                      policy.unclassified_manual_rules, policy.rules):
            yield from rules or []

    collections = (
        ("network_addresses", "network-addresses"), ("network_groups", "network-groups"),
        ("protocol_port_objects", "protocol-port-objects"), ("port_object_groups", "port-object-groups"),
        ("applications", "applications"),
        ("variable_sets", "variable-sets"), ("url_categories", "url-categories"), ("vlan_objects", "vlan-objects"),
        ("security_zones", "security-zones"), ("interface_groups", "interface-groups"),
        ("device_interfaces", "device-interfaces"),
        ("source_interfaces", "interfaces"), ("routes", "routes"),
        ("access_control_policies", "access-control-policies"),
        ("time_ranges", "time-ranges"), ("intrusion_policies", "intrusion-policies"),
        ("intrusion_rule_overrides", "intrusion-rule-overrides"),
        ("decryption_policies", "decryption-policies"), ("dns_policies", "dns-policies"),
        ("fmc_user_roles", "fmc-user-roles"), ("fmc_users", "fmc-users"),
        ("dhcp_servers", "dhcp-servers"), ("realms", "realms"),
        ("realm_user_groups", "realm-user-groups"), ("realm_users", "realm-users"),
        ("local_realm_users", "local-realm-users"), ("s2s_vpn_topologies", "s2s-vpn-topologies"),
        ("s2s_vpn_endpoints", "s2s-vpn-endpoints"), ("ike_policies", "ike-policies"),
        ("ipsec_proposals", "ipsec-proposals"), ("ra_vpn_policies", "ra-vpn-policies"),
        ("ra_vpn_connection_profiles", "ra-vpn-connection-profiles"), ("native_resources", "native-resources"),
    )
    items = []
    for attribute, path in collections:
        for index, record in enumerate(getattr(config, attribute), 1):
            items.append(SourceInventoryItem(
                domain="cisco_ftd", source_path=f"{config.source_plane}/{path}",
                source_id=str(record.source_id or index), name=record.name,
                source_type=attribute[:-1], source_context=record.source_context,
                source_attributes={"source_plane": record.source_plane, "device_id": record.device_id,
                    "device_name": record.source_attributes.get("device_name"), "domain_id": record.domain_id,
                    **record.source_attributes},
                status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED,
                requires_manual_review=any(item.get("source_name") == record.name for item in config.unsupported_evidence),
            ))
    for policy_attribute, path in (("access_control_policies", "access-control-rules"),):
        for policy in getattr(config, policy_attribute):
            for index, record in enumerate(policy.rules or [], 1):
                items.append(SourceInventoryItem(domain="cisco_ftd", source_path=f"{config.source_plane}/{path}",
                    source_id=str(record.source_id or f"{policy.source_id or policy.name}:{index}"), name=record.name,
                    source_type="rule", source_context=record.source_context,
                    source_attributes={"source_plane": record.source_plane, "policy_id": policy.source_id,
                        "policy_name": policy.name, "section": getattr(record, "section", None), **record.source_attributes},
                    status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED))
    for policy in config.nat_policies:
        items.append(SourceInventoryItem(domain="cisco_ftd", source_path=f"{config.source_plane}/nat-policies",
            source_id=policy.source_id or policy.name, name=policy.name, source_type="nat-policy",
            source_context=policy.source_context, source_attributes={"source_plane": policy.source_plane,
                "domain_id": policy.domain_id},
            status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED))
        for index, record in enumerate(nat_rules(policy), 1):
            if hasattr(record, "original_network"):
                kind = "auto-nat-rule"
                section = "AUTO"
            elif hasattr(record, "original_source"):
                kind = "manual-nat-rule"
                section = None
            else:
                kind = "nat-rule"
                section = None
            if record in (policy.manual_rules_before_auto or []):
                section = "BEFORE_AUTO"
            elif record in (policy.manual_rules_after_auto or []):
                section = "AFTER_AUTO"
            items.append(SourceInventoryItem(domain="cisco_ftd", source_path=f"{config.source_plane}/nat-rules",
                source_id=record.source_id or f"{policy.source_id or policy.name}:{index}", name=record.name,
                source_type=kind, source_context=record.source_context,
                source_attributes={"source_plane": record.source_plane, "policy_id": policy.source_id,
                    "policy_name": policy.name, "section": getattr(record, "section", None) or section,
                    **record.source_attributes},
                status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED))
    return items


def extract_cisco_ftd_source(text: str, zone_mapping: dict[str, str] | None = None) -> FTDSourceResult:
    from .fdm.fdm_adapter import CiscoFDMBundleParser, is_fdm_bundle
    from .fmc.fmc_adapter import CiscoFMCBundleParser, is_fmc_bundle

    def source_count(config):
        return sum(len(getattr(config, field)) for field in (
            "network_addresses", "network_groups", "protocol_port_objects", "port_object_groups", "applications",
            "file_policies", "variable_sets", "url_categories", "vlan_objects", "security_zones", "interface_groups",
            "source_interfaces", "routes", "access_control_policies", "nat_policies")) + sum(
            len(policy.rules) for policy in config.access_control_policies) + sum(
            sum(len(rules or []) for rules in (policy.manual_rules_before_auto, policy.auto_rules, policy.manual_rules_after_auto,
                policy.unclassified_manual_rules, policy.rules)) for policy in config.nat_policies)

    if is_fmc_bundle(text):
        config = CiscoFMCBundleParser(text).parse_source()
        collection_status = config.collection_metadata.status
        sections = [SourceSectionResult(path="fmc/source", source_context=config.source_metadata.get("domain_name"),
                                         status=(ExtractionStatus.UNKNOWN if collection_status == "UNKNOWN" else
                                                 ExtractionStatus.PARTIAL if collection_status in {"PARTIAL", "FAILED"} else
                                                 ExtractionStatus.EXTRACTED),
                                         object_count_source=source_count(config), object_count_parsed=source_count(config),
                                         object_count_extracted=source_count(config))]
    elif is_fdm_bundle(text):
        config = CiscoFDMBundleParser(text).parse_source()
        sections = [SourceSectionResult(path="fdm/source", source_context=config.source_metadata.get("domain_name"),
                                         status=ExtractionStatus.EXTRACTED,
                                         object_count_source=source_count(config), object_count_parsed=source_count(config),
                                         object_count_extracted=source_count(config))]
    else:
        config = _text_source(text, zone_mapping)
        sections = [SourceSectionResult(path="ftd-cli/source", status=ExtractionStatus.SOURCE_ONLY,
                                         object_count_source=len(config.interfaces) + len(config.static_routes),
                                         object_count_parsed=len(config.interfaces) + len(config.static_routes),
                                         object_count_extracted=0)]
    config = _sanitize(deepcopy(config))
    collection = config.collection_metadata
    if config.source_plane == "fmc-rest-bundle" and collection.status in {"PARTIAL", "FAILED"}:
        sections.append(SourceSectionResult(path="fmc/collection", status=ExtractionStatus.PARTIAL,
            source_context=config.source_metadata.get("domain_name"), object_count_source=len(collection.parts),
            object_count_parsed=len(collection.parts), object_count_extracted=sum(part.complete for part in collection.parts),
            collection_errors=[f"{part.name}: {part.status}" for part in collection.parts if not part.complete]))
    derived = build_ftd_derived_views(config)
    validation = validate_ftd_config(config, derived)
    return FTDSourceResult(config, sections, _inventory(config), config.unsupported_evidence, derived, validation)


class CiscoFTDSourceReporter:
    vendor_id = "cisco_ftd"
    display_name = "Cisco Firepower Threat Defense"
    supported_extensions = (".cfg", ".txt", ".conf", ".json")

    def analyze_source(self, source: str, **options: Any) -> FTDSourceResult:
        return extract_cisco_ftd_source(source, zone_mapping=options.get("zone_mapping"))

    def build_preview(self, analysis: FTDSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_ftd_preview
        return build_ftd_preview(analysis)

    def export_excel(self, analysis: FTDSourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_ftd_excel
        return export_ftd_excel(analysis, output)


__all__ = ["CiscoFTDSourceReporter", "FTDSourceResult", "extract_cisco_ftd_source"]
