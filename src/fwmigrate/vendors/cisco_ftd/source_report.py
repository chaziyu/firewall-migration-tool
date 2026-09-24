"""Cisco FTD vendor-native source extraction and reporting entry point."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, SourceSectionResult
from fwmigrate.extraction.sanitize import sanitize_raw_text

from .derived import FTDDerivedViews, build_ftd_derived_views
from .model import CiscoFTDConfig
from .cli.parser import CiscoFTDParser
from .cli.section_scanner import scan_cisco_ftd_sections
from .cli.coverage import classify_cisco_ftd_coverage
from .validation import FTDValidationResult, validate_ftd_config
from .reporting_counts import count_acp_rules, count_nat_rules


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
    return config


def _inventory(config: CiscoFTDConfig) -> list[SourceInventoryItem]:
    def nat_rules(policy):
        for rules in (policy.manual_rules_before_auto, policy.auto_rules, policy.manual_rules_after_auto,
                      policy.unclassified_manual_rules, policy.rules):
            yield from rules or []

    collections = (
        ("network_addresses", "network-addresses"), ("network_address_overrides", "network-address-overrides"),
        ("network_groups", "network-groups"),
        ("protocol_port_objects", "protocol-port-objects"), ("port_object_groups", "port-object-groups"),
        ("applications", "applications"),
        ("virtual_routers", "virtual-routers"), ("policy_based_routes", "policy-based-routes"),
        ("ecmp_zones", "ecmp-zones"), ("sla_monitors", "sla-monitors"),
        ("certificates", "certificates"), ("certificate_maps", "certificate-maps"),
        ("certificate_enrollments", "certificate-enrollments"), ("address_pools", "address-pools"),
        ("group_policies", "group-policies"),
        ("s2s_ike_settings", "s2s-ike-settings"), ("s2s_ipsec_settings", "s2s-ipsec-settings"),
        ("s2s_advanced_settings", "s2s-advanced-settings"),
        ("ra_vpn_ipsec_settings", "ra-vpn-ipsec-settings"), ("ldap_attribute_maps", "ldap-attribute-maps"),
        ("ra_vpn_load_balance_settings", "ra-vpn-load-balance-settings"),
        ("ra_vpn_address_assignment_settings", "ra-vpn-address-assignment-settings"),
        ("secure_client_settings", "secure-client-settings"), ("ra_vpn_ipsec_crypto_maps", "ra-vpn-ipsec-crypto-maps"),
        ("prefilter_policies", "prefilter-policies"), ("prefilter_rules", "prefilter-rules"),
        ("prefilter_default_actions", "prefilter-default-actions"),
        ("network_analysis_policies", "network-analysis-policies"), ("inspector_configs", "inspector-configs"),
        ("inspector_override_configs", "inspector-override-configs"),
        ("variable_sets", "variable-sets"), ("url_categories", "url-categories"), ("vlan_objects", "vlan-objects"),
        ("security_zones", "security-zones"), ("interface_groups", "interface-groups"),
        ("device_interfaces", "device-interfaces"),
        ("source_interfaces", "interfaces"), ("routes", "routes"),
        ("access_control_policies", "access-control-policies"),
        ("identity_policies", "identity-policies"),
        ("access_control_default_actions", "access-control-default-actions"),
        ("access_policy_inheritance_settings", "access-policy-inheritance-settings"),
        ("policy_assignments", "policy-assignments"),
        ("time_ranges", "time-ranges"), ("intrusion_policies", "intrusion-policies"),
        ("intrusion_rule_groups", "intrusion-rule-groups"),
        ("intrusion_rule_behaviors", "intrusion-rule-behaviors"),
        ("intrusion_rule_overrides", "intrusion-rule-overrides"),
        ("file_policies", "file-policies"),
        ("decryption_policies", "decryption-policies"), ("dns_policies", "dns-policies"),
        ("fmc_user_roles", "fmc-user-roles"), ("fmc_users", "fmc-users"),
        ("dhcp_servers", "dhcp-servers"), ("dhcp_relay_settings", "dhcp-relay-settings"), ("realms", "realms"),
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
                    "explicit_fields": list(record.explicit_fields),
                    **record.source_attributes},
                status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED,
                requires_manual_review=any(item.get("source_name") == record.name for item in config.unsupported_evidence),
            ))
    for policies, path in ((config.file_policies, "file-policy-rules"),
                           (config.decryption_policies, "decryption-policy-rules"),
                           (config.dns_policies, "dns-policy-rules")):
        for policy in policies:
            for index, rule in enumerate(policy.rules or [], 1):
                items.append(SourceInventoryItem(domain="cisco_ftd",
                    source_path=f"{config.source_plane}/{path}",
                    source_id=str(rule.source_id or f"{policy.source_id or policy.name}:{index}"),
                    name=rule.name, source_type="policy-rule",
                    source_context=rule.source_context,
                    source_attributes={"source_plane": rule.source_plane, "domain_id": rule.domain_id,
                        "policy_id": rule.parent_policy_id, "policy_name": rule.parent_policy_name,
                        "position": rule.position, "collection_order": rule.collection_order}))
    if config.source_plane == "ftd-text-evidence":
        for path, records, kind in (("interfaces", config.interfaces, "interface"),
                                    ("routes", config.static_routes, "static-route")):
            for record in records:
                items.append(SourceInventoryItem(domain="cisco_ftd", source_path=f"ftd-cli/{path}",
                    source_id=str(record.source_attributes.get("source_line_number", record.name)), name=record.name,
                    source_type=kind, source_attributes={"source_plane": config.source_plane,
                        "explicit_fields": list(getattr(record, "explicit_fields", ())),
                        "raw_lines": getattr(record, "raw_lines", None),
                        "raw_line": getattr(record, "raw_line", None), **record.source_attributes},
                    status=ExtractionStatus.SOURCE_ONLY,
                    requires_manual_review=any(item.get("source_name") == record.name for item in config.unsupported_evidence)))
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
        if not policy.source_attributes.get("synthetic_container"):
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
            "network_addresses", "network_address_overrides", "network_groups", "protocol_port_objects", "port_object_groups", "applications",
            "file_policies", "variable_sets", "url_categories", "vlan_objects", "security_zones", "interface_groups",
            "intrusion_policies", "intrusion_rule_groups", "intrusion_rule_behaviors", "intrusion_rule_overrides",
            "dhcp_servers", "dhcp_relay_settings", "access_control_default_actions",
            "access_policy_inheritance_settings", "policy_assignments", "decryption_policies", "dns_policies",
            "source_interfaces", "routes", "access_control_policies", "identity_policies", "nat_policies")) + count_acp_rules(config) + count_nat_rules(config) + sum(
                len(policy.rules or []) for policy in (*config.file_policies, *config.decryption_policies, *config.dns_policies))

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
        sections = scan_cisco_ftd_sections(text)
        classify_cisco_ftd_coverage(sections)
        interfaces = {item.source_attributes.get("source_line_number"): item for item in config.interfaces}
        routes = {item.source_attributes.get("source_line_number"): item for item in config.static_routes}
        management = {item.source_attributes.get("source_line_number"): item for item in config.management_settings}
        for section in sections:
            line = section.line_start
            if section.path == "interfaces":
                parsed = interfaces.get(line)
                section.object_count_parsed = int(parsed is not None)
                section.object_count_extracted = section.object_count_parsed
                if parsed is None:
                    section.status = ExtractionStatus.PARSE_ERROR
                    section.object_count_parse_error = 1
                    section.notes.append("Interface section was not parsed into Cisco FTD source state.")
            elif section.path == "routes":
                parsed = routes.get(line)
                malformed = parsed is not None and any(
                    item.get("source_name") == parsed.name and item.get("source_path") == "ftd-cli/routes"
                    for item in config.unsupported_evidence
                )
                section.object_count_parsed = int(parsed is not None and not malformed)
                section.object_count_extracted = int(parsed is not None and not malformed)
                if malformed:
                    section.status = ExtractionStatus.PARSE_ERROR
                    section.object_count_parse_error = 1
                    section.notes.append("Malformed FTD static route was preserved as source evidence.")
                elif parsed is None:
                    section.status = ExtractionStatus.PARSE_ERROR
                    section.object_count_parse_error = 1
                    section.notes.append("Route section was not parsed into Cisco FTD source state.")
            elif section.path == "management":
                section.object_count_parsed = int(line in management)
                section.object_count_extracted = 0
            else:
                section.object_count_parsed = 0
                section.object_count_extracted = 0
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
