"""Cisco FTD source inventory projection."""

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from .model import CiscoFTDConfig


def build_ftd_source_inventory(config: CiscoFTDConfig) -> list[SourceInventoryItem]:
    def source_name(record):
        return record.name if record.source_attributes.get("source_name_explicit", True) else None

    def record_id(path: str, index: int, record, parent_id: str | None = None) -> str:
        attributes = record.source_attributes
        scope = [
            f"domain={record.domain_id}" if record.domain_id else None,
            f"device={record.device_id or attributes.get('device_id')}" if record.device_id or attributes.get("device_id") else None,
            f"virtual-router={attributes.get('virtual_router_id')}" if attributes.get("virtual_router_id") else None,
            f"parent={parent_id or attributes.get('parent_policy_id') or attributes.get('parent_topology_id')}"
            if parent_id or attributes.get("parent_policy_id") or attributes.get("parent_topology_id") else None,
        ]
        identity = f"id={record.source_id}" if record.source_id else f"index={index}"
        return "/".join([config.source_plane, *[item for item in scope if item], path, identity])

    irregular_source_types = {
        "network_addresses": "network_address",
        "access_control_policies": "access_control_policy",
        "security_intelligence_policies": "security_intelligence_policy",
        "identity_policies": "identity_policy",
        "intrusion_policies": "intrusion_policy",
        "file_policies": "file_policy",
        "decryption_policies": "decryption_policy",
        "dns_policies": "dns_policy",
        "group_policies": "group_policy",
        "s2s_vpn_topologies": "s2s_vpn_topology",
        "ike_policies": "ike_policy",
        "ra_vpn_policies": "ra_vpn_policy",
        "prefilter_policies": "prefilter_policy",
        "network_analysis_policies": "network_analysis_policy",
        "url_categories": "url_category",
    }

    def source_type(attribute: str, record) -> str:
        if attribute == "native_resources":
            native_type = record.source_attributes.get("resource_type")
            if native_type:
                return str(native_type)
        return irregular_source_types.get(
            attribute, attribute[:-1] if attribute.endswith("s") else attribute)

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
        ("access_control_logging_settings", "access-control-logging-settings"),
        ("security_intelligence_policies", "security-intelligence-policies"),
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
    review_records = [
        record
        for attribute, _path in collections
        for record in getattr(config, attribute)
    ]
    review_records.extend(
        rule
        for policies in (config.file_policies, config.decryption_policies, config.dns_policies)
        for policy in policies
        for rule in (policy.rules or ())
    )
    review_records.extend(
        rule for policy in config.access_control_policies for rule in (policy.rules or ())
    )
    review_records.extend(
        rule for policy in config.nat_policies for rule in nat_rules(policy)
    )
    name_counts: dict[str, int] = {}
    for record in review_records:
        explicit_name = source_name(record)
        if explicit_name:
            name_counts[explicit_name] = name_counts.get(explicit_name, 0) + 1

    def evidence_matches(record, evidence: dict) -> bool:
        evidence_id = evidence.get("source_id") or evidence.get("id")
        if evidence_id is not None:
            if record.source_id is None or str(record.source_id) != str(evidence_id):
                return False
        else:
            evidence_name = evidence.get("source_name")
            if evidence_name is None or source_name(record) != evidence_name:
                return False
            if name_counts.get(str(evidence_name), 0) > 1 and not any(
                evidence.get(key) is not None for key in ("source_context", "domain_id", "device_id")
            ):
                return False
        for key, actual in (
            ("source_context", getattr(record, "source_context", None)),
            ("domain_id", getattr(record, "domain_id", None)),
            ("device_id", getattr(record, "device_id", None) or record.source_attributes.get("device_id")),
        ):
            if evidence.get(key) is not None and str(evidence[key]) != str(actual):
                return False
        return True

    items = []
    for attribute, path in collections:
        for index, record in enumerate(getattr(config, attribute), 1):
            items.append(SourceInventoryItem(
                domain="cisco_ftd", source_path=f"{config.source_plane}/{path}",
                source_id=record.source_id, source_record_id=record_id(path, index, record), name=source_name(record),
                source_type=source_type(attribute, record), source_context=record.source_context,
                source_attributes={"source_plane": record.source_plane, "device_id": record.device_id,
                    "device_name": record.source_attributes.get("device_name"), "domain_id": record.domain_id,
                    "explicit_fields": list(record.explicit_fields),
                    **record.source_attributes},
                status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED,
                requires_manual_review=any(evidence_matches(record, item) for item in config.unsupported_evidence),
            ))
    for policies, path in ((config.file_policies, "file-policy-rules"),
                           (config.decryption_policies, "decryption-policy-rules"),
                           (config.dns_policies, "dns-policy-rules")):
        for policy_index, policy in enumerate(policies, 1):
            parent_record_id = policy.source_id or record_id(path.removesuffix("-rules"), policy_index, policy)
            for index, rule in enumerate(policy.rules or [], 1):
                items.append(SourceInventoryItem(domain="cisco_ftd",
                    source_path=f"{config.source_plane}/{path}",
                    source_id=rule.source_id,
                    source_record_id=record_id(path, index, rule, parent_record_id),
                    name=source_name(rule), source_type="policy-rule",
                    source_context=rule.source_context,
                    source_attributes={"source_plane": rule.source_plane, "domain_id": rule.domain_id,
                        "policy_id": rule.parent_policy_id, "policy_name": rule.parent_policy_name,
                        "position": rule.position, "collection_order": rule.collection_order},
                    requires_manual_review=any(evidence_matches(rule, item) for item in config.unsupported_evidence)))
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
                    requires_manual_review=any(evidence_matches(record, item) for item in config.unsupported_evidence)))
    for policy_attribute, path in (("access_control_policies", "access-control-rules"),):
        for policy_index, policy in enumerate(getattr(config, policy_attribute), 1):
            parent_record_id = policy.source_id or record_id("access-control-policies", policy_index, policy)
            for index, record in enumerate(policy.rules or [], 1):
                items.append(SourceInventoryItem(domain="cisco_ftd", source_path=f"{config.source_plane}/{path}",
                    source_id=record.source_id,
                    source_record_id=record_id(path, index, record, parent_record_id), name=source_name(record),
                    source_type="rule", source_context=record.source_context,
                    source_attributes={"source_plane": record.source_plane, "policy_id": policy.source_id,
                        "policy_name": policy.name, "section": getattr(record, "section", None), **record.source_attributes},
                    status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED,
                    requires_manual_review=any(evidence_matches(record, item) for item in config.unsupported_evidence)))
    for policy_index, policy in enumerate(config.nat_policies, 1):
        policy_record_id = record_id("nat-policies", policy_index, policy)
        if not policy.source_attributes.get("synthetic_container"):
            items.append(SourceInventoryItem(domain="cisco_ftd", source_path=f"{config.source_plane}/nat-policies",
            source_id=policy.source_id, source_record_id=policy_record_id,
            name=source_name(policy), source_type="nat-policy",
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
                source_id=record.source_id,
                source_record_id=record_id("nat-rules", index, record, policy.source_id or policy_record_id), name=source_name(record),
                source_type=kind, source_context=record.source_context,
                source_attributes={"source_plane": record.source_plane, "policy_id": policy.source_id,
                    "policy_name": policy.name, "section": getattr(record, "section", None) or section,
                    **record.source_attributes},
                status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED,
                requires_manual_review=any(evidence_matches(record, item) for item in config.unsupported_evidence)))
    return items


