"""Vendor-native adapter for offline FMC REST bundles."""

from __future__ import annotations

import json
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..model import (
    CiscoFTDAccessControlRule, CiscoFTDAccessControlPolicy, CiscoFTDConfig,
    CiscoFTDInterfaceGroup, CiscoFTDNetworkAddress, CiscoFTDNetworkGroup, CiscoFTDPortObjectGroup,
    CiscoFTDProtocolPortObject, CiscoFTDReference, CiscoFTDSecurityZone, CiscoFTDNativeResource,
    CiscoFTDManualNATRule, CiscoFTDAutoNATRule, CiscoFTDNATPolicy,
    CiscoFTDTimeRange, CiscoFTDIntrusionPolicy, CiscoFTDIntrusionRuleOverride,
    CiscoFTDFilePolicy, CiscoFTDDecryptionPolicy, CiscoFTDDNSPolicy, CiscoFTDInterfaceSource,
    CiscoFTDFMCUserRole, CiscoFTDFMCUser, CiscoFTDDHCPServer, CiscoFTDRealm,
    CiscoFTDRealmUserGroup, CiscoFTDRealmUser, CiscoFTDLocalRealmUser,
    CiscoFTDS2SVPNTopology, CiscoFTDS2SVPNEndpoint, CiscoFTDIKEPolicy,
    CiscoFTDIPsecProposal, CiscoFTDRAVPNPolicy, CiscoFTDRAVPNConnectionProfile,
    CiscoFTDRoute, CiscoFTDApplication, CiscoFTDVariableSet, CiscoFTDURLCategory, CiscoFTDVLANObject,
    CiscoFTDCollectionMetadata, CiscoFTDCollectionPart,
)

FMC_BUNDLE_FORMAT = "cisco-fmc-rest-export-v1"


def _items(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, dict)]
    return []


def is_fmc_bundle(content: str) -> bool:
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return False
    return isinstance(payload, dict) and (
        payload.get("format") == FMC_BUNDLE_FORMAT
        or (
            any(key in payload for key in ("access_policies", "nat_policies", "objects"))
            and payload.get("source") in {"fmc-rest-api", "cisco-fmc-rest-api"}
        )
    )


class CiscoFMCBundleParser:
    """Decode authoritative FMC API data into Cisco FTD source state."""

    def __init__(self, content: str):
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("FMC bundle must be a JSON object")
        if payload.get("format") not in {None, FMC_BUNDLE_FORMAT}:
            raise ValueError(f"Unsupported FMC bundle format: {payload.get('format')!r}")
        self.payload = payload
        domain = payload.get("domain") if isinstance(payload.get("domain"), dict) else {}
        self.domain_id = domain.get("id") or payload.get("domainUUID")
        self.domain_name = domain.get("name") or "Global"
        self.context = f"fmc:{self.domain_name}"

    def _object_collections(self) -> dict[str, list[dict]]:
        objects = self.payload.get("objects") if isinstance(self.payload.get("objects"), dict) else {}
        names = (
            "networkaddresses", "hosts", "networks", "ranges", "fqdnobjects", "networkgroups", "protocolportobjects",
            "portobjectgroups", "securityzones", "interfacegroups",
            "applications", "timeranges", "users", "ips", "filepolicies", "decryptionpolicies", "dnspolicies", "intrusionpolicies",
            "realms", "realmusergroups", "realmusers", "localrealmusers", "s2svpns", "ravpns", "variablesets",
            "urlcategories", "vlanobjects",
        )
        return {name: _items(objects.get(name)) for name in names}

    def parse_source(self) -> CiscoFTDConfig:
        objects = self._object_collections()
        plane = "fmc-rest-bundle"
        collection = self.payload.get("collection")
        collection_provided = isinstance(collection, dict)
        collection = collection if collection_provided else {}
        collection_metadata = CiscoFTDCollectionMetadata(
            status=str(collection.get("status") or "UNKNOWN"), provided=collection_provided,
            parts=[CiscoFTDCollectionPart(
                name=str(part.get("name", "unknown")), status=str(part.get("status", "UNKNOWN")),
                complete=part.get("complete", False), count=part.get("count"),
            ) for part in _items(collection.get("parts"))],
        )

        def name(item: dict, index: int) -> str:
            return str(item.get("name") or item.get("id") or index)

        def reference(value: Any) -> CiscoFTDReference:
            if isinstance(value, dict):
                return CiscoFTDReference(source_id=str(value["id"]) if value.get("id") is not None else None,
                    name=str(value["name"]) if value.get("name") is not None else None,
                    source_type=value.get("type") or value.get("objectType"), value=value.get("value"),
                    source_attributes=sanitize_source_attributes({key: item for key, item in value.items()
                                                                  if key not in {"id", "name", "type", "objectType", "value"}}))
            return CiscoFTDReference(name=str(value))

        def refs(value: Any) -> list[CiscoFTDReference]:
            if isinstance(value, dict):
                value = [value]
            return [reference(item) for item in (value or [])]

        def refs_field(item: dict, *keys: str) -> list[CiscoFTDReference] | None:
            key = next((key for key in keys if key in item), None)
            return refs(item[key]) if key is not None else None

        def acp_refs(item: dict, key: str) -> list[CiscoFTDReference] | None:
            if key not in item:
                return None
            value = item[key]
            if isinstance(value, dict) and ("objects" in value or "literals" in value):
                return refs([*_items(value.get("objects")), *_items(value.get("literals"))])
            if isinstance(value, dict) and not any(value.get(field) for field in ("id", "name", "value")):
                return []
            return refs(value)

        def record(item: dict, index: int, cls, **values):
            attributes = {"provenance": "FMC REST", "domain_id": self.domain_id}
            attributes.update(values.pop("source_attributes", {}))
            return cls(
                name=name(item, index), source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, domain_id=self.domain_id,
                raw_extra=sanitize_source_attributes(item),
                source_attributes=attributes,
                **values,
            )

        # Newer FMC bundles use networkaddresses; older exports split hosts/networks/ranges.
        if objects.get("networkaddresses"):
            objects["hosts"] = objects["networks"] = objects["ranges"] = []
        network_groups = [
            record(item, index, CiscoFTDNetworkGroup, members=refs_field(item, "objects", "members"))
            for index, item in enumerate(objects.get("networkgroups", []), 1)
        ]
        network_address_items = objects.get("networkaddresses") or [
            *objects.get("hosts", []), *objects.get("networks", []), *objects.get("ranges", []), *objects.get("fqdnobjects", [])]
        network_addresses = [record(item, index, CiscoFTDNetworkAddress, address_type=item.get("type"), value=item.get("value"))
            for index, item in enumerate(network_address_items, 1)]
        protocol_ports = [
            record(item, index, CiscoFTDProtocolPortObject, protocol=item.get("protocol"), ports=item.get("ports"))
            for index, item in enumerate(objects.get("protocolportobjects", []), 1)
        ]
        port_groups = [
            record(item, index, CiscoFTDPortObjectGroup, members=refs_field(item, "objects", "members"))
            for index, item in enumerate(objects.get("portobjectgroups", []), 1)
        ]
        zones = [
            record(item, index, CiscoFTDSecurityZone, interfaces=refs_field(item, "interfaces"))
            for index, item in enumerate(objects.get("securityzones", []), 1)
        ]
        interface_groups = [record(item, index, CiscoFTDInterfaceGroup, interfaces=refs_field(item, "interfaces", "members"))
            for index, item in enumerate(objects.get("interfacegroups", []), 1)]
        interfaces = [record(item, index, CiscoFTDDeviceInterface,
            interface_type=item.get("type"), address=item.get("address"),
            zone=reference(item["securityZone"]) if item.get("securityZone") else None)
            for index, item in enumerate(objects.get("interfaces", []), 1)]
        acp_policies = []
        for policy_index, policy in enumerate(_items(self.payload.get("access_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            acp_rules = []
            for rule_index, item in enumerate(_items(policy.get("rules")), 1):
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                apps = item.get("applications") if isinstance(item.get("applications"), dict) else {}
                urls = item.get("urls") if isinstance(item.get("urls"), dict) else {}
                url_categories = urls.get("urlCategoriesWithReputation")
                if "urlCategoriesWithReputation" in urls:
                    url_categories = [entry.get("category", entry) if isinstance(entry, dict) else entry for entry in _items(url_categories)]
                acp_values = {
                    "policy_id": str(policy.get("id")) if policy.get("id") is not None else None,
                    "policy_name": policy_name,
                    "enabled": item.get("enabled"),
                    "position": item.get("position", metadata.get("ruleIndex")),
                    "collection_order": rule_index,
                    "section": metadata.get("section"),
                    "category": metadata.get("category"),
                    "action": item.get("action"),
                    "comments": item.get("comments"),
                    "source_zones": acp_refs(item, "sourceZones"),
                    "destination_zones": acp_refs(item, "destinationZones"),
                    "source_networks": acp_refs(item, "sourceNetworks"),
                    "destination_networks": acp_refs(item, "destinationNetworks"),
                    "source_ports": acp_refs(item, "sourcePorts"),
                    "destination_ports": acp_refs(item, "destinationPorts"),
                    "source_dynamic_objects": acp_refs(item, "sourceDynamicObjects"),
                    "destination_dynamic_objects": acp_refs(item, "destinationDynamicObjects"),
                    "vlan_tags": acp_refs(item, "vlanTags"),
                    "source_security_group_tags": acp_refs(item, "sourceSecurityGroupTags"),
                    "destination_security_group_tags": acp_refs(item, "destinationSecurityGroupTags"),
                    "realm": reference(item["realm"]) if "realm" in item and item["realm"] is not None else None,
                    "realm_users": acp_refs(item, "realmUsers"),
                    "users": acp_refs(item, "users"),
                    "user_groups": acp_refs(item, "realmUserGroups"),
                    "applications": acp_refs(apps, "applications"),
                    "application_filters": acp_refs(apps, "applicationFilters"),
                    "inline_application_filters": acp_refs(apps, "inlineApplicationFilters"),
                    "urls": sanitize_source_attributes(urls) if "urls" in item else None,
                    "url_categories": refs(url_categories) if url_categories is not None else None,
                    "time_range": reference(item["timeRange"]) if item.get("timeRange") is not None else None,
                    "intrusion_policy": reference(item["ipsPolicy"]) if item.get("ipsPolicy") is not None else None,
                    "variable_set": reference(item["variableSet"]) if item.get("variableSet") is not None else None,
                    "file_policy": reference(item["filePolicy"]) if item.get("filePolicy") is not None else None,
                    "log_begin": item.get("logBegin"),
                    "log_end": item.get("logEnd"),
                    "logging": sanitize_source_attributes({key: item[key] for key in ("logFiles", "sendEventsToFMC", "enableSyslog", "advancedLogging") if key in item}) or None,
                    "source_attributes": {"policy_id": policy.get("id"), "policy_name": policy_name},
                }
                acp_values["explicit_fields"] = [key for key, present in (
                    ("enabled", "enabled" in item), ("position", "position" in item or "ruleIndex" in metadata),
                    ("section", "section" in metadata), ("category", "category" in metadata),
                    ("action", "action" in item), ("comments", "comments" in item),
                    ("source_zones", "sourceZones" in item), ("destination_zones", "destinationZones" in item),
                    ("source_networks", "sourceNetworks" in item), ("destination_networks", "destinationNetworks" in item),
                    ("source_ports", "sourcePorts" in item), ("destination_ports", "destinationPorts" in item),
                    ("source_dynamic_objects", "sourceDynamicObjects" in item),
                    ("destination_dynamic_objects", "destinationDynamicObjects" in item),
                    ("vlan_tags", "vlanTags" in item),
                    ("source_security_group_tags", "sourceSecurityGroupTags" in item),
                    ("destination_security_group_tags", "destinationSecurityGroupTags" in item),
                    ("realm", "realm" in item), ("realm_users", "realmUsers" in item),
                    ("users", "users" in item), ("user_groups", "realmUserGroups" in item),
                    ("applications", "applications" in item), ("time_range", "timeRange" in item),
                    ("application_filters", "applicationFilters" in apps),
                    ("inline_application_filters", "inlineApplicationFilters" in apps),
                    ("urls", "urls" in item), ("url_categories", "urlCategoriesWithReputation" in urls),
                    ("intrusion_policy", "ipsPolicy" in item), ("variable_set", "variableSet" in item),
                    ("file_policy", "filePolicy" in item), ("log_begin", "logBegin" in item), ("log_end", "logEnd" in item),
                    ("logging", any(key in item for key in ("logFiles", "sendEventsToFMC", "enableSyslog", "advancedLogging"))),
                ) if present]
                acp_rules.append(record(
                    item, rule_index, CiscoFTDAccessControlRule, **acp_values,
                ))
            acp_policies.append(record(policy, policy_index, CiscoFTDAccessControlPolicy,
                rules=acp_rules if "rules" in policy else None))

        nat_policies = []
        for policy_index, policy in enumerate(_items(self.payload.get("nat_policies")), 1):
            ownership = {"policy_id": policy.get("id"), "policy_name": policy.get("name")}

            def common_rule(item: dict, rule_index: int, rule_section: str | None = None):
                section = item.get("section") or rule_section
                return dict(
                    source_interface=reference(item["sourceInterface"]) if item.get("sourceInterface") else None,
                    destination_interface=reference(item["destinationInterface"]) if item.get("destinationInterface") else None,
                    nat_type=item.get("natType"), enabled=item.get("enabled"), section=section,
                    position=item.get("position", item.get("order")), observed_collection_order=rule_index,
                    source_attributes={**ownership, "observed_collection_order": rule_index},
                )

            def manual_rules(key: str, section: str | None = None):
                if key not in policy:
                    return None
                parsed = []
                for rule_index, item in enumerate(_items(policy.get(key)), 1):
                    values = common_rule(item, rule_index, section)
                    actual_section = values.pop("section")
                    # Collection membership establishes before/after; unknown generic manual sections stay unknown.
                    if section is None and not actual_section:
                        values["section"] = None
                    else:
                        values["section"] = actual_section
                    values.update(
                        original_source=item.get("originalSource", item.get("source")),
                        translated_source=item.get("translatedSource"),
                        original_destination=item.get("originalDestination", item.get("destination")),
                        translated_destination=item.get("translatedDestination"),
                        original_source_port=item.get("originalSourcePort"),
                        translated_source_port=item.get("translatedSourcePort"),
                        original_destination_port=item.get("originalDestinationPort"),
                        translated_destination_port=item.get("translatedDestinationPort"),
                        original_source_service=item.get("originalSourceService"),
                        translated_source_service=item.get("translatedSourceService"),
                        original_destination_service=item.get("originalDestinationService"),
                        translated_destination_service=item.get("translatedDestinationService"),
                        identity_nat=item.get("identityNat"), interface_pat=item.get("interfacePat"),
                        dns=item.get("dns"), route_lookup=item.get("routeLookup"), proxy_arp=item.get("noProxyArp") is False if "noProxyArp" in item else item.get("proxyArp"),
                    )
                    parsed.append(record(item, rule_index, CiscoFTDManualNATRule, **values))
                return parsed

            auto_rules = []
            for rule_index, item in enumerate(_items(policy.get("auto_rules")), 1):
                values = common_rule(item, rule_index)
                values.pop("section", None)
                original_network = item.get("originalNetwork")
                auto_rules.append(record(item, rule_index, CiscoFTDAutoNATRule,
                    **values, original_network=original_network,
                    translated_network=item.get("translatedNetwork"),
                    owning_network=item.get("originalNetwork"),
                    interface_pat=item.get("interfaceInTranslatedNetwork", item.get("interfacePat")),
                    identity_nat=item.get("identityNat"), dns=item.get("dns"),
                    route_lookup=item.get("routeLookup"), proxy_arp=item.get("proxyArp")))

            before = manual_rules("manual_rules_before_auto", "BEFORE_AUTO")
            unclassified = manual_rules("manual_rules")
            after = manual_rules("manual_rules_after_auto", "AFTER_AUTO")
            nat_policies.append(record(policy, policy_index, CiscoFTDNATPolicy,
                manual_rules_before_auto=before, auto_rules=auto_rules if "auto_rules" in policy else None,
                manual_rules_after_auto=after, unclassified_manual_rules=unclassified))

        def records(key, cls):
            return [record(item, i, cls) for i, item in enumerate(_items(self.payload.get(key)), 1)]

        def object_records(key, cls):
            return [record(item, i, cls) for i, item in enumerate(objects.get(key, []), 1)]

        routes, dhcp, interfaces, native = [], [], [], []
        for device in _items(self.payload.get("devices")):
            device_id = str(device.get("id") or "")
            device_name = str(device.get("name") or device_id)
            resources = device.get("resources") if isinstance(device.get("resources"), dict) else {}
            interfaces.extend(record(item, index, CiscoFTDInterfaceSource,
                interface_type=item.get("interfaceType", item.get("type")), address=item.get("address"), device_id=device_id,
                source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id})
                for index, item in enumerate(_items(resources.get("ftd_interfaces")), 1))
            for index, item in enumerate(_items(resources.get("static_routes")) + _items(resources.get("ipv6_static_routes")), 1):
                routes.append(record(item, index, CiscoFTDRoute, device_id=device_id,
                    interface=reference(item.get("interfaceName") or item.get("interface")) if item.get("interfaceName") or item.get("interface") else None,
                    destination=reference(item.get("network") or item.get("destination")) if item.get("network") or item.get("destination") else None,
                    gateway=reference(item["gateway"]) if item.get("gateway") else None, address_family=item.get("addressFamily"),
                    metric=item.get("metric"), virtual_router=reference(item["virtualRouter"]) if item.get("virtualRouter") else None,
                    sla_monitor=reference(item["slaMonitor"]) if item.get("slaMonitor") else None,
                    source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id}))
            dhcp.extend(record(item, index, CiscoFTDDHCPServer,
                source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id})
                for index, item in enumerate(_items(resources.get("dhcp_servers")), 1))
            for key in ("sla_monitors", "pbr_policies", "vtis"):
                native.extend(record(item, index, CiscoFTDNativeResource,
                    source_attributes={"device_id": device_id, "device_name": device_name, "resource_type": key})
                    for index, item in enumerate(_items(resources.get(key)), 1))

        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={
                "domain_id": self.domain_id, "domain_name": self.domain_name,
                "source": self.payload.get("source", "fmc-rest-api"),
                "collection": collection or {},
            },
            collection_metadata=collection_metadata,
            unsupported_evidence=[{"source_path": part.name, "reason": "FMC collection incomplete",
                                   "status": part.status, "complete": part.complete, "count": part.count}
                for part in collection_metadata.parts if not part.complete],
            network_addresses=network_addresses, network_groups=network_groups, protocol_port_objects=protocol_ports,
            port_object_groups=port_groups, security_zones=zones, interface_groups=interface_groups,
            device_interfaces=[], source_interfaces=interfaces,
            applications=object_records("applications", CiscoFTDApplication), variable_sets=object_records("variablesets", CiscoFTDVariableSet),
            url_categories=object_records("urlcategories", CiscoFTDURLCategory), vlan_objects=object_records("vlanobjects", CiscoFTDVLANObject),
            access_control_policies=acp_policies, nat_policies=nat_policies,
            time_ranges=object_records("timeranges", CiscoFTDTimeRange),
            intrusion_policies=object_records("intrusionpolicies", CiscoFTDIntrusionPolicy),
            intrusion_rule_overrides=[record(child, i, CiscoFTDIntrusionRuleOverride,
                source_attributes={"parent_policy_id": policy.get("id"), "parent_policy_name": policy.get("name"), "rule_group": group.get("name")})
                for policy in objects.get("intrusionpolicies", []) for group in _items(policy.get("rule_groups"))
                for i, child in enumerate(_items(group.get("rules")), 1)],
            file_policies=object_records("filepolicies", CiscoFTDFilePolicy),
            decryption_policies=object_records("decryptionpolicies", CiscoFTDDecryptionPolicy),
            dns_policies=object_records("dnspolicies", CiscoFTDDNSPolicy),
            fmc_user_roles=records("fmc_roles", CiscoFTDFMCUserRole), fmc_users=records("fmc_users", CiscoFTDFMCUser),
            dhcp_servers=dhcp, routes=routes, realms=object_records("realms", CiscoFTDRealm),
            realm_user_groups=object_records("realmusergroups", CiscoFTDRealmUserGroup),
            realm_users=object_records("realmusers", CiscoFTDRealmUser),
            local_realm_users=object_records("localrealmusers", CiscoFTDLocalRealmUser),
            s2s_vpn_topologies=object_records("s2svpns", CiscoFTDS2SVPNTopology),
            s2s_vpn_endpoints=[record(item, i, CiscoFTDS2SVPNEndpoint,
                source_attributes={"parent_topology_id": vpn.get("id"), "parent_topology_name": vpn.get("name")})
                for vpn in objects.get("s2svpns", []) for i, item in enumerate(_items(vpn.get("endpoints")), 1)],
            ike_policies=records("ike_policies", CiscoFTDIKEPolicy), ipsec_proposals=records("ipsec_proposals", CiscoFTDIPsecProposal),
            ra_vpn_policies=object_records("ravpns", CiscoFTDRAVPNPolicy),
            ra_vpn_connection_profiles=[record(item, i, CiscoFTDRAVPNConnectionProfile,
                source_attributes={"parent_policy_id": vpn.get("id"), "parent_policy_name": vpn.get("name")})
                for vpn in objects.get("ravpns", []) for i, item in enumerate(_items(vpn.get("connection_profiles")), 1)],
            native_resources=native,
        )


__all__ = ["CiscoFMCBundleParser", "FMC_BUNDLE_FORMAT", "is_fmc_bundle"]
