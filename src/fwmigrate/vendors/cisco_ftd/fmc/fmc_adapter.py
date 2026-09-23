"""Vendor-native adapter for offline FMC REST bundles."""

from __future__ import annotations

import json
from typing import Any

from ..model import (
    CiscoFTDACPRule, CiscoFTDACPolicy, CiscoFTDConfig, CiscoFTDInterfaceSource, CiscoFTDNativeResource,
    CiscoFTDNATRule, CiscoFTDObject, CiscoFTDService, CiscoFTDZone,
    CiscoFTDTimeRange, CiscoFTDIntrusionPolicy, CiscoFTDIntrusionRuleOverride,
    CiscoFTDFilePolicy, CiscoFTDDecryptionPolicy, CiscoFTDDNSPolicy,
    CiscoFTDFMCUserRole, CiscoFTDFMCUser, CiscoFTDDHCPServer, CiscoFTDRealm,
    CiscoFTDRealmUserGroup, CiscoFTDRealmUser, CiscoFTDLocalRealmUser,
    CiscoFTDS2SVPNTopology, CiscoFTDS2SVPNEndpoint, CiscoFTDIKEPolicy,
    CiscoFTDIPsecProposal, CiscoFTDRAVPNPolicy, CiscoFTDRAVPNConnectionProfile,
    CiscoFTDRoute,
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
            "portobjectgroups", "securityzones", "interfacegroups", "interfaces",
            "applications", "timeranges", "users", "ips", "filepolicies", "decryptionpolicies", "dnspolicies", "intrusionpolicies",
            "realms", "realmusergroups", "realmusers", "localrealmusers", "s2svpns", "ravpns", "variablesets",
            "urlcategories", "vlanobjects",
        )
        return {name: _items(objects.get(name)) for name in names}

    def parse_source(self) -> CiscoFTDConfig:
        objects = self._object_collections()
        plane = "fmc-rest-bundle"

        def name(item: dict, index: int) -> str:
            return str(item.get("name") or item.get("id") or index)

        def ref_name(value: Any) -> str | None:
            if isinstance(value, dict):
                value = value.get("name") or value.get("id")
            return str(value) if value is not None else None

        def refs(value: Any) -> list[str]:
            if isinstance(value, dict):
                value = [value]
            return [
                str(item.get("name") or item.get("id") or item) if isinstance(item, dict) else str(item)
                for item in _items(value)
            ]

        def record(item: dict, index: int, cls, **values):
            attributes = {"provenance": "FMC REST", "domain_id": self.domain_id}
            attributes.update(values.pop("source_attributes", {}))
            return cls(
                name=name(item, index), source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, raw=item,
                source_attributes=attributes,
                **values,
            )

        # Newer FMC bundles use networkaddresses; older exports split hosts/networks/ranges.
        if objects.get("networkaddresses"):
            objects["hosts"] = objects["networks"] = objects["ranges"] = []
        groups = [
            record(item, index, CiscoFTDObject, object_type="network-group", members=refs(item.get("objects", item.get("members", []))))
            for index, item in enumerate(objects.get("networkgroups", []), 1)
        ]
        excluded = {"networkgroups", "protocolportobjects", "portobjectgroups", "securityzones", "interfaces"}
        managed = [
            record(item, index, CiscoFTDObject, object_type=kind)
            for kind, collection in objects.items() if kind not in excluded
            for index, item in enumerate(collection, 1)
        ]
        services = [
            record(item, index, CiscoFTDService, protocol=item.get("protocol"), ports=item.get("ports", []))
            for index, item in enumerate(objects.get("protocolportobjects", []), 1)
        ]
        services.extend(
            record(item, index, CiscoFTDService, protocol=item.get("protocol"), members=refs(item.get("objects", item.get("members", []))))
            for index, item in enumerate(objects.get("portobjectgroups", []), 1)
        )
        zones = [
            record(item, index, CiscoFTDZone, interfaces=refs(item.get("interfaces", [])))
            for index, item in enumerate(objects.get("securityzones", []), 1)
        ]
        interfaces = [
            record(
                item, index, CiscoFTDInterfaceSource,
                interface_type=item.get("type"), address=item.get("address"),
                zone=(item.get("securityZone") or {}).get("name")
                if isinstance(item.get("securityZone"), dict) else item.get("securityZone"),
            )
            for index, item in enumerate(objects.get("interfaces", []), 1)
        ]

        acp_rules = []
        for policy_index, policy in enumerate(_items(self.payload.get("access_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            for rule_index, item in enumerate(_items(policy.get("rules")), 1):
                acp_rules.append(record(
                    item, rule_index, CiscoFTDACPRule, policy=policy_name,
                    action=item.get("action"), order=rule_index,
                    source=refs(item.get("source")), destination=refs(item.get("destination")),
                    services=refs(item.get("sourcePorts") or item.get("destinationPorts")),
                    source_zones=refs(item.get("sourceZones")), destination_zones=refs(item.get("destinationZones")),
                    source_attributes={"policy_id": policy.get("id"), "policy_name": policy_name},
                ))

        nat_rules = []
        for policy_index, policy in enumerate(_items(self.payload.get("nat_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            raw_rules = (
                _items(policy.get("manual_rules_before_auto")) + _items(policy.get("manual_rules"))
                + _items(policy.get("auto_rules")) + _items(policy.get("manual_rules_after_auto"))
            )
            for rule_index, item in enumerate(raw_rules, 1):
                original = {"source": item.get("originalSource", item.get("source")),
                    "destination": item.get("originalDestination", item.get("destination")),
                    "service": item.get("originalSourcePort", item.get("originalDestinationPort", item.get("service")))}
                translated = {"source": item.get("translatedSource"), "destination": item.get("translatedDestination"),
                    "service": item.get("translatedSourcePort", item.get("translatedDestinationPort"))}
                nat_rules.append(record(
                    item, rule_index, CiscoFTDNATRule, policy=policy_name,
                    source_interface=ref_name(item.get("sourceInterface")),
                    destination_interface=ref_name(item.get("destinationInterface")),
                    original={key: value for key, value in original.items() if value is not None},
                    translated={key: value for key, value in translated.items() if value is not None}, order=rule_index,
                    section=item.get("section"), nat_type=item.get("natType"), enabled=item.get("enabled"),
                ))

        def records(key, cls):
            return [record(item, i, cls) for i, item in enumerate(_items(self.payload.get(key)), 1)]

        def object_records(key, cls):
            return [record(item, i, cls) for i, item in enumerate(objects.get(key, []), 1)]

        routes, dhcp, native = [], [], []
        for device in _items(self.payload.get("devices")):
            device_id = str(device.get("id") or "")
            device_name = str(device.get("name") or device_id)
            resources = device.get("resources") if isinstance(device.get("resources"), dict) else {}
            for index, item in enumerate(_items(resources.get("static_routes")) + _items(resources.get("ipv6_static_routes")), 1):
                routes.append(record(item, index, CiscoFTDRoute, device_id=device_id,
                    interface=ref_name(item.get("interfaceName") or item.get("interface")),
                    destination=ref_name(item.get("network") or item.get("destination")),
                    gateway=ref_name(item.get("gateway")), address_family=item.get("addressFamily"),
                    metric=item.get("metric"), virtual_router=ref_name(item.get("virtualRouter")),
                    sla_monitor=ref_name(item.get("slaMonitor")),
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
                "collection": self.payload.get("collection", {}),
            },
            unsupported_evidence=[{"source_path": part.get("name"), "reason": "FMC collection incomplete"}
                for part in _items((self.payload.get("collection") or {}).get("parts")) if not part.get("complete", True)],
            managed_objects=managed, object_groups=groups, services=services,
            security_zones=zones, source_interfaces=interfaces,
            acp_rules=acp_rules, nat_policies=nat_rules,
            acp_policies=[record(policy, index, CiscoFTDACPolicy) for index, policy in enumerate(_items(self.payload.get("access_policies")), 1)],
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
