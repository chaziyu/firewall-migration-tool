"""Vendor-native adapter for offline FDM REST bundles."""

from __future__ import annotations

import json
from typing import Any

from ..model import (
    CiscoFTDConfig, CiscoFTDDeviceInterface, CiscoFTDNetworkAddress, CiscoFTDNetworkGroup,
    CiscoFTDPortObjectGroup, CiscoFTDProtocolPortObject, CiscoFTDReference, CiscoFTDSecurityZone,
    CiscoFTDNATRule, CiscoFTDNATPolicy, CiscoFTDRoute,
)

FDM_BUNDLE_FORMAT = "cisco-fdm-rest-export-v1"


def _items(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, dict)]
    return []


def is_fdm_bundle(content: str) -> bool:
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("format") == FDM_BUNDLE_FORMAT


class CiscoFDMBundleParser:
    """Decode authoritative FDM API data into Cisco FTD source state."""

    def __init__(self, content: str):
        self.payload = json.loads(content)
        if not isinstance(self.payload, dict) or self.payload.get("format") != FDM_BUNDLE_FORMAT:
            raise ValueError(f"Expected {FDM_BUNDLE_FORMAT}")
        domain = self.payload.get("domain") if isinstance(self.payload.get("domain"), dict) else {}
        self.domain_id = domain.get("id") or self.payload.get("domainUUID")
        self.domain_name = domain.get("name") or "Default"
        self.context = f"fdm:{self.domain_name}"

    def _collection(self, *names: str) -> list[dict]:
        objects = self.payload.get("objects") if isinstance(self.payload.get("objects"), dict) else {}
        for name in names:
            values = _items(objects.get(name))
            if values:
                return values
        return []

    def _nat_rules(self) -> list[dict]:
        if isinstance(self.payload.get("nat_rules"), list):
            return _items(self.payload.get("nat_rules"))
        policy = self.payload.get("nat_policy")
        if isinstance(policy, dict):
            return _items(policy.get("rules"))
        rules = []
        for item in _items(self.payload.get("nat_policies")):
            rules.extend(_items(item.get("rules")))
        return rules

    def parse_source(self) -> CiscoFTDConfig:
        plane = "fdm-rest-bundle"

        def items(*names: str) -> list[dict]:
            return self._collection(*names)

        def record(item: dict, index: int, cls, **values):
            return cls(
                name=str(item.get("name") or item.get("id") or index),
                source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, domain_id=str(self.domain_id) if self.domain_id else None,
                raw_extra=item,
                source_attributes={"provenance": "FDM REST", "domain_id": self.domain_id},
                **values,
            )

        def reference(value: Any) -> CiscoFTDReference:
            if isinstance(value, dict):
                return CiscoFTDReference(source_id=str(value["id"]) if value.get("id") is not None else None,
                    name=str(value["name"]) if value.get("name") is not None else None,
                    source_type=value.get("type") or value.get("objectType"), value=value.get("value"),
                    source_attributes={key: item for key, item in value.items()
                        if key not in {"id", "name", "type", "objectType", "value"}})
            return CiscoFTDReference(name=str(value))

        def refs(values: Any) -> list[CiscoFTDReference]:
            if isinstance(values, dict):
                values = [values]
            return [reference(value) for value in (values or [])]

        def refs_field(item: dict, *keys: str):
            key = next((key for key in keys if key in item), None)
            return refs(item[key]) if key is not None else None

        network_groups = [
            record(item, index, CiscoFTDNetworkGroup, members=refs_field(item, "objects", "members"))
            for index, item in enumerate(items("network_groups", "networkgroups"), 1)
        ]
        network_addresses = [
            record(item, index, CiscoFTDNetworkAddress, address_type=item.get("type"), value=item.get("value"))
            for collection_name in ("hosts", "network_hosts", "networks", "network_objects", "ranges", "network_ranges")
            for index, item in enumerate(items(collection_name), 1)
        ]
        services = [
            record(item, index, CiscoFTDProtocolPortObject, protocol=item.get("protocol"), ports=item.get("ports"))
            for index, item in enumerate(items("services", "service_objects"), 1)
        ]
        port_groups = [
            record(item, index, CiscoFTDPortObjectGroup, members=refs_field(item, "objects", "members"))
            for index, item in enumerate(items("service_groups", "servicegroups"), 1)
        ]
        zones = [record(item, index, CiscoFTDSecurityZone, interfaces=refs_field(item, "interfaces")) for index, item in enumerate(items("zones", "security_zones"), 1)]
        interfaces = [
            record(item, index, CiscoFTDDeviceInterface, interface_type=item.get("type"), address=item.get("address"), zone=reference(item["zone"]) if item.get("zone") else None)
            for index, item in enumerate(items("interfaces"), 1)
        ]
        routes = [
            record(item, index, CiscoFTDRoute,
                interface=reference(item["interface"]) if item.get("interface") else None,
                destination=reference(item["destination"]) if item.get("destination") else None,
                gateway=reference(item["gateway"]) if item.get("gateway") else None)
            for index, item in enumerate(items("routes", "static_routes"), 1)
        ]
        policy_records = _items(self.payload.get("nat_policies"))
        if not policy_records and isinstance(self.payload.get("nat_policy"), dict):
            policy_records = [self.payload["nat_policy"]]
        if not policy_records and self._nat_rules():
            policy_records = [{"id": None, "name": "default", "rules": self._nat_rules()}]
        nat_policies = [record(policy, pindex, CiscoFTDNATPolicy, rules=[
            record(item, index, CiscoFTDNATRule,
                source_interface=reference(item["sourceInterface"]) if item.get("sourceInterface") else None,
                destination_interface=reference(item["destinationInterface"]) if item.get("destinationInterface") else None,
                original=item.get("original", {}), translated=item.get("translated", {}), order=index,
                section=item.get("section"))
            for index, item in enumerate(_items(policy.get("rules")), 1)] if "rules" in policy else None)
            for pindex, policy in enumerate(policy_records, 1)]
        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={
                "domain_id": self.domain_id, "domain_name": self.domain_name,
                "source": self.payload.get("source", "fdm-rest-api"),
            },
            network_addresses=network_addresses, network_groups=network_groups,
            protocol_port_objects=services, port_object_groups=port_groups,
            security_zones=zones, device_interfaces=interfaces, routes=routes,
            nat_policies=nat_policies,
            unsupported_evidence=[] if nat_policies else [
                {"source_path": "fdm/nat-policies", "reason": "No NAT policy data in FDM bundle"}
            ],
        )


__all__ = ["CiscoFDMBundleParser", "FDM_BUNDLE_FORMAT", "is_fdm_bundle"]
