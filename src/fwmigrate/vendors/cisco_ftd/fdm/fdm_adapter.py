"""Vendor-native adapter for offline FDM REST bundles."""

from __future__ import annotations

import json
from typing import Any

from ..model import (
    CiscoFTDConfig, CiscoFTDInterfaceSource, CiscoFTDNATRule, CiscoFTDObject,
    CiscoFTDRoute, CiscoFTDService, CiscoFTDZone,
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
                source_plane=plane, source_context=self.context, raw=item,
                source_attributes={"provenance": "FDM REST", "domain_id": self.domain_id},
                **values,
            )

        def members(item: dict) -> list[str]:
            return [
                str(value.get("name") or value.get("id") or value) if isinstance(value, dict) else str(value)
                for value in item.get("objects", item.get("members", []))
            ]

        object_groups = [
            record(item, index, CiscoFTDObject, object_type="network-group", members=members(item))
            for index, item in enumerate(items("network_groups", "networkgroups"), 1)
        ]
        managed = [
            record(item, index, CiscoFTDObject, object_type="network")
            for collection_name in ("hosts", "network_hosts", "networks", "network_objects", "ranges", "network_ranges")
            for index, item in enumerate(items(collection_name), 1)
        ]
        services = [
            record(item, index, CiscoFTDService, protocol=item.get("protocol"), ports=item.get("ports", []))
            for index, item in enumerate(items("services", "service_objects"), 1)
        ]
        services.extend(
            record(item, index, CiscoFTDService, protocol=item.get("protocol"), members=members(item))
            for index, item in enumerate(items("service_groups", "servicegroups"), 1)
        )
        zones = [record(item, index, CiscoFTDZone, interfaces=item.get("interfaces", [])) for index, item in enumerate(items("zones", "security_zones"), 1)]
        interfaces = [
            record(item, index, CiscoFTDInterfaceSource, interface_type=item.get("type"), address=item.get("address"), zone=item.get("zone"))
            for index, item in enumerate(items("interfaces"), 1)
        ]
        routes = [
            record(item, index, CiscoFTDRoute, interface=item.get("interface"), destination=item.get("destination"), gateway=item.get("gateway"))
            for index, item in enumerate(items("routes", "static_routes"), 1)
        ]
        nat_rules = [
            record(
                item, index, CiscoFTDNATRule,
                policy=str(item.get("policy") or item.get("policyName") or "default"),
                source_interface=item.get("sourceInterface"), destination_interface=item.get("destinationInterface"),
                original=item.get("original", {}), translated=item.get("translated", {}), order=index,
            )
            for index, item in enumerate(self._nat_rules(), 1)
        ]
        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={
                "domain_id": self.domain_id, "domain_name": self.domain_name,
                "source": self.payload.get("source", "fdm-rest-api"),
            },
            managed_objects=managed, object_groups=object_groups, services=services,
            security_zones=zones, source_interfaces=interfaces, routes=routes,
            nat_policies=nat_rules,
            unsupported_evidence=[] if nat_rules else [
                {"source_path": "fdm/nat-policies", "reason": "No NAT policy data in FDM bundle"}
            ],
        )


__all__ = ["CiscoFDMBundleParser", "FDM_BUNDLE_FORMAT", "is_fdm_bundle"]
