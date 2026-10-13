"""Vendor-native adapter for offline FDM REST bundles."""

from __future__ import annotations

import json
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..model import (
    CiscoFTDConfig, CiscoFTDDeviceInterface, CiscoFTDNetworkAddress, CiscoFTDNetworkGroup,
    CiscoFTDPortObjectGroup, CiscoFTDProtocolPortObject, CiscoFTDReference, CiscoFTDSecurityZone,
    CiscoFTDFDMNATRule, CiscoFTDNATPolicy, CiscoFTDRoute,
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
            source_attributes = {"provenance": "FDM REST", "domain_id": self.domain_id}
            source_attributes.update(values.pop("source_attributes", {}))
            return cls(
                name=str(item.get("name") or item.get("id") or index),
                source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, domain_id=str(self.domain_id) if self.domain_id else None,
                raw_extra=sanitize_source_attributes(item),
                source_attributes=source_attributes,
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

        def override_metadata(item: dict) -> dict | None:
            found = {key: value for key, value in item.items() if "override" in key.lower()}
            return sanitize_source_attributes(found) or None

        def has_override(item: dict) -> bool:
            return any("override" in key.lower() for key in item)

        def network_address(item: dict, index: int, collection_name: str):
            fields = {
                "address_type": ("type",), "value": ("value",), "description": ("description",),
                "fqdn_lookup_type": ("lookupType", "fqdnLookupType", "dnsResolutionType"),
                "address_family": ("addressFamily",),
            }
            values = {target: item[source] for target, aliases in fields.items()
                      if (source := next((key for key in aliases if key in item), None)) is not None}
            if "address_type" not in values:
                implied_type = {"hosts": "Host", "network_hosts": "Host", "networks": "Network",
                                "ranges": "Range", "network_ranges": "Range"}.get(collection_name)
                if implied_type:
                    values["address_type"] = implied_type
            values["override_metadata"] = override_metadata(item)
            values["explicit_fields"] = [target for target, aliases in fields.items()
                                         if any(key in item for key in aliases)]
            if has_override(item):
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDNetworkAddress, **values)

        def network_group(item: dict, index: int):
            values = {
                "members": refs_field(item, "objects", "members"),
                "literal_members": refs_field(item, "literals"),
                "description": item.get("description"), "override_metadata": override_metadata(item),
                "explicit_fields": [field for field, keys in (
                    ("members", ("objects", "members")), ("literal_members", ("literals",)),
                    ("description", ("description",))) if any(key in item for key in keys)],
            }
            if has_override(item):
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDNetworkGroup, **values)

        def protocol_port_object(item: dict, index: int):
            fields = {
                "protocol": ("protocol",), "port": ("port", "destinationPort"),
                "end_port": ("endPort", "end_port"), "icmp_type": ("icmpType", "icmp_type"),
                "icmp_code": ("icmpCode", "icmp_code"), "description": ("description",),
            }
            values = {target: item[source] for target, aliases in fields.items()
                      if (source := next((key for key in aliases if key in item), None)) is not None}
            if "ports" in item:
                values["ports"] = item["ports"]
            values["override_metadata"] = override_metadata(item)
            values["explicit_fields"] = [target for target, aliases in fields.items()
                                         if any(key in item for key in aliases)]
            if "ports" in item:
                values["explicit_fields"].append("ports")
            if has_override(item):
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDProtocolPortObject, **values)

        def port_object_group(item: dict, index: int):
            values = {
                "members": refs_field(item, "objects", "members"), "description": item.get("description"),
                "override_metadata": override_metadata(item),
                "explicit_fields": [field for field, aliases in (("members", ("objects", "members")),
                    ("description", ("description",))) if any(key in item for key in aliases)],
            }
            if has_override(item):
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDPortObjectGroup, **values)

        network_groups = [
            network_group(item, index)
            for index, item in enumerate(items("network_groups", "networkgroups"), 1)
        ]
        network_addresses = [
            network_address(item, index, collection_name)
            for collection_name in ("hosts", "network_hosts", "networks", "network_objects", "ranges", "network_ranges")
            for index, item in enumerate(items(collection_name), 1)
        ]
        services = [
            protocol_port_object(item, index)
            for index, item in enumerate(items("services", "service_objects"), 1)
        ]
        port_groups = [
            port_object_group(item, index)
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
        synthetic_policy = not policy_records and bool(self._nat_rules())
        if synthetic_policy:
            policy_records = [{"id": None, "name": "default", "rules": self._nat_rules()}]
        nat_policies = [record(policy, pindex, CiscoFTDNATPolicy, source_attributes={
            **({"synthetic_container": True, "source_collection": "nat_rules"} if synthetic_policy else {})
        }, rules=[
            record(item, index, CiscoFTDFDMNATRule,
                source_interface=reference(item["sourceInterface"]) if item.get("sourceInterface") else None,
                destination_interface=reference(item["destinationInterface"]) if item.get("destinationInterface") else None,
                original_source=reference(item["originalSource"]) if item.get("originalSource") is not None else None,
                translated_source=reference(item["translatedSource"]) if item.get("translatedSource") is not None else None,
                original_destination=reference(item["originalDestination"]) if item.get("originalDestination") is not None else None,
                translated_destination=reference(item["translatedDestination"]) if item.get("translatedDestination") is not None else None,
                service=reference(item["service"]) if item.get("service") is not None else None,
                rule_type=item.get("type"), sequence=item.get("sequence"), observed_collection_order=index,
                enabled=item.get("enabled"), source_translation_mode=item.get("sourceTranslationMode"),
                destination_translation_mode=item.get("destinationTranslationMode"))
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
