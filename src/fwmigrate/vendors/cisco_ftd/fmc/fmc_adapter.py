"""Vendor-native adapter for offline FMC REST bundles."""

from __future__ import annotations

import json
from typing import Any

from ..model import (
    CiscoFTDACPRule, CiscoFTDConfig, CiscoFTDInterfaceSource,
    CiscoFTDNATRule, CiscoFTDObject, CiscoFTDService, CiscoFTDZone,
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
            "hosts", "networks", "ranges", "networkgroups", "protocolportobjects",
            "portobjectgroups", "securityzones", "interfacegroups", "interfaces",
            "applications", "users", "ips", "filepolicies", "variablesets",
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
            return [
                str(item.get("name") or item.get("id") or item) if isinstance(item, dict) else str(item)
                for item in _items(value)
            ]

        def record(item: dict, index: int, cls, **values):
            return cls(
                name=name(item, index), source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, raw=item,
                source_attributes={"provenance": "FMC REST", "domain_id": self.domain_id},
                **values,
            )

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
                ))

        nat_rules = []
        for policy_index, policy in enumerate(_items(self.payload.get("nat_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            raw_rules = (
                _items(policy.get("manual_rules_before_auto")) + _items(policy.get("manual_rules"))
                + _items(policy.get("auto_rules")) + _items(policy.get("manual_rules_after_auto"))
            )
            for rule_index, item in enumerate(raw_rules, 1):
                original = item.get("originalSource", item.get("source", {}))
                translated = item.get("translatedSource", item.get("translated", {}))
                nat_rules.append(record(
                    item, rule_index, CiscoFTDNATRule, policy=policy_name,
                    source_interface=ref_name(item.get("sourceInterface")),
                    destination_interface=ref_name(item.get("destinationInterface")),
                    original=original if isinstance(original, dict) else {},
                    translated=translated if isinstance(translated, dict) else {}, order=rule_index,
                ))

        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={
                "domain_id": self.domain_id, "domain_name": self.domain_name,
                "source": self.payload.get("source", "fmc-rest-api"),
            },
            managed_objects=managed, object_groups=groups, services=services,
            security_zones=zones, source_interfaces=interfaces,
            acp_rules=acp_rules, nat_policies=nat_rules,
        )


__all__ = ["CiscoFMCBundleParser", "FMC_BUNDLE_FORMAT", "is_fmc_bundle"]
