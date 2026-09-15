from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional

from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir import IRConfig
from fwmigrate.ir.address import IRAddress, IRAddressGroup
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, ServiceProtocol
from fwmigrate.ir.metadata import IRMetadata
from fwmigrate.ir.nat import IRNATPortRange, IRNATRule
from fwmigrate.ir.network import IRInterface, IRInterfaceGroup, IRZone
from fwmigrate.ir.service import IRService, IRServiceGroup, IRServicePort


FDM_BUNDLE_FORMAT = "cisco-fdm-rest-export-v1"


def _items(value: Any) -> List[dict]:
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


def _port_ranges(value: Any) -> List[IRNATPortRange]:
    values = value if isinstance(value, list) else [value]
    result: List[IRNATPortRange] = []
    for item in values:
        if isinstance(item, dict):
            start = item.get("port") or item.get("start") or item.get("startPort")
            end = item.get("end") or item.get("endPort")
        else:
            start, end = item, None
        text = str(start).strip() if start is not None else ""
        if "-" in text:
            text, end = (part.strip() for part in text.split("-", 1))
        if not text.isdigit() or (end is not None and not str(end).isdigit()):
            continue
        start_value = int(text)
        end_value = int(end) if end is not None else start_value
        if not 0 <= start_value <= end_value <= 65535:
            continue
        result.append(IRNATPortRange(start=start_value, end=end_value))
    return result


class CiscoFDMBundleParser:
    """Parse the explicit offline FDM export contract into canonical IR."""

    def __init__(self, content: str):
        self.payload = json.loads(content)
        if not isinstance(self.payload, dict) or self.payload.get("format") != FDM_BUNDLE_FORMAT:
            raise ValueError(f"Expected {FDM_BUNDLE_FORMAT}")
        domain = self.payload.get("domain") if isinstance(self.payload.get("domain"), dict) else {}
        self.domain_id = domain.get("id") or self.payload.get("domainUUID")
        self.domain_name = domain.get("name") or "Default"
        self.context = f"fdm:{self.domain_name}"
        self._object_by_id: Dict[str, dict] = {}
        self._object_by_name: Dict[str, dict] = {}
        self._unresolved: List[dict] = []
        self._index_objects()

    @property
    def unresolved_references(self) -> List[dict]:
        return list(self._unresolved)

    def _collection(self, *names: str) -> List[dict]:
        objects = self.payload.get("objects") if isinstance(self.payload.get("objects"), dict) else {}
        for name in names:
            values = _items(objects.get(name))
            if values:
                return values
        return []

    def _index_objects(self) -> None:
        for item in (
            self._collection("hosts", "network_hosts")
            + self._collection("networks", "network_objects")
            + self._collection("ranges", "network_ranges")
            + self._collection("network_groups", "networkgroups")
            + self._collection("services", "service_objects")
            + self._collection("service_groups", "servicegroups")
            + self._collection("interfaces")
            + self._collection("zones", "security_zones")
        ):
            if isinstance(item.get("id"), str):
                self._object_by_id[item["id"]] = item
            if isinstance(item.get("name"), str):
                self._object_by_name[item["name"]] = item

    def _resolve(self, value: Any, *, owner: str, field: str, allow_any: bool = False) -> Optional[str]:
        if value is None:
            return IR_KEYWORD_ANY if allow_any else None
        if isinstance(value, dict):
            reference = value.get("id") or value.get("name")
            if reference is None and value.get("value") is not None:
                reference = value["value"]
        else:
            reference = value
        text = str(reference).strip() if reference is not None else ""
        if text in self._object_by_id:
            return self._object_by_id[text].get("name") or text
        if text in self._object_by_name:
            return text
        if text.lower() == IR_KEYWORD_ANY:
            return IR_KEYWORD_ANY
        try:
            ipaddress.ip_network(text, strict=False)
            return text
        except ValueError:
            self._unresolved.append({"owner": owner, "field": field, "reference": text})
            return None

    def _refs(self, value: Any, *, owner: str, field: str, allow_any: bool = False) -> List[str]:
        values = value if isinstance(value, list) else [value]
        result = []
        for item in values:
            resolved = self._resolve(item, owner=owner, field=field, allow_any=allow_any)
            if resolved is not None:
                result.append(resolved)
        return result

    def _parse_addresses(self, ir: IRConfig) -> None:
        for collection, address_type in (
            (("hosts", "network_hosts"), AddressType.HOST),
            (("networks", "network_objects"), AddressType.NETWORK),
        ):
            for item in self._collection(*collection):
                value = item.get("value") or item.get("subnet")
                ir.addresses.append(IRAddress(
                    name=str(item.get("name") or item.get("id")), type=address_type,
                    subnet=str(value) if value is not None else None,
                    source_uuid=item.get("id"), source_context=self.context,
                    source_attributes={"fdm_object": item},
                ))
        for item in self._collection("ranges", "network_ranges"):
            start = item.get("start") or item.get("startAddress")
            end = item.get("end") or item.get("endAddress")
            ir.addresses.append(IRAddress(
                name=str(item.get("name") or item.get("id")), type=AddressType.RANGE,
                ip_range_start=str(start), ip_range_end=str(end),
                source_uuid=item.get("id"), source_context=self.context,
                source_attributes={"fdm_object": item},
            ))

    def _parse_network_groups(self, ir: IRConfig) -> None:
        for item in self._collection("network_groups", "networkgroups"):
            owner = str(item.get("name") or item.get("id"))
            members = self._refs(
                item.get("members") or item.get("objects") or item.get("children") or [],
                owner=owner, field="members",
            )
            unresolved = [entry["reference"] for entry in self._unresolved if entry["owner"] == owner]
            ir.address_groups.append(IRAddressGroup(
                name=owner, members=members, unsafe_members=unresolved,
                source_uuid=item.get("id"), source_context=self.context,
                migration_status="PARTIALLY_NORMALIZED" if unresolved else "NORMALIZED",
                requires_manual_review=bool(unresolved),
                review_reasons=["Unresolved FDM network-group member"] if unresolved else [],
                source_attributes={"fdm_object": item},
            ))

    def _service_protocol(self, value: Any) -> Optional[ServiceProtocol]:
        text = str(value or "").strip().lower()
        return {
            "tcp": ServiceProtocol.TCP, "udp": ServiceProtocol.UDP,
            "sctp": ServiceProtocol.SCTP, "icmp": ServiceProtocol.ICMP,
            "icmpv6": ServiceProtocol.ICMPV6, "ip": ServiceProtocol.IP,
        }.get(text)

    def _parse_services(self, ir: IRConfig) -> None:
        for item in self._collection("services", "service_objects"):
            protocol = self._service_protocol(item.get("protocol"))
            raw_ports = item.get("ports") or item.get("port") or []
            ports = _port_ranges(raw_ports)
            ir.services.append(IRService(
                name=str(item.get("name") or item.get("id")), source_uuid=item.get("id"),
                source_context=self.context,
                ports=[IRServicePort(protocol=protocol or ServiceProtocol.IP, port=(
                    f"{port.start}-{port.end}" if port.end is not None else str(port.start)
                )) for port in ports],
                migration_status="NORMALIZED" if protocol else "PARTIALLY_NORMALIZED",
                requires_manual_review=protocol is None,
                review_reasons=[] if protocol else ["Unsupported or missing FDM service protocol"],
                source_attributes={"fdm_object": item},
            ))
        for item in self._collection("service_groups", "servicegroups"):
            owner = str(item.get("name") or item.get("id"))
            members = self._refs(item.get("members") or item.get("objects") or [], owner=owner, field="members")
            unresolved = [entry["reference"] for entry in self._unresolved if entry["owner"] == owner]
            ir.service_groups.append(IRServiceGroup(
                name=owner, members=members, unsafe_members=unresolved,
                source_uuid=item.get("id"), source_context=self.context,
                migration_status="PARTIALLY_NORMALIZED" if unresolved else "NORMALIZED",
                requires_manual_review=bool(unresolved),
                review_reasons=["Unresolved FDM service-group member"] if unresolved else [],
                source_attributes={"fdm_object": item},
            ))

    def _parse_interfaces(self, ir: IRConfig) -> None:
        interfaces = self._collection("interfaces")
        zone_members: Dict[str, List[str]] = {}
        for item in interfaces:
            name = str(item.get("name") or item.get("id"))
            zone = item.get("zone") or item.get("securityZone")
            zone_name = self._resolve(zone, owner=name, field="zone") if zone else None
            ir.interfaces.append(IRInterface(
                name=name, zone=zone_name, source_uuid=item.get("id"),
                source_context=self.context, source_attributes={"fdm_object": item},
            ))
            if zone_name:
                zone_members.setdefault(zone_name, []).append(name)
        for item in self._collection("zones", "security_zones"):
            name = str(item.get("name") or item.get("id"))
            zone_members.setdefault(name, []).extend(
                self._refs(item.get("interfaces") or [], owner=name, field="interfaces")
            )
        for name, members in zone_members.items():
            ir.zones.append(IRZone(name=name, interfaces=list(dict.fromkeys(members)), source_context=self.context))
        for item in self._collection("interface_groups"):
            ir.interface_groups.append(IRInterfaceGroup(
                name=str(item.get("name") or item.get("id")),
                members=self._refs(item.get("interfaces") or item.get("members") or [], owner=str(item.get("name") or item.get("id")), field="interfaces"),
                source_uuid=item.get("id"), source_context=self.context,
            ))

    def _mode(self, value: Any) -> Optional[NATTranslationMode]:
        text = str(value or "").strip().lower().replace("_", "-")
        return next((mode for mode in NATTranslationMode if mode.value == text), None)

    def _nat_rules(self) -> Iterable[dict]:
        if isinstance(self.payload.get("nat_rules"), list):
            return _items(self.payload.get("nat_rules"))
        policy = self.payload.get("nat_policy")
        if isinstance(policy, dict):
            return _items(policy.get("rules"))
        rules: List[dict] = []
        for policy in _items(self.payload.get("nat_policies")):
            rules.extend(_items(policy.get("rules")))
        return rules

    def _parse_nat_policies(self, ir: IRConfig) -> None:
        for index, rule in enumerate(self._nat_rules(), 1):
            owner = str(rule.get("name") or rule.get("id") or index)
            raw_type = str(rule.get("type") or rule.get("natType") or "").upper().replace("-", "_")
            nat_type = {"SOURCE": NATType.SOURCE, "DESTINATION": NATType.DESTINATION, "TWICE": NATType.TWICE}.get(raw_type)
            source = self._refs(rule.get("originalSource"), owner=owner, field="originalSource", allow_any=True)
            destination = self._refs(rule.get("originalDestination"), owner=owner, field="originalDestination", allow_any=True)
            translated_source = self._refs(rule.get("translatedSource"), owner=owner, field="translatedSource")
            translated_destination = self._refs(rule.get("translatedDestination"), owner=owner, field="translatedDestination")
            source_mode = self._mode(rule.get("sourceTranslationMode") or rule.get("source_translation_mode"))
            destination_mode = self._mode(rule.get("destinationTranslationMode") or rule.get("destination_translation_mode"))
            reasons = []
            if nat_type is None:
                reasons.append("Missing or unsupported FDM NAT type")
                nat_type = NATType.SOURCE
            if translated_source and source_mode is None:
                reasons.append("FDM source translation mode is missing")
            if translated_destination and destination_mode is None:
                reasons.append("FDM destination translation mode is missing")
            if rule.get("patMethod"):
                pat_method = str(rule["patMethod"]).lower()
                if pat_method not in {"pat", "dynamic-ip-and-port", "interface-pat"}:
                    reasons.append("Unsupported FDM PAT method is source-preserved")
            unresolved_owner = {entry["owner"] for entry in self._unresolved}
            if owner in unresolved_owner:
                reasons.append("Unresolved FDM NAT reference")
            sequence = rule.get("sequence") or rule.get("ruleIndex") or index
            ir.nat_rules.append(IRNATRule(
                name=owner, type=nat_type, source_context=self.context,
                source_uuid=rule.get("id"), source_rule_id=str(rule.get("id") or sequence),
                sequence=int(sequence), enabled=bool(rule.get("enabled", True)),
                source_from_interfaces=self._refs(rule.get("sourceInterface"), owner=owner, field="sourceInterface"),
                source_to_interfaces=self._refs(rule.get("destinationInterface"), owner=owner, field="destinationInterface"),
                from_zone=self._refs(rule.get("sourceZone"), owner=owner, field="sourceZone"),
                to_zone=self._refs(rule.get("destinationZone"), owner=owner, field="destinationZone"),
                source=source, destination=destination, services=self._refs(rule.get("service"), owner=owner, field="service", allow_any=True),
                translated_sources=translated_source, translated_destinations=translated_destination,
                original_source_ports=_port_ranges(rule.get("originalSourcePort")),
                translated_source_ports=_port_ranges(rule.get("translatedSourcePort")),
                original_destination_ports=_port_ranges(rule.get("originalDestinationPort")),
                translated_destination_ports=_port_ranges(rule.get("translatedDestinationPort")),
                source_translation_mode=source_mode, destination_translation_mode=destination_mode,
                identity=bool(rule.get("identity", False)), exemption=bool(rule.get("exemption", False)),
                protocol_name=rule.get("protocol"), description=rule.get("description"),
                migration_status="PARTIALLY_NORMALIZED" if reasons else "NORMALIZED",
                requires_manual_review=bool(reasons), review_reasons=reasons,
                source_attributes={
                    "fdm_rule": rule, "fdm_nat_section": rule.get("section"),
                    "fdm_pat_method": rule.get("patMethod"),
                },
            ))

    def parse(self) -> IRConfig:
        ir = IRConfig(metadata=IRMetadata(
            source_vendor="cisco_ftd", source_product="Cisco Firepower Device Manager / FTD",
            input_type="fdm-rest-export", source_context=self.context,
        ))
        self._parse_addresses(ir)
        self._parse_network_groups(ir)
        self._parse_services(ir)
        self._parse_interfaces(ir)
        self._parse_nat_policies(ir)
        if self._unresolved:
            ir.generation_safe = False
            ir.generation_blocking_reasons.append("Unresolved FDM object/policy reference")
        return ir
