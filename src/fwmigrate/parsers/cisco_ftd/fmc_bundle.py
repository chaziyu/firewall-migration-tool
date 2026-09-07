from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRApplication,
    IRConfig,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRService,
    IRServiceGroup,
    IRServicePort,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, PolicyAction, ServiceProtocol


FMC_BUNDLE_FORMAT = "cisco-fmc-rest-export-v1"


def _items(value: Any) -> List[dict]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        nested = value.get("items")
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
    return []


def _safe_name(prefix: str, expression: str) -> str:
    clean = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in expression).strip("_")
    digest = hashlib.sha1(expression.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}_{clean[:40] or 'value'}_{digest}"


def is_fmc_bundle(content: str) -> bool:
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return False
    if not isinstance(payload, dict):
        return False
    return payload.get("format") == FMC_BUNDLE_FORMAT or any(
        key in payload for key in ("access_policies", "nat_policies", "objects")
    ) and payload.get("source") in {"fmc-rest-api", "cisco-fmc-rest-api"}


class CiscoFMCBundleParser:
    """Parse an offline bundle assembled from documented FMC REST responses.

    This parser intentionally consumes FMC policy/object API payloads.  It does
    not infer Access Control Policy or NAT semantics from ASA/LINA CLI text.
    """

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
        self._object_by_id: Dict[str, dict] = {}
        self._object_by_name: Dict[str, dict] = {}
        self._unresolved: List[dict] = []
        self._synthetic_addresses: Dict[str, IRAddress] = {}
        self._synthetic_services: Dict[str, IRService] = {}
        self._index_objects()

    def _object_collections(self) -> Dict[str, List[dict]]:
        objects = self.payload.get("objects") if isinstance(self.payload.get("objects"), dict) else {}
        names = (
            "hosts", "networks", "ranges", "networkgroups", "protocolportobjects",
            "portobjectgroups", "securityzones", "applications", "users",
        )
        return {name: _items(objects.get(name)) for name in names}

    def _index_objects(self) -> None:
        for collection in self._object_collections().values():
            for item in collection:
                object_id = item.get("id")
                name = item.get("name")
                if isinstance(object_id, str):
                    self._object_by_id[object_id] = item
                if isinstance(name, str):
                    self._object_by_name[name] = item

    @staticmethod
    def _refs(container: Any) -> Tuple[List[dict], List[dict]]:
        if container is None:
            return [], []
        if isinstance(container, list):
            return [item for item in container if isinstance(item, dict)], []
        if not isinstance(container, dict):
            return [], []
        objects = _items(container.get("objects"))
        literals = _items(container.get("literals"))
        # Some expanded FMC payloads use an `items` envelope directly.
        if not objects and not literals and isinstance(container.get("items"), list):
            objects = _items(container)
        return objects, literals

    def _resolve_ref(self, ref: Any, *, field: str, owner: str) -> Optional[str]:
        if ref is None:
            return None
        if isinstance(ref, str):
            if ref in self._object_by_id:
                return self._object_by_id[ref].get("name") or ref
            if ref in self._object_by_name:
                return ref
            self._unresolved.append({"owner": owner, "field": field, "reference": ref})
            return ref
        if not isinstance(ref, dict):
            self._unresolved.append({"owner": owner, "field": field, "reference": repr(ref)})
            return None
        object_id = ref.get("id")
        name = ref.get("name")
        if isinstance(object_id, str) and object_id in self._object_by_id:
            return self._object_by_id[object_id].get("name") or name or object_id
        if isinstance(name, str):
            if name not in self._object_by_name and object_id:
                self._unresolved.append({"owner": owner, "field": field, "reference": object_id, "name": name})
            return name
        if isinstance(object_id, str):
            self._unresolved.append({"owner": owner, "field": field, "reference": object_id})
            return object_id
        self._unresolved.append({"owner": owner, "field": field, "reference": ref})
        return None

    def _literal_address(self, literal: dict, *, owner: str, field: str) -> Optional[str]:
        value = literal.get("value") or literal.get("name")
        if not isinstance(value, str) or not value.strip():
            self._unresolved.append({"owner": owner, "field": field, "literal": literal})
            return None
        value = value.strip()
        name = _safe_name("fmc_literal", value)
        if name in self._synthetic_addresses:
            return name
        try:
            if "-" in value and value.count("-") == 1:
                start, end = (part.strip() for part in value.split("-", 1))
                first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
                if first.version != last.version or int(first) > int(last):
                    raise ValueError
                address = IRAddress(
                    name=name, source_context=self.context, type=AddressType.RANGE,
                    ip_range_start=start, ip_range_end=end,
                    address_family=f"ipv{first.version}", is_ipv6=first.version == 6,
                    raw_value=value,
                    source_attributes={"fmc_literal": literal, "owner": owner, "field": field},
                )
            else:
                parsed = ipaddress.ip_network(value, strict=False)
                address = IRAddress(
                    name=name, source_context=self.context,
                    type=AddressType.HOST if parsed.prefixlen == parsed.max_prefixlen else AddressType.NETWORK,
                    subnet=str(parsed), address_family=f"ipv{parsed.version}", is_ipv6=parsed.version == 6,
                    raw_value=value,
                    source_attributes={"fmc_literal": literal, "owner": owner, "field": field},
                )
        except ValueError:
            self._unresolved.append({"owner": owner, "field": field, "literal": value, "reason": "invalid-network-literal"})
            return None
        self._synthetic_addresses[name] = address
        return name

    def _network_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        objects, literals = self._refs(container)
        values: List[str] = []
        unresolved_before = len(self._unresolved)
        for ref in objects:
            name = self._resolve_ref(ref, field=field, owner=owner)
            if name:
                values.append(name)
        for literal in literals:
            name = self._literal_address(literal, owner=owner, field=field)
            if name:
                values.append(name)
        return values or [IR_KEYWORD_ANY], len(self._unresolved) > unresolved_before

    def _zone_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        objects, _ = self._refs(container)
        unresolved_before = len(self._unresolved)
        values = [name for ref in objects if (name := self._resolve_ref(ref, field=field, owner=owner))]
        return values or [IR_KEYWORD_ANY], len(self._unresolved) > unresolved_before

    @staticmethod
    def _protocol(value: Any) -> Optional[ServiceProtocol]:
        text = str(value or "").strip().lower()
        return {
            "6": ServiceProtocol.TCP, "tcp": ServiceProtocol.TCP,
            "17": ServiceProtocol.UDP, "udp": ServiceProtocol.UDP,
            "132": ServiceProtocol.SCTP, "sctp": ServiceProtocol.SCTP,
            "1": ServiceProtocol.ICMP, "icmp": ServiceProtocol.ICMP,
            "58": ServiceProtocol.ICMPV6, "icmpv6": ServiceProtocol.ICMPV6, "icmp6": ServiceProtocol.ICMPV6,
            "ip": ServiceProtocol.IP, "0": ServiceProtocol.IP,
        }.get(text)

    def _literal_service(self, literal: dict, *, owner: str, field: str) -> Optional[str]:
        protocol = self._protocol(literal.get("protocol"))
        port = literal.get("port") or literal.get("value") or literal.get("name")
        if protocol is None:
            self._unresolved.append({"owner": owner, "field": field, "literal": literal, "reason": "unsupported-protocol-literal"})
            return None
        if port is None:
            port = "any" if protocol in {ServiceProtocol.IP, ServiceProtocol.ICMP, ServiceProtocol.ICMPV6} else "1-65535"
        port_text = str(port)
        expression = f"{protocol.value}:{port_text}"
        name = _safe_name("fmc_service_literal", expression)
        if name not in self._synthetic_services:
            self._synthetic_services[name] = IRService(
                name=name, source_context=self.context,
                ports=[IRServicePort(protocol=protocol, port=port_text, raw_source_value=json.dumps(literal, sort_keys=True))],
                source_protocol=protocol.value,
                source_attributes={"fmc_literal": literal, "owner": owner, "field": field},
            )
        return name

    def _service_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        objects, literals = self._refs(container)
        values: List[str] = []
        unresolved_before = len(self._unresolved)
        for ref in objects:
            name = self._resolve_ref(ref, field=field, owner=owner)
            if name:
                values.append(name)
        for literal in literals:
            name = self._literal_service(literal, owner=owner, field=field)
            if name:
                values.append(name)
        return values or [IR_KEYWORD_ANY], len(self._unresolved) > unresolved_before

    def _parse_objects(self, ir: IRConfig) -> None:
        collections = self._object_collections()
        for kind in ("hosts", "networks", "ranges"):
            for obj in collections[kind]:
                name = obj.get("name")
                value = obj.get("value")
                if not isinstance(name, str) or not isinstance(value, str):
                    continue
                kwargs: Dict[str, Any] = {
                    "name": name, "source_context": self.context,
                    "source_uuid": obj.get("id"),
                    "source_attributes": {"fmc_object": obj, "fmc_type": obj.get("type")},
                    "raw_value": value,
                }
                try:
                    if kind == "ranges":
                        start, end = (part.strip() for part in value.split("-", 1))
                        first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
                        if first.version != last.version or int(first) > int(last):
                            raise ValueError
                        kwargs.update(type=AddressType.RANGE, ip_range_start=start, ip_range_end=end,
                                      address_family=f"ipv{first.version}", is_ipv6=first.version == 6)
                    else:
                        parsed = ipaddress.ip_network(value, strict=False)
                        kwargs.update(
                            type=AddressType.HOST if kind == "hosts" or parsed.prefixlen == parsed.max_prefixlen else AddressType.NETWORK,
                            subnet=str(parsed), address_family=f"ipv{parsed.version}", is_ipv6=parsed.version == 6,
                        )
                    ir.addresses.append(IRAddress(**kwargs))
                except (ValueError, TypeError):
                    self._unresolved.append({"owner": name, "field": "value", "literal": value, "reason": "invalid-fmc-address-object"})

        for group in collections["networkgroups"]:
            name = group.get("name")
            if not isinstance(name, str):
                continue
            members: List[str] = []
            unresolved_before = len(self._unresolved)
            objects, literals = self._refs(group)
            # FMC NetworkGroup uses top-level `objects` and `literals`.
            if not objects and isinstance(group.get("objects"), list):
                objects = _items(group.get("objects"))
            if not literals and isinstance(group.get("literals"), list):
                literals = _items(group.get("literals"))
            for ref in objects:
                member = self._resolve_ref(ref, field="members", owner=name)
                if member:
                    members.append(member)
            for literal in literals:
                member = self._literal_address(literal, owner=name, field="members")
                if member:
                    members.append(member)
            unresolved = len(self._unresolved) > unresolved_before
            ir.address_groups.append(IRAddressGroup(
                name=name, source_context=self.context, members=members,
                description=group.get("description"), source_uuid=group.get("id"),
                migration_status="PARTIALLY_NORMALIZED" if unresolved else "NORMALIZED",
                requires_manual_review=unresolved,
                source_attributes={"fmc_object": group, "fmc_type": group.get("type")},
            ))

        for obj in collections["protocolportobjects"]:
            name = obj.get("name")
            if not isinstance(name, str):
                continue
            protocol = self._protocol(obj.get("protocol"))
            port = obj.get("port") or obj.get("value")
            if protocol is None:
                self._unresolved.append({"owner": name, "field": "protocol", "reference": obj.get("protocol")})
                continue
            if port is None:
                port = "any" if protocol in {ServiceProtocol.IP, ServiceProtocol.ICMP, ServiceProtocol.ICMPV6} else "1-65535"
            ir.services.append(IRService(
                name=name, source_context=self.context,
                ports=[IRServicePort(protocol=protocol, port=str(port), raw_source_value=str(port))],
                source_uuid=obj.get("id"), source_protocol=protocol.value,
                description=obj.get("description"),
                source_attributes={"fmc_object": obj, "fmc_type": obj.get("type")},
            ))

        for group in collections["portobjectgroups"]:
            name = group.get("name")
            if not isinstance(name, str):
                continue
            objects, literals = self._refs(group)
            members: List[str] = []
            unresolved_before = len(self._unresolved)
            for ref in objects:
                member = self._resolve_ref(ref, field="members", owner=name)
                if member:
                    members.append(member)
            for literal in literals:
                member = self._literal_service(literal, owner=name, field="members")
                if member:
                    members.append(member)
            unresolved = len(self._unresolved) > unresolved_before
            ir.service_groups.append(IRServiceGroup(
                name=name, source_context=self.context, members=members,
                description=group.get("description"), source_uuid=group.get("id"),
                migration_status="PARTIALLY_NORMALIZED" if unresolved else "NORMALIZED",
                requires_manual_review=unresolved,
                source_attributes={"fmc_object": group, "fmc_type": group.get("type")},
            ))

        for zone in collections["securityzones"]:
            name = zone.get("name")
            if isinstance(name, str):
                ir.zones.append(IRZone(
                    name=name, source_context=self.context,
                    source_attributes={"fmc_object": zone, "fmc_type": zone.get("type")},
                ))

        for app in collections["applications"]:
            name = app.get("name")
            if isinstance(name, str):
                ir.applications.append(IRApplication(
                    name=name, source_context=self.context, source_uuid=app.get("id"),
                    category=app.get("category"), description=app.get("description"),
                    source_attributes={"fmc_object": app, "fmc_type": app.get("type")},
                ))

    @staticmethod
    def _action(value: Any) -> Tuple[Optional[PolicyAction], bool, Optional[str]]:
        text = str(value or "").strip().upper()
        if text == "ALLOW":
            return PolicyAction.ALLOW, False, None
        if text == "TRUST":
            return PolicyAction.ALLOW, True, "FMC TRUST action allows traffic while bypassing inspection semantics"
        if text == "BLOCK":
            return PolicyAction.DENY, False, None
        if text == "BLOCK_RESET":
            return PolicyAction.DENY, True, "FMC BLOCK_RESET reset behavior is source-preserved"
        return None, True, f"Unsupported FMC access-rule action: {text or '<missing>'}"

    def _named_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        objects, literals = self._refs(container)
        unresolved_before = len(self._unresolved)
        values: List[str] = []
        for ref in objects:
            name = self._resolve_ref(ref, field=field, owner=owner)
            if name:
                values.append(name)
        for literal in literals:
            value = literal.get("name") or literal.get("value")
            if isinstance(value, str):
                values.append(value)
            else:
                self._unresolved.append({"owner": owner, "field": field, "literal": literal})
        return values, len(self._unresolved) > unresolved_before

    def _parse_access_policies(self, ir: IRConfig) -> None:
        for policy in _items(self.payload.get("access_policies")):
            policy_name = policy.get("name") or policy.get("id") or "FMC_Access_Policy"
            policy_id = policy.get("id")
            rules = _items(policy.get("rules"))
            for index, rule in enumerate(rules, 1):
                rule_name = rule.get("name") or rule.get("id") or f"rule_{index}"
                owner = f"{policy_name}/{rule_name}"
                from_zone, zone_src_unresolved = self._zone_refs(rule.get("sourceZones"), owner=owner, field="sourceZones")
                to_zone, zone_dst_unresolved = self._zone_refs(rule.get("destinationZones"), owner=owner, field="destinationZones")
                source, src_unresolved = self._network_refs(rule.get("sourceNetworks"), owner=owner, field="sourceNetworks")
                destination, dst_unresolved = self._network_refs(rule.get("destinationNetworks"), owner=owner, field="destinationNetworks")
                services, svc_unresolved = self._service_refs(rule.get("destinationPorts") or rule.get("sourcePorts"), owner=owner, field="ports")
                applications, app_unresolved = self._named_refs(rule.get("applications"), owner=owner, field="applications")
                users, user_unresolved = self._named_refs(rule.get("users"), owner=owner, field="users")
                action, action_review, action_reason = self._action(rule.get("action"))
                review_reasons = [reason for reason in [action_reason] if reason]
                unresolved = any((zone_src_unresolved, zone_dst_unresolved, src_unresolved, dst_unresolved, svc_unresolved, app_unresolved, user_unresolved))
                if unresolved:
                    review_reasons.append("One or more FMC rule references were unresolved in the exported bundle")
                profile_refs = {
                    "ipsPolicy": rule.get("ipsPolicy"),
                    "filePolicy": rule.get("filePolicy"),
                    "variableSet": rule.get("variableSet"),
                }
                if any(value for value in profile_refs.values()):
                    review_reasons.append("FMC inspection/file policy references are source-preserved for target capability review")
                requires_review = action_review or unresolved or bool(review_reasons)
                ir.policies.append(IRPolicy(
                    name=f"{policy_name}__{rule_name}", source_context=self.context,
                    source_rule_id=str(rule.get("metadata", {}).get("ruleIndex") or index),
                    source_uuid=rule.get("id"), from_zone=from_zone, to_zone=to_zone,
                    source=source, destination=destination, service=services,
                    action=action, source_action=rule.get("action"), applications=applications,
                    source_users=users, disabled=not bool(rule.get("enabled", True)),
                    log_start=bool(rule.get("logBegin", False)), log_end=bool(rule.get("logEnd", False)),
                    description=rule.get("description"),
                    migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
                    requires_manual_review=requires_review, review_reasons=review_reasons,
                    source_extra_settings={
                        "fmc_policy_id": policy_id, "fmc_policy_name": policy_name,
                        "fmc_rule": rule, "send_events_to_fmc": rule.get("sendEventsToFMC"),
                        "enable_syslog": rule.get("enableSyslog"), "profile_references": profile_refs,
                    },
                ))

            default = policy.get("defaultAction") if isinstance(policy.get("defaultAction"), dict) else None
            if default:
                action, action_review, action_reason = self._action(default.get("action"))
                reasons = [action_reason] if action_reason else []
                ir.policies.append(IRPolicy(
                    name=f"{policy_name}__default", source_context=self.context,
                    source_rule_id="default", source_uuid=default.get("id"),
                    from_zone=[IR_KEYWORD_ANY], to_zone=[IR_KEYWORD_ANY],
                    source=[IR_KEYWORD_ANY], destination=[IR_KEYWORD_ANY], service=[IR_KEYWORD_ANY],
                    action=action, source_action=default.get("action"),
                    log_start=bool(default.get("logBegin", False)), log_end=bool(default.get("logEnd", False)),
                    migration_status="PARTIALLY_NORMALIZED" if action_review else "NORMALIZED",
                    requires_manual_review=action_review, review_reasons=reasons,
                    source_extra_settings={"fmc_policy_id": policy_id, "fmc_default_action": True, "fmc_default_action_payload": default},
                ))

    def _nat_ref(self, value: Any, *, owner: str, field: str, any_when_none: bool = True) -> Tuple[List[str], bool]:
        if value is None:
            return ([IR_KEYWORD_ANY] if any_when_none else []), False
        unresolved_before = len(self._unresolved)
        name = self._resolve_ref(value, field=field, owner=owner)
        return ([name] if name else []), len(self._unresolved) > unresolved_before

    def _parse_nat_rule(self, policy: dict, rule: dict, *, section: str, index: int, auto: bool) -> IRNATRule:
        policy_name = policy.get("name") or policy.get("id") or "FMC_NAT_Policy"
        rule_name = rule.get("name") or rule.get("id") or f"nat_{index}"
        owner = f"{policy_name}/{rule_name}"
        nat_type = str(rule.get("natType") or "").upper()
        src_if, src_if_unresolved = self._nat_ref(rule.get("sourceInterface"), owner=owner, field="sourceInterface", any_when_none=False)
        dst_if, dst_if_unresolved = self._nat_ref(rule.get("destinationInterface"), owner=owner, field="destinationInterface", any_when_none=False)

        if auto:
            source, src_unresolved = self._nat_ref(rule.get("originalNetwork"), owner=owner, field="originalNetwork")
            destination = [IR_KEYWORD_ANY]
            translated_source, trans_unresolved = self._nat_ref(rule.get("translatedNetwork"), owner=owner, field="translatedNetwork", any_when_none=False)
            translated_destination: List[str] = []
            interface_translation = bool(rule.get("interfaceInTranslatedNetwork"))
            original_source_port = rule.get("originalPort")
            translated_source_port = rule.get("translatedPort")
        else:
            source, src_unresolved = self._nat_ref(rule.get("originalSource"), owner=owner, field="originalSource")
            destination, dst_unresolved = self._nat_ref(rule.get("originalDestination"), owner=owner, field="originalDestination")
            translated_source, trans_unresolved = self._nat_ref(rule.get("translatedSource"), owner=owner, field="translatedSource", any_when_none=False)
            translated_destination, trans_dst_unresolved = self._nat_ref(rule.get("translatedDestination"), owner=owner, field="translatedDestination", any_when_none=False)
            interface_translation = bool(rule.get("interfaceInTranslatedSource"))
            original_source_port = rule.get("originalSourcePort")
            translated_source_port = rule.get("translatedSourcePort")
            if dst_unresolved or trans_dst_unresolved:
                src_unresolved = True

        if interface_translation:
            source_mode = NATTranslationMode.INTERFACE_ADDRESS
        elif nat_type == "STATIC":
            source_mode = NATTranslationMode.STATIC
        elif nat_type == "DYNAMIC":
            pat_options = rule.get("patOptions") if isinstance(rule.get("patOptions"), dict) else {}
            # Port translation is explicit when PAT options/translated source
            # port are present. Otherwise FMC dynamic NAT is address-only.
            source_mode = NATTranslationMode.DYNAMIC_IP_AND_PORT if (pat_options or translated_source_port) else NATTranslationMode.DYNAMIC_IP
        else:
            source_mode = None

        has_destination_translation = bool(translated_destination)
        ir_type = NATType.TWICE if has_destination_translation else NATType.SOURCE
        unresolved = any((src_if_unresolved, dst_if_unresolved, src_unresolved, trans_unresolved))
        review_reasons: List[str] = []
        if unresolved:
            review_reasons.append("One or more FMC NAT references were unresolved in the exported bundle")
        if source_mode is None:
            review_reasons.append(f"Unsupported or missing FMC NAT type: {nat_type or '<missing>'}")
        if original_source_port or translated_source_port or (not auto and (rule.get("originalDestinationPort") or rule.get("translatedDestinationPort"))):
            review_reasons.append("FMC NAT port-translation references are source-preserved for target capability review")
        if rule.get("patOptions"):
            review_reasons.append("FMC PAT options are source-preserved for target capability review")

        requires_review = bool(review_reasons)
        return IRNATRule(
            name=f"{policy_name}__{rule_name}", type=ir_type, source_context=self.context,
            source_uuid=rule.get("id"), source_rule_id=str(rule.get("targetIndex") or index),
            from_zone=src_if, to_zone=dst_if,
            source_from_interfaces=src_if, source_to_interfaces=dst_if,
            source=source, destination=destination,
            services=[IR_KEYWORD_ANY], translated_sources=translated_source,
            translated_destinations=translated_destination,
            source_translation_mode=source_mode,
            enabled=bool(rule.get("enabled", True)), description=rule.get("description"),
            migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
            requires_manual_review=requires_review, review_reasons=review_reasons,
            source_attributes={
                "fmc_policy_id": policy.get("id"), "fmc_policy_name": policy_name,
                "fmc_nat_rule": rule, "fmc_nat_section": section, "fmc_auto_nat": auto,
                "fmc_nat_type": nat_type, "fmc_interface_translation": interface_translation,
                "dns": rule.get("dns"), "route_lookup": rule.get("routeLookup"),
                "no_proxy_arp": rule.get("noProxyArp"), "net_to_net": rule.get("netToNet"),
                "fall_through": rule.get("fallThrough"), "unidirectional": rule.get("unidirectional"),
                "original_source_port": original_source_port, "translated_source_port": translated_source_port,
            },
        )

    def _parse_nat_policies(self, ir: IRConfig) -> None:
        for policy in _items(self.payload.get("nat_policies")):
            before = _items(policy.get("manual_rules_before_auto"))
            after = _items(policy.get("manual_rules_after_auto"))
            manual = _items(policy.get("manual_rules"))
            if manual and not before and not after:
                for rule in manual:
                    section = str(rule.get("section") or "before_auto").lower()
                    (after if section == "after_auto" else before).append(rule)
            auto = _items(policy.get("auto_rules"))
            sequence = 0
            for section, rules, is_auto in (("before_auto", before, False), ("auto", auto, True), ("after_auto", after, False)):
                for rule in rules:
                    sequence += 1
                    ir.nat_rules.append(self._parse_nat_rule(policy, rule, section=section, index=sequence, auto=is_auto))

    def parse(self) -> IRConfig:
        ir = IRConfig(metadata=IRMetadata(
            source_vendor="cisco_ftd", source_product="Cisco Secure Firewall Management Center / FTD",
            source_attributes={
                "fmc_bundle_format": self.payload.get("format") or FMC_BUNDLE_FORMAT,
                "fmc_domain_id": self.domain_id, "fmc_domain_name": self.domain_name,
                "fmc_api_source": self.payload.get("source") or "fmc-rest-api",
            },
        ))
        self._parse_objects(ir)
        self._parse_access_policies(ir)
        self._parse_nat_policies(ir)
        ir.addresses.extend(self._synthetic_addresses.values())
        ir.services.extend(self._synthetic_services.values())
        if self._unresolved:
            ir.metadata.source_attributes["fmc_unresolved_references"] = self._unresolved
            ir.generation_safe = False
        return ir
