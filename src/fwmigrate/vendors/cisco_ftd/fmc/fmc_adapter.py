from __future__ import annotations

from typing import Any, List, Tuple

from fwmigrate.ir import IRConfig
from .fmc_bundle import (
    CiscoFMCBundleParser as _RawCiscoFMCBundleParser,
    FMC_BUNDLE_FORMAT,
    _items,
    is_fmc_bundle,
)
from ..model import (
    CiscoFTDACPRule, CiscoFTDConfig, CiscoFTDInterfaceSource,
    CiscoFTDNATRule, CiscoFTDObject, CiscoFTDService, CiscoFTDZone,
)


class CiscoFMCBundleParser(_RawCiscoFMCBundleParser):
    """Production FMC bundle adapter with canonical safety gates.

    The raw parser owns FMC REST payload decoding. This wrapper owns the
    target-neutral safety decisions that must not be guessed from FMC fields.
    """

    @staticmethod
    def _fail_closed_refs(result: Tuple[List[str], bool]) -> Tuple[List[str], bool]:
        values, unresolved = result
        if unresolved and values == [IR_KEYWORD_ANY]:
            return [], True
        return values, unresolved

    @staticmethod
    def _coerce_nat_order_index(value: Any) -> int | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip()
            if text and text.lstrip("+-").isdigit():
                return int(text)
        return None

    @classmethod
    def _order_values_conflict(cls, rules: List[Any], key: str) -> bool:
        values = []
        for position, rule in enumerate(rules, 1):
            value = cls._coerce_nat_order_index(rule.source_attributes.get(key))
            if value is not None:
                values.append((position, value))
        if len(values) < 2:
            return False
        numeric = [value for _, value in values]
        return len(set(numeric)) != len(numeric) or any(
            current <= previous for previous, current in zip(numeric, numeric[1:])
        )

    @classmethod
    def _mark_nat_order_conflicts(cls, rules: List[Any]) -> None:
        grouped: dict[tuple[Any, Any], List[Any]] = {}
        for rule in rules:
            key = (
                rule.source_attributes.get("fmc_policy_id"),
                rule.source_attributes.get("fmc_nat_section"),
            )
            grouped.setdefault(key, []).append(rule)

        reason = (
            "FMC NAT ordering metadata conflicts with bundle traversal order; "
            "effective order is source-preserved and requires review"
        )
        for section_rules in grouped.values():
            for position, rule in enumerate(section_rules, 1):
                rule.source_attributes["fmc_bundle_position"] = position

            conflict = cls._order_values_conflict(section_rules, "fmc_target_index") or cls._order_values_conflict(
                section_rules, "fmc_source_index"
            )
            for rule in section_rules:
                rule.source_attributes["fmc_order_consistent"] = not conflict
                if not conflict:
                    continue
                rule.source_attributes["fmc_order_review_reason"] = reason
                if reason not in rule.review_reasons:
                    rule.review_reasons.append(reason)
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"

    def _network_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        return self._fail_closed_refs(
            super()._network_refs(container, owner=owner, field=field)
        )

    def _zone_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        return self._fail_closed_refs(
            super()._zone_refs(container, owner=owner, field=field)
        )

    def _service_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        return self._fail_closed_refs(
            super()._service_refs(container, owner=owner, field=field)
        )

    def parse(self) -> IRConfig:
        from ..transformer import FMCToIRTransformer

        return FMCToIRTransformer(self).transform()

    def parse_source(self) -> CiscoFTDConfig:
        """Build FTD source state directly from the FMC REST payload."""
        objects = self._object_collections()
        plane = "fmc-rest-bundle"

        def name(item: dict, index: int) -> str:
            return str(item.get("name") or item.get("id") or index)

        def ref_name(value: Any) -> str | None:
            if isinstance(value, dict):
                value = value.get("name") or value.get("id")
            return str(value) if value is not None else None

        def record(item: dict, index: int, cls, **values):
            return cls(
                name=name(item, index), source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, raw=item,
                source_attributes={"provenance": "FMC REST", "domain_id": self.domain_id},
                **values,
            )

        network_names = {name(item, i) for i, item in enumerate(
            objects.get("hosts", []) + objects.get("networks", []) + objects.get("ranges", []), 1
        )}
        groups = [record(item, i, CiscoFTDObject, object_type="network-group",
                         members=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                                  for x in item.get("objects", item.get("members", []))])
                  for i, item in enumerate(objects.get("networkgroups", []), 1)]
        managed = [record(item, i, CiscoFTDObject, object_type=kind)
                   for kind, collection in objects.items()
                   if kind not in {
                       "networkgroups", "protocolportobjects", "portobjectgroups",
                       "securityzones", "interfaces",
                   }
                   for i, item in enumerate(collection, 1)]
        services = [record(item, i, CiscoFTDService, protocol=item.get("protocol"),
                           ports=item.get("ports", []))
                    for i, item in enumerate(objects.get("protocolportobjects", []), 1)]
        services += [record(item, i, CiscoFTDService, protocol=item.get("protocol"),
                            members=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                                     for x in item.get("objects", item.get("members", []))])
                     for i, item in enumerate(objects.get("portobjectgroups", []), 1)]
        zones = [record(item, i, CiscoFTDZone,
                        interfaces=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                                   for x in item.get("interfaces", [])])
                 for i, item in enumerate(objects.get("securityzones", []), 1)]
        interfaces = [record(item, i, CiscoFTDInterfaceSource,
                             interface_type=item.get("type"), address=item.get("address"),
                             zone=(item.get("securityZone") or {}).get("name")
                             if isinstance(item.get("securityZone"), dict) else item.get("securityZone"))
                      for i, item in enumerate(objects.get("interfaces", []), 1)]

        acp_rules = []
        for policy_index, policy in enumerate(_items(self.payload.get("access_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            for rule_index, item in enumerate(_items(policy.get("rules")), 1):
                acp_rules.append(record(item, rule_index, CiscoFTDACPRule,
                    policy=policy_name, action=item.get("action"), order=rule_index,
                    source=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                            for x in _items(item.get("source"))],
                    destination=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                                 for x in _items(item.get("destination"))],
                    services=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                              for x in _items(item.get("sourcePorts") or item.get("destinationPorts"))],
                ))
        nat_rules = []
        for policy_index, policy in enumerate(_items(self.payload.get("nat_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            raw_rules = _items(policy.get("manual_rules_before_auto")) + _items(policy.get("manual_rules")) + _items(policy.get("auto_rules")) + _items(policy.get("manual_rules_after_auto"))
            for rule_index, item in enumerate(raw_rules, 1):
                nat_rules.append(record(item, rule_index, CiscoFTDNATRule,
                    policy=policy_name, source_interface=ref_name(item.get("sourceInterface")),
                    destination_interface=ref_name(item.get("destinationInterface")),
                    original=item.get("originalSource", item.get("source", {})) if isinstance(item.get("originalSource", item.get("source", {})), dict) else {},
                    translated=item.get("translatedSource", item.get("translated", {})) if isinstance(item.get("translatedSource", item.get("translated", {})), dict) else {},
                    order=rule_index))
        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={"domain_id": self.domain_id, "domain_name": self.domain_name,
                             "source": self.payload.get("source", "fmc-rest-api")},
            managed_objects=managed, object_groups=groups, services=services,
            security_zones=zones, source_interfaces=interfaces, acp_rules=acp_rules,
            nat_policies=nat_rules,
        )


__all__ = ["CiscoFMCBundleParser", "FMC_BUNDLE_FORMAT", "is_fmc_bundle"]
