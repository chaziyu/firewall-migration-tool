from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Type

from ..model.common import CheckPointSourceObject
from ..model.policy import (
    CPAccessLayer, CPAccessRule, CPAccessSection, CPAutoNATRule, CPNATRule, CPNATSection,
)
from ..model.threat import CPHTTPSInspectionRule, CPThreatLayer, CPThreatRule, CPThreatRuleException, CPThreatSection
from ..models import CheckPointResponse
from .common import build_typed_object


def extract_access_rulebase(response: CheckPointResponse):
    return _extract_structured(response, CPAccessSection, CPAccessRule, "access_sections", "access_rules")


def extract_nat_rulebase(response: CheckPointResponse):
    return _extract_structured(response, CPNATSection, _nat_rule, "nat_sections", "nat_rules")


def extract_threat_rulebase(response: CheckPointResponse):
    return _extract_structured(response, CPThreatSection, _threat_rule, "threat_sections", "threat_rules")


def extract_https_rulebase(response: CheckPointResponse):
    return _extract_structured(response, None, CPHTTPSInspectionRule, None, "https_inspection_rules")


def extract_policy_records(response: CheckPointResponse):
    extractors = {
        "show-access-rulebase": extract_access_rulebase,
        "show-nat-rulebase": extract_nat_rulebase,
        "show-threat-rulebase": extract_threat_rulebase,
        "show-threat-rule-exception-rulebase": extract_threat_rulebase,
        "show-https-rulebase": extract_https_rulebase,
        "show-https-inspection-rulebase": extract_https_rulebase,
    }
    return extractors.get(response.command.lower(), lambda _: [])(response)


def _extract_structured(
    response: CheckPointResponse,
    section_model: Type[CheckPointSourceObject] | None,
    rule_model: Type[CheckPointSourceObject] | Callable[[dict[str, Any]], Type[CheckPointSourceObject]],
    section_bucket: str | None,
    rule_bucket: str,
):
    payload = response.data.get("rulebase", [])
    if not isinstance(payload, list):
        return []

    results = []
    section_order = 0
    rule_orders: defaultdict[str, int] = defaultdict(int)
    root_layer_uid = response.layer_uid or response.data.get("uid")
    root_response = response.model_copy(update={
        "layer": response.layer or response.data.get("name"),
        "layer_uid": root_layer_uid,
        "package": None,
        "package_uid": None,
        "parent_layer_uid": response.parent_layer_uid or response.data.get("parent-layer-uid"),
        "parent_rule_uid": response.parent_rule_uid or response.data.get("parent-rule-uid"),
    })
    if response.command.lower() == "show-access-rulebase" and response.data.get("uid"):
        root_layer = {"uid": response.data.get("uid"), "name": response.data.get("name"), "type": "access-layer"}
        for key in ("package", "package-uid", "parent-layer-uid", "parent-rule-uid"):
            if key in response.data:
                root_layer[key] = response.data[key]
        layer_response = root_response.model_copy(update={"parent_layer_uid": None, "parent_rule_uid": None})
        results.append(("access_layers", build_typed_object(
            layer_response,
            root_layer,
            CPAccessLayer,
        )))

    def walk(
        entries: list[Any],
        current_response: CheckPointResponse,
        path: tuple[str, ...] = (),
        current_layer_uid: str | None = root_layer_uid,
        parent_rule_uid: str | None = None,
    ) -> None:
        nonlocal section_order
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get("type") or "").lower()
            nested = entry.get("rulebase")
            if section_model is not None and (kind.endswith("-section") or kind == "section"):
                section_order += 1
                section_path = (*path, str(entry.get("name") or ""))
                section = {**entry, "_checkpoint_section_path": [part for part in section_path if part]}
                results.append((section_bucket, build_typed_object(current_response, section, section_model, section_order)))
                if isinstance(nested, list):
                    walk(nested, current_response, section_path, current_layer_uid, parent_rule_uid)
                continue
            if isinstance(nested, list) and kind not in {"access-rule", "nat-rule", "threat-rule", "https-rule"}:
                layer_uid = str(entry.get("uid") or "") or None
                layer_response = current_response.model_copy(update={
                    "layer": entry.get("name") or current_response.layer,
                    "layer_uid": layer_uid,
                    "package": None,
                    "package_uid": None,
                    "parent_layer_uid": current_layer_uid,
                    "parent_rule_uid": parent_rule_uid,
                })
                if section_model is not None and kind in {"access-layer", "threat-layer", "threat-protection-layer"}:
                    layer_model = CPAccessLayer if kind == "access-layer" else CPThreatLayer
                    source_layer_response = layer_response.model_copy(update={"parent_layer_uid": None, "parent_rule_uid": None})
                    results.append(("access_layers" if kind == "access-layer" else "threat_layers", build_typed_object(source_layer_response, entry, layer_model, None)))
                walk(nested, layer_response, path, layer_uid, parent_rule_uid)
                continue
            rule_orders[str(current_layer_uid or "root")] += 1
            rule = {**entry, "_checkpoint_section_path": [part for part in path if part]}
            model = rule_model(entry) if not isinstance(rule_model, type) else rule_model
            bucket = "threat_rule_exceptions" if model is CPThreatRuleException else rule_bucket
            results.append((bucket, build_typed_object(current_response, rule, model, rule_orders[str(current_layer_uid or "root")])))

    walk(payload, root_response)
    return results


def _nat_rule(value: dict[str, Any]):
    return CPAutoNATRule if value.get("automatic") or str(value.get("type") or "").lower() in {"automatic-nat-rule", "auto-nat-rule"} else CPNATRule


def _threat_rule(value: dict[str, Any]):
    return CPThreatRuleException if "exception" in str(value.get("type") or "").lower() else CPThreatRule
