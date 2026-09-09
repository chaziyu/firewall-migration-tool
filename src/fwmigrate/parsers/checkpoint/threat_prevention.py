"""Source-only Check Point Threat Prevention rulebase extraction."""

from __future__ import annotations

from typing import Any, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRCheckpointThreatPreventionRule
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase


def _list(value: Any) -> List[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [str(v.get("name") or v.get("uid") or v) if isinstance(v, dict) else str(v) for v in values]


def extract_threat_prevention(responses: List[CheckPointResponse]) -> Tuple[List[IRCheckpointThreatPreventionRule], List[SourceInventoryItem]]:
    rules: List[IRCheckpointThreatPreventionRule] = []
    inventory: List[SourceInventoryItem] = []
    for response in responses:
        if response.command.lower() not in {"show-threat-rulebase", "show-threat-prevention-rulebase"}:
            continue
        for rule, section in flatten_rulebase(response.data.get("rulebase", [])):
            rule_obj = IRCheckpointThreatPreventionRule(
                name=rule.get("name"), source_uuid=rule.get("uid"), rule_number=rule.get("rule-number"),
                source_context=response.domain, source_scope=_list(rule.get("source") or rule.get("protected-scope")),
                destination=_list(rule.get("destination")), service=_list(rule.get("service")),
                profile=(rule.get("profile") or {}).get("name") if isinstance(rule.get("profile"), dict) else rule.get("profile"),
                action=rule.get("action"), track=rule.get("track"), install_on=_list(rule.get("install-on")),
                comments=rule.get("comments"), enabled=rule.get("enabled"), exceptions=rule.get("exceptions") or [],
                source_attributes={**rule, "section": section},
            )
            rules.append(rule_obj)
            inventory.append(SourceInventoryItem(
                domain=response.domain or "global", source_path=f"checkpoint/{response.command}", name=rule_obj.name or "threat-rule",
                source_id=rule_obj.source_uuid, source_type="threat-prevention-rule", source_attributes=rule_obj.source_attributes,
                status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
            ))
    return rules, inventory
