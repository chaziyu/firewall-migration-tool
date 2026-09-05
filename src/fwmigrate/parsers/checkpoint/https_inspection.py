"""Check Point HTTPS Inspection rulebase extraction."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRHTTPSInspectionRule
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase, parse_required_bool


def _safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): _safe(v) for k, v in value.items()
            if not any(token in str(k).lower() for token in ("private", "password", "passphrase", "secret"))
        }
    if isinstance(value, list):
        return [_safe(item) for item in value]
    return value


def _list(value: Any) -> List[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [str(item.get("name") or item.get("uid") if isinstance(item, dict) else item) for item in values]


def extract_https_inspection_rulebase(
    responses: List[CheckPointResponse],
) -> Tuple[List[IRHTTPSInspectionRule], List[SourceInventoryItem]]:
    rules: List[IRHTTPSInspectionRule] = []
    inventory: List[SourceInventoryItem] = []
    commands = {"show-https-inspection-rulebase", "show-https-inspection-policy"}
    for response in responses:
        if canonicalize_command(response.command) not in commands:
            continue
        for rule, section_title in flatten_rulebase(response.data.get("rulebase", [])):
            number = rule.get("rule-number")
            name = rule.get("name") or f"Rule_{number or len(rules) + 1}"
            enabled, enabled_error = parse_required_bool(rule.get("enabled"), "enabled")
            if enabled_error:
                enabled = None
            attrs = _safe(dict(rule))
            rules.append(IRHTTPSInspectionRule(
                name=name, source_uuid=rule.get("uid"), rule_number=number,
                source_context=response.domain, source=_list(rule.get("source")),
                destination=_list(rule.get("destination")), service=_list(rule.get("service")),
                action=rule.get("action"),
                certificate=(rule.get("certificate") or rule.get("server-certificate") or rule.get("ca-certificate")),
                bypass=rule.get("bypass") if isinstance(rule.get("bypass"), bool) else None,
                comments=rule.get("comments"), enabled=enabled,
                install_on=_list(rule.get("install-on") or rule.get("install_on")),
                migration_status=ExtractionStatus.NORMALIZED.value if not enabled_error else ExtractionStatus.PARSE_ERROR.value,
                requires_manual_review=bool(enabled_error), source_attributes=attrs,
            ))
            inventory.append(SourceInventoryItem(
                domain=response.domain or "global",
                source_path=f"checkpoint/{canonicalize_command(response.command)}",
                name=name, source_id=rule.get("uid"), source_type="https-inspection-rule",
                source_attributes=attrs,
                status=ExtractionStatus.PARSE_ERROR if enabled_error else ExtractionStatus.NORMALIZED,
                requires_manual_review=bool(enabled_error),
                notes=[enabled_error] if enabled_error else ([f"Section: {section_title}"] if section_title else []),
            ))
    return rules, inventory
