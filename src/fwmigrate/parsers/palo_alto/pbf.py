"""Extract PAN-OS Policy Based Forwarding rules as source-only evidence.

PBF is kept separate from static routes and Security Policy because its
selectors and forwarding actions use a distinct PAN-OS hierarchy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any, Dict, Iterable
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import (
    add_source_section,
    record_extract_only,
    record_parse_error,
    record_unsupported,
)
from .source_model import PANScope, pan_scope_identity
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


PBF_COMMON_FIELDS = [
    "from", "to", "source", "destination", "source-user", "service", "application",
    "user", "from-zone", "to-zone", "from-interface", "to-interface", "hip",
    "action", "disabled", "description", "tag", "group-tag", "log-start", "log-end",
    "log-setting", "schedule", "negate-source", "negate-destination",
]
PBF_ROOT_FIELDS = ["enforce-symmetric-return", "active-active-device-binding"]
PBF_RULE_KNOWN_CHILDREN = PBF_COMMON_FIELDS + PBF_ROOT_FIELDS
PBF_ACTION_FIELDS = ["forward", "forward-to-vsys", "discard", "no-pbf"]
PBF_FORWARD_FIELDS = ["egress-interface", "nexthop", "next-vr", "monitor"]
PBF_NEXTHOP_FIELDS = ["ip-address", "fqdn", "none"]
PBF_MONITOR_FIELDS = ["profile", "ip-address", "disable-if-unreachable", "enabled"]
PBF_ACTIVE_ACTIVE_BINDINGS = {"primary", "both", "0", "1"}


@dataclass(frozen=True)
class _PBFClassification:
    """The single rule-level decision used for PBF inventory recording."""

    status: ExtractionStatus
    requires_manual_review: bool
    review_reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _issue(reason: str, detail: str) -> tuple[str, str]:
    return reason, detail


def _append_issues(target: Dict[str, Any], key: str, values: Iterable[tuple[str, str]]) -> None:
    target.setdefault(key, []).extend(values)


def _looks_like_forwarding_target(field_name: str) -> bool:
    normalized = field_name.lower().replace("_", "-")
    return any(marker in normalized for marker in ("target", "next-hop", "nexthop-type", "egress"))


def _dedupe_reasons(reasons: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(reasons))


def _section_status(statuses: Iterable[ExtractionStatus]) -> ExtractionStatus:
    values = set(statuses)
    if not values:
        return ExtractionStatus.EXTRACT_ONLY
    if len(values) == 1:
        return next(iter(values))
    return ExtractionStatus.PARTIALLY_NORMALIZED


def _entries(root: ET.Element, container: str) -> Iterable[ET.Element]:
    return root.findall(f"./{container}/pbf/rules/entry")


def _strict_yes_no(node: ET.Element | None, path: str) -> tuple[Any, str | None]:
    """Read a PAN-OS yes/no field without turning malformed input into False."""
    if node is None:
        return None, None
    value_node = node.find(path)
    if value_node is None:
        return None, None
    value = (value_node.text or "").strip()
    if value == "yes":
        return True, None
    if value == "no":
        return False, None
    return None, f"Malformed PAN-OS yes/no value at {path}: {value!r}."


def _direct_text(node: ET.Element | None, path: str) -> str | None:
    if node is None:
        return None
    child = node.find(path)
    value = (child.text or "").strip() if child is not None else ""
    return value or None


class PANPBFRuleExtractor:
    """Extract nested PAN-OS PBF rules without creating canonical IR objects."""

    @classmethod
    def parse_rules(cls, root: ET.Element, scope: PANScope, extraction) -> int:
        return cls()._parse_rules(root, scope, extraction)

    def _parse_rules(self, root: ET.Element, scope: PANScope, extraction) -> int:
        total = 0
        for position, container in (
            ("pre", "pre-rulebase"),
            ("local", "rulebase"),
            ("post", "post-rulebase"),
        ):
            entries = list(_entries(root, container))
            section_inventory_start = len(extraction.inventory_items)
            for index, entry in enumerate(entries):
                self._extract_rule(entry, scope, position, container, index, extraction)
                total += 1
            if entries:
                section_items = extraction.inventory_items[section_inventory_start:]
                add_source_section(
                    extraction,
                    f"{container}/pbf/rules",
                    _section_status(item.status for item in section_items),
                    len(entries),
                    sum(item.status != ExtractionStatus.PARSE_ERROR for item in section_items),
                    0,
                    "PANPBFRuleExtractor.parse_rules",
                    source_context=f"{scope.kind}:{scope.name}",
                )
        return total

    def _extract_rule(
        self,
        entry: ET.Element,
        scope: PANScope,
        position: str,
        container: str,
        index: int,
        extraction,
    ) -> None:
        family = "pbf"
        name = entry.get("name")
        path = f"{container}/{family}/rules/entry[@name='{name}']"
        source_rule_id = f"palo_alto:{pan_scope_identity(scope)}:{position}:{family}:{index}:{name}"
        pbf_action = self._extract_action(entry)
        symmetric_return = entry.find("./enforce-symmetric-return")
        symmetric_return_value, symmetric_return_issue = _strict_yes_no(
            symmetric_return, "./enabled"
        )
        active_binding = _direct_text(entry, "./active-active-device-binding")
        attributes = self._build_evidence(
            entry,
            scope,
            position,
            index,
            source_rule_id,
            pbf_action,
            symmetric_return,
            symmetric_return_value,
            symmetric_return_issue,
        )
        classification = self._determine_status(
            name, entry, pbf_action, symmetric_return_issue, active_binding
        )
        attributes["pan_pbf_review_reasons"] = classification.review_reasons
        if classification.status == ExtractionStatus.PARSE_ERROR:
            record_parse_error(
                extraction,
                f"policy:{family}",
                path,
                scope,
                name,
                attributes,
                notes=classification.notes,
            )
        elif classification.status == ExtractionStatus.UNSUPPORTED:
            record_unsupported(
                extraction,
                f"policy:{family}",
                path,
                scope,
                name,
                attributes,
                notes=classification.notes,
            )
        else:
            record_extract_only(
                extraction,
                f"policy:{family}",
                path,
                scope,
                name,
                attributes,
                notes=classification.notes,
                requires_manual_review=classification.requires_manual_review,
            )

    def _extract_common_match_fields(self, entry: ET.Element) -> Dict[str, Any]:
        # PBF's authoritative ingress selectors live below from/zone and
        # from/interface; retain the legacy pan_from key without using it.
        from_node = entry.find("./from")
        return {
            "pan_from": [],
            "pan_from_zones": member_texts(from_node, "./zone/member"),
            "pan_from_interfaces": member_texts(from_node, "./interface/member"),
            "pan_to": member_texts(entry, "./to/member"),
            "pan_source": member_texts(entry, "./source/member"),
            "pan_destination": member_texts(entry, "./destination/member"),
            "pan_source_user": member_texts(entry, "./source-user/member"),
            "pan_service": member_texts(entry, "./service/member"),
            "pan_application": member_texts(entry, "./application/member"),
            # PBF action semantics are nested below action/{type}.
            "pan_action": None,
            "pan_disabled": text_or_none(entry, "./disabled"),
            "pan_description": text_or_none(entry, "./description"),
            "pan_tags": member_texts(entry, "./tag/member"),
            "pan_group_tag": text_or_none(entry, "./group-tag"),
            "pan_log_start": text_or_none(entry, "./log-start"),
            "pan_log_end": text_or_none(entry, "./log-end"),
            "pan_log_setting": text_or_none(entry, "./log-setting"),
            "pan_family_specific": {},
        }

    def _extract_from(self, entry: ET.Element, attributes: Dict[str, Any]) -> None:
        from_node = entry.find("./from")
        if from_node is None:
            return
        attributes["pan_pbf_from_source"] = structured_xml_capture(from_node)
        unknown_from = collect_unknown_children(from_node, ["zone", "interface"])
        if unknown_from:
            attributes["pan_unknown_from_fields"] = unknown_from

    def _extract_action(self, entry: ET.Element) -> Dict[str, Any]:
        action = entry.find("./action")
        result: Dict[str, Any] = {
            "action": None,
            "action_candidates": [],
            "fatal_issues": [],
            "unsupported_issues": [],
        }
        if action is None:
            return result

        result["action_source"] = structured_xml_capture(action)
        unknown_action = collect_unknown_children(action, PBF_ACTION_FIELDS)
        if unknown_action:
            result["unknown_action_fields"] = unknown_action

        candidates = [name for name in PBF_ACTION_FIELDS if action.find(f"./{name}") is not None]
        result["action_candidates"] = candidates
        if len(candidates) > 1:
            _append_issues(
                result,
                "fatal_issues",
                [_issue(
                    "conflicting-actions",
                    "PBF action contains conflicting action types: " + ", ".join(candidates) + ".",
                )],
            )
            return result
        if not candidates:
            _append_issues(
                result,
                "unsupported_issues",
                [_issue(
                    "unsupported-action",
                    "PBF action contains no recognized action child.",
                )],
            )
            return result

        selected = candidates[0]
        result["action"] = selected
        if selected == "forward-to-vsys":
            result["forward_vsys"] = _direct_text(action, "./forward-to-vsys")
        elif selected == "forward":
            # Forward-specific fields are only meaningful for the forward
            # branch; discard and no-pbf must not invoke this parser.
            result.update(self._extract_forward(action.find("./forward")))
        return result

    def _extract_forward(self, forward: ET.Element | None) -> Dict[str, Any]:
        if forward is None:
            return {
                "fatal_issues": [_issue(
                    "missing-forward",
                    "PBF forward action is missing its forward subtree.",
                )]
            }

        result: Dict[str, Any] = {
            "forward_source": structured_xml_capture(forward),
            "egress_interface": _direct_text(forward, "./egress-interface"),
            "next_vr": _direct_text(forward, "./next-vr"),
        }
        unknown_forward = collect_unknown_children(forward, PBF_FORWARD_FIELDS)
        if unknown_forward:
            result["unknown_forward_fields"] = unknown_forward
        nexthop = self._extract_nexthop(forward.find("./nexthop"))
        monitor = self._extract_monitor(forward.find("./monitor"))
        result.update(nexthop)
        result.update(monitor)
        result["fatal_issues"] = (
            nexthop.get("fatal_issues", []) + monitor.get("fatal_issues", [])
        )
        result["unsupported_issues"] = (
            nexthop.get("unsupported_issues", []) + monitor.get("unsupported_issues", [])
        )
        return result

    def _extract_nexthop(self, nexthop: ET.Element | None) -> Dict[str, Any]:
        if nexthop is None:
            return {}
        result: Dict[str, Any] = {
            "nexthop_source": structured_xml_capture(nexthop),
            "fatal_issues": [],
            "unsupported_issues": [],
        }
        unknown_nexthop = collect_unknown_children(nexthop, PBF_NEXTHOP_FIELDS)
        if unknown_nexthop:
            result["unknown_nexthop_fields"] = unknown_nexthop
        next_hop_types = [
            name for name in PBF_NEXTHOP_FIELDS if nexthop.find(f"./{name}") is not None
        ]
        if len(next_hop_types) > 1:
            result["nexthop_candidates"] = next_hop_types
            _append_issues(
                result,
                "fatal_issues",
                [_issue(
                    "conflicting-nexthop-types",
                    "PBF nexthop contains conflicting types: " + ", ".join(next_hop_types) + ".",
                )],
            )
        elif not next_hop_types:
            if unknown_nexthop:
                _append_issues(
                    result,
                    "unsupported_issues",
                    [_issue(
                        "unsupported-nexthop",
                        "PBF nexthop contains an unrecognized nexthop type.",
                    )],
                )
            else:
                _append_issues(
                    result,
                    "fatal_issues",
                    [_issue(
                        "invalid-nexthop-structure",
                        "PBF nexthop has no recognized nexthop type.",
                    )],
                )
        elif next_hop_types:
            result["next_hop_type"] = next_hop_types[0]
            result["next_hop"] = _direct_text(nexthop, f"./{next_hop_types[0]}")
            if next_hop_types[0] == "ip-address":
                value_node = nexthop.find("./ip-address")
                raw_value = (value_node.text or "").strip() if value_node is not None else ""
                try:
                    ipaddress.ip_address(raw_value)
                except ValueError:
                    _append_issues(
                        result,
                        "fatal_issues",
                        [_issue(
                            "invalid-next-hop",
                            f"PBF ip-address nexthop is not a valid IP literal: {raw_value!r}.",
                        )],
                    )
        return result

    def _extract_monitor(self, monitor: ET.Element | None) -> Dict[str, Any]:
        if monitor is None:
            return {}
        result: Dict[str, Any] = {
            "monitor_source": structured_xml_capture(monitor),
            "monitor_enabled": True,
            "monitor_profile": _direct_text(monitor, "./profile"),
            "monitor_ip": _direct_text(monitor, "./ip-address"),
            "monitor_disable_if_unreachable": _direct_text(
                monitor, "./disable-if-unreachable"
            ),
            "fatal_issues": [],
        }
        unknown_monitor = collect_unknown_children(monitor, PBF_MONITOR_FIELDS)
        if unknown_monitor:
            result["unknown_monitor_fields"] = unknown_monitor
        monitor_enabled, monitor_issue = _strict_yes_no(monitor, "./enabled")
        if monitor_enabled is not None:
            result["monitor_enabled"] = monitor_enabled
        if monitor_issue:
            _append_issues(
                result,
                "fatal_issues",
                [_issue("invalid-monitor-enabled", monitor_issue)],
            )
        _, disable_if_unreachable_issue = _strict_yes_no(
            monitor, "./disable-if-unreachable"
        )
        if disable_if_unreachable_issue:
            _append_issues(
                result,
                "fatal_issues",
                [_issue("invalid-monitor-disable-if-unreachable", disable_if_unreachable_issue)],
            )
        return result

    def _build_evidence(
        self,
        entry: ET.Element,
        scope: PANScope,
        position: str,
        index: int,
        source_rule_id: str,
        pbf_action: Dict[str, Any],
        symmetric_return: ET.Element | None,
        symmetric_return_value: Any,
        symmetric_return_issue: str | None,
    ) -> Dict[str, Any]:
        attributes = {
            "pan_policy_family": "pbf",
            "pan_scope_kind": scope.kind,
            "pan_scope_name": scope.name,
            "pan_rulebase_position": position,
            "pan_source_rule_index": index,
            "pan_source_rule_id": source_rule_id,
            **self._extract_common_match_fields(entry),
            "pan_pbf_action": pbf_action.get("action"),
            "pan_unknown_fields": collect_unknown_children(entry, PBF_RULE_KNOWN_CHILDREN),
            "pan_source_entry": structured_xml_capture(entry),
        }
        if pbf_action.get("action_source") is not None:
            attributes["pan_pbf_action_source"] = pbf_action["action_source"]
        if len(pbf_action["action_candidates"]) > 1:
            attributes["pan_pbf_action_candidates"] = pbf_action["action_candidates"]
        if pbf_action.get("forward_source") is not None:
            attributes["pan_pbf_forward_source"] = pbf_action["forward_source"]
        if pbf_action.get("nexthop_source") is not None:
            attributes["pan_pbf_nexthop_source"] = pbf_action["nexthop_source"]
        if pbf_action.get("monitor_source") is not None:
            attributes["pan_pbf_monitor_source"] = pbf_action["monitor_source"]
        if pbf_action.get("egress_interface") is not None:
            attributes["pan_pbf_egress_interface"] = pbf_action["egress_interface"]
        if pbf_action.get("next_hop_type") is not None:
            attributes["pan_pbf_next_hop_type"] = pbf_action["next_hop_type"]
            if pbf_action.get("next_hop") is not None:
                attributes["pan_pbf_next_hop"] = pbf_action["next_hop"]
        if pbf_action.get("nexthop_candidates") is not None:
            attributes["pan_pbf_nexthop_candidates"] = pbf_action["nexthop_candidates"]
        if pbf_action.get("next_vr") is not None:
            attributes["pan_pbf_next_vr"] = pbf_action["next_vr"]
        if pbf_action.get("forward_vsys") is not None:
            attributes["pan_pbf_forward_vsys"] = pbf_action["forward_vsys"]
        if pbf_action.get("monitor_enabled") is not None:
            attributes["pan_pbf_monitor_enabled"] = pbf_action["monitor_enabled"]
        if pbf_action.get("monitor_profile") is not None:
            attributes["pan_pbf_monitor_profile"] = pbf_action["monitor_profile"]
        if pbf_action.get("monitor_ip") is not None:
            attributes["pan_pbf_monitor_ip"] = pbf_action["monitor_ip"]
        if pbf_action.get("monitor_disable_if_unreachable") is not None:
            attributes["pan_pbf_monitor_disable_if_unreachable"] = pbf_action[
                "monitor_disable_if_unreachable"
            ]
        if symmetric_return is not None:
            attributes["pan_pbf_symmetric_return_source"] = structured_xml_capture(
                symmetric_return
            )
        if symmetric_return_value is not None:
            attributes["pan_pbf_enforce_symmetric_return"] = symmetric_return_value
        elif symmetric_return_issue:
            attributes["pan_pbf_enforce_symmetric_return_source"] = _direct_text(
                symmetric_return, "./enabled"
            )
        active_binding = _direct_text(entry, "./active-active-device-binding")
        if active_binding is not None:
            attributes["pan_pbf_active_active_device_binding"] = active_binding

        for result_key, attribute_key in (
            ("unknown_action_fields", "pan_unknown_pbf_action_fields"),
            ("unknown_forward_fields", "pan_unknown_pbf_forward_fields"),
            ("unknown_nexthop_fields", "pan_unknown_pbf_nexthop_fields"),
            ("unknown_monitor_fields", "pan_unknown_pbf_monitor_fields"),
        ):
            if pbf_action.get(result_key):
                attributes[attribute_key] = pbf_action[result_key]
        self._extract_from(entry, attributes)
        if scope.device_serial:
            attributes["pan_device_serial"] = scope.device_serial
        return attributes

    def _determine_status(
        self,
        name: str | None,
        entry: ET.Element,
        pbf_action: Dict[str, Any],
        symmetric_return_issue: str | None,
        active_binding: str | None,
    ) -> _PBFClassification:
        """Classify one PBF rule after all source evidence has been collected.

        ``PARSE_ERROR`` is reserved for malformed or invalid known source.
        ``UNSUPPORTED`` means the source is structurally valid but contains a
        semantic branch this extractor cannot interpret safely.  ``EXTRACT_ONLY``
        means the source semantics were captured without canonical IR.
        """
        fatal: list[tuple[str, str]] = []
        unsupported: list[tuple[str, str]] = []
        review: list[str] = []

        if not name:
            fatal.append(_issue(
                "missing-name",
                "PAN-OS PBF rule is missing its required name.",
            ))

        candidates = pbf_action["action_candidates"]
        if not candidates:
            if pbf_action.get("action_source") is None:
                fatal.append(_issue(
                    "missing-action",
                    "PAN-OS PBF rule is missing its action subtree.",
                ))

        fatal.extend(pbf_action.get("fatal_issues", []))
        unsupported.extend(pbf_action.get("unsupported_issues", []))
        if symmetric_return_issue:
            fatal.append(_issue(
                "invalid-enforce-symmetric-return",
                symmetric_return_issue,
            ))
        if active_binding is not None and active_binding not in PBF_ACTIVE_ACTIVE_BINDINGS:
            unsupported.append(_issue(
                "unsupported-active-active-device-binding",
                f"PBF active-active-device-binding value is not recognized: {active_binding!r}.",
            ))

        unknown_rule = collect_unknown_children(entry, PBF_RULE_KNOWN_CHILDREN)
        if unknown_rule:
            review.append("unknown-rule-fields")
        from_node = entry.find("./from")
        if from_node is not None and collect_unknown_children(from_node, ["zone", "interface"]):
            review.append("unknown-from-fields")

        action_unknown = pbf_action.get("unknown_action_fields", {})
        if action_unknown and candidates:
            review.append("unknown-action-fields")

        forward_unknown = pbf_action.get("unknown_forward_fields", {})
        if forward_unknown:
            if any(_looks_like_forwarding_target(key) for key in forward_unknown):
                unsupported.append(_issue(
                    "unsupported-forwarding-semantics",
                    "PBF forward contains an unrecognized forwarding target field.",
                ))
            else:
                review.append("unknown-forward-fields")

        nexthop_unknown = pbf_action.get("unknown_nexthop_fields", {})
        if nexthop_unknown and pbf_action.get("next_hop_type") is not None:
            if any(_looks_like_forwarding_target(key) for key in nexthop_unknown):
                unsupported.append(_issue(
                    "unsupported-nexthop",
                    "PBF nexthop contains an unrecognized nexthop semantic.",
                ))
            else:
                review.append("unknown-nexthop-fields")

        monitor_unknown = pbf_action.get("unknown_monitor_fields", {})
        if monitor_unknown:
            review.append("unknown-monitor-fields")

        fatal_reasons = [reason for reason, _ in fatal]
        unsupported_reasons = [reason for reason, _ in unsupported]
        reasons = _dedupe_reasons(
            fatal_reasons + unsupported_reasons + review
        )

        if fatal:
            details = _dedupe_reasons(detail for _, detail in fatal)
            notes = [
                "PAN-OS PBF extraction error ({}): {}".format(
                    ", ".join(reasons), " ".join(details)
                )
            ]
            return _PBFClassification(
                ExtractionStatus.PARSE_ERROR,
                True,
                reasons,
                notes,
            )
        if unsupported:
            details = _dedupe_reasons(detail for _, detail in unsupported)
            notes = [
                "PAN-OS PBF contains unsupported source semantics ({}): {}".format(
                    ", ".join(reasons), " ".join(details)
                )
            ]
            return _PBFClassification(
                ExtractionStatus.UNSUPPORTED,
                True,
                reasons,
                notes,
            )
        if review:
            return _PBFClassification(
                ExtractionStatus.EXTRACT_ONLY,
                True,
                reasons,
                [
                    "PAN-OS PBF rule retained as structured source-only policy evidence; "
                    "manual review required for: " + ", ".join(reasons) + "."
                ],
            )
        return _PBFClassification(
            ExtractionStatus.EXTRACT_ONLY,
            False,
            [],
            ["PAN-OS PBF rule retained as structured source-only policy evidence."],
        )
