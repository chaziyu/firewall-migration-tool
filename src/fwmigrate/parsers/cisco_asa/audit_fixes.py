from __future__ import annotations

import re
from datetime import date
from typing import Any, Iterable, List, Optional

from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.ir.enums import NATTranslationMode
from fwmigrate.parsers.cisco_asa.model import CiscoNATRule, CiscoTimeRangeClause
from fwmigrate.parsers.cisco_asa.reference_validation import ReferenceIssue


_PATCHED = False


def _context_of(item: Any) -> Optional[str]:
    return getattr(item, "source_context", None) or getattr(item, "source_attributes", {}).get("source_context")


def _scoped_named(items: Iterable[Any], name: str, context: Optional[str]) -> bool:
    return any(getattr(item, "name", None) == name and _context_of(item) == context for item in items)


def _normalize_interface_headers(config: Any) -> None:
    """Repair ASA logical-interface headers that use a space before the ID."""
    prefixes = {
        "bvi": "BVI",
        "redundant": "Redundant",
        "port-channel": "Port-channel",
        "vlan": "Vlan",
    }
    for interface in config.interfaces:
        raw_header = interface.source_attributes.get("raw_header", "")
        match = re.fullmatch(
            r"interface\s+(bvi|redundant|port-channel|vlan)\s+(\d+)(?:\.(\d+))?",
            raw_header.strip(),
            re.I,
        )
        if not match:
            continue
        family, number, sub_id = match.groups()
        base = f"{prefixes[family.lower()]}{number}"
        interface.name = f"{base}.{sub_id}" if sub_id else base
        interface.source_attributes["source_interface_header"] = raw_header
        interface.source_attributes["normalized_interface_name"] = interface.name
        if sub_id:
            interface.interface_type = "subinterface"
            interface.parent_interface = base
            interface.interface_suffix_vlan_id = int(sub_id)
            if interface.vlan_id is None:
                interface.vlan_id = int(sub_id)
        elif family.lower() == "bvi":
            interface.interface_type = "bvi"
            interface.bvi_id = int(number)
        elif family.lower() == "redundant":
            interface.interface_type = "redundant"
        elif family.lower() == "port-channel":
            interface.interface_type = "port-channel"
            interface.port_channel_id = int(number)
        else:
            interface.interface_type = "vlan"
            interface.vlan_id = int(number)


def _normalize_standard_acls(config: Any) -> None:
    """ASA standard ACLs are destination-only IPv4 filters."""
    for rule in config.access_rules:
        if rule.acl_type != "standard":
            continue
        if rule.destination_endpoint is None and rule.source_endpoint is not None:
            rule.destination_endpoint = rule.source_endpoint
            rule.source_endpoint = None
        rule.source_attributes["standard_acl_semantics"] = "destination-only-ipv4"
        endpoint = rule.destination_endpoint
        if endpoint is None:
            continue
        if endpoint.address_family == "ipv6" or endpoint.value == "any6":
            rule.migration_status = "PARSE_ERROR"
            rule.requires_manual_review = True
            reason = "ASA standard ACLs are IPv4-only"
            if reason not in rule.review_reasons:
                rule.review_reasons.append(reason)


def _normalize_nat_source_model(config: Any) -> None:
    """Preserve dynamic NAT versus PAT and interface-PAT fallback evidence."""
    for rule in config.nat_rules:
        if rule.source_mode != "dynamic":
            continue
        if rule.mapped_source_mode == "interface":
            rule.source_attributes["translation_semantics"] = "dynamic-pat-interface"
        elif rule.mapped_source_mode == "pat_pool":
            rule.source_attributes["translation_semantics"] = "dynamic-pat-pool"
        else:
            rule.mapped_source_mode = "dynamic"
            rule.source_attributes["translation_semantics"] = "dynamic-nat"

        raw = rule.raw_line or ""
        if rule.owning_object:
            fallback = bool(re.search(r"\bdynamic\s+\S+\s+interface(?:\s|$)", raw, re.I))
        else:
            fallback = bool(re.search(r"\bsource\s+dynamic\s+\S+\s+\S+\s+interface(?:\s|$)", raw, re.I))
        if not fallback or rule.mapped_source_mode in {"interface", "pat_pool"}:
            continue
        rule.source_attributes["interface_pat_fallback"] = True
        rule.source_attributes["fallback_translation_mode"] = "interface-address"
        if "interface" in rule.raw_options:
            rule.raw_options.remove("interface")
        rule.requires_manual_review = True
        if rule.migration_status == "NORMALIZED":
            rule.migration_status = "PARTIALLY_NORMALIZED"
        reason = "Dynamic NAT interface PAT fallback is source-preserved"
        if reason not in rule.review_reasons:
            rule.review_reasons.append(reason)


def _apply_global_mtu(self: Any) -> None:
    """Parse global `mtu <interface-name> <bytes>` statements."""
    for line_number, raw in enumerate(self.raw_lines, 1):
        if raw[:1].isspace():
            continue
        match = re.fullmatch(r"mtu\s+(\S+)\s+(\d+)", raw.strip(), re.I)
        if not match:
            continue
        interface_name, value = match.group(1), int(match.group(2))
        context = self._line_contexts.get(line_number)
        candidates = [
            item for item in self.config.interfaces
            if _context_of(item) == context
            and interface_name.casefold() in {
                item.name.casefold(),
                (item.nameif or "").casefold(),
            }
        ]
        if len(candidates) != 1:
            continue
        interface = candidates[0]
        if interface.mtu is not None and interface.mtu != value:
            interface.source_attributes.setdefault("mtu_history", []).append(interface.mtu)
        interface.mtu = value
        interface.source_attributes.setdefault("global_mtu_commands", []).append(sanitize_raw_text(raw.strip()))
        self.config.unsupported_commands = [
            item for item in self.config.unsupported_commands
            if not (
                item.get("line_number") == line_number
                and item.get("raw_line") == sanitize_raw_text(raw.strip())
            )
        ]


def _wrap_reference_validation(original: Any):
    def validate(config: Any) -> List[ReferenceIssue]:
        # Normalize fields before the legacy validator builds indexes so valid
        # logical-interface and ACL relationships do not get falsely marked.
        _normalize_interface_headers(config)
        _normalize_standard_acls(config)
        _normalize_nat_source_model(config)
        issues = list(original(config))

        replacements: List[ReferenceIssue] = []
        remove_ids: set[int] = set()

        for rule in config.access_rules:
            if rule.protocol not in {"object", "object-group"} or not rule.protocol_object:
                continue
            context = _context_of(rule)
            name = rule.protocol_object
            service_object = _scoped_named(config.service_objects, name, context)
            service_group = _scoped_named(config.service_groups, name, context)
            protocol_group = _scoped_named(config.protocol_groups, name, context)
            for index, issue in enumerate(issues):
                if (
                    issue.reference_type == "protocol_group"
                    and issue.source_object == rule.acl_name
                    and issue.reference_name == name
                    and issue.source_context == context
                ):
                    remove_ids.add(index)
            if rule.protocol == "object":
                replacements.append(ReferenceIssue(
                    "service_object", rule.acl_name, name, service_object,
                    "resolved" if service_object else "Unresolved service object reference",
                    context, "acl-protocol",
                ))
            else:
                resolved = service_group or protocol_group
                replacements.append(ReferenceIssue(
                    "service_or_protocol_group", rule.acl_name, name, resolved,
                    "resolved" if resolved else "Unresolved service/protocol group reference",
                    context, "acl-protocol",
                ))

        nat_by_name = {(rule.source_context, rule.name): rule for rule in config.nat_rules}
        for index, issue in enumerate(issues):
            if issue.reference_type != "network_object" or issue.reference_context != "nat":
                continue
            nat = nat_by_name.get((issue.source_context, issue.source_object))
            if nat is None:
                continue
            if _scoped_named(config.network_groups, issue.reference_name, issue.source_context):
                remove_ids.add(index)
                replacements.append(ReferenceIssue(
                    "network_group", issue.source_object, issue.reference_name, True,
                    "resolved", issue.source_context, "nat",
                ))

        return [issue for index, issue in enumerate(issues) if index not in remove_ids] + replacements

    return validate


def _parse_nat_line_audit(original: Any):
    def parse(self: Any, line: str, line_number: int, owning_object: Optional[str] = None) -> None:
        # Legacy pre-8.3 NAT exemption uses a single interface tuple. Preserve it
        # as extract-only instead of forcing it into modern twice-NAT grammar.
        if owning_object is None:
            match = re.fullmatch(
                r"nat\s+\(([^,)]+)\)\s+0\s+access-list\s+(\S+)(?:\s+(.*))?",
                line.strip(),
                re.I,
            )
            if match:
                src_if, acl_name, remainder = match.groups()
                self._nat_section_counts["manual"] = self._nat_section_counts.get("manual", 0) + 1
                rule = CiscoNATRule(
                    name=f"nat_legacy_exemption_{line_number}",
                    source_interface=src_if.strip(),
                    section="manual",
                    section_order=1,
                    syntax_family="legacy-exemption",
                    sequence=0,
                    source_sequence=0,
                    source_order=line_number,
                    source_order_within_section=self._nat_section_counts["manual"],
                    access_list=acl_name,
                    identity_nat=True,
                    nat_exemption=True,
                    raw_line=line,
                    raw_options=remainder.split() if remainder else [],
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    review_reasons=["ASA legacy NAT exemption is preserved as source-only access-list semantics"],
                    source_attributes={"raw_command": sanitize_raw_text(line), "legacy_nat": True},
                )
                self.config.nat_rules.append(self._with_source_context(rule, line_number))
                self._record_acl_consumer(acl_name, "nat-exemption", line_number, line)
                return
        original(self, line, line_number, owning_object=owning_object)

    return parse


def _parse_time_range_absolute_clause_audit(cls: Any, raw: str, source_order: int):
    """Parse the official `absolute [end ...] [start ...]` grammar in either order."""
    parts = raw.split()
    clause = CiscoTimeRangeClause(clause_type="absolute", raw=raw, source_order=source_order)
    if not parts or parts[0].lower() != "absolute":
        return clause, "Malformed absolute time-range clause"

    months = {name.lower(): number for number, name in enumerate(
        ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"), 1
    )}

    def timestamp(tokens: List[str]) -> Optional[str]:
        if len(tokens) != 4 or not cls._validate_time_range_clock(tokens[0]):
            return None
        if not tokens[1].isdigit() or tokens[2].lower() not in months or not tokens[3].isdigit():
            return None
        year = int(tokens[3])
        if not 1993 <= year <= 2035:
            return None
        try:
            date(year, months[tokens[2].lower()], int(tokens[1]))
        except ValueError:
            return None
        return " ".join(tokens)

    index = 1
    seen: set[str] = set()
    while index < len(parts):
        key = parts[index].lower()
        if key not in {"start", "end"} or key in seen:
            return clause, "Malformed absolute time-range clause"
        value = timestamp(parts[index + 1:index + 5])
        if value is None:
            return clause, f"Malformed absolute {key} value"
        setattr(clause, key, value)
        seen.add(key)
        index += 5
    return clause, None


def _wrap_parse_raw(original: Any):
    def parse(self: Any):
        config = original(self)
        _normalize_interface_headers(config)
        _normalize_standard_acls(config)
        _normalize_nat_source_model(config)
        _apply_global_mtu(self)
        # The original parser validates before this final source-line enrichment.
        # Re-run so reference inventory reflects the normalized relationships.
        import fwmigrate.parsers.cisco_asa.parser as parser_module
        parser_module.apply_reference_issues(config, parser_module.validate_references(config))
        self._compute_object_nat_order()
        return config

    return parse


def _wrap_transform_to_ir(original: Any):
    def transform(self: Any):
        ir = original(self)
        config = self.config
        nat_by_name = {(rule.source_context, rule.name): rule for rule in config.nat_rules}
        for ir_rule in ir.nat_rules:
            source_rule = nat_by_name.get((ir_rule.source_context, ir_rule.name))
            if source_rule is None or source_rule.source_mode != "dynamic":
                continue
            if source_rule.mapped_source_mode not in {"interface", "pat_pool"}:
                ir_rule.source_translation_mode = NATTranslationMode.DYNAMIC_IP
            ir_rule.source_attributes["asa_translation_semantics"] = source_rule.source_attributes.get("translation_semantics")
            if source_rule.source_attributes.get("interface_pat_fallback"):
                ir_rule.source_attributes["interface_pat_fallback"] = True
                ir_rule.source_attributes["fallback_translation_mode"] = "interface-address"
                ir_rule.requires_manual_review = True
                if ir_rule.migration_status == "NORMALIZED":
                    ir_rule.migration_status = "PARTIALLY_NORMALIZED"
                reason = "Dynamic NAT interface PAT fallback requires target-specific handling"
                if reason not in ir_rule.review_reasons:
                    ir_rule.review_reasons.append(reason)

        members_by_channel: dict[int, List[str]] = {}
        for interface in config.interfaces:
            if interface.channel_group is not None:
                members_by_channel.setdefault(interface.channel_group, []).append(interface.name)
        for interface in ir.interfaces:
            match = re.fullmatch(r"Port-channel(\d+)", interface.name, re.I)
            if not match:
                continue
            for member in members_by_channel.get(int(match.group(1)), []):
                if member not in interface.members:
                    interface.members.append(member)
            if interface.members:
                interface.source_attributes["port_channel_members"] = list(interface.members)
        return ir

    return transform


def apply_cisco_asa_audit_fixes(parser_cls: Any) -> None:
    """Install ASA fixes derived from the Cisco interface/ACL/NAT audit."""
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True

    import fwmigrate.parsers.cisco_asa.parser as parser_module

    parser_module.validate_references = _wrap_reference_validation(parser_module.validate_references)
    parser_cls._parse_nat_line = _parse_nat_line_audit(parser_cls._parse_nat_line)
    parser_cls._parse_time_range_absolute_clause = classmethod(_parse_time_range_absolute_clause_audit)
    parser_cls.parse_raw = _wrap_parse_raw(parser_cls.parse_raw)
    parser_cls.transform_to_ir = _wrap_transform_to_ir(parser_cls.transform_to_ir)
