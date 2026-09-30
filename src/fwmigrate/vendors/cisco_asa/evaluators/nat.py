"""ASA nat command evaluation."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from fwmigrate.vendors.cisco_asa.model.nat import CiscoNATRule
from fwmigrate.extraction.sanitize import sanitize_raw_text
from . import _mark_explicit


class NATEvaluator:

    def _parse_nat_line(self, line: str, line_number: int, owning_object: Optional[str] = None) -> None:
        legacy = re.fullmatch(r"nat\s+\(([^,)]+)\)\s+0\s+access-list\s+(\S+)(?:\s+(.*))?", line.strip(), re.I)
        if legacy and owning_object is None:
            interface_name, acl_name, remainder = legacy.groups()
            self._nat_section_counts["manual"] = self._nat_section_counts.get("manual", 0) + 1
            extras = remainder.split() if remainder else []
            rule = CiscoNATRule(
                name=f"nat_legacy_exemption_{line_number}", source_interface=interface_name.strip(),
                section="manual", section_order=1, syntax_family="legacy-exemption", sequence=0,
                source_sequence=0, source_order=line_number,
                source_order_within_section=self._nat_section_counts["manual"], access_list=acl_name,
                identity_nat=True, nat_exemption=True, raw_line=line, raw_options=extras,
                extraction_status="SOURCE_ONLY", requires_manual_review=True,
                review_reasons=["ASA legacy NAT exemption is preserved as source-only access-list semantics"],
                source_attributes={"raw_command": sanitize_raw_text(line), "legacy_nat": True},
                explicit_fields={"source_interface", "section", "section_order", "syntax_family", "sequence", "source_sequence", "source_order", "source_order_within_section", "access_list", "identity_nat", "nat_exemption"},
                raw_extra={"unparsed_tokens": [sanitize_raw_text(token) for token in extras]} if extras else {},
            )
            self.config.nat_rules.append(self._with_source_context(rule, line_number))
            self._record_acl_consumer(acl_name, "nat-exemption", line_number, line)
            return
        match = re.match(r"^nat(?:\s+\(([^,]*),([^)]*)\))?\s+(.+)$", line, re.IGNORECASE)
        if not match:
            self._record_diagnostic(line_number, line, "Malformed NAT statement", "nat")
            return
        src_if = match.group(1).strip() or None if match.group(1) is not None else None
        dst_if = match.group(2).strip() or None if match.group(2) is not None else None
        tail = match.group(3).split()
        section = "after-auto" if tail and tail[0].lower() == "after-auto" else "object" if owning_object else "manual"
        if section == "after-auto":
            tail = tail[1:]
        sequence = None
        if tail and tail[0].isdigit():
            sequence = int(tail.pop(0))
        self._nat_section_counts[section] = self._nat_section_counts.get(section, 0) + 1
        within = self._nat_section_counts[section]
        section_order = {"manual": 1, "object": 2, "after-auto": 3}[section]
        rule = CiscoNATRule(
            name=f"nat_{section}_{line_number}", source_interface=src_if, destination_interface=dst_if,
            section=section, syntax_family="object" if owning_object else "manual", sequence=sequence, source_sequence=sequence, owning_object=owning_object,
            source_order=line_number, source_order_within_section=within, section_order=section_order,
            raw_line=line,
            source_attributes={"raw_command": line},
        )
        _mark_explicit(rule, "section", "syntax_family", "source_order", "source_order_within_section", "section_order")
        if src_if is not None or match.group(1) is not None:
            _mark_explicit(rule, "source_interface", "destination_interface")
        if sequence is not None:
            _mark_explicit(rule, "sequence", "source_sequence")
        index = 0

        def parse_mapped_source(position: int) -> int:
            if position >= len(tail):
                return position
            token = tail[position]
            lower = token.lower()
            if lower == "interface":
                rule.mapped_source_mode = "interface"
                rule.mapped_source = "interface"
                _mark_explicit(rule, "mapped_source_mode", "mapped_source")
                position += 1
                if position < len(tail) and tail[position].lower() == "ipv6":
                    rule.mapped_source_address_family = "ipv6"
                    _mark_explicit(rule, "mapped_source_address_family")
                    position += 1
                return position
            if lower == "pat-pool":
                rule.mapped_source_mode = "pat_pool"
                _mark_explicit(rule, "mapped_source_mode", "pat_pool", "mapped_source")
                if position + 1 < len(tail):
                    rule.pat_pool = tail[position + 1]
                    rule.mapped_source = rule.pat_pool
                    position += 2
                    while position < len(tail) and tail[position].lower() in {
                        "round-robin", "extended", "flat", "include-reserve", "block-allocation"
                    }:
                        rule.pat_pool_options.append(tail[position])
                        _mark_explicit(rule, "pat_pool_options")
                        position += 1
                return position
            rule.mapped_source_mode = rule.source_mode
            rule.mapped_source = token
            _mark_explicit(rule, "mapped_source_mode", "mapped_source")
            return position + 1

        if owning_object:
            if index < len(tail) and tail[index].lower() in {"static", "dynamic"}:
                rule.source_mode = tail[index].lower()
                rule.real_source = owning_object
                _mark_explicit(rule, "source_mode", "real_source", "owning_object")
                index = parse_mapped_source(index + 1)
            else:
                rule.review_reasons.append("Object NAT is missing static/dynamic translation mode")
        elif index < len(tail) and tail[index].lower() == "source":
            if index + 2 < len(tail):
                rule.source_mode = tail[index + 1].lower()
                rule.real_source = tail[index + 2]
                _mark_explicit(rule, "source_mode", "real_source")
                if rule.source_mode not in {"static", "dynamic"}:
                    rule.extraction_status = "PARSE_ERROR"
                    rule.review_reasons.append(f"Unsupported twice-NAT source mode: {rule.source_mode}")
                index = parse_mapped_source(index + 3)
            else:
                index = len(tail)
                rule.review_reasons.append("Incomplete NAT source clause")

        if index < len(tail) and tail[index].lower() == "destination":
            if index + 3 < len(tail):
                rule.destination_mode = tail[index + 1].lower()
                # Cisco twice-NAT grammar is destination static MAPPED REAL.
                rule.mapped_destination = tail[index + 2]
                rule.real_destination = tail[index + 3]
                _mark_explicit(rule, "destination_mode", "mapped_destination", "real_destination")
                if rule.destination_mode != "static":
                    rule.extraction_status = "PARSE_ERROR"
                    rule.review_reasons.append(f"Unsupported twice-NAT destination mode: {rule.destination_mode}")
                index += 4
            else:
                rule.review_reasons.append("Incomplete NAT destination clause")
                index = len(tail)

        if index < len(tail) and tail[index].lower() == "service":
            if owning_object and index + 3 < len(tail):
                rule.service_protocol = tail[index + 1].lower()
                rule.original_service = tail[index + 2]
                rule.translated_service = tail[index + 3]
                _mark_explicit(rule, "service_protocol", "original_service", "translated_service")
                index += 4
            elif not owning_object and index + 2 < len(tail):
                rule.service_operand_1, rule.service_operand_2 = tail[index + 1:index + 3]
                _mark_explicit(rule, "service_operand_1", "service_operand_2")
                index += 3
            else:
                tokens = tail[index:]
                rule.raw_options.extend(tokens)
                rule.raw_extra.setdefault("unparsed_tokens", []).extend(sanitize_raw_text(token) for token in tokens)
                rule.extraction_status = "PARSE_ERROR"
                rule.requires_manual_review = True
                rule.review_reasons.append("NAT service clause does not match object NAT or twice NAT grammar")
                index = len(tail)

        option_names = {
            "dns", "no-proxy-arp", "route-lookup", "unidirectional", "inactive", "net-to-net",
            "round-robin", "extended", "flat", "include-reserve", "block-allocation",
        }
        while index < len(tail):
            token = tail[index]
            lower = token.lower()
            if lower == "description":
                rule.description = " ".join(tail[index + 1:]) or None
                _mark_explicit(rule, "description")
                index = len(tail)
            elif lower in option_names:
                rule.options.append(lower)
                _mark_explicit(rule, "options")
                option_field = {"dns": "dns", "no-proxy-arp": "no_proxy_arp", "route-lookup": "route_lookup",
                                "unidirectional": "unidirectional", "inactive": "inactive", "net-to-net": "net_to_net"}.get(lower)
                if option_field:
                    _mark_explicit(rule, option_field)
                elif lower in {"round-robin", "extended", "flat", "include-reserve", "block-allocation"}:
                    _mark_explicit(rule, "pat_pool_options")
                if lower in {"round-robin", "extended", "flat", "include-reserve", "block-allocation"}:
                    rule.pat_pool_options.append(lower)
                    _mark_explicit(rule, "pat_pool_options")
                index += 1
            else:
                rule.raw_options.append(token)
                rule.raw_extra.setdefault("unparsed_tokens", []).append(sanitize_raw_text(token))
                index += 1

        rule.dns = "dns" in rule.options
        rule.no_proxy_arp = "no-proxy-arp" in rule.options
        rule.route_lookup = "route-lookup" in rule.options
        rule.unidirectional = "unidirectional" in rule.options
        rule.inactive = "inactive" in rule.options
        rule.net_to_net = "net-to-net" in rule.options

        if not owning_object:
            for field in ("real_source", "mapped_source", "mapped_destination", "real_destination"):
                value = getattr(rule, field)
                if not value or value.lower() in {"any", "interface", "original", "translated"}:
                    continue
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                rule.extraction_status = "PARSE_ERROR"
                rule.requires_manual_review = True
                rule.review_reasons.append(f"Inline IP address is not supported for manual NAT operand {field}")
                rule.raw_extra.setdefault("unsupported_inline_addresses", []).append(value)
                break

        if sequence == 0 and len(tail) >= 2 and tail[0].lower() == "access-list":
            rule.access_list = tail[1]
            rule.identity_nat = rule.nat_exemption = True
            _mark_explicit(rule, "access_list", "identity_nat", "nat_exemption")
            rule.syntax_family = "legacy-exemption"
            rule.extraction_status = "SOURCE_ONLY"
            rule.requires_manual_review = True
            rule.review_reasons.append("ASA NAT exemption is preserved as source-only access-list semantics")
        elif rule.source_mode == "static" and rule.real_source == rule.mapped_source:
            rule.identity_nat = True
        elif not rule.real_source or not rule.mapped_source:
            rule.extraction_status = "PARSE_ERROR"
            rule.requires_manual_review = True
            rule.review_reasons.append("NAT source translation operands are incomplete")
        partial_details = []
        if rule.destination_mode:
            partial_details.append("twice-NAT destination translation")
        if rule.original_service:
            partial_details.append("service/PAT translation")
        if rule.mapped_source_address_family == "ipv6":
            partial_details.append("interface IPv6 translation")
        if rule.pat_pool_options:
            partial_details.append(f"PAT pool modifiers: {' '.join(rule.pat_pool_options)}")
        noncanonical_options = [opt for opt in rule.options if opt != "inactive"]
        if noncanonical_options:
            partial_details.append(f"NAT modifiers: {' '.join(noncanonical_options)}")
        if rule.raw_options:
            partial_details.append(f"Unparsed NAT tokens: {' '.join(rule.raw_options)}")
        if partial_details and rule.extraction_status != "PARSE_ERROR":
            rule.extraction_status = "PARTIAL"
            rule.requires_manual_review = True
            rule.review_reasons.extend(partial_details)
        if rule.nat_exemption:
            rule.extraction_status = "SOURCE_ONLY"
        if rule.extraction_status == "PARSE_ERROR":
            self._record_diagnostic(line_number, line, "; ".join(rule.review_reasons), "nat", owning_object)
        self.config.nat_rules.append(self._with_source_context(rule, line_number))
        if rule.access_list:
            self._record_acl_consumer(rule.access_list, "nat-exemption", line_number, line)
