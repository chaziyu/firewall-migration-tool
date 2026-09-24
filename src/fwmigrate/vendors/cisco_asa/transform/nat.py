"""Derived ASA NAT order and translation semantics."""

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any


@dataclass(frozen=True, slots=True)
class ASANATOrderInputs:
    source_context: str | None
    source_rule_name: str
    section: str
    source_mode: str | None
    owning_object: Any = None
    address_family: int | None = None
    address_kind: str | None = None
    address_quantity: int | None = None
    lowest_real_ip: Any = None
    object_name: str | None = None
    precedence: int | None = None
    determinable: bool = False


@dataclass(frozen=True, slots=True)
class ASATransformedNATRule:
    source_context: str | None
    source_rule: Any
    source_order: int | None
    source_order_within_section: int | None
    source_sequence: int | None
    section: str
    effective_order: int | None
    ordering_status: str
    ordering_inputs: ASANATOrderInputs
    translation_semantics: str | None
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASANATTransformResult:
    rules: tuple[ASATransformedNATRule, ...] = ()
    issues: tuple[str, ...] = ()


def _address_inputs(owner: Any) -> tuple[int | None, str | None, int | None, Any, str | None]:
    if owner is None:
        return None, None, None, None, "Owning network object is missing or unresolved"
    kind, value = (getattr(owner, "type", None) or "").lower(), getattr(owner, "value", None)
    try:
        if kind == "host":
            address = ip_address(value)
            return address.version, kind, 1, address, None
        if kind in {"network", "subnet"}:
            network = ip_network(value, strict=False)
            return network.version, "subnet", network.num_addresses, network.network_address, None
        if kind == "range":
            start, end = value.split("-", 1)
            first, last = ip_address(start.strip()), ip_address(end.strip())
            if first.version != last.version or int(first) > int(last): raise ValueError
            return first.version, kind, int(last) - int(first) + 1, first, None
        return None, kind or None, None, None, "Owning object address representation is unsupported"
    except (ValueError, TypeError, AttributeError):
        return None, kind or None, None, None, "Owning object address is malformed or unknown"


def _translation(rule: Any) -> str:
    if rule.identity_nat: return "identity"
    if rule.nat_exemption: return "nat_exemption"
    if rule.pat_pool: return "dynamic_pat_pool"
    if rule.source_mode == "dynamic" and rule.mapped_source_mode == "interface": return "dynamic_pat_interface"
    if rule.source_mode == "dynamic": return "dynamic_nat"
    if rule.source_mode == "static" and rule.original_service: return "static_port_translation"
    if rule.source_mode == "static" and rule.destination_mode: return "destination_static"
    return "static" if rule.source_mode == "static" else "unknown"


def transform_nat(config: Any, relationships: Any) -> ASANATTransformResult:
    related = {id(row.rule): row for row in relationships.rules}
    grouped: dict[str | None, list[tuple[Any, Any, ASANATOrderInputs, str | None]]] = {}
    issues: list[str] = []
    sections = {"manual": 1, "object": 2, "after-auto": 3, "after_auto": 3}
    for rule in config.nat_rules:
        rel = related.get(id(rule)); section = str(rule.section).lower(); number = sections.get(section)
        error = None; family = quantity = None; lowest = None; kind = None
        order_evidence = any(getattr(rule, field, None) is not None for field in ("source_order_within_section", "source_order", "source_sequence"))
        if number == 2:
            if rule.source_mode not in {"static", "dynamic"}: error = "Object NAT translation mode is unknown"
            else: family, kind, quantity, lowest, error = _address_inputs(rel.owning_object if rel else None)
        elif number is None: error = "NAT section is unknown"
        elif not order_evidence: error = "Configured manual NAT order evidence is unavailable"
        values = ASANATOrderInputs(rule.source_context, rule.name, section, rule.source_mode,
            rel.owning_object if rel else None, family, kind, quantity, lowest,
            getattr(rel.owning_object, "name", None) if rel else None,
            (0 if rule.source_mode == "static" else 1) if number == 2 else number,
            number is not None and (number != 2 or error is None) and (number == 2 or order_evidence))
        grouped.setdefault(rule.source_context, []).append((rule, rel, values, error))
    output = []
    for context, rows in grouped.items():
        position = 1
        for section in (1, 2, 3):
            candidates = [row for row in rows if sections.get(row[2].section) == section]
            families = {row[2].address_family for row in candidates if row[2].address_family is not None}
            complete = all(row[2].determinable for row in candidates) and len(families) <= 1
            if section == 2:
                candidates.sort(key=lambda row: (row[2].precedence,
                    row[2].address_quantity if row[2].determinable else float("inf"),
                    int(row[2].lowest_real_ip) if row[2].determinable else float("inf"),
                    (row[2].object_name or "").casefold()))
            else:
                candidates.sort(key=lambda row: (getattr(row[0], "source_order_within_section", None) is None,
                    getattr(row[0], "source_order_within_section", None) or getattr(row[0], "source_order", None) or 0,
                    getattr(row[0], "source_sequence", None) or 0))
            for rule, _, values, error in candidates:
                known = values.determinable and (section != 2 or complete)
                row_issues = ((error,) if error else ("Object NAT address-family comparison is unknown",) if section == 2 and len(families) > 1 else ())
                output.append(ASATransformedNATRule(context, rule, rule.source_order, rule.source_order_within_section,
                    rule.source_sequence, values.section, position if known else None,
                    "KNOWN" if known else "PARTIAL" if section == 2 and values.determinable else "UNKNOWN",
                    values, _translation(rule), row_issues))
                issues.extend(row_issues); position += 1
    order = {id(rule): index for index, rule in enumerate(config.nat_rules)}
    output.sort(key=lambda row: order[id(row.source_rule)])
    return ASANATTransformResult(tuple(output), tuple(issues))
