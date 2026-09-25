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
class ASADerivedSourceNATPool:
    source_context: str | None
    source_rule: Any
    pool_type: str
    mapped_source: str | None
    mapped_object: Any = None
    mapped_interface: Any = None
    address_family: str | None = None
    source_interface: Any = None
    destination_interface: Any = None
    translation_semantics: str | None = None
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASADerivedVIP:
    source_context: str | None
    source_rule: Any
    source_nat_order: int | None
    source_nat_interface: Any = None
    destination_nat_interface: Any = None
    mapped_address: str | None = None
    real_address: str | None = None
    mapped_service: str | None = None
    real_service: str | None = None
    protocol: str | None = None
    translation_type: str | None = None
    inactive: bool = False
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASANATTransformResult:
    rules: tuple[ASATransformedNATRule, ...] = ()
    source_nat_pools: tuple[ASADerivedSourceNATPool, ...] = ()
    vips: tuple[ASADerivedVIP, ...] = ()
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


def _address_family(value: str | None, resolved: Any, owner: Any) -> str | None:
    family = getattr(resolved, "address_family", None) or getattr(owner, "address_family", None)
    if family:
        return str(family)
    address = getattr(resolved, "value", None) or value
    if not address or str(address).lower() == "interface":
        return None
    try:
        return f"ipv{ip_address(address).version}"
    except ValueError:
        try:
            return f"ipv{ip_network(address, strict=False).version}"
        except ValueError:
            return None


def derive_twice_nat_service_semantics(rule: Any) -> tuple[str | None, str | None, str | None]:
    """Keep twice-NAT service operands source-faithful until grammar proves their roles."""
    if not getattr(rule, "service_operand_1", None) and not getattr(rule, "service_operand_2", None):
        return None, None, None
    return None, None, "Twice NAT service operand mapping is unknown; source operands are preserved"


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
    by_rule = {id(row.rule): row for row in relationships.rules}
    source_pools: list[ASADerivedSourceNATPool] = []
    vips: list[ASADerivedVIP] = []
    for transformed in output:
        rule = transformed.source_rule
        rel = by_rule.get(id(rule))
        if rule.identity_nat or rule.nat_exemption:
            continue
        has_source_translation = (
            rule.source_mode == "dynamic" and bool(rule.pat_pool or rule.mapped_source_mode == "interface" or rule.mapped_source)
        ) or (rule.source_mode == "static" and bool(rule.mapped_source))
        if has_source_translation:
            pool_issues = [issue.reason for issue in (rel.issues if rel else ())]
            family = rule.mapped_source_address_family or _address_family(
                rule.mapped_source, rel.mapped_source if rel else None, rel.owning_object if rel else None)
            if family is None:
                pool_issues.append("Mapped-source address family is unknown")
            pool_type = (
                "interface_pat" if rule.mapped_source_mode == "interface"
                else "dynamic_pat_pool" if rule.pat_pool
                else "dynamic_nat" if rule.source_mode == "dynamic"
                else "static_source_nat"
            )
            source_pools.append(ASADerivedSourceNATPool(
                rule.source_context, rule, pool_type, rule.mapped_source,
                rel.mapped_source if rel else None,
                (rel.destination_interface if rel else None) or (rule.destination_interface if rule.mapped_source_mode == "interface" else None),
                family,
                (rel.source_interface if rel else None) or rule.source_interface,
                (rel.destination_interface if rel else None) or rule.destination_interface,
                transformed.translation_semantics,
                tuple(dict.fromkeys(pool_issues)),
            ))
            issues.extend(pool_issues)

        object_static = rule.syntax_family == "object" and rule.source_mode == "static" and bool(rule.mapped_source)
        destination_static = rule.destination_mode == "static" and bool(rule.mapped_destination)
        if object_static and destination_static:
            issues.append(f"VIP classification is ambiguous for NAT rule {rule.name}")
            continue
        if object_static or destination_static:
            mapped_ref = (rel.mapped_source if object_static else rel.mapped_destination) if rel else None
            real_ref = rel.owning_object if object_static and rel else rel.real_destination if rel else None
            mapped = getattr(mapped_ref, "value", None) or (rule.mapped_source if object_static else rule.mapped_destination)
            real = (getattr(real_ref, "value", None) or rule.real_source) if object_static else (getattr(real_ref, "value", None) or rule.real_destination)
            mapped_service, real_service, service_issue = derive_twice_nat_service_semantics(rule)
            vip_issues = [issue.reason for issue in (rel.issues if rel else ())]
            if service_issue:
                vip_issues.append(service_issue)
            vips.append(ASADerivedVIP(
                rule.source_context, rule, transformed.effective_order,
                (rel.source_interface if rel else None) or rule.source_interface,
                (rel.destination_interface if rel else None) or rule.destination_interface,
                mapped, real, mapped_service or rule.translated_service, real_service or rule.original_service,
                rule.service_protocol, transformed.translation_semantics, rule.inactive,
                tuple(dict.fromkeys(vip_issues)),
            ))
            issues.extend(vips[-1].issues)
    return ASANATTransformResult(tuple(output), tuple(source_pools), tuple(vips), tuple(dict.fromkeys(issues)))
