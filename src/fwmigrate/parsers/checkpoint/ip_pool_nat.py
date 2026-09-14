"""Check Point Management IP-pool NAT extraction.

An address-range object is not an IP-pool NAT definition by itself. This
module only promotes records found under explicit gateway/cluster/global
properties pool settings and keeps the original object as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.nat import IRIPPool
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver


_POOL_KEYS = {
    "ip-pool", "ip_pool", "ip-pools", "ip_pools", "nat-ip-pool", "nat_ip_pool",
    "nat-ip-pools", "nat_ip_pools", "ip-pool-nat", "ip_pool_nat", "address-pool", "address_pool",
}
_POOL_COMMANDS = {
    "show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters",
    "show-global-properties", "show-global-property",
}
_INTERFACE_KEYS = {
    "interfaces", "interface-list", "network-interfaces", "network-interface",
    "physical-interfaces", "physical-interface",
}
_CLUSTER_MEMBER_KEYS = {"cluster-members", "cluster-member", "members-of-cluster"}


@dataclass(frozen=True)
class CheckPointIPPoolContainerContext:
    owner_gateway: Optional[str] = None
    parent_path: Tuple[str, ...] = ()
    interface: Optional[str] = None
    interface_uid: Optional[str] = None
    cluster_member: Optional[str] = None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _label(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("uid") or value.get("name")
    return str(value) if value is not None and str(value).strip() else None


def _labels(record: Dict[str, Any], keys: Iterable[str]) -> List[str]:
    result: List[str] = []
    for key in keys:
        for value in _as_list(record.get(key)):
            label = _label(value)
            if label and label not in result:
                result.append(label)
    return result


def _interface_ref(record: Dict[str, Any], keys: Iterable[str]) -> Tuple[Optional[str], Optional[str]]:
    for key in keys:
        value = record.get(key)
        if isinstance(value, dict):
            name = value.get("name") or value.get("interface-name") or value.get("interface_name")
            uid = value.get("uid") or value.get("interface-uid") or value.get("interface_uid")
            if name or uid:
                return (str(name) if name is not None else None, str(uid) if uid is not None else None)
        elif value is not None and str(value).strip():
            return str(value), None
    return None, None


def _containers(
    value: Any,
    parent_key: Optional[str] = None,
    path: Tuple[str, ...] = (),
    context: Optional[CheckPointIPPoolContainerContext] = None,
) -> Iterable[Tuple[str, Dict[str, Any], CheckPointIPPoolContainerContext]]:
    context = context or CheckPointIPPoolContainerContext()
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace(" ", "-")
            child_path = (*path, normalized)
            if normalized in _POOL_KEYS:
                for index, record in enumerate(_as_list(child)):
                    if isinstance(record, dict):
                        record_context = replace(context, parent_path=child_path)
                        interface, interface_uid = _interface_ref(
                            record, ("associated-interface", "associated_interface", "interface-name", "interface_name", "interface")
                        )
                        if interface:
                            record_context = replace(
                                record_context, interface=interface,
                                interface_uid=interface_uid or record_context.interface_uid,
                            )
                        yield normalized, record, record_context
                yield from _containers(child, normalized, child_path, context)
            elif normalized in _INTERFACE_KEYS:
                for index, entry in enumerate(_as_list(child)):
                    entry_context = context
                    if isinstance(entry, dict):
                        interface = _label(entry.get("name") or entry.get("interface-name") or entry.get("interface_name"))
                        interface_uid = _label(entry.get("uid") or entry.get("interface-uid") or entry.get("interface_uid"))
                        entry_context = replace(
                            context, parent_path=child_path,
                            interface=interface or context.interface,
                            interface_uid=interface_uid or context.interface_uid,
                        )
                    yield from _containers(entry, normalized, (*child_path, str(index)), entry_context)
            elif normalized in _CLUSTER_MEMBER_KEYS or (
                normalized == "members" and parent_key in {"cluster", "cluster-object"}
            ):
                for index, entry in enumerate(_as_list(child)):
                    member = _label(entry)
                    yield from _containers(
                        entry, normalized, (*child_path, str(index)),
                        replace(context, parent_path=child_path, cluster_member=member or context.cluster_member),
                    )
            else:
                yield from _containers(child, normalized, child_path, context)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _containers(child, parent_key, (*path, str(index)), context)


def _ref_status(
    refs: List[str], resolver: CheckPointObjectResolver, domain: Optional[str],
    expected: Tuple[str, ...], domain_uid: Optional[str] = None,
) -> List[str]:
    reasons: List[str] = []
    for ref in refs:
        resolution = resolver.resolve(
            ref, domain=domain, domain_uid=domain_uid,
            allow_special_symbolic_names=False,
        )
        if not resolution.resolved or resolution.semantic_kind.value.lower() not in expected:
            reasons.append(f"unresolved-ip-pool-reference:{ref}")
    return reasons


def extract_ip_pool_nat(
    responses: List[CheckPointResponse], resolver: CheckPointObjectResolver,
) -> Tuple[List[IRIPPool], List[SourceInventoryItem]]:
    pools: List[IRIPPool] = []
    inventory: List[SourceInventoryItem] = []
    seen: set[Tuple[Optional[str], Optional[str], str, Optional[str], Tuple[str, ...]]] = set()
    for response in responses:
        command = canonicalize_command(response.command)
        if command not in _POOL_COMMANDS:
            continue
        objects = response.data.get("objects")
        if objects is None:
            objects = response.data.get("global-properties") or response.data.get("properties") or response.data.get("settings") or []
        if isinstance(objects, dict):
            normalized_keys = {str(key).lower().replace(" ", "-") for key in objects}
            objects = [objects] if normalized_keys & _POOL_KEYS or {"name", "uid", "type"} & normalized_keys else list(objects.values())
        for gateway in objects if isinstance(objects, list) else []:
            if not isinstance(gateway, dict):
                continue
            owner_gateway = _label(gateway.get("uid") or gateway.get("name"))
            base_context = CheckPointIPPoolContainerContext(owner_gateway=owner_gateway)
            for container_key, raw, context in _containers(gateway, context=base_context):
                uid = _label(raw.get("uid"))
                name = _label(raw.get("name")) or uid
                if not name:
                    continue
                identity = (response.domain_uid or response.domain, uid, name, context.interface, context.parent_path)
                if identity in seen:
                    continue
                seen.add(identity)
                raw_associated_interface, raw_associated_interface_uid = _interface_ref(
                    raw, ("associated-interface", "associated_interface", "interface-name", "interface_name", "interface")
                )
                associated_interface = raw_associated_interface or context.interface
                associated_interface_uid = raw_associated_interface_uid or context.interface_uid
                network_refs = _labels(raw, ("network", "network-object", "networks"))
                network_group_refs = _labels(raw, ("network-group", "network-group-object", "network-groups"))
                range_refs = _labels(raw, ("address-range", "address-range-object", "address-ranges", "range"))
                gateway_refs = _labels(raw, ("gateway", "gateway-object", "gateways", "cluster", "cluster-object"))
                if context.owner_gateway and context.owner_gateway not in gateway_refs:
                    gateway_refs.append(context.owner_gateway)
                member_assignments = raw.get("member-assignment") or raw.get("member_assignment") or raw.get("members") or {}
                applicability = _labels(raw, ("applicability", "install-on", "install_on", "scope"))
                domain = response.domain_name or response.domain
                if associated_interface and not raw_associated_interface:
                    resolver.register_object(
                        {"uid": associated_interface_uid, "name": associated_interface, "type": "interface"},
                        domain=domain, domain_uid=response.domain_uid,
                    )
                reasons = _ref_status(network_refs, resolver, domain, ("address", "address-group"), response.domain_uid)
                reasons.extend(_ref_status(network_group_refs, resolver, domain, ("address-group",), response.domain_uid))
                reasons.extend(_ref_status(range_refs, resolver, domain, ("address",), response.domain_uid))
                if associated_interface:
                    interface_resolution = resolver.resolve(
                        associated_interface_uid or associated_interface,
                        domain=domain, domain_uid=response.domain_uid,
                    )
                    if not interface_resolution.resolved:
                        reasons.append(f"unresolved-ip-pool-interface:{associated_interface}")
                status = ExtractionStatus.PARTIALLY_NORMALIZED if reasons else ExtractionStatus.EXTRACT_ONLY
                source_attributes = {
                    **raw,
                    "checkpoint-pool-container": container_key,
                    "checkpoint-owner": context.owner_gateway,
                    "checkpoint-parent-path": list(context.parent_path),
                    "checkpoint-associated-interface": associated_interface,
                    "checkpoint-associated-interface-uid": associated_interface_uid,
                    "checkpoint-cluster-member": context.cluster_member,
                    "checkpoint-domain-uid": response.domain_uid,
                    "checkpoint-domain-name": domain,
                }
                pool = IRIPPool(
                    name=name, source_uuid=uid, source_context=domain,
                    address_family=str(raw.get("address-family") or raw.get("address_family") or "ipv4"),
                    pool_type=raw.get("pool-type") or raw.get("pool_type") or raw.get("type"),
                    start_ip=raw.get("start-ip") or raw.get("start_ip") or raw.get("ipv4-address-first"),
                    end_ip=raw.get("end-ip") or raw.get("end_ip") or raw.get("ipv4-address-last"),
                    source_origin="checkpoint-management-ip-pool",
                    checkpoint_pool_object_type=raw.get("type") or raw.get("object-type"),
                    checkpoint_network_references=network_refs,
                    checkpoint_network_group_references=network_group_refs,
                    checkpoint_address_range_references=range_refs,
                    checkpoint_gateway_references=gateway_refs,
                    checkpoint_member_assignments=member_assignments if isinstance(member_assignments, dict) else {"members": member_assignments},
                    checkpoint_applicability=applicability,
                    checkpoint_precedence=raw.get("precedence") if isinstance(raw.get("precedence"), int) else None,
                    checkpoint_vpn_scope=_label(raw.get("vpn") or raw.get("vpn-scope") or raw.get("vpn_scope")),
                    checkpoint_mep=raw.get("mep") if isinstance(raw.get("mep"), bool) else None,
                    associated_interface=associated_interface,
                    migration_status=status.value, requires_manual_review=True,
                    audit_note="Check Point management IP-pool NAT; source-only until target semantics are reviewed.",
                    source_attributes=source_attributes,
                )
                pools.append(pool)
                inventory.append(SourceInventoryItem(
                    domain=domain or "global", domain_uid=response.domain_uid,
                    domain_name=response.domain_name or domain, source_path=f"checkpoint/{command}/ip-pool-nat",
                    name=name, source_id=uid, source_type="checkpoint-ip-pool-nat",
                    source_context=response.gateway or response.domain,
                    source_attributes=source_attributes, status=status,
                    requires_manual_review=True,
                    notes=reasons or ["checkpoint-ip-pool-nat-retained-source-only"],
                ))
    return pools, inventory
