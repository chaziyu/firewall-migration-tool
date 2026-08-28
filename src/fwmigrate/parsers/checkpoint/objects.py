"""Check Point address objects, groups, nonportable types, and nat-settings extraction."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import IRAddress, IRAddressGroup
from fwmigrate.ir.enums import AddressType
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
    infer_semantic_kind,
)


def _mask_to_prefix_len(mask_str: str) -> Optional[int]:
    """Convert IPv4 subnet mask string (e.g. 255.255.255.0) to prefix length."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen
    except Exception:
        return None


def extract_address_objects(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
) -> Tuple[List[IRAddress], List[IRAddressGroup], List[SourceInventoryItem], List[UnsupportedItem]]:
    """
    Extract Check Point address objects, groups, dynamic/updatable types, and nat-settings.
    Registers normalization results with resolver.
    """
    addresses: List[IRAddress] = []
    address_groups: List[IRAddressGroup] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    SERVICE_TYPES = {
        "service-tcp", "service-udp", "service-sctp", "service-icmp",
        "service-icmp6", "service-other", "service-group", "service-dce-rpc",
        "service-rpc", "service-gtp", "service-compound-tcp"
    }
    TIME_TYPES = {"time", "time-group"}

    for resp in responses:
        cmd = canonicalize_command(resp.command)
        if cmd in (
            "show-services-tcp", "show-services-udp", "show-services-sctp",
            "show-services-icmp", "show-services-icmp6", "show-services-other",
            "show-service-groups", "show-times", "show-time-groups",
            "show-access-rulebase", "show-nat-rulebase", "gaia/show-configuration",
        ):
            continue

        data = resp.data
        domain = resp.domain or "global"
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            obj_type = obj.get("type", "").strip().lower()
            if obj_type in SERVICE_TYPES or obj_type in TIME_TYPES:
                continue
            uid = obj.get("uid")
            name = obj.get("name")
            comments = obj.get("comments")
            src_path = f"checkpoint/{cmd}"
            if not name:
                continue

            status = ExtractionStatus.NORMALIZED
            requires_review = False
            notes: List[str] = []

            # 1. Host Objects
            if obj_type == "host" or cmd == "show-hosts":
                ip4 = obj.get("ipv4-address") or obj.get("ipv4_address")
                ip6 = obj.get("ipv6-address") or obj.get("ipv6_address")
                nat_settings = obj.get("nat-settings")

                if ip4:
                    try:
                        ipaddress.IPv4Address(ip4)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.HOST,
                            subnet=f"{ip4}/32",
                            description=comments,
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv4 host address: {ip4}")
                elif ip6:
                    try:
                        ipaddress.IPv6Address(ip6)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.HOST,
                            subnet=f"{ip6}/128",
                            description=comments,
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv6 host address: {ip6}")
                else:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.append("Host object missing IP address definition")

                if nat_settings and isinstance(nat_settings, dict):
                    if nat_settings.get("auto-stat") is True or nat_settings.get("auto-rule") is True:
                        notes.append("host-contains-auto-nat-settings")

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.ADDRESS,
                )

            # 2. Network Objects
            elif obj_type == "network" or cmd == "show-networks":
                subnet4 = obj.get("subnet4") or obj.get("subnet")
                mask_len4 = obj.get("mask-length4") if obj.get("mask-length4") is not None else obj.get("mask_length4")
                subnet_mask4 = obj.get("subnet-mask") or obj.get("subnet_mask")
                subnet6 = obj.get("subnet6")
                mask_len6 = obj.get("mask-length6") if obj.get("mask-length6") is not None else obj.get("mask_length6")

                if mask_len4 is None and subnet_mask4:
                    mask_len4 = _mask_to_prefix_len(str(subnet_mask4))

                if subnet4 and mask_len4 is not None:
                    try:
                        net = ipaddress.IPv4Network(f"{subnet4}/{mask_len4}", strict=False)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.NETWORK,
                            subnet=str(net),
                            description=comments,
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv4 network definition: {subnet4}/{mask_len4}")
                elif subnet6 and mask_len6 is not None:
                    try:
                        net6 = ipaddress.IPv6Network(f"{subnet6}/{mask_len6}", strict=False)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.NETWORK,
                            subnet=str(net6),
                            description=comments,
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv6 network definition: {subnet6}/{mask_len6}")
                else:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.append("Network object missing valid subnet and netmask")

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.ADDRESS,
                )

            # 3. Address Range Objects
            elif obj_type == "address-range" or cmd == "show-address-ranges":
                first4 = obj.get("ipv4-address-first") or obj.get("ipv4_address_first")
                last4 = obj.get("ipv4-address-last") or obj.get("ipv4_address_last")
                first6 = obj.get("ipv6-address-first") or obj.get("ipv6_address_first")
                last6 = obj.get("ipv6-address-last") or obj.get("ipv6_address_last")

                if first4 and last4:
                    try:
                        ipaddress.IPv4Address(first4)
                        ipaddress.IPv4Address(last4)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.RANGE,
                            ip_range_start=first4,
                            ip_range_end=last4,
                            description=comments,
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv4 address range: {first4}-{last4}")
                elif first6 and last6:
                    try:
                        ipaddress.IPv6Address(first6)
                        ipaddress.IPv6Address(last6)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.RANGE,
                            ip_range_start=first6,
                            ip_range_end=last6,
                            description=comments,
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv6 address range: {first6}-{last6}")
                else:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.append("Address range missing first and last boundary")

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.ADDRESS,
                )

            # 4. Address Groups
            elif obj_type == "group" or cmd == "show-groups":
                raw_members = obj.get("members", [])
                member_names: List[str] = []
                for m in raw_members:
                    res = resolver.resolve(m, domain=domain)
                    if res.resolved and res.name:
                        member_names.append(res.name)
                    elif isinstance(m, str):
                        member_names.append(m)

                # Check recursive dependency safety
                is_safe = all(resolver.is_dependency_safe(m, domain=domain) for m in raw_members)
                if not is_safe:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.append("Group contains members requiring manual review or unmodeled semantics")

                address_groups.append(IRAddressGroup(
                    name=name,
                    members=member_names,
                    description=comments,
                    requires_manual_review=requires_review,
                ))

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.ADDRESS_GROUP,
                )

            # 5. Groups with Exclusion
            elif obj_type == "group-with-exclusion" or cmd == "show-groups-with-exclusion":
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                requires_review = True
                notes.append("Exclusion groups (include/except) cannot be expressed directly in canonical IR")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path,
                    source_name=name,
                    reason="Check Point group-with-exclusion requires policy rule expansion",
                    requires_manual_review=True,
                    raw_capture=str(obj),
                ))
                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=True,
                    usable=False,
                    semantic_kind=SemanticKind.ADDRESS_GROUP,
                )

            # 6. Non-portable / Special Objects
            elif obj_type in (
                "dynamic-object", "updatable-object", "data-center-object",
                "access-role", "checkpoint-host", "interoperable-device",
                "wildcard", "multicast-address-range", "network-feed", "dns-domain"
            ):
                status = ExtractionStatus.EXTRACT_ONLY
                requires_review = True
                reason_msg = f"Check Point object type '{obj_type}' is not portable to canonical IR"
                notes.append(reason_msg)
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path,
                    source_name=name,
                    reason=reason_msg,
                    requires_manual_review=True,
                    raw_capture=str(obj),
                ))
                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=True,
                    usable=False,
                    semantic_kind=infer_semantic_kind(obj_type, name),
                )

            # 7. Security Zones
            elif obj_type == "security-zone" or cmd == "show-security-zones":
                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=ExtractionStatus.NORMALIZED,
                    requires_manual_review=False,
                    usable=True,
                    semantic_kind=SemanticKind.SECURITY_ZONE,
                )

            # Leaf Inventory Item
            inventory_items.append(SourceInventoryItem(
                domain=domain,
                source_path=src_path,
                name=name,
                source_id=uid,
                source_type=obj_type,
                source_attributes=obj,
                status=status,
                requires_manual_review=requires_review,
                notes=notes,
            ))

    return addresses, address_groups, inventory_items, unsupported_items
