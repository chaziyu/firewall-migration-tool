"""Check Point address objects, groups, nonportable types, and nat-settings extraction."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import (
    IRAddress, IRAddressGroup, IRApplication, IRApplicationCategory,
    IRApplicationGroup,
)
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
    nat_rulebase_complete: bool = True,
    nat_completeness_by_scope: Optional[Mapping[Tuple[str, Optional[str]], bool]] = None,
    selected_package: Optional[str] = None,
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
            "show-security-zones", "show-gateways-and-servers",
        ):
            continue

        data = resp.data
        domain = resp.domain or "global"
        nat_scope_package = resp.package or selected_package
        scoped_nat_complete = nat_rulebase_complete
        if nat_completeness_by_scope is not None:
            scoped_nat_complete = nat_completeness_by_scope.get((domain, nat_scope_package), False)
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())

        for obj_index, obj in enumerate(objects):
            if not isinstance(obj, dict):
                inventory_items.append(SourceInventoryItem(
                    domain=domain,
                    source_path=f"checkpoint/{cmd}",
                    name=f"<malformed:{obj_index}>",
                    source_type="malformed-object",
                    source_attributes={"raw_value": str(obj)},
                    status=ExtractionStatus.PARSE_ERROR,
                    requires_manual_review=True,
                    notes=["malformed-non-dict-object"],
                ))
                continue

            resolver.register_object(obj, domain=domain)

            obj_type = obj.get("type", "").strip().lower()
            if obj_type in SERVICE_TYPES or obj_type in TIME_TYPES or obj_type in {
                "application", "application-site", "application-group",
                "application-site-group", "application-category",
                "application-site-category",
            }:
                continue
            uid = obj.get("uid")
            source_name = obj.get("name")
            name = source_name or f"<unnamed:{uid or obj_index}>"
            comments = obj.get("comments")
            src_path = f"checkpoint/{cmd}"
            status = ExtractionStatus.UNSUPPORTED
            requires_review = True
            notes: List[str] = []

            if not source_name:
                status = ExtractionStatus.PARSE_ERROR
                notes.append("missing-object-name")
                resolver.set_object_normalization(
                    uid_or_name=uid or name, canonical_name=None, status=status,
                    requires_manual_review=True, usable=False,
                    semantic_kind=infer_semantic_kind(obj_type, None),
                )

            # 1. Host Objects
            elif obj_type == "host" or cmd == "show-hosts":
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                ip4 = obj.get("ipv4-address") or obj.get("ipv4_address")
                ip6 = obj.get("ipv6-address") or obj.get("ipv6_address")
                nat_settings = obj.get("nat-settings")

                if ip4 and ip6:
                    for family, value, bits in (("ipv4", ip4, 32), ("ipv6", ip6, 128)):
                        try:
                            (ipaddress.IPv4Address if family == "ipv4" else ipaddress.IPv6Address)(value)
                            addresses.append(IRAddress(
                                name=f"{name}__{family}", type=AddressType.HOST,
                                subnet=f"{value}/{bits}", description=comments,
                                source_uuid=uid, address_family=family,
                                source_attributes={"checkpoint-original-name": name, "checkpoint-source-object": obj},
                            ))
                        except ValueError:
                            status = ExtractionStatus.PARTIALLY_NORMALIZED
                            requires_review = True
                            notes.append(f"Invalid {family} host address: {value}")
                elif ip4:
                    try:
                        ipaddress.IPv4Address(ip4)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.HOST,
                            subnet=f"{ip4}/32",
                            description=comments, source_uuid=uid, address_family="ipv4",
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
                            description=comments, source_uuid=uid, address_family="ipv6",
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
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                subnet4 = obj.get("subnet4") or obj.get("subnet")
                mask_len4 = obj.get("mask-length4") if obj.get("mask-length4") is not None else obj.get("mask_length4")
                subnet_mask4 = obj.get("subnet-mask") or obj.get("subnet_mask")
                subnet6 = obj.get("subnet6")
                mask_len6 = obj.get("mask-length6") if obj.get("mask-length6") is not None else obj.get("mask_length6")

                if mask_len4 is None and subnet_mask4:
                    mask_len4 = _mask_to_prefix_len(str(subnet_mask4))

                if subnet4 and mask_len4 is not None and subnet6 and mask_len6 is not None:
                    for family, value, prefix in (("ipv4", subnet4, mask_len4), ("ipv6", subnet6, mask_len6)):
                        try:
                            network = (ipaddress.IPv4Network if family == "ipv4" else ipaddress.IPv6Network)(f"{value}/{prefix}", strict=False)
                            addresses.append(IRAddress(
                                name=f"{name}__{family}", type=AddressType.NETWORK,
                                subnet=str(network), description=comments,
                                source_uuid=uid, address_family=family,
                                source_attributes={"checkpoint-original-name": name, "checkpoint-source-object": obj},
                            ))
                        except ValueError:
                            status = ExtractionStatus.PARTIALLY_NORMALIZED
                            requires_review = True
                            notes.append(f"Invalid {family} network definition: {value}/{prefix}")
                elif subnet4 and mask_len4 is not None:
                    try:
                        net = ipaddress.IPv4Network(f"{subnet4}/{mask_len4}", strict=False)
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.NETWORK,
                            subnet=str(net),
                            description=comments, source_uuid=uid, address_family="ipv4",
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
                            description=comments, source_uuid=uid, address_family="ipv6",
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
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                first4 = obj.get("ipv4-address-first") or obj.get("ipv4_address_first")
                last4 = obj.get("ipv4-address-last") or obj.get("ipv4_address_last")
                first6 = obj.get("ipv6-address-first") or obj.get("ipv6_address_first")
                last6 = obj.get("ipv6-address-last") or obj.get("ipv6_address_last")

                if first4 and last4 and first6 and last6:
                    for family, first, last in (("ipv4", first4, last4), ("ipv6", first6, last6)):
                        try:
                            address_type = ipaddress.IPv4Address if family == "ipv4" else ipaddress.IPv6Address
                            if address_type(first) > address_type(last):
                                raise ValueError("range start is greater than range end")
                            addresses.append(IRAddress(
                                name=f"{name}__{family}", type=AddressType.RANGE,
                                ip_range_start=first, ip_range_end=last, description=comments,
                                source_uuid=uid, address_family=family,
                                source_attributes={"checkpoint-original-name": name, "checkpoint-source-object": obj},
                            ))
                        except ValueError:
                            status = ExtractionStatus.PARTIALLY_NORMALIZED
                            requires_review = True
                            notes.append(f"Invalid {family} address range: {first}-{last}")
                elif first4 and last4:
                    try:
                        first_ip = ipaddress.IPv4Address(first4)
                        last_ip = ipaddress.IPv4Address(last4)
                        if first_ip > last_ip:
                            raise ValueError("range start is greater than range end")
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.RANGE,
                            ip_range_start=first4,
                            ip_range_end=last4,
                            description=comments, source_uuid=uid, address_family="ipv4",
                        ))
                    except Exception:
                        status = ExtractionStatus.PARTIALLY_NORMALIZED
                        requires_review = True
                        notes.append(f"Invalid IPv4 address range: {first4}-{last4}")
                elif first6 and last6:
                    try:
                        first_ip = ipaddress.IPv6Address(first6)
                        last_ip = ipaddress.IPv6Address(last6)
                        if first_ip > last_ip:
                            raise ValueError("range start is greater than range end")
                        addresses.append(IRAddress(
                            name=name,
                            type=AddressType.RANGE,
                            ip_range_start=first6,
                            ip_range_end=last6,
                            description=comments, source_uuid=uid, address_family="ipv6",
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
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                raw_members = obj.get("members", [])
                member_names: List[str] = []
                for m in raw_members:
                    res = resolver.resolve(m, domain=domain)
                    if res.resolved and res.canonical_names:
                        member_names.extend(res.canonical_names)
                    elif res.resolved and res.name:
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
                include_ref = obj.get("include") or obj.get("members", [])
                except_ref = obj.get("except") or obj.get("exclude") or obj.get("except-members", [])
                include_refs = include_ref if isinstance(include_ref, list) else [include_ref]
                except_refs = except_ref if isinstance(except_ref, list) else [except_ref]
                include_names = [resolver.resolve(ref, domain=domain).name or str(ref) for ref in include_refs if ref]
                except_names = [resolver.resolve(ref, domain=domain).name or str(ref) for ref in except_refs if ref]
                address_groups.append(IRAddressGroup(
                    name=name, members=include_names, exclusion_enabled=True,
                    exclude_members=except_names, description=comments,
                    source_uuid=uid, source_attributes=obj,
                    migration_status=status.value, requires_manual_review=True,
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
                "wildcard", "multicast-address-range", "network-feed", "dns-domain",
                "application", "application-site", "application-group",
                "application-site-group", "application-category",
                "application-site-category"
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
                status = ExtractionStatus.EXTRACT_ONLY
                requires_review = True
                notes.append("security-zone-awaiting-canonical-topology-emission")
                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=True,
                    usable=False,
                    semantic_kind=SemanticKind.SECURITY_ZONE,
                )

            else:
                reason_msg = f"Unhandled Check Point object type '{obj_type or '<missing>'}'"
                notes.append(reason_msg)
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name, reason=reason_msg,
                    requires_manual_review=True, raw_capture=str(obj),
                ))
                resolver.set_object_normalization(
                    uid_or_name=uid or name, canonical_name=None, status=status,
                    requires_manual_review=True, usable=False,
                    semantic_kind=infer_semantic_kind(obj_type, name),
                )

            nat_settings = obj.get("nat-settings")
            has_automatic_nat = isinstance(nat_settings, dict) and (
                nat_settings.get("auto-stat") is True
                or nat_settings.get("auto-rule") is True
                or bool(nat_settings.get("method"))
            )
            if isinstance(nat_settings, dict) and nat_settings.get("method"):
                notes.append(f"automatic-nat-method:{nat_settings.get('method')}")
            if has_automatic_nat and not scoped_nat_complete:
                if status == ExtractionStatus.NORMALIZED:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                requires_review = True
                reason = "automatic-nat-intent-without-complete-nat-rulebase"
                notes.append(reason)
                notes.append(f"automatic-nat-scope:{domain}/{nat_scope_package or '<missing-package>'}")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name, reason=reason,
                    requires_manual_review=True, raw_capture=str(nat_settings),
                ))

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


def extract_application_objects(
    responses: List[CheckPointResponse], resolver: CheckPointObjectResolver,
) -> Tuple[List[IRApplication], List[IRApplicationGroup], List[IRApplicationCategory], List[SourceInventoryItem]]:
    """Extract Check Point application/site objects without treating them as services."""
    applications: List[IRApplication] = []
    groups: List[IRApplicationGroup] = []
    categories: List[IRApplicationCategory] = []
    inventory: List[SourceInventoryItem] = []
    command_types = {
        "show-application-sites": "application-site",
        "show-application-site-groups": "application-site-group",
        "show-application-site-categories": "application-site-category",
    }
    object_types = set(command_types.values()) | {
        "application", "application-group", "application-category",
    }
    for response in responses:
        command = canonicalize_command(response.command)
        expected_type = command_types.get(command)
        objects = response.data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        for index, obj in enumerate(objects if isinstance(objects, list) else []):
            if not isinstance(obj, dict):
                continue
            obj_type = str(obj.get("type") or expected_type or "").strip().lower()
            if obj_type not in object_types and expected_type is None:
                continue
            resolver.register_object(obj, domain=response.domain or "global")
            name = obj.get("name") or f"<unnamed:{obj.get('uid') or index}>"
            uid = obj.get("uid")
            members = obj.get("members") or obj.get("member") or obj.get("objects") or []
            members = members if isinstance(members, list) else [members]
            member_names = []
            for member in members:
                resolved = resolver.resolve(member, domain=response.domain or "global")
                member_names.append(resolved.name or str(member))
            urls = obj.get("urls") or obj.get("url") or obj.get("site") or []
            urls = urls if isinstance(urls, list) else [urls]
            attrs = dict(obj)
            is_group = "group" in obj_type
            is_category = "category" in obj_type
            common = dict(
                name=name, source_uuid=uid, source_context=response.domain,
                category=obj.get("category"), urls=[str(v) for v in urls if v],
                description=obj.get("comments") or obj.get("description"),
                risk=obj.get("risk"), metadata=obj.get("metadata") or {},
                source_attributes=attrs,
            )
            if is_category:
                categories.append(IRApplicationCategory(members=member_names, **common))
                kind = SemanticKind.APPLICATION_CATEGORY
            elif is_group:
                groups.append(IRApplicationGroup(members=member_names, **common))
                kind = SemanticKind.APPLICATION_GROUP
            else:
                applications.append(IRApplication(**common))
                kind = SemanticKind.APPLICATION
            resolver.set_object_normalization(
                uid or name, name, ExtractionStatus.NORMALIZED,
                semantic_kind=kind, domain=response.domain or "global",
            )
            inventory.append(SourceInventoryItem(
                domain=response.domain or "global", source_path=f"checkpoint/{command}",
                name=name, source_id=uid, source_type=obj_type,
                source_attributes=attrs, status=ExtractionStatus.NORMALIZED,
            ))
    return applications, groups, categories, inventory
