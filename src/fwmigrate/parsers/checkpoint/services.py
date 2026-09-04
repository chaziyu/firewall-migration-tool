"""Check Point service objects and service groups extraction."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir.core import IRService, IRServiceGroup, IRServicePort
from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
    infer_semantic_kind,
)


def _first_present(obj: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    for key in keys:
        if key in obj:
            return obj[key]
    return None


def classify_service_semantic_settings(obj: Dict[str, Any]) -> List[str]:
    """Return unmodeled settings that can change packet/session matching semantics."""
    traffic_affecting = {
        "match-for-any", "session-timeout", "aggressive-aging",
        "protocol-signature", "protocol-signatures", "sync-connections-on-cluster",
        "keep-connections-open-after-policy-installation", "use-default-session-timeout",
    }
    return sorted(key for key in traffic_affecting if key in obj and obj.get(key) is not None)


def classify_other_service_semantic_settings(obj: Dict[str, Any]) -> List[str]:
    """Detect INSPECT and session behavior omitted by protocol-only canonical IR."""
    traffic_affecting = {
        "match", "action", "accept-replies", "match-for-any", "session-timeout",
        "aggressive-aging", "sync-connections-on-cluster",
        "keep-connections-open-after-policy-installation", "use-default-session-timeout",
        "protocol-signature", "protocol-signatures",
    }
    return sorted(
        key for key in traffic_affecting
        if key in obj and obj.get(key) not in (None, "", [], {})
    )


def _modeled_service_fields(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Map Check Point names to typed IR fields without treating false as absent."""
    values = {
        "match_for_any": _first_present(obj, ("match-for-any", "match_for_any")),
        "session_timeout": _first_present(obj, ("session-timeout", "session_timeout")),
        "use_default_session_timeout": _first_present(obj, ("use-default-session-timeout", "use_default_session_timeout")),
        "aggressive_aging": _first_present(obj, ("aggressive-aging", "aggressive_aging")),
        "sync_connections_on_cluster": _first_present(obj, ("sync-connections-on-cluster", "sync_connections_on_cluster")),
        "keep_connections_open_after_policy_installation": _first_present(obj, (
            "keep-connections-open-after-policy-installation",
            "keep_connections_open_after_policy_installation",
        )),
        "accept_replies": _first_present(obj, ("accept-replies", "accept_replies")),
        "match": obj.get("match"),
        "action": obj.get("action"),
    }
    signatures = _first_present(obj, ("protocol-signatures", "protocol_signatures", "protocol-signature"))
    if signatures is not None:
        values["protocol_signatures"] = signatures if isinstance(signatures, list) else [signatures]
    values["session_behavior"] = {
        key: obj[key] for key in ("session-timeout", "session_timeout", "use-default-session-timeout",
                                  "use_default_session_timeout", "aggressive-aging", "aggressive_aging",
                                  "sync-connections-on-cluster", "sync_connections_on_cluster",
                                  "keep-connections-open-after-policy-installation",
                                  "keep_connections_open_after_policy_installation") if key in obj
    }
    return {key: value for key, value in values.items() if value is not None}


def extract_service_objects(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
) -> Tuple[List[IRService], List[IRServiceGroup], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Extract Check Point TCP, UDP, SCTP, ICMP, and other services with advanced option tracking."""
    services: List[IRService] = []
    service_groups: List[IRServiceGroup] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    SERVICE_COMMANDS = {
        "show-services-tcp", "show-services-udp", "show-services-sctp",
        "show-services-icmp", "show-services-icmp6", "show-services-other",
        "show-service-groups", "show-services-citrix-tcp", "show-services-dce-rpc",
        "show-services-rpc", "show-services-gtp", "show-services-compound-tcp",
    }
    SERVICE_TYPES = {
        "service-tcp", "service-udp", "service-sctp", "service-icmp",
        "service-icmp6", "service-other", "service-group", "service-dce-rpc",
        "service-rpc", "service-gtp", "service-compound-tcp", "service-citrix-tcp"
    }

    for resp in responses:
        cmd = canonicalize_command(resp.command)
        is_dictionary = cmd.endswith("/objects-dictionary")
        if cmd not in SERVICE_COMMANDS and cmd != "show-objects" and not is_dictionary:
            continue

        data = resp.data
        domain = resp.domain or "global"
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())

        for obj_index, obj in enumerate(objects):
            if not isinstance(obj, dict):
                if cmd == "show-objects":
                    continue
                inventory_items.append(SourceInventoryItem(
                    domain=domain, source_path=f"checkpoint/{cmd}",
                    name=f"<malformed-service:{obj_index}>", source_type="malformed-service",
                    source_attributes={"raw_value": str(obj)}, status=ExtractionStatus.PARSE_ERROR,
                    requires_manual_review=True, notes=["malformed-non-dict-service"],
                ))
                continue

            obj_type = obj.get("type", "").strip().lower()
            if (cmd == "show-objects" or is_dictionary) and obj_type not in SERVICE_TYPES:
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
                notes.append("missing-service-name")
                resolver.set_object_normalization(
                    uid_or_name=uid or name, canonical_name=None, status=status,
                    requires_manual_review=True, usable=False, semantic_kind=SemanticKind.SERVICE,
                )

            # 1. Specialized RPC / GTP / Compound Services
            elif obj_type in ("service-dce-rpc", "service-rpc", "service-gtp", "service-compound-tcp", "service-citrix-tcp") or cmd in {
                "show-services-dce-rpc", "show-services-rpc", "show-services-gtp",
                "show-services-compound-tcp", "show-services-citrix-tcp",
            }:
                status = ExtractionStatus.EXTRACT_ONLY
                requires_review = True
                reason_msg = f"Specialized Check Point service type '{obj_type}' requires target inspection profile"
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
                    semantic_kind=SemanticKind.SERVICE,
                )

            # 2. TCP / UDP / SCTP Services
            elif obj_type in ("service-tcp", "service-udp", "service-sctp") or cmd in (
                "show-services-tcp", "show-services-udp", "show-services-sctp"
            ):
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                proto = (
                    ServiceProtocol.TCP if "tcp" in obj_type or "tcp" in cmd
                    else (ServiceProtocol.UDP if "udp" in obj_type or "udp" in cmd else ServiceProtocol.SCTP)
                )
                port_raw = obj.get("port")
                source_port_raw = obj.get("source-port") or obj.get("source_port")

                if port_raw is None or str(port_raw).strip() == "":
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.append(f"{proto.value.upper()} service missing destination port definition")
                else:
                    port_str = str(port_raw).strip()
                    source_port_str = str(source_port_raw).strip() if source_port_raw is not None else None
                    services.append(IRService(
                        name=name,
                        ports=[IRServicePort(
                            protocol=proto,
                            port=port_str,
                            source_port=source_port_str,
                        )],
                        source_uuid=uid,
                        **_modeled_service_fields(obj),
                        source_attributes=obj,
                        description=comments,
                    ))

                advanced = classify_service_semantic_settings(obj)
                if advanced:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.extend(f"unmodeled-service-setting:{key}" for key in advanced)
                    if services and services[-1].name == name:
                        services[-1].source_unmodeled_semantic_settings = advanced
                        services[-1].migration_status = status.value
                        services[-1].requires_manual_review = True

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.SERVICE,
                )

            # 3. ICMP / ICMPv6 Services
            elif obj_type in ("service-icmp", "service-icmp6") or cmd in ("show-services-icmp", "show-services-icmp6"):
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                proto = ServiceProtocol.ICMP if "icmp6" not in obj_type and "icmp6" not in cmd else ServiceProtocol.ICMPV6
                icmp_type = _first_present(obj, ("icmp-type", "icmp_type"))
                icmp_code = _first_present(obj, ("icmp-code", "icmp_code"))

                try:
                    icmptype_val = int(icmp_type) if icmp_type is not None else None
                    icmpcode_val = int(icmp_code) if icmp_code is not None else None
                    if icmptype_val is not None and not 0 <= icmptype_val <= 255:
                        raise ValueError("ICMP type out of range")
                    if icmpcode_val is not None and not 0 <= icmpcode_val <= 255:
                        raise ValueError("ICMP code out of range")
                    services.append(IRService(
                        name=name, ports=[IRServicePort(
                            protocol=proto, port=IR_KEYWORD_ANY,
                            icmptype=icmptype_val, icmpcode=icmpcode_val,
                        )], source_uuid=uid, source_attributes=obj, description=comments,
                    ))
                except (TypeError, ValueError) as exc:
                    status = ExtractionStatus.PARSE_ERROR
                    requires_review = True
                    notes.append(f"invalid-icmp-type-or-code:{exc}")

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.SERVICE,
                )

            # 4. Other / Protocol Services
            elif obj_type == "service-other" or cmd == "show-services-other":
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                proto_num = _first_present(obj, ("ip-protocol", "ip_protocol", "protocol"))
                if proto_num is None or str(proto_num).strip() == "":
                    status = ExtractionStatus.PARSE_ERROR
                    requires_review = True
                    notes.append("missing-ip-protocol")
                else:
                    try:
                        proto_int = int(proto_num)
                        if not 0 <= proto_int <= 255:
                            raise ValueError("IP protocol out of range")
                        services.append(IRService(
                            name=name, ports=[IRServicePort(
                                protocol=ServiceProtocol.IP, port=str(proto_int),
                            )], source_uuid=uid, source_protocol_number=proto_int,
                            **_modeled_service_fields(obj),
                            source_attributes=obj, description=comments,
                        ))
                    except (TypeError, ValueError) as exc:
                        status = ExtractionStatus.PARSE_ERROR
                        requires_review = True
                        notes.append(f"invalid-ip-protocol:{exc}")

                semantic_settings = classify_other_service_semantic_settings(obj)
                if semantic_settings and status != ExtractionStatus.PARSE_ERROR:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.extend(f"unmodeled-service-setting:{key}" for key in semantic_settings)
                    if services and services[-1].name == name:
                        services[-1].source_unmodeled_semantic_settings = semantic_settings
                        services[-1].migration_status = status.value
                        services[-1].requires_manual_review = True

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.SERVICE,
                )

            # 5. Service Groups
            elif obj_type == "service-group" or cmd == "show-service-groups":
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                raw_members = obj.get("members", [])
                member_names: List[str] = []
                unsafe_members: List[str] = []
                for m in raw_members:
                    res = resolver.resolve(m, domain=domain)
                    if res.resolved and res.name:
                        member_names.append(res.name)
                    elif isinstance(m, str):
                        member_names.append(m)
                    if not resolver.is_dependency_safe(m, domain=domain):
                        unsafe_members.append(str(m.get("name") or m.get("uid")) if isinstance(m, dict) else str(m))

                # Recursive dependency safety check
                is_safe = all(resolver.is_dependency_safe(m, domain=domain) for m in raw_members)
                if not is_safe:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.append("Service group contains members requiring manual review or unmodeled semantics")

                service_groups.append(IRServiceGroup(
                    name=name,
                    members=member_names,
                    unsafe_members=unsafe_members,
                    description=comments,
                    requires_manual_review=requires_review,
                ))

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.SERVICE_GROUP,
                )

            else:
                reason_msg = f"Unhandled Check Point service type '{obj_type or '<missing>'}'"
                notes.append(reason_msg)
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name, reason=reason_msg,
                    requires_manual_review=True, raw_capture=str(obj),
                ))
                resolver.set_object_normalization(
                    uid_or_name=uid or name, canonical_name=None, status=status,
                    requires_manual_review=True, usable=False, semantic_kind=infer_semantic_kind(obj_type, name),
                )

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

    return services, service_groups, inventory_items, unsupported_items
