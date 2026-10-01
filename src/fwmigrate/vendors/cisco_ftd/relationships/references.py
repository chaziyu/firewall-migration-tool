"""Cisco FTD source-reference indexing and resolution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class FTDReferenceKind(str, Enum):
    NETWORK_ADDRESS = "NETWORK_ADDRESS"
    NETWORK_GROUP = "NETWORK_GROUP"
    SERVICE_OBJECT = "SERVICE_OBJECT"
    SERVICE_GROUP = "SERVICE_GROUP"
    SECURITY_ZONE = "SECURITY_ZONE"
    INTERFACE = "INTERFACE"
    TIME_RANGE = "TIME_RANGE"
    REALM = "REALM"
    REALM_USER = "REALM_USER"
    REALM_USER_GROUP = "REALM_USER_GROUP"
    LOCAL_REALM_USER = "LOCAL_REALM_USER"
    FMC_USER_ROLE = "FMC_USER_ROLE"
    INTRUSION_POLICY = "INTRUSION_POLICY"
    FILE_POLICY = "FILE_POLICY"
    DECRYPTION_POLICY = "DECRYPTION_POLICY"
    DNS_POLICY = "DNS_POLICY"
    SECURITY_INTELLIGENCE_SOURCE = "SECURITY_INTELLIGENCE_SOURCE"
    VARIABLE_SET = "VARIABLE_SET"
    SLA_MONITOR = "SLA_MONITOR"
    VPN_ENDPOINT = "VPN_ENDPOINT"
    IKE_POLICY = "IKE_POLICY"
    IPSEC_PROPOSAL = "IPSEC_PROPOSAL"
    APPLICATION = "APPLICATION"
    URL_CATEGORY = "URL_CATEGORY"
    VLAN_OBJECT = "VLAN_OBJECT"
    VIRTUAL_ROUTER = "VIRTUAL_ROUTER"
    ADDRESS_POOL = "ADDRESS_POOL"
    CERTIFICATE = "CERTIFICATE"
    CERTIFICATE_MAP = "CERTIFICATE_MAP"
    GROUP_POLICY = "GROUP_POLICY"
    PREFILTER_POLICY = "PREFILTER_POLICY"
    NETWORK_ANALYSIS_POLICY = "NETWORK_ANALYSIS_POLICY"
    RAVPN_CONNECTION_PROFILE = "RAVPN_CONNECTION_PROFILE"
    INTRUSION_RULE_GROUP = "INTRUSION_RULE_GROUP"
    INTRUSION_RULE_BEHAVIOR = "INTRUSION_RULE_BEHAVIOR"
    ACCESS_CONTROL_POLICY = "ACCESS_CONTROL_POLICY"
    IDENTITY_POLICY = "IDENTITY_POLICY"
    ACCESS_CONTROL_DEFAULT_ACTION = "ACCESS_CONTROL_DEFAULT_ACTION"


@dataclass(frozen=True)
class FTDReferenceIssue:
    owner: str
    field: str
    reference: str
    source_plane: str
    source_context: str | None = None
    domain_id: str | None = None
    status: str = "UNRESOLVED"
    reference_id: str | None = None
    reference_name: str | None = None
    expected_kinds: tuple[str, ...] = ()
    found_kinds: tuple[str, ...] = ()
    scope: str | None = None
    reason: str = "unresolved"


class FTDReferenceResolver:
    """Resolve vendor-native references without mutating CiscoFTDConfig."""

    def __init__(self) -> None:
        self.by_id: dict[tuple[str, FTDReferenceKind, str], list[Any]] = {}
        self.by_name: dict[tuple[str, FTDReferenceKind, str], list[Any]] = {}
        self.issues: list[FTDReferenceIssue] = []
        self.resolved: list[dict[str, str | None]] = []
        self.identity_relationships: list[dict[str, Any]] = []

    @staticmethod
    def key_scope(record: Any) -> str:
        return record.domain_id or f"{record.source_plane}:{record.source_context or ''}"

    @staticmethod
    def identity(value: Any) -> tuple[str | None, str | None]:
        if isinstance(value, dict):
            return (
                str(value["id"]) if value.get("id") is not None else None,
                str(value["name"]) if value.get("name") is not None else None,
            )
        if hasattr(value, "source_id"):
            return (
                str(value.source_id) if value.source_id else None,
                str(value.name) if value.name else None,
            )
        return (None, str(value)) if value is not None else (None, None)

    def register(self, kind: FTDReferenceKind, records: Any) -> None:
        for item in records:
            domain = self.key_scope(item)
            if item.source_id:
                self.by_id.setdefault((domain, kind, str(item.source_id)), []).append(item)
            if item.name:
                self.by_name.setdefault((domain, kind, item.name), []).append(item)

    def resolve(
        self,
        owner: Any,
        field_name: str,
        value: Any,
        kinds: tuple[FTDReferenceKind, ...],
        *,
        special: frozenset[str] = frozenset(),
        scope: str | None = None,
        relationship_type: str | None = None,
    ) -> None:
        ref_id, ref_name = self.identity(value)
        if ref_id is None and ref_name is None:
            return
        if ref_id is None and ref_name and ref_name.casefold() in special:
            return

        domain = self.key_scope(owner)
        source_type = getattr(value, "source_type", None)
        if source_type and source_type.casefold() in {"securityzone", "security-zone"}:
            kinds = tuple(dict.fromkeys((*kinds, FTDReferenceKind.SECURITY_ZONE)))
        elif source_type and source_type.casefold().replace("_", "").replace("-", "") in {
            "localrealmuser", "localuser"
        }:
            kinds = (FTDReferenceKind.LOCAL_REALM_USER,)

        found = (
            [item for kind in kinds for item in self.by_id.get((domain, kind, ref_id), ())]
            if ref_id else
            [item for kind in kinds for item in self.by_name.get((domain, kind, ref_name), ())]
        )
        if scope:
            found = [item for item in found if item.device_id == scope]

        if len(found) == 1:
            match = found[0]
            actual_kind = next(
                kind for kind in kinds
                if match in self.by_id.get((domain, kind, str(match.source_id)), ())
                or match in self.by_name.get((domain, kind, match.name), ())
            )
            self.resolved.append({
                "owner": owner.name,
                "field": field_name,
                "reference_id": ref_id,
                "reference_name": ref_name,
                "kind": actual_kind.value,
                "target_id": match.source_id,
                "target_name": match.name,
            })
            if relationship_type:
                self.identity_relationships.append({
                    "relationship_type": relationship_type,
                    "owner_id": owner.source_id,
                    "owner_name": owner.name,
                    "target_id": match.source_id,
                    "target_name": match.name,
                    "source_plane": owner.source_plane,
                })
            return

        reason, status = "unresolved", "UNRESOLVED"
        if len(found) > 1:
            reason, status = "ambiguous", "AMBIGUOUS"
        else:
            other = [
                item
                for kind in FTDReferenceKind if kind not in kinds
                for item in (
                    self.by_id.get((domain, kind, ref_id), ())
                    if ref_id else self.by_name.get((domain, kind, ref_name), ())
                )
            ]
            if other:
                reason, status = "wrong-kind", "WRONG_KIND"

        found_kinds = tuple(
            kind.value for kind in FTDReferenceKind
            if bool(self.by_id.get((domain, kind, ref_id), ()))
            or bool(self.by_name.get((domain, kind, ref_name), ()))
        )
        self.issues.append(FTDReferenceIssue(
            owner.name,
            field_name,
            ref_id or ref_name or "",
            owner.source_plane,
            owner.source_context,
            owner.domain_id,
            status,
            ref_id,
            ref_name,
            tuple(kind.value for kind in kinds),
            found_kinds,
            scope or owner.source_context or owner.source_plane,
            reason,
        ))


__all__ = ["FTDReferenceIssue", "FTDReferenceKind", "FTDReferenceResolver"]
