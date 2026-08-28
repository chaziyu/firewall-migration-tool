"""Check Point centralized object and reference resolver with semantic typing."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import PolicyAction

KNOWN_ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
KNOWN_ORIGINAL_UID = "97aeb369-9aea-11d5-bd16-0090272ccb31"


class SemanticKind(str, Enum):
    ADDRESS = "ADDRESS"
    ADDRESS_GROUP = "ADDRESS_GROUP"
    SECURITY_ZONE = "SECURITY_ZONE"
    ACCESS_ROLE = "ACCESS_ROLE"
    SERVICE = "SERVICE"
    SERVICE_GROUP = "SERVICE_GROUP"
    APPLICATION = "APPLICATION"
    APPLICATION_GROUP = "APPLICATION_GROUP"
    APPLICATION_CATEGORY = "APPLICATION_CATEGORY"
    SITE = "SITE"
    VPN_COMMUNITY = "VPN_COMMUNITY"
    TIME = "TIME"
    TIME_GROUP = "TIME_GROUP"
    ACTION = "ACTION"
    TRACK = "TRACK"
    INSTALL_TARGET = "INSTALL_TARGET"
    SPECIAL_ANY = "SPECIAL_ANY"
    SPECIAL_ORIGINAL = "SPECIAL_ORIGINAL"
    DNS_DOMAIN = "DNS_DOMAIN"
    UPDATABLE_OBJECT = "UPDATABLE_OBJECT"
    DATA_CENTER_OBJECT = "DATA_CENTER_OBJECT"
    DYNAMIC_OBJECT = "DYNAMIC_OBJECT"
    NETWORK_FEED = "NETWORK_FEED"
    NONPORTABLE_MATCH_OBJECT = "NONPORTABLE_MATCH_OBJECT"
    UNKNOWN = "UNKNOWN"


def is_any_object(obj: Any) -> bool:
    """Return True if the object or reference represents Check Point Any."""
    if obj is None:
        return False
    if isinstance(obj, str):
        return obj.strip().lower() == "any" or obj == KNOWN_ANY_UID
    if isinstance(obj, dict):
        obj_type = str(obj.get("type", "")).strip()
        uid = str(obj.get("uid", "")).strip()
        name = str(obj.get("name", "")).strip()
        return (
            obj_type == "CpmiAnyObject"
            or (uid == KNOWN_ANY_UID and name == "Any")
            or name == "Any"
            or uid == KNOWN_ANY_UID
        )
    return False


def is_original_object(obj: Any) -> bool:
    """Return True if the object represents Check Point NAT Original."""
    if obj is None:
        return False
    if isinstance(obj, str):
        return obj.strip().lower() == "original" or obj == KNOWN_ORIGINAL_UID
    if isinstance(obj, dict):
        obj_type = str(obj.get("type", "")).strip()
        uid = str(obj.get("uid", "")).strip()
        name = str(obj.get("name", "")).strip()
        return (
            obj_type == "CpmiOriginalObject"
            or name == "Original"
            or uid == KNOWN_ORIGINAL_UID
        )
    return False


def infer_semantic_kind(obj_type: Optional[str], name: Optional[str]) -> SemanticKind:
    """Infer high-level semantic kind from Check Point type name."""
    if not obj_type and not name:
        return SemanticKind.UNKNOWN

    t = (obj_type or "").strip().lower()
    n = (name or "").strip().lower()

    if t == "cpmianyobject" or n == "any":
        return SemanticKind.SPECIAL_ANY
    if t == "cpmioriginalobject" or n == "original":
        return SemanticKind.SPECIAL_ORIGINAL

    if t in ("host", "network", "address-range", "multicast-address-range", "wildcard"):
        return SemanticKind.ADDRESS
    if t in ("group", "group-with-exclusion"):
        return SemanticKind.ADDRESS_GROUP
    if t == "security-zone":
        return SemanticKind.SECURITY_ZONE
    if t in ("service-tcp", "service-udp", "service-sctp", "service-icmp", "service-icmp6", "service-other", "service-dce-rpc", "service-rpc", "service-gtp"):
        return SemanticKind.SERVICE
    if t == "service-group":
        return SemanticKind.SERVICE_GROUP
    if t in ("application-site", "application"):
        return SemanticKind.APPLICATION
    if t in ("application-site-group", "application-group"):
        return SemanticKind.APPLICATION_GROUP
    if t in ("application-site-category", "application-category"):
        return SemanticKind.APPLICATION_CATEGORY
    if t == "access-role":
        return SemanticKind.ACCESS_ROLE
    if t == "time":
        return SemanticKind.TIME
    if t == "time-group":
        return SemanticKind.TIME_GROUP
    if "vpn-community" in t:
        return SemanticKind.VPN_COMMUNITY
    if t == "rulebaseaction":
        return SemanticKind.ACTION
    if t in ("checkpointgateway", "checkpointcluster", "simplegateway", "simplecluster", "gateway", "cluster"):
        return SemanticKind.INSTALL_TARGET
    if t == "dns-domain":
        return SemanticKind.DNS_DOMAIN
    if t in ("updatable-object", "updatable_object"):
        return SemanticKind.UPDATABLE_OBJECT
    if t in ("data-center-object", "datacenter-object"):
        return SemanticKind.DATA_CENTER_OBJECT
    if t == "dynamic-object":
        return SemanticKind.DYNAMIC_OBJECT
    if t == "network-feed":
        return SemanticKind.NETWORK_FEED

    return SemanticKind.NONPORTABLE_MATCH_OBJECT if t else SemanticKind.UNKNOWN


class ResolutionResult(BaseModel):
    """Result of resolving a Check Point UID or object reference."""
    resolved: bool
    uid: Optional[str] = None
    name: Optional[str] = None
    object_type: Optional[str] = None
    semantic_kind: SemanticKind = SemanticKind.UNKNOWN
    canonical_name: Optional[str] = None
    normalization_status: ExtractionStatus = ExtractionStatus.EXTRACT_ONLY
    requires_manual_review: bool = False
    usable_in_canonical_reference: bool = False
    source_object: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class CheckPointObjectResolver:
    """Centralized resolver for Check Point UIDs, names, and dictionary entries."""

    def __init__(self):
        self.by_uid: Dict[str, Dict[str, Any]] = {}
        self.by_domain_and_name: Dict[Tuple[Optional[str], str], Dict[str, Any]] = {}
        self.by_name: Dict[str, Dict[str, Any]] = {}
        self.object_metadata: Dict[str, ResolutionResult] = {}

    def register_object(self, obj: Dict[str, Any], domain: Optional[str] = None) -> None:
        """Register a single Check Point object dictionary into resolution indexes."""
        if not isinstance(obj, dict):
            return
        uid = obj.get("uid")
        name = obj.get("name")
        obj_domain = obj.get("domain") or domain

        if uid:
            self.by_uid[str(uid)] = obj
        if name:
            s_name = str(name)
            self.by_domain_and_name[(obj_domain, s_name)] = obj
            self.by_name[s_name] = obj

    def register_dictionary(
        self,
        objects_dict: Union[List[Dict[str, Any]], Dict[str, Dict[str, Any]]],
        domain: Optional[str] = None,
    ) -> None:
        """Register an objects-dictionary structure from an API response."""
        if isinstance(objects_dict, dict):
            for item in objects_dict.values():
                if isinstance(item, dict):
                    self.register_object(item, domain=domain)
        elif isinstance(objects_dict, list):
            for item in objects_dict:
                if isinstance(item, dict):
                    self.register_object(item, domain=domain)

    def set_object_normalization(
        self,
        uid_or_name: str,
        canonical_name: Optional[str],
        status: ExtractionStatus,
        requires_manual_review: bool = False,
        usable: bool = True,
        semantic_kind: Optional[SemanticKind] = None,
    ) -> None:
        """Record the normalization outcome of an object for dependency tracking."""
        obj = self.by_uid.get(uid_or_name) or self.by_name.get(uid_or_name)
        uid = obj.get("uid") if obj else (uid_or_name if "-" in uid_or_name else None)
        name = obj.get("name") if obj else uid_or_name
        obj_type = obj.get("type") if obj else None
        kind = semantic_kind or infer_semantic_kind(obj_type, name)

        res = ResolutionResult(
            resolved=True,
            uid=uid,
            name=name,
            object_type=obj_type,
            semantic_kind=kind,
            canonical_name=canonical_name or name,
            normalization_status=status,
            requires_manual_review=requires_manual_review,
            usable_in_canonical_reference=usable and (status == ExtractionStatus.NORMALIZED) and not requires_manual_review,
            source_object=obj,
        )
        if uid:
            self.object_metadata[uid] = res
        if name:
            self.object_metadata[name] = res

    def resolve(self, ref: Any, domain: Optional[str] = None) -> ResolutionResult:
        """Resolve a reference (dict, UID string, or name) into a typed ResolutionResult."""
        if is_any_object(ref):
            return ResolutionResult(
                resolved=True,
                uid=KNOWN_ANY_UID,
                name="Any",
                object_type="CpmiAnyObject",
                semantic_kind=SemanticKind.SPECIAL_ANY,
                canonical_name="any",
                normalization_status=ExtractionStatus.NORMALIZED,
                requires_manual_review=False,
                usable_in_canonical_reference=True,
            )

        if is_original_object(ref):
            return ResolutionResult(
                resolved=True,
                uid=KNOWN_ORIGINAL_UID,
                name="Original",
                object_type="CpmiOriginalObject",
                semantic_kind=SemanticKind.SPECIAL_ORIGINAL,
                canonical_name="Original",
                normalization_status=ExtractionStatus.NORMALIZED,
                requires_manual_review=False,
                usable_in_canonical_reference=True,
            )

        target_uid: Optional[str] = None
        target_name: Optional[str] = None
        target_type: Optional[str] = None
        inline_obj: Optional[Dict[str, Any]] = None

        if isinstance(ref, dict):
            inline_obj = ref
            target_uid = ref.get("uid")
            target_name = ref.get("name")
            target_type = ref.get("type")
            # Auto-register inline dictionary object
            self.register_object(ref, domain=domain)
        elif isinstance(ref, str):
            if ref in self.by_uid:
                target_uid = ref
            elif (domain, ref) in self.by_domain_and_name or ref in self.by_name:
                target_name = ref
            elif "-" in ref:
                target_uid = ref
            else:
                target_name = ref

        # Lookup in metadata cache first
        if target_uid and target_uid in self.object_metadata:
            return self.object_metadata[target_uid]
        if target_name and target_name in self.object_metadata:
            return self.object_metadata[target_name]

        # Lookup in indexes
        obj: Optional[Dict[str, Any]] = None
        if target_uid and target_uid in self.by_uid:
            obj = self.by_uid[target_uid]
        elif (domain, target_name) in self.by_domain_and_name:
            obj = self.by_domain_and_name[(domain, target_name)]
        elif target_name and target_name in self.by_name:
            obj = self.by_name[target_name]
        elif inline_obj:
            obj = inline_obj

        if not obj:
            return ResolutionResult(
                resolved=False,
                uid=target_uid,
                name=target_name,
                object_type=target_type,
                semantic_kind=SemanticKind.UNKNOWN,
                normalization_status=ExtractionStatus.PARSE_ERROR,
                requires_manual_review=True,
                usable_in_canonical_reference=False,
                reason="unresolved-object-reference",
            )

        uid = obj.get("uid") or target_uid
        name = obj.get("name") or target_name
        obj_type = obj.get("type") or target_type
        kind = infer_semantic_kind(obj_type, name)

        # Default outcome before explicit normalization registration
        usable = kind in (
            SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP,
            SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP,
            SemanticKind.SECURITY_ZONE, SemanticKind.SPECIAL_ANY,
        )

        return ResolutionResult(
            resolved=True,
            uid=uid,
            name=name,
            object_type=obj_type,
            semantic_kind=kind,
            canonical_name=name,
            normalization_status=ExtractionStatus.NORMALIZED if usable else ExtractionStatus.PARTIALLY_NORMALIZED,
            requires_manual_review=not usable,
            usable_in_canonical_reference=usable,
            source_object=obj,
        )

    def resolve_many(self, refs: List[Any], domain: Optional[str] = None) -> List[ResolutionResult]:
        """Resolve a list of references."""
        return [self.resolve(ref, domain=domain) for ref in refs]

    def resolve_action(self, action_ref: Any) -> Tuple[Optional[PolicyAction], ResolutionResult]:
        """Resolve an action reference into canonical PolicyAction and ResolutionResult."""
        action_name: Optional[str] = None
        if isinstance(action_ref, str):
            action_name = action_ref.strip()
        elif isinstance(action_ref, dict):
            action_name = action_ref.get("name") or action_ref.get("type")

        res = self.resolve(action_ref)
        if res.resolved and res.name:
            action_name = res.name

        if not action_name:
            return None, res

        action_name_lower = action_name.strip().lower()
        if action_name_lower == "accept":
            res.resolved = True
            res.name = "Accept"
            res.semantic_kind = SemanticKind.ACTION
            return PolicyAction.ALLOW, res
        elif action_name_lower == "drop":
            res.resolved = True
            res.name = "Drop"
            res.semantic_kind = SemanticKind.ACTION
            return PolicyAction.DROP, res
        elif action_name_lower == "reject":
            res.resolved = True
            res.name = "Reject"
            res.semantic_kind = SemanticKind.ACTION
            return PolicyAction.DENY, res
        else:
            res.requires_manual_review = True
            res.usable_in_canonical_reference = False
            res.name = action_name
            res.reason = f"unsupported-action-{action_name}"
            return None, res

    def is_dependency_safe(
        self,
        ref: Any,
        domain: Optional[str] = None,
        visited: Optional[Set[str]] = None,
    ) -> bool:
        """Recursively verify if an object and all its members are safe for canonical reference."""
        res = self.resolve(ref, domain=domain)
        if not res.resolved or not res.usable_in_canonical_reference or res.requires_manual_review:
            return False

        if visited is None:
            visited = set()

        ref_id = res.uid or res.name or ""
        if ref_id in visited:
            return True
        visited.add(ref_id)

        # If it is a group, check its members
        if res.source_object and res.semantic_kind in (SemanticKind.ADDRESS_GROUP, SemanticKind.SERVICE_GROUP):
            members = res.source_object.get("members", [])
            for member in members:
                if not self.is_dependency_safe(member, domain=domain, visited=visited):
                    return False

        return True
