"""Check Point centralized object and reference resolver with semantic typing."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import PolicyAction

KNOWN_ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
KNOWN_ORIGINAL_UID = "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"


def normalize_domain_identity(domain: Any) -> Tuple[Optional[str], Optional[str]]:
    """Return a domain UID and name without retaining mutable API structures."""
    if isinstance(domain, dict):
        uid = domain.get("uid") or domain.get("domain-uid") or domain.get("domain_uid")
        name = domain.get("name")
        return (str(uid) if uid is not None else None, str(name) if name is not None else None)
    return (None, str(domain) if domain is not None else None)


def iter_dictionary_objects(
    objects_dict: Any,
) -> Iterable[Dict[str, Any]]:
    """Yield dictionary objects, preserving a UID supplied as the map key."""
    if isinstance(objects_dict, dict):
        for key, item in objects_dict.items():
            if not isinstance(item, dict):
                continue
            normalized = dict(item)
            if not normalized.get("uid") and key:
                normalized["uid"] = str(key)
            yield normalized
    elif isinstance(objects_dict, list):
        for item in objects_dict:
            if isinstance(item, dict):
                yield dict(item)


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


def is_any_object(obj: Any, *, allow_symbolic_name: bool = True) -> bool:
    """Return True if the object or reference represents Check Point Any."""
    if obj is None:
        return False
    if isinstance(obj, str):
        return obj == KNOWN_ANY_UID or (allow_symbolic_name and obj.strip().lower() == "any")
    if isinstance(obj, dict):
        obj_type = str(obj.get("type", "")).strip()
        uid = str(obj.get("uid", "")).strip()
        name = str(obj.get("name", "")).strip()
        return (
            obj_type == "CpmiAnyObject"
            or (uid == KNOWN_ANY_UID and name == "Any")
            or uid == KNOWN_ANY_UID
        )
    return False


def is_original_object(obj: Any, *, allow_symbolic_name: bool = True) -> bool:
    """Return True if the object represents Check Point NAT Original."""
    if obj is None:
        return False
    if isinstance(obj, str):
        return obj == KNOWN_ORIGINAL_UID or (allow_symbolic_name and obj.strip().lower() == "original")
    if isinstance(obj, dict):
        obj_type = str(obj.get("type", "")).strip()
        uid = str(obj.get("uid", "")).strip()
        name = str(obj.get("name", "")).strip()
        return (
            obj_type == "CpmiOriginalObject"
            or uid == KNOWN_ORIGINAL_UID
        )
    return False


def infer_semantic_kind(obj_type: Optional[str], name: Optional[str]) -> SemanticKind:
    """Infer high-level semantic kind from Check Point type name."""
    if not obj_type and not name:
        return SemanticKind.UNKNOWN

    t = (obj_type or "").strip().lower()
    n = (name or "").strip().lower()

    if t == "cpmianyobject" or (not t and n == "any"):
        return SemanticKind.SPECIAL_ANY
    if t == "cpmioriginalobject" or (not t and n == "original"):
        return SemanticKind.SPECIAL_ORIGINAL

    if t in ("host", "network", "address-range", "multicast-address-range", "wildcard"):
        return SemanticKind.ADDRESS
    if t in ("group", "group-with-exclusion"):
        return SemanticKind.ADDRESS_GROUP
    if t == "security-zone":
        return SemanticKind.SECURITY_ZONE
    if t in (
        "service-tcp", "service-udp", "service-sctp", "service-icmp", "service-icmp6",
        "service-other", "service-dce-rpc", "service-rpc", "service-gtp",
        "service-compound-tcp", "service-citrix-tcp",
    ):
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
    if t in ("track", "rulebasetrack", "trackobject"):
        return SemanticKind.TRACK
    if t in (
        "checkpointgateway", "checkpointcluster", "simplegateway", "simplecluster",
        "simple-gateway", "simple-cluster", "checkpoint-gateway", "checkpoint-cluster",
        "gateway", "cluster",
    ):
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
    canonical_names: List[str] = Field(default_factory=list)
    normalization_status: ExtractionStatus = ExtractionStatus.EXTRACT_ONLY
    requires_manual_review: bool = False
    usable_in_canonical_reference: bool = False
    source_object: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class CheckPointObjectResolver:
    """Centralized resolver for Check Point UIDs, names, and dictionary entries."""

    def __init__(self):
        self.by_uid: Dict[str, Dict[str, Any]] = {}
        self.by_domain_and_uid: Dict[Tuple[Optional[str], str], Dict[str, Any]] = {}
        self.by_domain_and_name: Dict[Tuple[Optional[str], str], Dict[str, Any]] = {}
        self.by_name: Dict[str, Dict[str, Any]] = {}
        self.name_domains: Dict[str, Set[Optional[str]]] = {}
        self.object_metadata: Dict[str, ResolutionResult] = {}
        self.metadata_by_uid: Dict[str, ResolutionResult] = {}
        self.metadata_by_domain_uid: Dict[Tuple[Optional[str], str], ResolutionResult] = {}
        self.metadata_by_domain_name: Dict[Tuple[Optional[str], str], ResolutionResult] = {}
        self.automatic_nat_metadata: Dict[str, Dict[str, Any]] = {}
        self.automatic_nat_metadata_by_domain: Dict[Tuple[Optional[str], str], Dict[str, Any]] = {}
        self.conflicting_uid_definitions: Dict[str, List[Dict[str, Any]]] = {}
        self.object_domain_by_uid: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
        self.global_assignments: Dict[Tuple[Optional[str], Optional[str]], Set[str]] = {}
        self._active_domain_uid: Optional[str] = None
        self._active_domain_name: Optional[str] = None

    def set_active_scope(self, domain_uid: Optional[str], domain_name: Optional[str]) -> None:
        self._active_domain_uid = domain_uid
        self._active_domain_name = domain_name

    def register_global_assignment(
        self,
        target_domain_uid: Optional[str],
        target_domain_name: Optional[str],
        object_refs: Iterable[Any],
    ) -> None:
        """Allow only explicitly assigned global objects into a local scope."""
        target = (target_domain_uid, target_domain_name)
        assigned = self.global_assignments.setdefault(target, set())
        for ref in object_refs:
            if isinstance(ref, dict):
                ref = ref.get("uid") or ref.get("name")
            if ref:
                assigned.add(str(ref))

    def register_object(self, obj: Dict[str, Any], domain: Any = None, domain_uid: Any = None) -> None:
        """Register a single Check Point object dictionary into resolution indexes."""
        if not isinstance(obj, dict):
            return
        uid = obj.get("uid")
        name = obj.get("name")
        obj_domain_uid, obj_domain = normalize_domain_identity(obj.get("domain"))
        explicit_obj_uid = normalize_domain_identity(
            obj.get("domain-uid") or obj.get("domain_uid")
        )[0]
        fallback_uid = (
            str(domain_uid)
            if isinstance(domain_uid, (str, int))
            else normalize_domain_identity(domain_uid)[0]
        )
        fallback_name_from_domain = normalize_domain_identity(domain)[1]
        obj_domain_uid = obj_domain_uid or explicit_obj_uid or fallback_uid
        obj_domain = obj_domain or fallback_name_from_domain
        domain_keys = {key for key in (obj_domain_uid, obj_domain) if isinstance(key, str)}

        if uid:
            uid = str(uid)
            self.object_domain_by_uid.setdefault(uid, (obj_domain_uid, obj_domain))
            prior = self.by_uid.get(uid)
            if prior is not None and prior != obj:
                definitions = self.conflicting_uid_definitions.setdefault(uid, [prior])
                if obj not in definitions:
                    definitions.append(obj)
            elif prior is None:
                self.by_uid[uid] = obj
            for domain_key in domain_keys:
                self.by_domain_and_uid[(domain_key, uid)] = obj

        if name:
            s_name = str(name)
            for domain_key in domain_keys:
                self.by_domain_and_name[(domain_key, s_name)] = obj
            domains = self.name_domains.setdefault(s_name, set())
            domains.add(obj_domain)
            if len(domains) == 1:
                self.by_name[s_name] = obj
            else:
                self.by_name.pop(s_name, None)

        nat_settings = obj.get("nat-settings")
        if isinstance(nat_settings, dict):
            metadata = dict(nat_settings)
            nat_domain_keys = domain_keys or {None}
            if uid:
                self.automatic_nat_metadata[str(uid)] = metadata
                for domain_key in nat_domain_keys:
                    self.automatic_nat_metadata_by_domain[(domain_key, str(uid))] = metadata
            if name:
                self.automatic_nat_metadata[str(name)] = metadata
                for domain_key in nat_domain_keys:
                    self.automatic_nat_metadata_by_domain[(domain_key, str(name))] = metadata

    def object_domain(self, uid: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        return self.object_domain_by_uid.get(str(uid), (None, None)) if uid else (None, None)

    def _object_matches_scope(
        self, obj: Optional[Dict[str, Any]], domain_uid: Optional[str], domain: Optional[str]
    ) -> bool:
        if not obj:
            return False
        owner_uid, owner_name = self.object_domain(obj.get("uid"))
        if owner_uid or owner_name:
            return owner_uid == domain_uid or owner_name == domain
        return domain in (None, "global") and domain_uid is None

    def register_dictionary(
        self,
        objects_dict: Union[List[Dict[str, Any]], Dict[str, Dict[str, Any]]],
        domain: Optional[str] = None,
        canonical_names: Optional[List[str]] = None,
    ) -> None:
        """Register an objects-dictionary structure from an API response."""
        for item in iter_dictionary_objects(objects_dict):
            self.register_object(item, domain=domain)

    def get_automatic_nat_metadata(
        self,
        ref: Any,
        domain: Optional[str] = None,
        *,
        domain_uid: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return native object NAT settings correlated by UID or name."""
        resolution = self.resolve_scoped(ref, domain_uid=domain_uid, domain_name=domain)
        for key in (resolution.uid, resolution.name):
            if key and domain_uid and (domain_uid, key) in self.automatic_nat_metadata_by_domain:
                return dict(self.automatic_nat_metadata_by_domain[(domain_uid, key)])
            if key and domain and (domain, key) in self.automatic_nat_metadata_by_domain:
                return dict(self.automatic_nat_metadata_by_domain[(domain, key)])
            if key and domain == "global" and (None, key) in self.automatic_nat_metadata_by_domain:
                return dict(self.automatic_nat_metadata_by_domain[(None, key)])
            if key and domain is None and (None, key) in self.automatic_nat_metadata_by_domain:
                return dict(self.automatic_nat_metadata_by_domain[(None, key)])
            if key and domain is None and ("global", key) in self.automatic_nat_metadata_by_domain:
                return dict(self.automatic_nat_metadata_by_domain[("global", key)])
        return None

    def set_object_normalization(
        self,
        uid_or_name: str,
        canonical_name: Optional[str],
        status: ExtractionStatus,
        requires_manual_review: bool = False,
        usable: bool = True,
        semantic_kind: Optional[SemanticKind] = None,
        domain: Optional[str] = None,
        canonical_names: Optional[List[str]] = None,
    ) -> None:
        """Record the normalization outcome of an object for dependency tracking."""
        obj = self.by_domain_and_uid.get((domain, uid_or_name)) or self.by_uid.get(uid_or_name) or self.by_domain_and_name.get((domain, uid_or_name)) or self.by_name.get(uid_or_name)
        obj_domain = (obj.get("domain") if obj else None) or domain
        uid = obj.get("uid") if obj else (uid_or_name if "-" in uid_or_name else None)
        name = obj.get("name") if obj else uid_or_name
        obj_type = obj.get("type") if obj else None
        kind = semantic_kind or infer_semantic_kind(obj_type, name)
        if canonical_names is None and obj and name and str(obj_type).lower() in {"host", "network", "address-range"}:
            has_v4 = any(obj.get(key) for key in ("ipv4-address", "ipv4_address", "subnet4", "subnet", "ipv4-address-first"))
            has_v6 = any(obj.get(key) for key in ("ipv6-address", "ipv6_address", "subnet6", "ipv6-address-first"))
            if has_v4 and has_v6:
                canonical_names = [f"{name}__ipv4", f"{name}__ipv6"]

        res = ResolutionResult(
            resolved=True,
            uid=uid,
            name=name,
            object_type=obj_type,
            semantic_kind=kind,
            canonical_name=(canonical_name or name) if len(canonical_names or []) <= 1 else None,
            canonical_names=list(canonical_names or ([canonical_name or name] if canonical_name or name else [])),
            normalization_status=status,
            requires_manual_review=requires_manual_review,
            usable_in_canonical_reference=usable and (status == ExtractionStatus.NORMALIZED) and not requires_manual_review,
            source_object=obj,
        )
        if uid:
            self.object_metadata[uid] = res
            self.metadata_by_uid[uid] = res
            self.metadata_by_domain_uid[(obj_domain, uid)] = res
        if name:
            self.metadata_by_domain_name[(obj_domain, name)] = res
            if len(self.name_domains.get(name, {obj_domain})) == 1:
                self.object_metadata[name] = res
            else:
                self.object_metadata.pop(name, None)

    def resolve(
        self,
        ref: Any,
        domain: Optional[str] = None,
        *,
        domain_uid: Optional[str] = None,
        allow_special_symbolic_names: bool = False,
        strict_scope: bool = False,
        allow_global_assignment: bool = True,
    ) -> ResolutionResult:
        """Resolve a reference (dict, UID string, or name) into a typed ResolutionResult."""
        if domain_uid is None and domain is not None and domain == self._active_domain_name:
            domain_uid = self._active_domain_uid
        strict_scope = strict_scope or domain is not None or domain_uid is not None
        scope_keys = [scope for scope in (domain_uid, domain) if scope is not None]
        if strict_scope and domain_uid is None and domain == "global":
            scope_keys.append(None)
        if not strict_scope:
            scope_keys = list(dict.fromkeys(scope_keys))
        assigned_global_refs = set()
        if strict_scope and allow_global_assignment:
            for target, refs in self.global_assignments.items():
                if (domain_uid, domain) == target or any(
                    value is not None and value in target for value in (domain_uid, domain)
                ):
                    assigned_global_refs.update(refs)
        registered_symbolic_name = isinstance(ref, str) and (
            any((scope, ref) in self.by_domain_and_name for scope in scope_keys)
            or (not strict_scope and ref in self.by_name)
        )
        if is_any_object(
            ref, allow_symbolic_name=allow_special_symbolic_names
        ) and not registered_symbolic_name:
            return ResolutionResult(
                resolved=True,
                uid=KNOWN_ANY_UID,
                name="Any",
                object_type="CpmiAnyObject",
                semantic_kind=SemanticKind.SPECIAL_ANY,
                canonical_name="any",
                canonical_names=["any"],
                normalization_status=ExtractionStatus.NORMALIZED,
                requires_manual_review=False,
                usable_in_canonical_reference=True,
            )

        if is_original_object(
            ref, allow_symbolic_name=allow_special_symbolic_names
        ) and not registered_symbolic_name:
            return ResolutionResult(
                resolved=True,
                uid=KNOWN_ORIGINAL_UID,
                name="Original",
                object_type="CpmiOriginalObject",
                semantic_kind=SemanticKind.SPECIAL_ORIGINAL,
                canonical_name="Original",
                canonical_names=["Original"],
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
            self.register_object(ref, domain=domain, domain_uid=domain_uid)
        elif isinstance(ref, str):
            if ref in self.by_uid:
                target_uid = ref
            elif any((scope, ref) in self.by_domain_and_name for scope in scope_keys) or ref in self.by_name:
                target_name = ref
            elif ref in self.name_domains and len(self.name_domains[ref]) > 1:
                return ResolutionResult(
                    resolved=False, name=ref, semantic_kind=SemanticKind.UNKNOWN,
                    normalization_status=ExtractionStatus.PARSE_ERROR,
                    requires_manual_review=True, usable_in_canonical_reference=False,
                    reason="ambiguous-cross-domain-object-reference",
                )
            elif "-" in ref:
                target_uid = ref
            else:
                target_name = ref

        # Lookup in metadata cache first
        for scope in scope_keys:
            if target_uid and (scope, target_uid) in self.metadata_by_domain_uid:
                return self.metadata_by_domain_uid[(scope, target_uid)]
        if strict_scope and target_uid and target_uid in assigned_global_refs:
            global_result = self.metadata_by_uid.get(target_uid)
            if global_result:
                return global_result
        if (not strict_scope or self._object_matches_scope(self.by_uid.get(target_uid), domain_uid, domain)) and target_uid and target_uid not in self.conflicting_uid_definitions and target_uid in self.metadata_by_uid:
            return self.metadata_by_uid[target_uid]
        for scope in scope_keys:
            if target_name and (scope, target_name) in self.metadata_by_domain_name:
                return self.metadata_by_domain_name[(scope, target_name)]
        if strict_scope and target_name and target_name in assigned_global_refs:
            global_result = self.object_metadata.get(target_name)
            if global_result:
                return global_result
        if (not strict_scope or self._object_matches_scope(self.by_name.get(target_name), domain_uid, domain)) and target_name and target_name in self.object_metadata:
            return self.object_metadata[target_name]

        # Lookup in indexes
        obj: Optional[Dict[str, Any]] = None
        for scope in scope_keys:
            if target_uid and (scope, target_uid) in self.by_domain_and_uid:
                obj = self.by_domain_and_uid[(scope, target_uid)]
                break
        if strict_scope and obj is None and target_uid and target_uid in assigned_global_refs:
            obj = self.by_uid.get(target_uid)
        if (not strict_scope or self._object_matches_scope(self.by_uid.get(target_uid), domain_uid, domain)) and obj is None and target_uid and target_uid in self.by_uid and target_uid not in self.conflicting_uid_definitions:
            obj = self.by_uid[target_uid]
        if obj is None and target_name:
            for scope in scope_keys:
                if (scope, target_name) in self.by_domain_and_name:
                    obj = self.by_domain_and_name[(scope, target_name)]
                    break
        if strict_scope and obj is None and target_name and target_name in assigned_global_refs:
            obj = self.by_name.get(target_name)
        if (not strict_scope or self._object_matches_scope(self.by_name.get(target_name), domain_uid, domain)) and obj is None and target_name and target_name in self.by_name:
            obj = self.by_name[target_name]
        if obj is None and inline_obj:
            obj = inline_obj

        if not obj:
            blocked = strict_scope and (
                (target_uid and target_uid in self.by_uid)
                or (target_name and target_name in self.name_domains)
            )
            return ResolutionResult(
                resolved=False,
                uid=target_uid,
                name=target_name,
                object_type=target_type,
                semantic_kind=SemanticKind.UNKNOWN,
                normalization_status=ExtractionStatus.PARSE_ERROR,
                requires_manual_review=True,
                usable_in_canonical_reference=False,
                reason=(
                    "cross-domain-reference-resolution-blocked"
                    if blocked else "unresolved-object-reference"
                ),
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
            canonical_names=[name] if name else [],
            normalization_status=ExtractionStatus.NORMALIZED if usable else ExtractionStatus.PARTIALLY_NORMALIZED,
            requires_manual_review=not usable,
            usable_in_canonical_reference=usable,
                source_object=obj,
        )

    def resolve_scoped(
        self,
        ref: Any,
        domain_uid: Optional[str] = None,
        domain_name: Optional[str] = None,
        *,
        allow_global_assignment: bool = True,
        allow_special_symbolic_names: bool = False,
    ) -> ResolutionResult:
        """Resolve policy references without crossing ordinary domain boundaries."""
        if not allow_global_assignment:
            return self.resolve(
                ref, domain=domain_name, domain_uid=domain_uid,
                allow_special_symbolic_names=allow_special_symbolic_names,
                strict_scope=True, allow_global_assignment=False,
            )
        return self.resolve(
            ref, domain=domain_name, domain_uid=domain_uid,
            allow_special_symbolic_names=allow_special_symbolic_names,
            strict_scope=True,
        )

    def resolve_many(self, refs: List[Any], domain: Optional[str] = None) -> List[ResolutionResult]:
        """Resolve a list of references."""
        return [self.resolve(ref, domain=domain) for ref in refs]

    def resolve_action(self, action_ref: Any, domain: Optional[str] = None) -> Tuple[Optional[PolicyAction], ResolutionResult]:
        """Resolve an action reference into canonical PolicyAction and ResolutionResult."""
        action_name: Optional[str] = None
        if isinstance(action_ref, str):
            action_name = action_ref.strip()
        elif isinstance(action_ref, dict):
            action_name = action_ref.get("name") or action_ref.get("type")

        res = self.resolve(action_ref, domain=domain)
        if res.resolved and res.name:
            action_name = res.name

        if res.resolved and res.source_object and res.semantic_kind != SemanticKind.ACTION:
            res.resolved = False
            res.requires_manual_review = True
            res.usable_in_canonical_reference = False
            res.reason = "invalid-action-object-type"
            return None, res

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
            return False
        visited.add(ref_id)

        # If it is a group, check its members
        if res.source_object and res.semantic_kind in (SemanticKind.ADDRESS_GROUP, SemanticKind.SERVICE_GROUP):
            members = res.source_object.get("members", [])
            for member in members:
                if not self.is_dependency_safe(member, domain=domain, visited=visited):
                    return False

        return True
