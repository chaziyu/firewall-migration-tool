"""Reference and dependency resolver for Junos SRX configuration objects."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from fwmigrate.vendors.juniper_srx.model import (
    JuniperAddress,
    JuniperAddressBook,
    JuniperAddressSet,
    JuniperApplication,
    JuniperApplicationSet,
    JuniperContextConfig,
)
from fwmigrate.vendors.juniper_srx.provenance import is_effective_candidate
from fwmigrate.vendors.juniper_srx.builtin_applications import (
    PREDEFINED_APPLICATIONS,
    PREDEFINED_APPLICATION_SETS,
)


class ResolvedAddressReference(BaseModel):
    name: str
    original_name: str
    address_book: str
    is_group: bool = False
    is_builtin_any: bool = False
    builtin_type: Optional[str] = None  # "any", "any-ipv4", "any-ipv6"
    address: Optional[JuniperAddress] = None
    address_set: Optional[JuniperAddressSet] = None
    resolved_members: List[str] = Field(default_factory=list)
    has_cycle: bool = False
    is_unresolved: bool = False


BUILTIN_ADDRESS_KEYWORDS = {
    "any": "any",
    "any-ipv4": "any-ipv4",
    "any-ipv6": "any-ipv6",
}

class JuniperReferenceResolver:
    """Resolves cross-object references according to Junos scope and hierarchy rules."""

    def __init__(self, context: JuniperContextConfig, effective_lookup=None) -> None:
        self.context = context
        self.effective_lookup = effective_lookup
        self.scope = context.name if context.context_type == "root" else f"{context.context_type} {context.name}"
        self._address_set_cache: Dict[Tuple[int, str], Tuple[List[str], bool]] = {}
        self.unverified_applications: Set[str] = set()
        # Precompute zone -> address book attachment map
        self.zone_to_book: Dict[str, str] = {}
        for book_name, book in self.context.address_books.items():
            for z in book.attached_zones:
                self.zone_to_book[z] = book_name

    def resolve_policy_source(
        self, from_zone: Optional[str], reference: str
    ) -> ResolvedAddressReference:
        """Resolve address reference in source of a policy scoped to a zone."""
        return self._resolve_address_in_zone(from_zone, reference)

    def resolve_policy_destination(
        self, to_zone: Optional[str], reference: str
    ) -> ResolvedAddressReference:
        """Resolve address reference in destination of a policy scoped to a zone."""
        return self._resolve_address_in_zone(to_zone, reference)

    def resolve_global_policy(self, reference: str) -> ResolvedAddressReference:
        """Global policies resolve address references strictly against the global address book."""
        return self._resolve_in_book("global", reference)

    def resolve_nat(self, reference: str) -> ResolvedAddressReference:
        """Junos NAT rule address-name references resolve strictly against the global address book."""
        return self._resolve_in_book("global", reference)

    def _resolve_address_in_zone(
        self, zone: Optional[str], reference: str
    ) -> ResolvedAddressReference:
        ref_lower = reference.lower()
        if ref_lower in BUILTIN_ADDRESS_KEYWORDS:
            return ResolvedAddressReference(
                name=reference,
                original_name=reference,
                address_book="global",
                is_builtin_any=True,
                builtin_type=ref_lower,
            )

        # 1. Search attached/zone book if zone is known
        if zone:
            # Check attached book
            attached_book_name = self.zone_to_book.get(zone)
            if zone in self.context.zones and attached_book_name and attached_book_name in self.context.address_books:
                res = self._resolve_in_book(attached_book_name, reference)
                if not res.is_unresolved:
                    return res

            # Check legacy zone-local book: f"zone_{zone}"
            legacy_book_name = f"zone_{zone}"
            if legacy_book_name in self.context.address_books:
                res = self._resolve_in_book(legacy_book_name, reference)
                if not res.is_unresolved:
                    return res

        # 2. Fallback to global address book
        res = self._resolve_in_book("global", reference)
        if not res.is_unresolved:
            return res

        # If not in zone-attached book or global book, address is unresolved in this zone scope
        return ResolvedAddressReference(
            name=reference,
            original_name=reference,
            address_book="unknown",
            is_unresolved=True,
        )

    def _resolve_in_book(
        self, book_name: str, reference: str
    ) -> ResolvedAddressReference:
        ref_lower = reference.lower()
        if ref_lower in BUILTIN_ADDRESS_KEYWORDS:
            return ResolvedAddressReference(
                name=reference,
                original_name=reference,
                address_book=book_name,
                is_builtin_any=True,
                builtin_type=ref_lower,
            )

        book = self.context.address_books.get(book_name)
        if not book:
            if self._effective(("security", "address-book", book_name, "address", reference)):
                return ResolvedAddressReference(name=reference, original_name=reference, address_book=book_name)
            if self._effective(("security", "address-book", book_name, "address-set", reference)):
                return ResolvedAddressReference(name=reference, original_name=reference,
                                                address_book=book_name, is_group=True)
            return ResolvedAddressReference(
                name=reference,
                original_name=reference,
                address_book=book_name,
                is_unresolved=True,
            )

        # Canonical name handling: prefix context if non-root, and book name if non-global book
        if self.context.name != "root":
            canonical_name = (
                f"{self.context.name}__{reference}"
                if book_name == "global"
                else f"{self.context.name}__{book_name}__{reference}"
            )
        else:
            canonical_name = (
                reference if book_name == "global" else f"{book_name}__{reference}"
            )

        # Check address object
        address_path = ("security", "address-book", book_name, "address", reference)
        if (reference in book.addresses and self._object_is_effective(book.addresses[reference])
                and self._explicit_effective(address_path)):
            return ResolvedAddressReference(
                name=canonical_name,
                original_name=reference,
                address_book=book_name,
                is_group=False,
                address=book.addresses[reference],
            )

        if self._effective(("security", "address-book", book_name, "address", reference)):
            return ResolvedAddressReference(name=reference, original_name=reference, address_book=book_name)

        # Check address-set
        set_path = ("security", "address-book", book_name, "address-set", reference)
        if (reference in book.address_sets and self._object_is_effective(book.address_sets[reference])
                and self._explicit_effective(set_path)):
            aset = book.address_sets[reference]
            members, has_cycle = self.expand_address_set(book, reference)
            return ResolvedAddressReference(
                name=canonical_name,
                original_name=reference,
                address_book=book_name,
                is_group=True,
                address_set=aset,
                resolved_members=members,
                has_cycle=has_cycle,
            )

        if self._effective(("security", "address-book", book_name, "address-set", reference)):
            return ResolvedAddressReference(name=reference, original_name=reference, address_book=book_name, is_group=True)

        return ResolvedAddressReference(
            name=reference,
            original_name=reference,
            address_book=book_name,
            is_unresolved=True,
        )

    def expand_address_set(
        self, book: JuniperAddressBook, set_name: str
    ) -> Tuple[List[str], bool]:
        """
        Recursively expand nested address sets with cycle detection.
        Returns (list of member names, has_cycle boolean).
        """
        resolved_members: List[str] = []
        has_cycle = False

        def _dfs(current_set_name: str, active_sets: Set[str]) -> None:
            nonlocal has_cycle
            cache_key = (id(book), current_set_name)
            if current_set_name in active_sets:
                has_cycle = True
                return
            cached = self._address_set_cache.get(cache_key)
            if cached is not None:
                for member in cached[0]:
                    if member not in resolved_members:
                        resolved_members.append(member)
                has_cycle = has_cycle or cached[1]
                return

            aset = book.address_sets.get(current_set_name)
            if not aset:
                return

            branch_members: List[str] = []
            branch_has_cycle = False
            for m in aset.members:
                if not self._member_is_effective(aset, m):
                    continue
                if m.member_type == "address":
                    # Canonical member name
                    if self.context.name != "root":
                        m_canonical = (
                            f"{self.context.name}__{m.name}"
                            if book.name == "global"
                            else f"{self.context.name}__{book.name}__{m.name}"
                        )
                    else:
                        m_canonical = (
                            m.name if book.name == "global" else f"{book.name}__{m.name}"
                        )
                    if m_canonical not in branch_members:
                        branch_members.append(m_canonical)
                elif m.member_type == "address-set":
                    before = len(resolved_members)
                    _dfs(m.name, active_sets | {current_set_name})
                    branch_has_cycle = branch_has_cycle or has_cycle
                    branch_members.extend(
                        member for member in resolved_members[before:]
                        if member not in branch_members
                    )

            if not branch_has_cycle:
                self._address_set_cache[cache_key] = (list(branch_members), False)
            for member in branch_members:
                if member not in resolved_members:
                    resolved_members.append(member)
            has_cycle = has_cycle or branch_has_cycle

        _dfs(set_name, set())
        return resolved_members, has_cycle

    @staticmethod
    def _member_is_effective(parent, member) -> bool:
        history = parent.member_candidate_history.get(member.member_type, [])
        if not history:
            return JuniperReferenceResolver._object_is_effective(member)
        return any(c.value == member.name and is_effective_candidate(c) for c in history)

    def resolve_application(self, reference: str) -> Tuple[bool, bool, Optional[str]]:
        """
        Check if application/application-set reference exists.
        Returns (is_app, is_app_set, canonical_name).
        """
        if reference.lower() in ("any", "junos-any"):
            return False, False, "any"

        if reference.lower() in PREDEFINED_APPLICATIONS:
            return True, False, reference

        if reference.lower() in PREDEFINED_APPLICATION_SETS:
            return False, True, reference

        if reference.lower().startswith("junos-"):
            self.unverified_applications.add(reference)
            return False, False, None

        ctx_prefix = f"{self.context.name}__" if self.context.name != "root" else ""

        if (reference in self.context.applications and self._object_is_effective(self.context.applications[reference])
                and self._explicit_effective(("applications", "application", reference))):
            return True, False, f"{ctx_prefix}{reference}"

        if self._effective(("applications", "application", reference)):
            return True, False, f"{ctx_prefix}{reference}"

        if (reference in self.context.application_sets and self._object_is_effective(self.context.application_sets[reference])
                and self._explicit_effective(("applications", "application-set", reference))):
            return False, True, f"{ctx_prefix}{reference}"

        if self._effective(("applications", "application-set", reference)):
            return False, True, f"{ctx_prefix}{reference}"

        return False, False, None

    def is_unverified_application(self, reference: str) -> bool:
        return reference in self.unverified_applications

    def resolve_scheduler(self, reference: str):
        scheduler = self.context.schedulers.get(reference)
        return scheduler if scheduler and self._object_is_effective(scheduler) else (
            True if self._effective(("schedulers", "scheduler", reference)) else None)

    def resolve_nat_pool(self, reference: str, nat_type: str):
        pools = self.context.nat.source_pools if nat_type == "source" else self.context.nat.destination_pools
        pool = pools.get(reference)
        return pool if pool and self._object_is_effective(pool) else (
            True if self._effective(("security", "nat", nat_type, "pool", reference)) else None)

    def resolve_routing_instance(self, reference: str):
        instance = self.context.routing_instances.get(reference)
        return instance if instance and self._object_is_effective(instance) else (
            True if self._effective(("routing-instances", reference), ("routing-instances", reference, "instance-type")) else None)

    def resolve_interface(self, reference: str):
        interface_path = ("interfaces", reference)
        if "." in reference:
            parent, unit = reference.rsplit(".", 1)
            interface_path = ("interfaces", parent, "unit", unit)
            interface = self.context.interfaces.get(parent)
            if interface and unit in interface.units and self._explicit_effective(interface_path):
                return interface.units[unit]
            if self._effective(interface_path):
                return True
        else:
            interface = self.context.interfaces.get(reference)
            if interface and self._explicit_effective(interface_path):
                return interface
        if self._effective(("interfaces", reference)):
            return True
        return None

    def resolve_zone(self, reference: str):
        path = ("security", "zones", "security-zone", reference)
        zone = self.context.zones.get(reference)
        return zone if zone and self._explicit_effective(path) else (True if self._effective(path) else None)

    def resolve_apbr_named(self, reference: str, kind: str):
        collection = getattr(self.context.apbr, {
            "metrics-profile": "metrics_profiles", "active-probe-params": "active_probe_params",
            "passive-probe-params": "passive_probe_params", "multipath-rule": "multipath_rules",
            "overlay-path": "overlay_paths", "destination-path-group": "destination_path_groups",
            "sla-rule": "sla_rules",
        }.get(kind, ""), {})
        return self._lookup(collection, reference,
                            ("security", "advance-policy-based-routing", kind, reference))

    def resolve_ike_policy(self, reference: str):
        return self._lookup(self.context.vpn.ike_policies, reference, ("security", "ike", "policy", reference))
    def resolve_ike_gateway(self, reference: str):
        return self._lookup(self.context.vpn.ike_gateways, reference, ("security", "ike", "gateway", reference))
    def resolve_ike_proposal(self, reference: str):
        return self._lookup(self.context.vpn.ike_proposals, reference, ("security", "ike", "proposal", reference))
    def resolve_ipsec_policy(self, reference: str):
        return self._lookup(self.context.vpn.ipsec_policies, reference, ("security", "ipsec", "policy", reference))
    def resolve_ipsec_proposal(self, reference: str):
        return self._lookup(self.context.vpn.ipsec_proposals, reference, ("security", "ipsec", "proposal", reference))
    def resolve_ipsec_vpn(self, reference: str):
        return self._lookup(self.context.vpn.ipsec_vpns, reference, ("security", "ipsec", "vpn", reference))
    def resolve_access_profile(self, reference: str):
        return self._lookup(self.context.access_profiles, reference, ("access", "profile", reference))
    def resolve_remote_access_client_config(self, reference: str):
        return self._lookup(self.context.remote_access.client_configs, reference,
                            ("security", "remote-access", "client-config", reference))
    def resolve_apbr_overlay_path(self, reference: str):
        return self._lookup(self.context.apbr.overlay_paths, reference,
                            ("security", "advance-policy-based-routing", "overlay-path", reference))

    def _effective(self, *paths):
        if not self.effective_lookup:
            return False
        if hasattr(self.effective_lookup, "contains_effective_path"):
            return self.effective_lookup.contains_effective_path(self.scope, *paths)
        return bool(self.effective_lookup.contains(self.scope, *paths))

    def _explicit_effective(self, path):
        if not self.effective_lookup or not getattr(self.effective_lookup, "has_source", False):
            return True
        return self.effective_lookup.explicit_object_is_effective(self.scope, path)

    def _lookup(self, collection, reference, path):
        item = collection.get(reference)
        if item and self._object_is_effective(item) and self._explicit_effective(path):
            return item
        return True if self._effective(path) else None

    def resolve_firewall_filter(self, reference: str, family: Optional[str] = None):
        filt = self.context.firewall_filters.get(reference)
        if filt is None or (family and filt.family.lower() != family.lower()):
            return None
        return filt if not filt.source_attributes.get("disabled") else None

    @staticmethod
    def _object_is_effective(obj) -> bool:
        """Reject an object only when its recorded candidates are all non-effective."""
        if getattr(obj, "disabled", None) is True or getattr(obj, "source_attributes", {}).get("disabled"):
            return False
        candidates = [c for history in (
            getattr(obj, "field_candidate_history", {}),
            getattr(obj, "member_candidate_history", {}),
        ) for values in history.values() for c in values]
        return not candidates or any(is_effective_candidate(c) for c in candidates)

    def resolve_named_reference(self, reference: str, collection: dict, path=()) -> Optional[str]:
        """Resolve a typed source-profile reference without inventing a target object."""
        if (reference in collection and self._object_is_effective(collection[reference])
                and self._explicit_effective(path)):
            return f"{self.context.name}__{reference}" if self.context.name != "root" else reference
        if path and self._effective(path):
            return f"{self.context.name}__{reference}" if self.context.name != "root" else reference
        return None

    def resolve_source_profile(self, profile_type: str, reference: str) -> Optional[str]:
        profiles = {
            "idp-policy": (self.context.idp_policies, ("security", "idp", "idp-policy", reference)),
            "utm-policy": (self.context.utm_policies, ("security", "utm", "utm-policy", reference)),
            "ssl-proxy-profile": (self.context.ssl_proxy_profiles, ("services", "ssl", "proxy", "profile", reference)),
            "security-intelligence": (self.context.security_intelligence_profiles,
                                      ("security", "intelligence", "profile", reference)),
        }
        collection, path = profiles.get(profile_type, ({}, ()))
        return self.resolve_named_reference(reference, collection, path)

    def resolve_reth_cluster(self, interface_name: str) -> Dict[str, Optional[str]]:
        """Resolve physical interface -> reth -> redundancy group without guessing."""
        physical = self.context.interfaces.get(interface_name)
        reth_name = physical.redundant_parent if physical else None
        reth = self.context.interfaces.get(reth_name) if reth_name else None
        return {
            "physical_interface": interface_name,
            "reth_interface": reth_name,
            "redundancy_group": reth.redundancy_group if reth else None,
        }
